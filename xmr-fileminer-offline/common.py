#!/usr/bin/env python3
"""
common.py -- shared helpers for xmr-fileminer.

Everything in this file is *protocol truth* for Monero / RandomX stratum mining.
It was verified against the xmrig source tree (src/base/net/stratum/Job.cpp,
Client.cpp, Job.h):

  * The block hashing blob has the 4-byte nonce at byte offset 39, and the
    nonce bytes stored in the blob are the little-endian encoding of the
    nonce integer (xmrig: memcpy of a uint32_t into nonceOffset()).
  * A pool "target" that is 8 hex chars long is interpreted as a LITTLE-ENDIAN
    u32:  target_u32 = t[0] | t[1]<<8 | t[2]<<16 | t[3]<<24
    (xmrig Job::setTarget -> *(const uint32_t*)raw).
  * A RandomX hash H satisfies the target iff:
        H[31] == 0   and   u32_le(H[28..31]) <= target_u32
    Note the H[31] == 0 gate: it is NOT optional. It is why a share is only
    possible for 1 in 256 hashes even with the easiest possible target.
  * "difficulty" as pools report it: shares with hash u32 == x are
    approximately as hard as difficulty 2^32 / x.  Effective pool difficulty
    for a target_u32 is therefore ~ 2^32 / (target_u32 + 1) -- but the share
    probability is exactly (target_u32 + 1) / 2^32 * (1/256) per hash, and
    that is what this project uses for share accounting (exact, no bias).

Nothing here does any network I/O.
"""

from __future__ import annotations

import contextlib
import os
import re
import sys
import time
from dataclasses import dataclass, field
import logging

# --------------------------------------------------------------------------
# Protocol constants
# --------------------------------------------------------------------------
NONCE_OFFSET = 39          # byte offset of the nonce inside the hashing blob
NONCE_SIZE = 4             # Monero uses a 4-byte nonce
HASH_SIZE = 32
MIN_BLOB_BYTES = 44        # NONCE_OFFSET + NONCE_SIZE, with room to spare
MAX_BLOB_BYTES = 253       # RandomX input size limit used by all miner software
SEED_HEX_LEN = 64          # 32-byte RandomX key (block template hash)

U32_MAX = 0xFFFFFFFF
U32_SIZE = 0x100000000

# xmrig-style "nicehash" jobs only give the miner 3 bytes of nonce (byte 42 is
# owned by the pool/template).  We support those jobs honestly via a nonce mask.
NICEHASH_MASK = 0x00FFFFFF


class JobError(Exception):
    """job.txt is missing, malformed, or incomplete."""


# --------------------------------------------------------------------------
# Small utilities
# --------------------------------------------------------------------------
def now_ts() -> float:
    return time.time()


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fmt_diff(value: float | int) -> str:
    if value >= 1e9:
        return f"{value:.3e}"
    if value >= 1e6:
        return f"{value/1e6:.3f}M"
    if value >= 1e3:
        return f"{value/1e3:.3f}k"
    if value >= 10:
        return f"{value:.1f}"
    return f"{value:.3f}"


def parse_bool(value, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on", "y")


def hex_to_bytes(hexstr: str, what: str = "hex field") -> bytes:
    s = (hexstr or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    s = re.sub(r"\s+", "", s)
    if not s or len(s) % 2:
        raise JobError(f"{what}: expected an even-length hex string, got {len(s)} chars")
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise JobError(f"{what}: invalid hex: {exc}") from None


def bytes_to_hex(b: bytes) -> str:
    return b.hex()


# --------------------------------------------------------------------------
# Target <-> difficulty math (protocol exact)
# --------------------------------------------------------------------------
def target_u32_from_be(hexstr: str) -> int:
    """Convert the pool's target hex string to the comparable u32.

    Accepts 8 hex chars (standard Monero) or 16 hex chars (8-byte target used
    by some Yada-style pools; we take the high 4 bytes and warn).
    """
    raw = hex_to_bytes(hexstr, "target")
    if len(raw) == 4:
        return raw[0] | (raw[1] << 8) | (raw[2] << 16) | (raw[3] << 24)
    if len(raw) == 8:
        # 64-bit target: keep the upper 32 bits (finer granularity, same order).
        u64 = int.from_bytes(raw, "little")
        return (u64 >> 32) & U32_MAX
    raise JobError(f"target: expected 4 or 8 bytes of hex, got {len(raw)}")


def target_be_from_u32(u32: int) -> str:
    """Inverse of target_u32_from_be (for demo/testing pools)."""
    u32 &= U32_MAX
    raw = bytes((u32 & 0xFF, (u32 >> 8) & 0xFF, (u32 >> 16) & 0xFF, (u32 >> 24) & 0xFF))
    return raw.hex()


def diff_from_target_u32(u32: int) -> float:
    """Pool-style difficulty implied by a target u32 (2^32 / target)."""
    if u32 == 0:
        return float(U32_SIZE)
    return U32_SIZE / u32


def target_u32_from_diff(diff: float) -> int:
    """Inverse: the target u32 a pool would hand out for `diff`."""
    if diff <= 0:
        raise ValueError("difficulty must be > 0")
    u32 = int(U32_MAX / diff)
    return max(1, min(U32_MAX, u32))


def hash_u32(hash32: bytes) -> int:
    """The 4 bytes the pool compares against the target (little-endian)."""
    return (
        hash32[28] | (hash32[29] << 8) | (hash32[30] << 16) | (hash32[31] << 24)
    )


def hash_meets_target(hash32: bytes, target_u32: int, protocol_gate: bool = True) -> bool:
    """True if this RandomX hash is a valid share for target_u32.

    protocol_gate=True is the REAL rule (and must stay True for anything that
    is submitted anywhere).  protocol_gate=False skips the H[31] == 0
    requirement and exists ONLY to smoke-test the file/share plumbing quickly;
    it is exposed behind --test-ignore-byte31 and never used by default.
    """
    if len(hash32) != HASH_SIZE:
        raise ValueError("hash must be 32 bytes")
    if protocol_gate and hash32[31] != 0:
        return False
    return hash_u32(hash32) <= target_u32 & U32_MAX


def diff_of_hash(hash32: bytes) -> float:
    """xmrig-compatible "actual difficulty" of a hash: ~2^32 / u32_le(H[28:32])."""
    return U32_SIZE / max(1, hash_u32(hash32))


def nonce_le_bytes(u32: int) -> bytes:
    return (u32 & U32_MAX).to_bytes(4, "little")


def nonce_le_hex(u32: int) -> str:
    """The exact string xmrig puts into the stratum 'nonce' field."""
    return nonce_le_bytes(u32).hex()


def nonce_from_le_hex(s: str) -> int:
    return int.from_bytes(hex_to_bytes(s, "nonce"), "little")


# --------------------------------------------------------------------------
# job.txt  <->  Job object
# --------------------------------------------------------------------------
@dataclass
class Job:
    algo: str = "randomx"
    url: str = ""
    user: str = ""
    job_id: str = ""
    target_hex: str = ""
    target_u32: int | None = None      # derived from target_hex when not given
    height: str = ""
    seed_hex: str = ""
    blob_hex: str = ""
    nicehash: bool = False
    demo: bool = False
    updated: float = 0.0
    source: str = ""
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Never let a Job carrying a target_hex have a stale/missing target_u32:
        # that mismatch would silently break share acceptance.
        if self.target_u32 is None:
            self.target_u32 = target_u32_from_be(self.target_hex) if self.target_hex else U32_MAX
        if self.target_hex:
            self.target_hex = self.target_hex.strip().lower()

    # -- derived -----------------------------------------------------------
    @property
    def blob(self) -> bytes:
        return bytes.fromhex(self.blob_hex)

    @property
    def seed(self) -> bytes:
        return bytes.fromhex(self.seed_hex)

    @property
    def nonce_mask(self) -> int:
        return NICEHASH_MASK if self.nicehash else U32_MAX

    @property
    def eff_diff(self) -> float:
        """Expected hashes per share, for THIS miner's acceptance rule.

        For real pool targets (target_u32 < 2^24, i.e. pool diff > 256) this is
        exactly 2^32 / (target + 1), matching the pool's own check. For
        ultra-easy targets the explicit H[31] == 0 check makes this miner
        stricter than the pool (1/256 as many candidates), so the honest
        figure is 2^40 / (target + 1).
        """
        denom = self.target_u32 + 1
        if self.target_u32 >= (1 << 24):
            return (1 << 40) / denom
        return U32_SIZE / denom

    def signature(self) -> tuple:
        """Identity used to detect 'this is a new job' (any change => restart)."""
        return (self.seed_hex, self.blob_hex, self.target_u32, self.job_id)

    def blob_with_nonce(self, nonce_u32: int) -> bytes:
        """Blob with `nonce_u32` placed at the protocol offset (LE bytes)."""
        b = bytearray(self.blob)
        if len(b) < NONCE_OFFSET + NONCE_SIZE:
            raise JobError("blob too short for a 4-byte nonce at offset 39")
        b[NONCE_OFFSET:NONCE_OFFSET + NONCE_SIZE] = nonce_le_bytes(nonce_u32 & self.nonce_mask)
        return bytes(b)

    def summary(self) -> str:
        return (
            f"job={self.job_id or '?'} algo={self.algo} h={self.height or '?'} "
            f"target={self.target_hex} (~diff {fmt_diff(diff_from_target_u32(self.target_u32))}) "
            f"blob={len(self.blob)}B seed={self.seed_hex[:12]}... "
            f"{'DEMO ' if self.demo else ''}{'nicehash ' if self.nicehash else ''}"
            f"from {self.source}"
        )


_KV_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*[:=]\s*(.*?)\s*$")
_SECTION_RE = re.compile(r"^\s*\[([A-Za-z0-9_.-]+)\]\s*$")


def _parse_kv(text: str) -> tuple[dict, dict]:
    """Parse our job/share file format: key=value lines + [section] blocks.

    Sections other than [blob]/[blob_prev] are just namespacing; keys inside
    them are flattened into the same dict (sections are for humans).
    """
    kv: dict[str, str] = {}
    sections: dict[str, list[str]] = {}
    current = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        m = _SECTION_RE.match(line)
        if m:
            current = m.group(1).lower()
            sections.setdefault(current, [])
            continue
        # strip trailing comments introduced by whitespace + '#'
        line = re.sub(r"\s+#.*$", "", line)
        if line.lstrip().startswith("#"):
            continue
        m = _KV_RE.match(line)
        if m and current not in ("blob", "blob_prev"):
            kv[m.group(1).lower()] = m.group(2).strip()
        elif current:
            text = line.strip()
            if current in ("blob", "blob_prev"):
                # inside a hex section only hex may appear (a stray key=value
                # here would otherwise be glued onto the blob and corrupt it)
                if not re.fullmatch(r"[0-9a-fA-F]+", text):
                    continue
            sections[current].append(text)
    return kv, sections


def load_job_text(text: str, source: str = "job.txt") -> Job:
    kv, sections = _parse_kv(text)

    blob_hex = kv.get("blob", "")
    if not blob_hex and "blob" in sections:
        blob_hex = "".join(sections["blob"])

    seed_hex = kv.get("seed") or kv.get("seed_hash") or kv.get("seedhash") or ""
    target_hex = kv.get("target") or kv.get("target_hex") or kv.get("targethex") or ""

    if not blob_hex:
        raise JobError(f"{source}: missing 'blob' (the block hashing blob in hex)")
    if not seed_hex:
        raise JobError(f"{source}: missing 'seed' (64-hex RandomX key = block template hash)")
    if not target_hex:
        raise JobError(f"{source}: missing 'target' (pool target hex)")

    blob = hex_to_bytes(blob_hex, "blob")
    if not (MIN_BLOB_BYTES <= len(blob) <= MAX_BLOB_BYTES):
        raise JobError(
            f"{source}: blob is {len(blob)} bytes; expected {MIN_BLOB_BYTES}..{MAX_BLOB_BYTES}. "
            f"(Monero hashing blobs are typically 76-84 bytes.)"
        )
    if len(hex_to_bytes(seed_hex, "seed")) != 32:
        raise JobError(f"{source}: 'seed' must be 64 hex chars (32 bytes)")

    job = Job(
        algo=kv.get("algo", "randomx"),
        url=kv.get("url", ""),
        user=kv.get("user", kv.get("login", "")),
        job_id=kv.get("job_id", kv.get("jobid", "")),
        target_hex=re.sub(r"\s+", "", target_hex).lower(),
        target_u32=target_u32_from_be(target_hex),
        height=kv.get("height", ""),
        seed_hex=re.sub(r"\s+", "", seed_hex).lower(),
        blob_hex=blob.hex(),
        nicehash=parse_bool(kv.get("nicehash"), False),
        demo=parse_bool(kv.get("demo"), False),
        updated=float(kv["updated"]) if kv.get("updated", "").replace(".", "", 1).isdigit() else 0.0,
        source=source,
        extra={k: v for k, v in kv.items() if k in ("sig", "commitment", "pass")},
    )
    return job


def load_job(path: str) -> Job:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return load_job_text(fh.read(), source=os.path.basename(path))
    except FileNotFoundError:
        raise JobError(f"{path}: not found") from None


def render_job_text(job: Job) -> str:
    """Serialize a Job back to the job.txt text format."""
    lines = [
        "# xmr-fileminer job file -- written atomically by pool_bridge.py/demo_job.py",
        "# The miner never talks to the network; it only reads this file.",
        "version=1",
        f"algo={job.algo}",
        f"url={job.url}",
        f"user={job.user}",
        f"job_id={job.job_id}",
        f"target={job.target_hex}",
        f"height={job.height}",
        f"seed={job.seed_hex}",
        f"nicehash={1 if job.nicehash else 0}",
        f"demo={1 if job.demo else 0}",
        f"updated={job.updated or now_ts():.3f}",
    ]
    # pass-through fields (sig/commitment for pools that use them) go HERE,
    # in the header -- never below, where they would be mistaken for blob hex.
    for k, v in (job.extra or {}).items():
        if v:
            lines.append(f"{k}={v}")
    lines += [
        "",
        "# The exact block hashing blob the pool sent (pool's blob, nonce bytes relevant",
        "# [39..42] are overwritten by the miner per hash attempt).",
        "[blob]",
        job.blob_hex,
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# shares.txt  <->  share records
# --------------------------------------------------------------------------
def make_share_record(job: Job, nonce_u32: int, hash_hex: str, diff: float,
                      engine: str, qualified: bool = True) -> dict:
    return {
        "job_id": job.job_id,
        "algo": job.algo,
        "nonce": nonce_le_hex(nonce_u32),          # LE hex == blob bytes at offset 39
        "nonce_u32": str(nonce_u32 & U32_MAX),     # same value, human form
        "result": hash_hex.lower(),
        "target": job.target_hex,
        "target_u32": str(job.target_u32),
        "diff": f"{diff:.6f}",
        "height": str(job.height),
        "seed": job.seed_hex,
        "blob": job.blob_with_nonce(nonce_u32).hex(),
        "url": job.url,
        "user": job.user,
        "nicehash": "1" if job.nicehash else "0",
        "demo": "1" if job.demo else "0",
        "qualified": "1" if qualified else "0",
        "engine": engine,
        "ts": f"{now_ts():.3f}",
    }


def render_share_record(rec: dict) -> str:
    lines = ["", "[share]"]
    for k, v in rec.items():
        lines.append(f"{k}={v}")
    return "\n".join(lines) + "\n"


def iter_share_blocks(text: str):
    """Yield (start_offset, end_offset, rec_dict) for each [share] block."""
    matches = list(re.finditer(r"(?m)^\s*\[share\]\s*$", text))
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[start:end]
        kv, _ = _parse_kv(block)
        if kv.get("result"):
            yield start, end, kv


def parse_share_records(text: str) -> list[dict]:
    return [rec for _, _, rec in iter_share_blocks(text)]


# --------------------------------------------------------------------------
# Filesystem tolerance
#
# Containers and sandboxes frequently mount the project directory on FUSE
# filesystems where write() works but flush()/fsync()/close()/flock() fail
# with EOPNOTSUPP (errno 95).  Durability primitives must never be fatal
# there: they are downgraded to a one-time warning, and every write is
# verified by READING THE DATA BACK.  A record that cannot be found on disk
# raises a clear RuntimeError instead of a bare OSError.
# --------------------------------------------------------------------------
_io_warned: set[str] = set()


def _io_warn(key: str, msg: str, *args) -> None:
    if key in _io_warned:
        return
    _io_warned.add(key)
    logging.getLogger("common.io").warning("[fs] " + msg, *args)


def _flush_file(fh) -> None:
    try:
        fh.flush()
    except OSError as exc:
        _io_warn("flush", "this filesystem rejects flush() (%s); continuing -- "
                          "written data is verified by read-back", exc)


def _fsync_file(fh) -> None:
    try:
        os.fsync(fh.fileno())
    except OSError as exc:
        _io_warn("fsync", "this filesystem rejects fsync() (%s); continuing", exc)
    except (AttributeError, ValueError):
        pass


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


# --------------------------------------------------------------------------
# Filesystem-tolerant writing: append, else delete-and-rewrite
#
# Some FUSE mounts accept the FIRST create/write of a file and then fail
# flush()/close() on every later APPEND (observed in a sandbox: share #1
# persisted and everything after it was lost with EOPNOTSUPP).  Other mounts
# reject rename-over or flock().
#
# Rule of this layer: a `flush()`/`fsync()`/`close()` error is only a WARNING
# -- those are durability hints, and several filesystems report them while
# still storing the data.  The SINGLE source of truth is the read-back: a
# write counts as successful only when the data can be read from the file
# again.  When an append does not survive the read-back, the file is switched
# to delete-and-rewrite (write the whole file afresh -- the same operation as
# the first write that worked), with the old content only replaced after the
# new content has been verified.
# --------------------------------------------------------------------------
_WRITE_STRATEGY: dict[str, str] = {}      # path -> "append" | "rewrite"
_STRATEGY_ANNOUNCED: set[str] = set()


def _tag(path: str) -> str:
    return os.path.basename(path) or path


def _attempt_append(path: str, text: str) -> bool:
    """Try appending `text`; verify by reading the tail back. True on success."""
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text)
            _flush_file(fh)
            _fsync_file(fh)
    except OSError as exc:
        # flush/fsync/close refused: the data may still be there -- read-back decides
        _io_warn("append-err", "append to %s reported %s; verifying by read-back",
                 _tag(path), exc)
    try:
        size = os.path.getsize(path)
        with open(path, "r", encoding="utf-8") as fh:
            fh.seek(max(0, size - len(text.encode("utf-8"))))
            return fh.read().endswith(text)
    except OSError:
        return False


def _attempt_replace(path: str, text: str) -> bool:
    """Write `path` afresh (delete-and-rewrite), verified by read-back.

    Attempts, in order:
      1. a NEW temp file (new inode -- the operation that keeps working on
         append-hostile mounts), verified, then os.replace()
      2. truncate-and-rewrite the destination in place
      3. unlink + create the destination (brand-new inode)
    Returns True when the file content is verified to equal `text`.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    tmp = os.path.join(directory, f".tmp-{os.path.basename(path)}-{os.getpid()}")
    try:
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(text)
                _flush_file(fh)
                _fsync_file(fh)
        except OSError as exc:
            _io_warn("tmp-err", "writing %s reported %s; verifying by read-back",
                     _tag(tmp), exc)
        try:
            tmp_ok = _read_text(tmp) == text
        except OSError:
            tmp_ok = False
        if tmp_ok:
            try:
                os.replace(tmp, path)
                return True
            except OSError as exc:
                _io_warn("replace", "this filesystem rejects rename-over (%s); "
                                    "rewriting in place instead", exc)
        else:
            _io_warn("tmp-lost", "the temporary copy for %s did not persist; trying "
                                 "other write paths", _tag(path))
        # 2. truncate + rewrite in place
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
                _flush_file(fh)
                _fsync_file(fh)
            if _read_text(path) == text:
                return True
        except OSError:
            pass
        # 3. unlink + create
        try:
            with contextlib.suppress(OSError):
                os.unlink(path)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
                _flush_file(fh)
                _fsync_file(fh)
            if _read_text(path) == text:
                return True
        except OSError:
            pass
        return False
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp)


def _probe_file(directory: str, pattern: str) -> tuple[bool, str]:
    probe = os.path.join(directory, f".xmr-write-probe-{os.getpid()}")
    chunk1, chunk2 = f"one-{os.getpid()}\n", f"two-{os.getpid()}\n"
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as exc:
        return False, f"cannot create {directory}: {exc}"
    try:
        if pattern == "append":
            ok = _attempt_append(probe, chunk1) and _attempt_append(probe, chunk2)
        else:
            ok = _attempt_replace(probe, chunk1) and _attempt_replace(probe, chunk1 + chunk2)
        if not ok:
            return False, "the write did not survive read-back"
        return True, ""
    finally:
        with contextlib.suppress(OSError):
            os.unlink(probe)


def choose_write_strategy(path: str) -> tuple[str, str]:
    """Decide (and remember) how this file must be written on this filesystem."""
    if path in _WRITE_STRATEGY:
        return _WRITE_STRATEGY[path], ""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    ok_append, why_append = _probe_file(directory, "append")
    if ok_append:
        _WRITE_STRATEGY[path] = "append"
        return "append", ""
    ok_rewrite, why_rewrite = _probe_file(directory, "rewrite")
    if ok_rewrite:
        _WRITE_STRATEGY[path] = "rewrite"
        return "rewrite", (f"this filesystem does not persist read-verified appends "
                           f"({why_append}) -> using delete-and-rewrite mode for "
                           f"{_tag(path)}")
    _WRITE_STRATEGY[path] = "append"
    return "append", (f"neither append nor delete-and-rewrite verifies here "
                      f"(append: {why_append}; rewrite: {why_rewrite}) -- writes "
                      f"are still attempted and verified individually")


def _announce_strategy(path: str, strategy: str, note: str) -> None:
    if strategy == "append" and not note:
        return                                  # normal case: stay quiet
    key = f"{path}:{strategy}:{note}"
    if key in _STRATEGY_ANNOUNCED:
        return
    _STRATEGY_ANNOUNCED.add(key)
    _io_warn(f"strategy-{key}", "%s", note or f"using {strategy} mode for {_tag(path)}")


def strategy_for(path: str) -> str:
    return _WRITE_STRATEGY.get(path, "append")


def write_text(path: str, text: str, mode: str = "w") -> str:
    """Filesystem-tolerant write; returns the strategy that actually worked.

    Raises RuntimeError only when NO write path survives read-back; the
    verified copy is left on disk and named in the message.
    """
    strategy, note = choose_write_strategy(path)
    _announce_strategy(path, strategy, note)

    if mode == "a":
        if strategy == "append" and _attempt_append(path, text):
            return "append"
        if strategy == "append":
            _io_warn("append-fail", "%s did not persist an append -- switching to "
                                    "delete-and-rewrite for this file", _tag(path))
            _WRITE_STRATEGY[path] = "rewrite"
        try:
            existing = _read_text(path)
        except OSError:
            existing = ""
        if _attempt_replace(path, existing + text):
            return "rewrite"
        raise RuntimeError(
            f"cannot persist {path}: neither appending nor rewriting survives a "
            "read-back on this filesystem. Every earlier record is still on disk; "
            "point --dir at a normal filesystem to keep mining here")

    if _attempt_replace(path, text):
        return "rewrite"
    raise RuntimeError(
        f"cannot persist {path}: no write path survives a read-back on this "
        "filesystem; point --dir at a normal filesystem")


def append_text(path: str, text: str) -> str:
    """Append `text`, falling back to delete-and-rewrite when needed."""
    return write_text(path, text, mode="a")


def atomic_write(path: str, text: str) -> None:
    """Replace `path` with `text` (verified delete-and-rewrite)."""
    write_text(path, text, mode="w")


@contextlib.contextmanager
def file_lock(lock_path: str, exclusive: bool = True):
    """Advisory flock on a dedicated lock file. No-op if flock unavailable."""
    fh = None
    try:
        fh = open(lock_path, "a+")
        try:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        except Exception as exc:
            _io_warn("flock", "this filesystem rejects flock() (%s) -- running WITHOUT "
                              "cross-process locking; keep the miner and the bridge on "
                              "the same directory only if you must", exc)
        yield
    finally:
        if fh is not None:
            try:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            with contextlib.suppress(OSError):
                fh.close()


def lock_path_for(path: str) -> str:
    return path + ".lock"


def append_record_locked(path: str, rec: dict, lock_path: str | None = None) -> None:
    """Append one share record to shares.txt, safely w.r.t. other writers.

    Uses the filesystem-tolerant writer: append when the filesystem supports
    it, delete-and-rewrite when it does not, and read-back verification in
    both cases.  Raises RuntimeError when the record genuinely did not
    survive, so the miner can report it without dying.
    """
    lock_path = lock_path or lock_path_for(path)
    with file_lock(lock_path):
        append_text(path, render_share_record(rec))
        _verify_record_on_disk(path, rec)


def _verify_record_on_disk(path: str, rec: dict) -> None:
    try:
        text = _read_text(path)
    except OSError as exc:
        raise RuntimeError(f"cannot read back {path} after writing ({exc})") from None
    want_nonce = str(rec.get("nonce", "")).lower()
    want_result = str(rec.get("result", "")).lower()
    for block in parse_share_records(text):
        if (str(block.get("nonce", "")).lower() == want_nonce
                and str(block.get("result", "")).lower() == want_result):
            return
    raise RuntimeError(
        f"share record did NOT survive the write to {path}: the filesystem "
        f"rejected flush/close and the data was lost. Move the miner directory "
        f"to a normal filesystem (e.g. your home folder) and mine from there")


# --------------------------------------------------------------------------
# Stratum JSON message builders (used by pool_bridge.py only)
# --------------------------------------------------------------------------
def stratum_login(seq: int, user: str, password: str, agent: str,
                  algo: str = "rx/0", rigid: str | None = None) -> dict:
    params = {"login": user, "pass": password, "agent": agent, "algo": [algo]}
    if rigid:
        params["rigid"] = rigid
    return {"id": seq, "jsonrpc": "2.0", "method": "login", "params": params}


def stratum_submit(seq: int, client_id: str, job_id: str, nonce_hex: str,
                   result_hex: str, sig: str | None = None,
                   commitment: str | None = None) -> dict:
    params = {
        "id": client_id,
        "job_id": job_id,
        "nonce": nonce_hex,     # little-endian hex of the 4 nonce bytes
        "result": result_hex,   # raw RandomX hash bytes, hex
    }
    if sig:
        params["sig"] = sig
    if commitment:
        params["commitment"] = commitment
    return {"id": seq, "jsonrpc": "2.0", "method": "submit", "params": params}


def stratum_keepalive(seq: int, client_id: str) -> dict:
    return {"id": seq, "method": "keepalived", "params": {"id": client_id}}


# --------------------------------------------------------------------------
# Self-check (run: python3 common.py)
# --------------------------------------------------------------------------
def _selfcheck() -> int:
    failures = []

    def check(name, cond):
        print(f"  {'ok  ' if cond else 'FAIL'} {name}")
        if not cond:
            failures.append(name)

    # target <-> u32 round trips (real kryptex/xmrig style values)
    for t in ("2d040000", "ffff7f00", "01000000", "ffffff00", "ffffffff", "10000000"):
        u = target_u32_from_be(t)
        check(f"target roundtrip {t} -> u32 {u:#010x}", target_be_from_u32(u) == t)

    # the H[31]==0 gate is mandatory
    h_ok = bytes(31) + bytes([0])
    check("h[31]==0 satisfied", hash_meets_target(h_ok, U32_MAX))
    h_bad = bytes(31) + bytes([1])
    check("h[31]!=0 rejected even with easiest target", not hash_meets_target(h_bad, U32_MAX))
    check("test-ignore gate", hash_meets_target(h_bad, U32_MAX, protocol_gate=False))

    # LE nonce handling: u32 0x12345678 -> blob bytes 78 56 34 12 at offset 39
    job = Job(blob_hex=bytes(84).hex(), seed_hex="00" * 32, target_hex="ffffffff",
              job_id="t", url="x", user="y")
    blob = job.blob_with_nonce(0x12345678)
    check("nonce bytes are little-endian at offset 39",
          blob[39:43] == b"\x78\x56\x34\x12" and blob[43] == 0)
    check("nonce_le_hex matches blob bytes", nonce_le_hex(0x12345678) == "78563412")
    check("nonce roundtrip", nonce_from_le_hex("78563412") == 0x12345678)

    # difficulty sanity: target 0x2d040000 -> u32 0x0000042d -> diff = 2^32/1069
    d = diff_from_target_u32(target_u32_from_be("2d040000"))
    check(f"diff of target 2d040000 = {d:,.0f} (expect ~4.02M)", 4.0e6 < d < 4.05e6)
    # probability model: real pool targets agree with the plain u32 rule
    job_rt = Job(blob_hex=bytes(84).hex(), seed_hex="00" * 32, target_hex="2d040000")
    check(f"eff_diff of a real target = {job_rt.eff_diff:,.0f} (~diff)",
          abs(job_rt.eff_diff - 2 ** 32 / (job_rt.target_u32 + 1)) < 1)
    easy = Job(blob_hex=bytes(84).hex(), seed_hex="00" * 32, target_hex="ffffffff")
    check(f"eff_diff of a diff-1 target = {easy.eff_diff:,.0f} (gate adds x256)",
          abs(easy.eff_diff - 256) < 1)
    # for every real pool target, u32 <= target already forces H[31] == 0
    t = 1 << 24
    check("u32 <= target implies H[31]==0 for target < 2^24", (t - 1) >> 24 == 0)

    # job round trip through the text format
    text = render_job_text(Job(algo="randomx", url="xmr.kryptex.network:7029",
                               user="krxYRPV4WQ", job_id="abc", target_hex="2d040000",
                               height="3456789", seed_hex="ab" * 32,
                               blob_hex=bytes(range(84)).hex(), updated=1.0))
    job2 = load_job_text(text)
    check("job text roundtrip", job2.signature() == load_job_text(text).signature()
          and job2.target_u32 == target_u32_from_be("2d040000") and len(job2.blob) == 84)

    # extra pass-through keys must not corrupt the blob section
    job_ex = Job(blob_hex="ab" * 60, seed_hex="11" * 32, target_hex="2d040000",
                 job_id="ex", extra={"sig": "deadbeef", "commitment": "cafe"})
    text_ex = render_job_text(job_ex)
    check("extra keys land before [blob]", text_ex.index("sig=") < text_ex.index("[blob]"))
    job_ex2 = load_job_text(text_ex)
    check("blob survives extra keys", job_ex2.blob_hex == "ab" * 60
          and job_ex2.extra.get("sig") == "deadbeef")
    # a stray key inside [blob] is ignored, not glued on
    broken = text_ex.replace("[blob]", "[blob]\ncomment=oops")
    check("stray line inside [blob] ignored",
          load_job_text(broken).blob_hex == "ab" * 60)

    # share record round trip
    rec = make_share_record(job2, 0x12345678, "aa" * 32, 123.456, "native")
    txt = render_share_record(rec)
    got = parse_share_records(txt)
    check("share record roundtrip", len(got) == 1 and got[0]["result"] == "aa" * 32
          and got[0]["nonce"] == "78563412" and got[0]["job_id"] == "abc")
    blocks = list(iter_share_blocks(txt + txt))
    check("share block offsets", len(blocks) == 2 and blocks[1][0] == blocks[0][1])

    print(f"\n{'(all good)' if not failures else str(len(failures)) + ' FAILURES'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_selfcheck())


# ---------------------------------------------------------------------------
# Logging helpers shared by the miner and the bridge
# ---------------------------------------------------------------------------
class SafeStreamHandler(logging.StreamHandler):
    """Console handler that survives streams whose write()/flush() fail.

    Sandboxed filesystems (FUSE mounts in containers, for example) can raise
    OSError errno 95 (EOPNOTSUPP) when a redirected stdout is flushed.  With
    the stock handler, EVERY log line then prints a full "--- Logging error ---"
    traceback.  Losing the console copy of a line is acceptable; drowning the
    log in tracebacks is not.
    """

    def flush(self) -> None:
        try:
            super().flush()
        except Exception:
            pass

    def emit(self, record: logging.LogRecord) -> None:
        try:
            super().emit(record)
        except Exception:
            pass

    def handleError(self, record: logging.LogRecord) -> None:   # noqa: N802
        # printing a full logging traceback per line is worse than losing the
        # line: degrade to one short notice per handler
        if getattr(self, "_errored", False):
            return
        self._errored = True
        try:
            sys.stderr.write("logging: dropping messages for this handler "
                             "(stream write failed); details suppressed\n")
        except Exception:
            pass


class SafeFileHandler(logging.FileHandler):
    """File handler with the same tolerance (some mounts fail on flush too)."""

    def flush(self) -> None:
        try:
            super().flush()
        except Exception:
            pass

    def emit(self, record: logging.LogRecord) -> None:
        try:
            super().emit(record)
        except Exception:
            pass

    def handleError(self, record: logging.LogRecord) -> None:   # noqa: N802
        if getattr(self, "_errored", False):
            return
        self._errored = True
        try:
            sys.stderr.write("logging: dropping messages for the log file "
                             "(write failed); details suppressed\n")
        except Exception:
            pass

