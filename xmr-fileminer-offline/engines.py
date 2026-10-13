#!/usr/bin/env python3
"""
engines.py -- hashing engines for xmr-fileminer.

Two engines implement the exact same event protocol:

  NativeEngine  wraps the C program bin/miner_native (the fast path; this is
                the one that reaches full xmrig-class hashrate: 2 GB dataset,
                huge pages, one VM per thread).
  PythonEngine  drives librandomx.so directly through ctypes with Python
                threads. Same math and same share quality, slightly lower
                top-end rate. It exists so the project still runs (and stays
                readable) if the C helper cannot be built.

Event protocol (dicts, emitted by both engines):
  {"kind": "READY"|"INITPROG"|"INITOK"|"INITERR"|"SELFTEST"|"STARTED"|"RATE"
           |"TOTAL"|"WIN"|"BEST"|"STALL"|"RESUME"|"STOPPED"|"BYE"|"ERR"
           |"WARN"|"EXIT", ...fields...}

Neither engine ever touches the network or the share files. That stays in
file_miner.py / pool_bridge.py.
"""

from __future__ import annotations

import atexit
import collections
import ctypes
import os
import queue
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))

# RandomX flag bits (randomx.h)
RANDOMX_FLAG_LARGE_PAGES = 1
RANDOMX_FLAG_HARD_AES = 2
RANDOMX_FLAG_FULL_MEM = 4
RANDOMX_FLAG_JIT = 8

U32_SIZE = 0x100000000

# Official RandomX test vector (see rx_vector.h) -- used by both engines as a
# hard correctness gate. key = "test key 001" (12 bytes, no NUL).
RX_TEST_KEY = b"test key 001"
RX_TEST_INPUT_HEX = (
    "0b0b98bea7e805e0010a2126d287a2a0cc833d312cb786385a7c2f9de69d2553"
    "7f584a9bc9977b00000000666fd8753bf61a8631f12984e3fd44f4014eca6292"
    "76817b56f32e9b68bd82f416")
RX_TEST_EXPECTED = "c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1"


def _now() -> float:
    return time.monotonic()


class EngineError(RuntimeError):
    pass


def physical_cores() -> int:
    """Best-effort physical core count (falls back to logical count)."""
    try:
        pairs = set()
        phys = core = None
        with open("/proc/cpuinfo") as fh:
            for line in fh:
                if line.startswith("physical id"):
                    phys = line.split(":")[1].strip()
                elif line.startswith("core id"):
                    core = line.split(":")[1].strip()
                elif line.strip() == "" and phys is not None and core is not None:
                    pairs.add((phys, core))
                    phys = core = None
        if pairs:
            return len(pairs)
    except OSError:
        pass
    return os.cpu_count() or 1


def logical_cores() -> int:
    return os.cpu_count() or 1


# ---------------------------------------------------------------------------
# Base engine helpers
# ---------------------------------------------------------------------------
class _BaseEngine:
    name = "base"
    fallback_reason: str | None = None    # set when 'auto' fell back to Python

    def __init__(self) -> None:
        self._q: queue.Queue = queue.Queue()
        self._pending: collections.deque = collections.deque()
        self.dead = False
        self.dead_reason = ""

    # -- event plumbing ----------------------------------------------------
    def _emit(self, ev: dict) -> None:
        self._q.put(ev)

    def _next_event(self, timeout: float | None) -> dict | None:
        if self._pending:
            return self._pending.popleft()
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None

    def poll(self, timeout: float = 0.0) -> list[dict]:
        """Return queued events; wait up to `timeout` for the first one."""
        out: list[dict] = []
        ev = self._next_event(max(0.0, timeout))
        while ev is not None:
            out.append(ev)
            ev = self._next_event(0.0)
        return out

    def _drain_into_pending(self) -> None:
        while True:
            try:
                self._pending.append(self._q.get_nowait())
            except queue.Empty:
                break

    def wait_for(self, kinds, timeout: float) -> dict | None:
        """Wait for an event of one of `kinds`, stashing the others.

        Non-matching events are moved to the pending queue and are NOT
        re-examined here (that was an infinite-loop bug: the stashed event
        would be popped again immediately). An EXIT event always matches, so
        a dead engine cannot hang a caller.
        """
        kinds = (kinds,) if isinstance(kinds, str) else tuple(kinds)
        kinds = kinds + ("EXIT",)

        # events already set aside by an earlier wait_for call
        for i, ev in enumerate(self._pending):
            if ev.get("kind") in kinds:
                del self._pending[i]
                return ev

        stash: list[dict] = []
        deadline = _now() + timeout
        try:
            while True:
                left = deadline - _now()
                if left <= 0:
                    return None
                try:
                    ev = self._q.get(timeout=left)
                except queue.Empty:
                    return None
                if ev.get("kind") in kinds:
                    return ev
                stash.append(ev)
        finally:
            self._pending.extend(stash)

    # -- lifecycle (implemented by subclasses) ------------------------------
    def init(self, seed_hex: str, mode: str, hugepages: bool, init_threads: int) -> dict:
        raise NotImplementedError

    def selftest(self) -> dict:
        raise NotImplementedError

    def start(self, job, threads: int, offset: int, cpus: list[int],
              yield_flag: bool, protocol_gate: bool) -> dict:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    def verify(self, seed_hex: str, blob_hex: str) -> str:
        """Compute the RandomX hash of blob_hex (light VM). Returns hex."""
        raise NotImplementedError

    def final_stats(self) -> dict:
        """Total work done, collected just before shutdown."""
        return {}

    def quit(self) -> None:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Native engine (subprocess around bin/miner_native)
# ---------------------------------------------------------------------------
class NativeEngine(_BaseEngine):
    name = "native"

    def __init__(self, report_ms: int = 2000, stall_secs: int = 30,
                 nice: int = 0, init_threads: int = 4, bin_path: str | None = None):
        super().__init__()
        self.bin_path = bin_path or os.path.join(HERE, "bin", "miner_native")
        ensure_executable(self.bin_path)
        # may return a relocated copy on filesystems that deny execve
        self.exec_path = ensure_runnable(self.bin_path)
        self.report_ms = report_ms
        self.stall_secs = stall_secs
        self.nice = nice
        self.init_threads = init_threads
        self.proc: subprocess.Popen | None = None
        self._lines: collections.deque = collections.deque()   # debug log of cmds
        self._boot: collections.deque = collections.deque(maxlen=8)  # pre-READY output
        self.ready: dict | None = None
        self._start_proc()

    # ------------------------------------------------------------------
    def _start_proc(self) -> None:
        if not os.path.exists(self.bin_path):
            raise EngineError(f"native engine not found: {self.bin_path} (run ./build.sh)")
        cmd = [self.exec_path, "--report-ms", str(self.report_ms),
               "--stall-secs", str(self.stall_secs), "--init-threads", str(self.init_threads)]
        if self.nice:
            cmd += ["--nice", str(self.nice)]
        try:
            self.proc = _popen(
                cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1, close_fds=True)
        except OSError as exc:
            raise EngineError(f"cannot start {self.bin_path}: {exc}") from None
        threading.Thread(target=self._reader, daemon=True).start()
        # NOTE: wait_for() treats an EXIT event as a match on purpose (a dead
        # engine must never hang a caller), so a dying process answers with its
        # EXIT event, not None.  Accept ONLY a real READY here -- otherwise the
        # failure would surface later as an unhandled EngineError mid-mining
        # instead of triggering the auto-fallback in make_engine().
        ev = self.wait_for("READY", 10.0)
        if not ev or ev.get("kind") != "READY":
            said = " | ".join(self._boot) if self._boot else "no output at all"
            with _suppress():
                if self.proc and self.proc.poll() is None:
                    self.proc.terminate()
                    self.proc.wait(timeout=5)
            note = probe_note(self.bin_path)
            extra = f"; exec probe said: {note}" if note else ""
            raise EngineError(
                "native engine did not report READY -- it may be built for a "
                "different libc/CPU, missing lib/librandomx.so, or on a filesystem "
                f"that cannot execute it (engine said: {said}{extra})")
        self.ready = ev

    def _reader(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        for raw in self.proc.stdout:
            line = raw.rstrip("\n")
            if not line:
                continue
            if self.ready is None:
                self._boot.append(line)      # keep pre-READY stdout/stderr for errors
            self._emit(self._parse_line(line))
        self.dead = True
        rc = self.proc.wait() if self.proc else None
        self.dead_reason = f"native engine exited (rc={rc})"
        self._emit({"kind": "EXIT", "rc": rc})

    @staticmethod
    def _parse_line(line: str) -> dict:
        parts = line.split()
        ev: dict = {"kind": parts[0], "raw": line}
        leftovers = []
        for tok in parts[1:]:
            if "=" in tok:
                k, _, v = tok.partition("=")
                ev[k] = v
            else:
                leftovers.append(tok)
        if leftovers:
            ev["text"] = " ".join(leftovers)
        for key in ("pct", "tid", "threads", "secs", "ok", "hp", "rc", "hashes"):
            if key in ev:
                try:
                    ev[key] = int(ev[key])
                except ValueError:
                    pass
        for key in ("hps", "diff", "cache_ms", "dataset_ms", "avail_mb", "dataset_mb"):
            if key in ev:
                try:
                    ev[key] = float(ev[key])
                except ValueError:
                    pass
        if "nonce" in ev:
            try:
                ev["nonce_u32"] = int(ev["nonce"], 0)
            except ValueError:
                pass
        return ev

    # ------------------------------------------------------------------
    def send(self, line: str) -> None:
        if self.proc is None or self.proc.poll() is not None:
            raise EngineError(self.dead_reason or "native engine is not running")
        assert self.proc.stdin is not None
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    # ------------------------------------------------------------------
    def init(self, seed_hex: str, mode: str, hugepages: bool, init_threads: int) -> dict:
        t0 = _now()
        self.send(f"INIT seed={seed_hex} mode={mode} hp={1 if hugepages else 0} "
                  f"initthreads={init_threads}")
        ev = self.wait_for(("INITOK", "INITERR"), timeout=900.0)
        if ev is None:
            raise EngineError("native engine did not answer INIT (is the process alive?)")
        if ev.get("kind") == "EXIT":
            raise EngineError(self.dead_reason or "native engine exited during INIT")
        ev["elapsed"] = _now() - t0
        return ev

    def selftest(self) -> dict:
        self.send("SELFTEST")
        ev = self.wait_for("SELFTEST", timeout=300.0)
        if ev is None or ev.get("kind") == "EXIT":
            return {"kind": "SELFTEST", "ok": -1, "reason": self.dead_reason or "no answer"}
        return ev

    def start(self, job, threads: int, offset: int, cpus: list[int],
              yield_flag: bool, protocol_gate: bool) -> dict:
        cpus_arg = f" cpus={','.join(str(c) for c in cpus)}" if cpus else ""
        self.send(
            f"START threads={threads} blob={job.blob_hex} "
            f"target32=0x{job.target_u32:08x} target={job.target_hex} "
            f"offset=0x{(offset & 0xFFFFFFFF):08x} mask=0x{job.nonce_mask:08X} "
            f"gate={1 if protocol_gate else 0} yield={1 if yield_flag else 0}{cpus_arg}")
        ev = self.wait_for(("STARTED", "ERR"), timeout=120.0)
        if ev is None or ev.get("kind") in ("ERR", "EXIT"):
            raise EngineError(f"native engine failed to start workers: {ev}")
        return ev

    def stop(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        try:
            self.send("STOP")
            self.wait_for("STOPPED", timeout=300.0)
        except EngineError:
            pass

    def final_stats(self) -> dict:
        if self.proc is None or self.proc.poll() is not None:
            return {}
        try:
            self.send("STATS")
        except EngineError:
            return {}
        ev = self.wait_for(("TOTAL", "BYE"), timeout=10.0)
        if ev and ev.get("kind") == "TOTAL":
            return {"hashes": int(ev.get("hashes", 0))}
        return {}

    def verify(self, seed_hex: str, blob_hex: str) -> str:
        proc = _run(
            [ensure_runnable(self.bin_path), "--verify", seed_hex],
            input=blob_hex + "\n", capture_output=True, text=True, timeout=600)
        for line in (proc.stdout or "").splitlines():
            if line.startswith("HASH "):
                return line.split()[1]
        raise EngineError(f"verification failed: {proc.stdout!r} {proc.stderr!r}")

    def quit(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            try:
                self.send("QUIT")
                self.wait_for("BYE", timeout=120.0)
                self.proc.wait(timeout=10)
            except Exception:
                with _suppress():
                    self.proc.terminate()
        with _suppress():
            assert self.proc.stdin is not None
            self.proc.stdin.close()


# Module-level indirections: tests patch these to simulate hostile environments.
_run = subprocess.run
_popen = subprocess.Popen

_RUNNABLE_CACHE: dict[tuple[str, tuple[str, ...]], str] = {}
_PROBE_NOTE: dict[tuple[str, tuple[str, ...]], str] = {}
_TEMP_DIRS: list[str] = []


def _cleanup_temp_dirs() -> None:
    for d in list(_TEMP_DIRS):
        shutil.rmtree(d, ignore_errors=True)
    del _TEMP_DIRS[:]


atexit.register(_cleanup_temp_dirs)


def ensure_executable(path: str) -> bool:
    """Best-effort restore of the exec bit; True if the file is executable after.

    tar/zip extracts, some network filesystems and workspace restores can drop
    the mode bits.  Some filesystems go further and silently IGNORE chmod (the
    FUSE data mounts used by several sandboxes do) -- so this re-stats the file
    instead of trusting the chmod call, and says so when the change did not
    stick.  When the mode cannot be fixed, ensure_runnable() takes over.
    """
    try:
        st = os.stat(path)
    except OSError:
        return False
    if st.st_mode & 0o111:
        return True
    try:
        os.chmod(path, st.st_mode | 0o755)
    except OSError as exc:
        print(f"[engines] cannot set the executable bit on {path}: {exc}", file=sys.stderr)
        return False
    try:
        st2 = os.stat(path)
    except OSError:
        return False
    if st2.st_mode & 0o111:
        print(f"[engines] restored the executable bit on {path}", file=sys.stderr)
        return True
    print(f"[engines] {path} is STILL not executable after chmod -- this filesystem "
          "ignores mode changes; will try running a relocated copy", file=sys.stderr)
    return False


def _probe_exec(path: str, probe_args: tuple[str, ...] = ("--info",),
                timeout: float = 30.0) -> tuple[bool, str]:
    """Try to actually EXECUTE `path`; return (ok, one-line description)."""
    try:
        proc = _run([path, *probe_args], capture_output=True, text=True,
                    timeout=timeout)
    except PermissionError as exc:
        return False, f"cannot execute: {exc}"
    except OSError as exc:
        return False, f"cannot execute: {exc}"
    except subprocess.TimeoutExpired:
        return False, f"probe timed out after {timeout:.0f}s"
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    first = " / ".join(ln for ln in out.splitlines() if ln)[:200]
    if proc.returncode == 0:
        return True, first
    return False, f"rc={proc.returncode}: {first or '(silent)'}"


def _looks_like_exec_denial(msg: str) -> bool:
    low = msg.lower()
    return "permission denied" in low or "operation not permitted" in low


def ensure_runnable(bin_path: str,
                    probe_args: tuple[str, ...] = ("--info",)) -> str:
    """Return a path from which the bundled engine can actually be EXECUTED.

    Some filesystems (FUSE data mounts in sandboxes/containers) allow writing,
    reading and even chmod, but deny execve with EACCES/EPERM.  Compiling there
    is useless and so is `chmod +x`.  In that case the engine binary and the
    `lib/` directory are copied to a private temp location (inside the same
    parent, so the `$ORIGIN/../lib` rpath still resolves) and the copy is used
    instead -- native hashrate on filesystems that refuse to execute the
    original.  The relocation is cached per process and announced on stderr.
    """
    key = (bin_path, tuple(probe_args))
    cached = _RUNNABLE_CACHE.get(key)
    if cached and os.path.exists(cached):
        return cached
    if not os.path.exists(bin_path):
        return bin_path

    ensure_executable(bin_path)
    ok, msg = _probe_exec(bin_path, probe_args)
    if ok:
        _RUNNABLE_CACHE[key] = bin_path
        return bin_path
    if not _looks_like_exec_denial(msg):
        _PROBE_NOTE[key] = msg            # broken for another reason; keep it
        return bin_path

    # exec-denied by the filesystem -> run a copy from a private temp dir
    dest_dir = tempfile.mkdtemp(prefix="xmr-fileminer-eng-")
    dest_bin = os.path.join(dest_dir, "bin", os.path.basename(bin_path))
    try:
        os.makedirs(os.path.dirname(dest_bin), exist_ok=True)
        shutil.copy2(bin_path, dest_bin)
        os.chmod(dest_bin, 0o755)
        src_lib = os.path.normpath(os.path.join(os.path.dirname(bin_path), "..", "lib"))
        if os.path.isdir(src_lib):
            shutil.copytree(src_lib, os.path.join(dest_dir, "lib"))
    except OSError as exc:
        shutil.rmtree(dest_dir, ignore_errors=True)
        _PROBE_NOTE[key] = f"{msg}; copying to {dest_dir} failed: {exc}"
        return bin_path
    _TEMP_DIRS.append(dest_dir)

    ok2, msg2 = _probe_exec(dest_bin, probe_args)
    if ok2:
        print(f"[engines] {bin_path} cannot be executed from this filesystem ({msg}); "
              f"running a copy from {dest_bin} instead -- native hashrate enabled",
              file=sys.stderr)
        _RUNNABLE_CACHE[key] = dest_bin
        _PROBE_NOTE[key] = f"relocated to {dest_bin} ({msg})"
        return dest_bin
    shutil.rmtree(dest_dir, ignore_errors=True)
    if dest_dir in _TEMP_DIRS:
        _TEMP_DIRS.remove(dest_dir)
    _PROBE_NOTE[key] = (f"{msg}; the relocated copy at {dest_bin} also failed: {msg2}")
    return bin_path


def probe_note(bin_path: str,
               probe_args: tuple[str, ...] = ("--info",)) -> str | None:
    return _PROBE_NOTE.get((bin_path, tuple(probe_args)))


class _suppress:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return True


# ---------------------------------------------------------------------------
# Pure-python engine (ctypes -> librandomx.so)
# ---------------------------------------------------------------------------
class LibRandomX:
    """Thin ctypes binding to the parts of librandomx we use."""

    def __init__(self, so_path: str):
        try:
            self.lib = ctypes.CDLL(so_path)
        except OSError as exc:
            raise EngineError(f"cannot load {so_path}: {exc}") from None
        L = self.lib
        L.randomx_get_flags.restype = ctypes.c_int
        L.randomx_alloc_cache.argtypes = [ctypes.c_int]
        L.randomx_alloc_cache.restype = ctypes.c_void_p
        L.randomx_init_cache.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        L.randomx_init_cache.restype = None
        L.randomx_release_cache.argtypes = [ctypes.c_void_p]
        L.randomx_alloc_dataset.argtypes = [ctypes.c_int]
        L.randomx_alloc_dataset.restype = ctypes.c_void_p
        L.randomx_dataset_item_count.restype = ctypes.c_ulong
        L.randomx_init_dataset.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                           ctypes.c_ulong, ctypes.c_ulong]
        L.randomx_init_dataset.restype = None
        L.randomx_release_dataset.argtypes = [ctypes.c_void_p]
        L.randomx_create_vm.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        L.randomx_create_vm.restype = ctypes.c_void_p
        L.randomx_destroy_vm.argtypes = [ctypes.c_void_p]
        L.randomx_calculate_hash.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                             ctypes.c_size_t, ctypes.c_void_p]
        L.randomx_calculate_hash.restype = None
        self.flags: int = L.randomx_get_flags()

    def alloc_cache(self, flags: int):
        return self.lib.randomx_alloc_cache(flags)

    def init_cache(self, cache, seed: bytes) -> None:
        buf = ctypes.create_string_buffer(seed, len(seed))
        self.lib.randomx_init_cache(cache, buf, len(seed))

    def release_cache(self, cache) -> None:
        if cache:
            self.lib.randomx_release_cache(cache)

    def alloc_dataset(self, flags: int):
        return self.lib.randomx_alloc_dataset(flags)

    def dataset_items(self) -> int:
        return int(self.lib.randomx_dataset_item_count())

    def init_dataset(self, ds, cache, start: int, count: int) -> None:
        self.lib.randomx_init_dataset(ds, cache, start, count)

    def release_dataset(self, ds) -> None:
        if ds:
            self.lib.randomx_release_dataset(ds)

    def create_vm(self, flags: int, cache, ds):
        return self.lib.randomx_create_vm(flags, cache, ds)

    def destroy_vm(self, vm) -> None:
        if vm:
            self.lib.randomx_destroy_vm(vm)

    def calc_hash(self, vm, blob: bytes, out_buf) -> None:
        self.lib.randomx_calculate_hash(vm, blob, len(blob), out_buf)


class PythonEngine(_BaseEngine):
    name = "python"

    def __init__(self, report_ms: int = 2000, stall_secs: int = 30,
                 so_path: str | None = None):
        super().__init__()
        so_path = so_path or os.path.join(HERE, "lib", "librandomx.so")
        self.rx = LibRandomX(so_path)
        self.report_ms = report_ms
        self.stall_secs = stall_secs

        self.cache = None
        self.ds = None
        self.full = False
        self.hp = False
        self.vm_flags = 0
        self.seed_hex = ""

        self.workers: list[dict] = []
        self._monitor: threading.Thread | None = None
        self._stop_all = threading.Event()
        self.verify_cache = None
        self.verify_seed = None
        self.verify_vm = None

    # ------------------------------------------------------------------
    def init(self, seed_hex: str, mode: str, hugepages: bool, init_threads: int) -> dict:
        t0 = _now()
        flags = self.rx.flags
        hp = bool(hugepages)
        if hp:
            flags |= RANDOMX_FLAG_LARGE_PAGES

        cache = None
        if hp:
            cache = self.rx.alloc_cache(flags)
            if not cache:
                self._emit({"kind": "WARN", "msg": "hugepages_cache_failed",
                            "text": "falling_back=normal_pages"})
                hp = False
                flags = self.rx.flags
        if cache is None:
            cache = self.rx.alloc_cache(flags)
        if not cache:
            self._emit({"kind": "INITERR", "reason": "cache_alloc_failed"})
            return {"kind": "INITERR", "reason": "cache_alloc_failed"}
        self.rx.init_cache(cache, bytes.fromhex(seed_hex))
        cache_ms = (_now() - t0) * 1000.0

        ds = None
        full = mode in ("auto", "full")
        if full:
            df = flags | RANDOMX_FLAG_FULL_MEM
            ds = self.rx.alloc_dataset(df)
            if not ds and hp:
                hp = False
                flags = self.rx.flags
                df = flags | RANDOMX_FLAG_FULL_MEM
                ds = self.rx.alloc_dataset(df)
            if not ds:
                if mode == "full":
                    self.rx.release_cache(cache)
                    self._emit({"kind": "INITERR", "reason": "dataset_alloc_failed"})
                    return {"kind": "INITERR", "reason": "dataset_alloc_failed"}
                full = False

        ds_ms = 0.0
        items = 0
        if full and ds:
            items = self.rx.dataset_items()
            t1 = _now()
            nt = max(1, min(16, init_threads))
            per = items // nt
            errs: list[Exception] = []

            chunk = 1 << 17
            total_chunks = sum(
                -(-((items - i * per) if i == nt - 1 else per) // chunk)
                for i in range(nt))
            done_chunks = [0]
            done_lock = threading.Lock()

            def init_chunk(i: int) -> None:
                try:
                    start = i * per
                    count = items - start if i == nt - 1 else per
                    chunk_sz = 1 << 17
                    off = 0
                    while off < count:
                        n = min(chunk_sz, count - off)
                        self.rx.init_dataset(ds, cache, start + off, n)
                        off += n
                        with done_lock:
                            done_chunks[0] += 1
                except Exception as exc:      # pragma: no cover
                    errs.append(exc)

            self._emit({"kind": "INITPROG", "phase": "dataset", "pct": 0})
            threads = [threading.Thread(target=init_chunk, args=(i,), daemon=True)
                       for i in range(nt)]
            [t.start() for t in threads]
            last = -1
            while any(t.is_alive() for t in threads):
                # ctypes calls release the GIL -> the init threads are real
                time.sleep(0.5)
                with done_lock:
                    pct = int(done_chunks[0] * 100 / max(1, total_chunks))
                if pct != last and pct < 100:
                    last = pct
                    self._emit({"kind": "INITPROG", "phase": "dataset", "pct": pct})
            [t.join() for t in threads]
            ds_ms = (_now() - t1) * 1000.0
            if errs:
                self._emit({"kind": "INITERR", "reason": f"dataset_init_failed: {errs[0]}"})
                self.rx.release_dataset(ds)
                self.rx.release_cache(cache)
                return {"kind": "INITERR", "reason": "dataset_init_failed"}

        if self.cache:
            self.rx.release_cache(self.cache)
        if self.ds:
            self.rx.release_dataset(self.ds)
        self.cache, self.ds = cache, ds
        self.full = bool(full and ds)
        self.hp = hp
        self.seed_hex = seed_hex
        self.vm_flags = self.rx.flags | (RANDOMX_FLAG_LARGE_PAGES if hp else 0)
        if self.full:
            self.vm_flags |= RANDOMX_FLAG_FULL_MEM

        ev = {"kind": "INITOK", "mode": "full" if self.full else "light",
              "hp": 1 if hp else 0, "cache_ms": cache_ms, "dataset_ms": ds_ms,
              "dataset_mb": (items * 8) // (1024 * 1024) if self.full else 0,
              "elapsed": _now() - t0}
        self._emit(ev)
        return ev

    def _make_vm(self):
        if self.full and self.ds:
            return self.rx.create_vm(self.vm_flags, None, self.ds)
        return self.rx.create_vm(self.vm_flags & ~RANDOMX_FLAG_FULL_MEM, self.cache, None)

    def selftest(self) -> dict:
        """Hash the official RandomX test vector on a throwaway light VM."""
        cache = self.rx.alloc_cache(self.rx.flags)
        if not cache:
            ev = {"kind": "SELFTEST", "ok": 0, "mode": "light", "reason": "cache_alloc_failed"}
            self._emit(ev)
            return ev
        try:
            self.rx.init_cache(cache, RX_TEST_KEY)
            vm = self.rx.create_vm(self.rx.flags & ~RANDOMX_FLAG_FULL_MEM, cache, None)
            if not vm:
                ev = {"kind": "SELFTEST", "ok": 0, "mode": "light", "reason": "vm_create_failed"}
                self._emit(ev)
                return ev
            try:
                out = ctypes.create_string_buffer(32)
                self.rx.calc_hash(vm, bytes.fromhex(RX_TEST_INPUT_HEX), out)
                got = out.raw.hex()
            finally:
                self.rx.destroy_vm(vm)
        finally:
            self.rx.release_cache(cache)
        ok = 1 if got == RX_TEST_EXPECTED else 0
        ev = {"kind": "SELFTEST", "ok": ok, "mode": "light", "got": got}
        self._emit(ev)
        return ev

    # ------------------------------------------------------------------
    def start(self, job, threads: int, offset: int, cpus: list[int],
              yield_flag: bool, protocol_gate: bool) -> dict:
        if self.cache is None:
            raise EngineError("engine used before INIT")
        self._stop_all.clear()
        self.workers = []
        space = job.nonce_mask + 1
        per = space // threads
        for tid in range(threads):
            length = per if tid != threads - 1 else space - per * (threads - 1)
            start = (offset + tid * per) & job.nonce_mask
            self.workers.append({
                "tid": tid, "start": start, "len": length,
                "cpu": cpus[tid % len(cpus)] if cpus else None,
                "hashes": 0, "seq": 0, "best_u32": 0xFFFFFFFF,
                "vm": None, "th": None, "stall": 0,
            })
        blob = job.blob_with_nonce(0)
        target = job.target_u32
        gate = protocol_gate
        yield_flag = bool(yield_flag)

        for w in self.workers:
            th = threading.Thread(
                target=self._worker, daemon=True,
                args=(w, blob, target, gate, yield_flag))
            w["th"] = th
            th.start()

        self._monitor = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor.start()
        return {"kind": "STARTED", "threads": threads,
                "mode": "full" if self.full else "light"}

    def _worker(self, w: dict, blob_template: bytes, target: int, gate: bool,
                yield_flag: bool) -> None:
        if w["cpu"] is not None:
            try:
                os.sched_setaffinity(0, {w["cpu"]})   # pin this python thread
            except Exception:
                pass
        vm = self._make_vm()
        if not vm:
            self._emit({"kind": "ERR", "msg": "vm_create_failed", "tid": w["tid"]})
            return
        w["vm"] = vm
        out = ctypes.create_string_buffer(32)
        mask = (1 << 32) - 1
        i = 0
        blob = bytearray(blob_template)
        try:
            while not self._stop_all.is_set():
                nonce = (w["start"] + (i % w["len"])) & mask
                blob[39:43] = nonce.to_bytes(4, "little")
                self.rx.calc_hash(vm, bytes(blob), out)
                h = out.raw
                i += 1
                if (i & 63) == 0:
                    w["hashes"] = i
                    if yield_flag:
                        time.sleep(0)
                w["seq"] = i
                if (h[31] == 0) if gate else True:
                    u = h[28] | (h[29] << 8) | (h[30] << 16) | (h[31] << 24)
                    if u <= target:
                        self._emit({"kind": "WIN", "tid": w["tid"],
                                    "nonce_u32": nonce, "hash": h.hex(),
                                    "diff": U32_SIZE / max(u, 1)})
                    if u < w["best_u32"]:
                        w["best_u32"] = u
                        self._emit({"kind": "BEST", "tid": w["tid"],
                                    "nonce_u32": nonce, "hash": h.hex(),
                                    "diff": U32_SIZE / max(u, 1)})
        finally:
            w["hashes"] = i
            self.rx.destroy_vm(vm)
            w["vm"] = None

    def _monitor_loop(self) -> None:
        last_t = _now()
        last_counts = [0] * len(self.workers)
        while not self._stop_all.is_set():
            time.sleep(0.5)
            now = _now()
            if now - last_t >= self.report_ms / 1000.0:
                dt = now - last_t
                total = 0
                total_hps = 0.0
                for idx, w in enumerate(list(self.workers)):
                    h = int(w["hashes"])
                    hps = (h - last_counts[idx]) / dt if dt > 0 else 0.0
                    last_counts[idx] = h
                    total += h
                    total_hps += hps
                    self._emit({"kind": "RATE", "tid": w["tid"], "hps": hps, "hashes": h})
                self._emit({"kind": "TOTAL", "hps": total_hps, "hashes": total})
                last_t = now
            # stall watchdog (wall-clock based)
            for w in list(self.workers):
                sq = int(w["seq"])
                if sq != w.get("_watch_seq", -1):
                    if w.get("_stall_reported"):
                        self._emit({"kind": "RESUME", "tid": w["tid"]})
                    w["_watch_seq"] = sq
                    w["_watch_t0"] = now
                    w["_stall_reported"] = False
                elif not w.get("_stall_reported") and \
                        now - w.get("_watch_t0", now) >= self.stall_secs:
                    w["_stall_reported"] = True
                    self._emit({"kind": "STALL", "tid": w["tid"], "secs": self.stall_secs})

    def stop(self) -> None:
        self._stop_all.set()
        for w in list(self.workers):
            th = w.get("th")
            if th is not None and th.is_alive():
                th.join(timeout=600.0)
        self.workers = []
        self._emit({"kind": "STOPPED"})

    # ------------------------------------------------------------------
    def verify(self, seed_hex: str, blob_hex: str) -> str:
        if self.verify_seed != seed_hex or self.verify_cache is None or self.verify_vm is None:
            if self.verify_vm:
                self.rx.destroy_vm(self.verify_vm)
                self.verify_vm = None
            if self.verify_cache and self.verify_seed != seed_hex:
                self.rx.release_cache(self.verify_cache)
                self.verify_cache = None
            if self.verify_cache is None:
                self.verify_cache = self.rx.alloc_cache(self.rx.flags)
                if not self.verify_cache:
                    raise EngineError("cannot allocate verification cache")
                self.rx.init_cache(self.verify_cache, bytes.fromhex(seed_hex))
            self.verify_vm = self.rx.create_vm(
                self.rx.flags & ~RANDOMX_FLAG_FULL_MEM, self.verify_cache, None)
            if not self.verify_vm:
                raise EngineError("cannot create verification VM")
            self.verify_seed = seed_hex
        out = ctypes.create_string_buffer(32)
        self.rx.calc_hash(self.verify_vm, bytes.fromhex(blob_hex), out)
        return out.raw.hex()

    def final_stats(self) -> dict:
        total = sum(int(w.get("hashes", 0)) for w in list(self.workers))
        for w in list(self.workers):
            self.rx_engine_noop = None
        return {"hashes": total}

    def quit(self) -> None:
        self.stop()
        if self.verify_vm:
            self.rx.destroy_vm(self.verify_vm)
            self.verify_vm = None
        if self.verify_cache:
            self.rx.release_cache(self.verify_cache)
            self.verify_cache = None
        if self.ds:
            self.rx.release_dataset(self.ds)
            self.ds = None
        if self.cache:
            self.rx.release_cache(self.cache)
            self.cache = None
        self._emit({"kind": "BYE"})


# ---------------------------------------------------------------------------
def make_engine(kind: str, **kw):
    """kind: 'auto' | 'native' | 'python'.

    With 'auto', a failed native engine falls back to the portable Python one,
    and the fallback engine carries `fallback_reason` so callers can tell the
    user *why* they are running 5x slower.
    """
    if kind == "python":
        return PythonEngine(**{k: v for k, v in kw.items()
                               if k in ("report_ms", "stall_secs")})
    if kind == "native":
        return NativeEngine(**{k: v for k, v in kw.items()
                               if k in ("report_ms", "stall_secs", "nice",
                                        "init_threads")})
    # auto
    reason = None
    try:
        return NativeEngine(**{k: v for k, v in kw.items()
                               if k in ("report_ms", "stall_secs", "nice",
                                        "init_threads")})
    except EngineError as exc:
        reason = str(exc)
    eng = PythonEngine(**{k: v for k, v in kw.items()
                          if k in ("report_ms", "stall_secs")})
    eng.fallback_reason = reason
    return eng


if __name__ == "__main__":
    # smoke-test: python3 engines.py  (uses a fixed key, runs ~2 seconds)
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default="auto")
    ap.add_argument("--light", action="store_true")
    ap.add_argument("--seconds", type=float, default=3.0)
    ap.add_argument("--threads", type=int, default=2)
    args = ap.parse_args()

    from common import Job
    j = Job(blob_hex=bytes(range(84)).hex(), seed_hex="aa" * 32,
            target_hex="ffffffff", job_id="smoke", url="", user="")
    eng = make_engine(args.engine, report_ms=1000, init_threads=2, nice=0)
    print("engine:", eng.name, "ready:", getattr(eng, "ready", None))
    print(eng.init(j.seed_hex, "light" if args.light else "auto", False, 2))
    eng.start(j, args.threads, random.randrange(0, 1 << 24), [], False, True)
    t0 = time.time()
    while time.time() - t0 < args.seconds:
        for ev in eng.poll(0.5):
            if ev["kind"] in ("RATE", "TOTAL", "WIN", "STALL"):
                print(ev)
    eng.quit()
    print("smoke ok")
