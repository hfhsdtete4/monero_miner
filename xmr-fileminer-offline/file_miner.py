#!/usr/bin/env python3
"""
file_miner.py -- the miner side of xmr-fileminer.

Contract (the whole point of this project):
  * READS  job.txt   -- written by pool_bridge.py (or demo_job.py for testing)
  * WRITES shares.txt -- consumed by pool_bridge.py
  * NEVER talks to the network itself. No sockets, no HTTP, no pool connection.
    If you unplug the network, this process keeps mining the last job it got.

The heavy lifting (RandomX) is handled by engines.py: a native C engine for
maximum hashrate, with a ctypes/Python engine as a portable fallback.

Typical use:
    ./build.sh                       # once: builds librandomx + bin/miner_native
    python3 pool_bridge.py ...       # terminal 1: pool <-> job.txt/shares.txt
    python3 file_miner.py            # terminal 2 (+3, +4...): pure hashing

Offline smoke test:
    python3 demo_job.py --diff 1
    python3 file_miner.py --light --once --stats 2
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import os
import random
import signal
import sys
import time

from common import (
    Job, JobError, SafeFileHandler, SafeStreamHandler, append_record_locked,
    atomic_write, choose_write_strategy, diff_from_target_u32, diff_of_hash,
    fmt_diff, load_job, lock_path_for, make_share_record, render_share_record,
)
from engines import (EngineError, ensure_runnable, logical_cores,
                     make_engine, physical_cores, probe_note)

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = logging.getLogger("miner")
VERSION = "1.3"

PRIORITY_NICE = {0: 19, 1: 10, 2: 0, 3: -5, 4: -10, 5: -20}


# ---------------------------------------------------------------------------
def setup_logging(verbose: bool, log_path: str | None) -> None:
    LOG.setLevel(logging.DEBUG)
    for old in list(LOG.handlers):          # idempotent: never double-log
        LOG.removeHandler(old)
    console = SafeStreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", "%H:%M:%S"))
    LOG.addHandler(console)
    if log_path:
        try:
            fh = SafeFileHandler(log_path, encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S"))
            LOG.addHandler(fh)
            LOG.debug("logging to %s", log_path)
        except OSError as exc:
            console.setLevel(logging.INFO)
            LOG.warning("cannot open log file %s: %s", log_path, exc)


def parse_affinity(spec: str, threads: int) -> list[int]:
    if spec == "none":
        return []
    if spec == "auto":
        return list(range(threads)) if threads <= logical_cores() else []
    cpus: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                cpus.extend(range(int(a), int(b) + 1))
            except ValueError:
                raise SystemExit(f"--affinity: cannot parse {part!r}")
        else:
            try:
                cpus.append(int(part))
            except ValueError:
                raise SystemExit(f"--affinity: cannot parse {part!r}")
    return cpus


# ---------------------------------------------------------------------------
class Miner:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.dir = os.path.abspath(args.dir)
        self.job_path = os.path.join(self.dir, args.job)
        self.shares_path = os.path.join(self.dir, args.shares)
        self.best_path = os.path.join(self.dir, args.best)
        self.shares_lock = lock_path_for(self.shares_path)

        self.threads = args.threads or physical_cores()
        if self.threads < 1:
            self.threads = 1
        self.mode = "light" if args.light else args.mode
        self.hugepages = self._resolve_hugepages(args.hugepages)
        self.cpus = parse_affinity(args.affinity, self.threads)
        self.gate = not args.test_ignore_byte31

        if args.nonce_offset == "auto":
            self.nonce_offset = random.randrange(0, 256) << 24
        elif args.nonce_offset in ("none", "0"):
            self.nonce_offset = 0
        else:
            self.nonce_offset = int(args.nonce_offset, 0) & 0xFFFFFFFF

        self.eng = None
        self.job: Job | None = None
        self.job_started = 0.0
        self.engine_inited_for = ""
        self.engine_mode = self.mode

        self.hashes = 0            # hashes on the CURRENT job
        self.session_hashes = 0    # hashes before the current job
        self.thread_hps: dict[int, float] = {}
        self.total_hps = 0.0
        self.shares = 0
        self.job_shares = 0
        self.session_best: dict | None = None
        self.job_best: dict | None = None
        self.best_attempt: float | None = None
        self.started = time.time()
        self._stop = False
        self._last_warn_job = 0.0
        self._last_stats = 0.0
        self._init_failures = 0
        self._engine_dead = False
        self._fell_back = False
        self._needs_restart = False
        self._unsaved: list[dict] = []      # shares found but not yet persisted
        self._last_save_warn = 0.0
        self._verifier = None               # in-process hasher for --verify
        self._warned_light = False

    def _resolve_hugepages(self, spec: str) -> bool:
        """Honor --hugepages, but don't ask for pages the kernel does not have."""
        if spec == "off":
            return False
        if spec == "on":
            return True
        try:
            total_kb = huge_kb = 0
            with open("/proc/meminfo") as fh:
                for line in fh:
                    if line.startswith("Hugepagesize:"):
                        huge_kb = int(line.split()[1])
                    elif line.startswith("HugePages_Total:"):
                        total_kb = int(line.split()[1])
            if huge_kb and total_kb:
                pages_mb = total_kb * huge_kb / 1024
                LOG.info("using %d huge pages (%d x %d kB = %.0f MB reserved)",
                         total_kb, total_kb, huge_kb, pages_mb)
                return True
            LOG.info("no huge pages reserved by the kernel -- running on normal pages "
                     "(a few % slower); see build.sh output for the one-line sysctl")
        except OSError:
            pass
        return False

    # -- engine setup ---------------------------------------------------
    def make_engine(self) -> None:
        nice = PRIORITY_NICE.get(self.args.priority, 0)
        if nice:
            try:
                got = os.nice(nice)
                LOG.info("process priority raised (nice %+d -> %+d)", nice, got)
            except (PermissionError, OSError) as exc:
                LOG.warning("cannot raise priority (needs privileges): %s", exc)
                nice = 0
        try:
            self.eng = make_engine(self.args.engine, report_ms=self.args.report_ms,
                                   stall_secs=self.args.stall_secs, nice=nice,
                                   init_threads=self.args.init_threads)
        except EngineError as exc:
            LOG.error("no usable hashing engine: %s", exc)
            LOG.error("run ./build.sh (builds lib/librandomx.so and bin/miner_native), "
                      "or use --engine python if lib/librandomx.so exists")
            sys.exit(6)
        if self.eng.name == "native":
            LOG.info("engine: native")
        else:
            LOG.warning("engine: python  (portable fallback, roughly 5x slower)")
            reason = getattr(self.eng, "fallback_reason", None)
            if reason:
                LOG.warning("  native engine unavailable: %s", reason)
            LOG.warning("  diagnose:  python3 file_miner.py --doctor")
            LOG.warning("  fix:       ./build.sh --force   # rebuilds lib+engine for THIS machine")
        if self.eng.name == "native" and getattr(self.eng, "ready", None):
            r = self.eng.ready
            LOG.debug("engine ready: %s", r)
            if not r.get("jit"):
                LOG.warning("RandomX JIT is OFF (flags=0x%x) -- hashrate will be much lower",
                            r.get("flags", 0))
            if not r.get("aes"):
                LOG.warning("hardware AES not detected -- hashrate will be much lower")

    # -- engine resilience ------------------------------------------------
    def _fallback_to_python(self, exc: BaseException) -> bool:
        """One-shot rescue: the native engine died -> portable python engine.

        Returns True when the fallback happened (caller should retry), False
        when it is not applicable (explicit --engine choice, already fell back,
        or the engine already is the python one).
        """
        if getattr(self, "_fell_back", False) or self.args.engine != "auto":
            return False
        if self.eng is None or self.eng.name != "native":
            return False
        self._fell_back = True
        LOG.error("native engine failed: %s", exc)
        LOG.warning("falling back to the portable python engine (roughly 5x slower)")
        LOG.warning("diagnose and rebuild with:  python3 file_miner.py --doctor ; ./build.sh --force")
        with contextlib.suppress(Exception):
            self.eng.quit()
        self.eng = make_engine("python", report_ms=self.args.report_ms,
                               stall_secs=self.args.stall_secs)
        self.eng.fallback_reason = str(exc)
        self.engine_inited_for = None
        self._init_failures = 0
        self._warned_light = False
        return True

    # -- jobs -----------------------------------------------------------
    def try_load_job(self) -> Job | None:
        try:
            job = load_job(self.job_path)
        except JobError as exc:
            now = time.time()
            if now - self._last_warn_job > 60:
                self._last_warn_job = now
                LOG.warning("no usable job: %s", exc)
                LOG.warning("start pool_bridge.py (real pool) or demo_job.py (offline test)")
            return None
        except Exception as exc:                     # malformed file, race, ...
            now = time.time()
            if now - self._last_warn_job > 60:
                self._last_warn_job = now
                LOG.warning("cannot read %s: %s", self.job_path, exc)
            return None
        return job

    def job_age(self) -> float:
        try:
            return time.time() - os.path.getmtime(self.job_path)
        except OSError:
            return -1.0

    def switch_job(self, job: Job) -> bool:
        assert self.eng is not None
        first = self.job is None
        seed_changed = first or job.seed_hex != self.job.seed_hex

        if not first:
            LOG.info("new job from %s: %s", job.source, job.summary())
        else:
            LOG.info("first job: %s", job.summary())

        if seed_changed:
            LOG.info("RandomX key changed -> re-initializing memory%s",
                     "" if self.engine_mode == "light" else
                     " (full dataset ~2 GB; this is normal once per new block key)")
        else:
            LOG.debug("same RandomX key -> workers restart only")

        # carry the finished job's hash count into the session total before
        # the engine counters reset for the next job
        self.session_hashes += int(self.hashes)
        self.hashes = 0

        try:
            return self._switch_job_engine(job, seed_changed)
        except EngineError as exc:
            # a native engine that cannot even start (wrong libc, noexec mount,
            # loader failure) must not take the miner down: degrade once to the
            # portable engine and retry the same job.
            if self._fallback_to_python(exc):
                return self.switch_job(job)
            LOG.error("engine failure on job switch: %s", exc)
            self._engine_dead = True
            self._stop = True
            return False

    def _switch_job_engine(self, job: Job, seed_changed: bool) -> bool:
        ev: dict | None = None
        try:
            self.eng.stop()
        except EngineError as exc:
            LOG.debug("engine stop: %s", exc)

        if seed_changed or self.engine_inited_for != job.seed_hex:
            ev = self.eng.init(job.seed_hex, self.engine_mode, self.hugepages,
                               self.args.init_threads)
            if ev.get("kind") != "INITOK":
                reason = ev.get("reason", ev.get("raw", "?"))
                LOG.error("engine INIT failed: %s", reason)
                if self.engine_mode == "full" and "memory" in str(reason):
                    LOG.warning("falling back to light mode (slower, but works)")
                    self.engine_mode = "light"
                    ev = self.eng.init(job.seed_hex, "light", False, self.args.init_threads)
                if ev.get("kind") != "INITOK":
                    self._init_failures += 1
                    if self._init_failures >= 5:
                        LOG.error("giving up after 5 failed initializations")
                        self._stop = True
                    return False
            self._init_failures = 0
            self.engine_inited_for = job.seed_hex

            if not self.args.no_selftest:
                st = self.eng.selftest()
                okval = st.get("ok")
                if okval == 0:
                    LOG.error("RandomX self-test FAILED: got %s, expected c5641412...3cd5f1",
                              st.get("got", "?"))
                    LOG.error("this build must not mine -- shares would be invalid. "
                              "Rebuild with ./build.sh on this machine.")
                    sys.exit(4)
                if okval != 1:
                    LOG.warning("RandomX self-test could not run (%s) -- continuing, but "
                                "check ./bin/rx_test manually", st)
                else:
                    LOG.info("RandomX self-test OK (%s mode)%s",
                             "full" if ev.get("mode") == "full" else "light",
                             " + dataset cross-check" if st.get("cross") else "")

        if ev is not None:
            self.engine_mode = str(ev.get("mode", self.engine_mode)) or self.engine_mode
        if self.engine_mode == "light" and not self._warned_light:
            self._warned_light = True
            LOG.warning("running in LIGHT mode: correct but ~5-10x slower than the full "
                        "dataset; free ~2.7 GB RAM (or lower --threads) for full mode")

        started = self.eng.start(job, self.threads, self.nonce_offset, self.cpus,
                                 self.args.yield_, self.gate)
        self.job = job
        self.job_started = time.time()
        self.job_shares = 0
        self.best_attempt = None    # per-job: the engine resets ITS best on every START too
        self.job_best = None
        LOG.info("mining with %d thread%s (engine=%s, mode=%s%s)", self.threads,
                 "s" if self.threads != 1 else "", self.eng.name, self.engine_mode,
                 f", affinity={self.cpus}" if self.cpus else "")
        LOG.debug("engine started: %s", started)
        return True

    # -- shares ---------------------------------------------------------
    def on_win(self, ev: dict) -> None:
        if self.job is None:
            return
        nonce = ev.get("nonce_u32")
        hash_hex = str(ev.get("hash", "")).lower()
        if nonce is None or len(hash_hex) != 64:
            LOG.error("engine sent a malformed WIN event: %s", ev)
            return
        diff = float(ev.get("diff") or diff_of_hash(bytes.fromhex(hash_hex)))

        # Boundary check: the engine said this hash meets the target; make sure
        # the claim survives an independent evaluation against the job's own
        # target before it ever reaches shares.txt.
        try:
            from common import hash_meets_target
            if not hash_meets_target(bytes.fromhex(hash_hex), self.job.target_u32, self.gate):
                LOG.error("engine reported a WIN that does NOT meet the job target "
                          "(hash=%s target32=0x%08x) -- dropping it. This is an engine "
                          "bug; please report it.", hash_hex, self.job.target_u32)
                return
        except ValueError:
            LOG.error("engine sent a non-hex hash: %r", hash_hex)
            return

        verified: bool | None = None
        want_verify = (self.args.verify == "on") or \
                      (self.args.verify == "auto" and self.job.demo)
        if want_verify:
            try:
                got = self._verify_share(nonce)
                verified = got == hash_hex
                if not verified:
                    LOG.error("share failed self-verification (got %s) -- not writing it. "
                              "This points at an engine/library mismatch.", got)
                    return
            except EngineError as exc:
                LOG.warning("could not self-verify share: %s", exc)

        rec = make_share_record(self.job, nonce, hash_hex, diff, self.eng.name, True)
        rec["verified"] = "1" if verified else "?"
        saved = self._try_save(rec)
        need = diff_from_target_u32(self.job.target_u32)
        if saved:
            LOG.info("SHARE #%d job=%s nonce=%s diff=%s (pool needs %s, x%.2f) -> %s%s",
                     self.shares, self.job.job_id, rec["nonce"], fmt_diff(diff),
                     fmt_diff(need), diff / need if need else 0.0,
                     args_rel(self.shares_path),
                     "" if verified is None else
                     (" [verified]" if verified else " [unverified]"))
        else:
            LOG.warning("share found but NOT yet on disk (queued, retried "
                        "automatically): job=%s nonce=%s diff=%s -- see the error above",
                        self.job.job_id, rec["nonce"], fmt_diff(diff))
        self._note_share_best(diff, hash_hex, nonce)
        if self.args.once:
            LOG.info("--once: share found, stopping")
            self._stop = True

    # -- share persistence ---------------------------------------------------
    def _try_save(self, rec: dict) -> bool:
        """Persist `rec` (plus anything queued before it). True if this one is on disk.

        A share that cannot be saved is NOT dropped: it stays in a queue and is
        retried on every later share (and at shutdown, where the remaining
        records are printed so they can be recovered by hand).  This covers
        filesystems that stop persisting appends -- the writer switches such
        files to delete-and-rewrite automatically; the queue covers everything
        else.
        """
        self._unsaved.append(rec)
        self._flush_unsaved()
        return not any(r is rec for r in self._unsaved)

    def _flush_unsaved(self) -> None:
        while self._unsaved:
            rec = self._unsaved[0]
            try:
                append_record_locked(self.shares_path, rec, self.shares_lock)
            except Exception as exc:
                now = time.time()
                if now - self._last_save_warn > 60:
                    self._last_save_warn = now
                    LOG.error("cannot save %d share(s) to %s: %s", len(self._unsaved),
                              args_rel(self.shares_path), exc)
                    LOG.error("they stay queued and are retried automatically; if this "
                              "persists, point --dir at a normal filesystem")
                return
            self._unsaved.pop(0)
            self.shares += 1
            self.job_shares += 1
            LOG.debug("saved share nonce=%s (queue depth %d)", rec.get("nonce"),
                      len(self._unsaved))

    def _verify_share(self, nonce: int) -> str:
        """Re-hash a found share.  Uses whatever engine is active, except that a
        native engine verifies through the persistent in-process (ctypes) hasher:
        spawning a subprocess per share re-initializes a 256 MB cache each time
        and starves the mining loop during share bursts (seen live: stats stuck
        at 0.00 H/s while shares streamed in)."""
        if self.eng is not None and self.eng.name == "python":
            return self.eng.verify(self.job.seed_hex,
                                   self.job.blob_with_nonce(nonce).hex())
        if self._verifier is None:
            from engines import PythonEngine
            self._verifier = PythonEngine()
        return self._verifier.verify(self.job.seed_hex,
                                     self.job.blob_with_nonce(nonce).hex())

    def _note_share_best(self, diff: float, hash_hex: str, nonce: int) -> None:
        """Best *qualified* share -> bestshare.txt + display."""
        if self.job is None:
            return
        if self.session_best is not None and diff <= self.session_best["diff"]:
            return
        self.session_best = {"diff": diff, "nonce": nonce, "hash": hash_hex}
        self.job_best = dict(self.session_best)
        rec = make_share_record(self.job, nonce, hash_hex, diff, self.eng.name, True)
        rec["verified"] = "?"
        try:
            atomic_write(self.best_path, render_share_record(rec))
        except OSError as exc:
            LOG.debug("cannot write %s: %s", self.best_path, exc)

    def _note_attempt_best(self, diff: float) -> None:
        """Best hash seen this session even if it never reached the target."""
        if self.best_attempt is None or diff > self.best_attempt:
            self.best_attempt = diff

    # -- events ---------------------------------------------------------
    def handle_event(self, ev: dict) -> None:
        kind = ev.get("kind")
        if kind == "WIN":
            self.on_win(ev)
        elif kind == "BEST":
            self._note_attempt_best(float(ev.get("diff", 0.0)))
        elif kind == "TOTAL":
            self.total_hps = float(ev.get("hps", 0.0))
            self.hashes = int(ev.get("hashes", self.hashes))
        elif kind == "RATE":
            self.thread_hps[int(ev.get("tid", 0))] = float(ev.get("hps", 0.0))
        elif kind == "INITPROG":
            pct = int(ev.get("pct", 0) or 0)
            if pct == 0 or pct >= 100 or pct % 10 == 0:
                LOG.info("dataset init %d%% (%s)", pct, ev.get("phase", ""))
        elif kind == "STALL":
            LOG.warning("thread %s completed no hash for %ss -- either this box is "
                        "heavily loaded by other processes, or there is a JIT/hugepage "
                        "issue (try --hugepages off)", ev.get("tid"), ev.get("secs"))
        elif kind == "RESUME":
            LOG.info("thread %s recovered", ev.get("tid"))
        elif kind == "WARN":
            LOG.warning("engine warning: %s %s", ev.get("msg", ""), ev.get("text", ""))
        elif kind == "ERR":
            LOG.error("engine error: %s", ev.get("msg", ev.get("raw", "")))
        elif kind == "EXIT":
            if not self._stop:
                reason = self.eng.dead_reason or f"engine exited ({ev})"
                if self._fallback_to_python(EngineError(reason)):
                    LOG.warning("engine died mid-run -- restarting the current job "
                                "on the python engine")
                    self._needs_restart = True
                else:
                    LOG.error("hashing engine exited unexpectedly (%s)", ev)
                    self._engine_dead = True
                    self._stop = True
        else:
            LOG.debug("event: %s", ev)

    # -- stats ----------------------------------------------------------
    def print_stats(self) -> None:
        if self.job is None:
            return
        age = self.job_age()
        parts = ["%.2f H/s" % self.total_hps]
        if len(self.thread_hps) > 1:
            parts.append("(" + " ".join(f"{h:.2f}" for _, h in sorted(self.thread_hps.items())) + ")")
        line = " ".join(parts)
        line += f" | job={self.job.job_id} h={self.job.height} age={age:.0f}s | "
        line += f"hashes={self.total_hashes()} shares={self.shares}"
        need = diff_from_target_u32(self.job.target_u32)
        if self.session_best:
            line += (f" | best share {fmt_diff(self.session_best['diff'])} "
                     f"(x{self.session_best['diff']/need:.2f})")
        elif self.best_attempt:
            # best attempt on the CURRENT job (reset at every job switch, as is
            # the engine's own best tracker), shown as a factor of the target
            line += (f" | best hash {fmt_diff(self.best_attempt)}"
                     + (f" (x{self.best_attempt / need:.2f} of target)" if need else ""))
        if self.total_hps > 0:
            eta = self.job.eff_diff / self.total_hps
            line += f" | E[share]={eta:.0f}s"
        LOG.info(line)
        if (self.job.source and not self.job.demo and age > self.args.job_warn):
            if time.time() - self._last_warn_job > 60:
                self._last_warn_job = time.time()
                LOG.warning("job.txt has not been updated for %.0fs -- is pool_bridge.py "
                            "still running?", age)

    def total_hashes(self) -> int:
        return self.session_hashes + int(self.hashes)

    def summary_line(self) -> str:
        rt = time.time() - self.started
        total = self.total_hashes()
        hps = self.total_hps
        if hps <= 0 and total > 0 and rt > 0:
            hps = total / rt                        # average over the run
        return ("SUMMARY engine=%s mode=%s hps=%.3f hashes=%d shares=%d runtime=%.1f"
                % (self.eng.name if self.eng else "?", self.engine_mode, hps,
                   total, self.shares, rt))

    # -- main loop ------------------------------------------------------
    def run(self) -> int:
        self.make_engine()

        def on_signal(signum, _frame):
            LOG.info("signal %d received -> stopping", signum)
            self._stop = True

        signal.signal(signal.SIGINT, on_signal)
        signal.signal(signal.SIGTERM, on_signal)

        strat, note = choose_write_strategy(self.shares_path)
        if note:
            LOG.warning("shares.txt: %s", note)
        else:
            LOG.debug("shares.txt write strategy: %s", strat)
        LOG.info("%s file-based miner: job=%s shares=%s (no network in this process)",
                 self.eng.name, args_rel(self.job_path), args_rel(self.shares_path))
        if not self.gate:
            LOG.warning("=" * 72)
            LOG.warning("--test-ignore-byte31 ENABLED: the H[31]==0 protocol gate is OFF.")
            LOG.warning("Share rates will be ~256x higher than reality. This is a")
            LOG.warning("PLUMBING TEST ONLY. Never mine to a real pool with this flag.")
            LOG.warning("=" * 72)

        last_job_check = 0.0
        while not self._stop:
            for ev in self.eng.poll(0.25):
                try:
                    self.handle_event(ev)
                except Exception as exc:      # one bad event must not end the run
                    LOG.error("error while handling engine event %r: %s",
                              ev.get("kind"), exc, exc_info=self.args.verbose)

            now = time.time()
            if now - last_job_check >= self.args.poll_job:
                last_job_check = now
                job = self.try_load_job()
                if self._needs_restart:
                    self._needs_restart = False
                    self.job = None            # force a re-init on the next job
                if job is not None and (self.job is None
                                        or job.signature() != self.job.signature()):
                    if not self.switch_job(job):
                        time.sleep(2.0)

            if now - self._last_stats >= self.args.stats:
                self._last_stats = now
                self.print_stats()

            if self.args.max_runtime and (now - self.started) >= self.args.max_runtime:
                LOG.info("--max-runtime reached")
                self._stop = True

        # shutdown: one last attempt to persist queued shares, then print
        # whatever could not be saved so the records are not lost
        self._flush_unsaved()
        if self._unsaved:
            LOG.error("%d share(s) could not be written to %s -- printing them "
                      "so they can be recovered manually:", len(self._unsaved),
                      args_rel(self.shares_path))
            for rec in self._unsaved:
                try:
                    print(render_share_record(rec).rstrip("\n"))
                except OSError:
                    break
        if self._verifier is not None:
            with contextlib.suppress(Exception):
                self._verifier.quit()
            self._verifier = None

        # shutdown: grab final counters before stopping the workers
        try:
            st = self.eng.final_stats()
            if st.get("hashes"):
                self.hashes = max(self.hashes, int(st["hashes"]))
        except Exception as exc:                      # pragma: no cover
            LOG.debug("final stats: %s", exc)
        self.session_hashes += int(self.hashes)
        self.hashes = 0
        try:
            self.eng.stop()
            self.eng.quit()
        except Exception as exc:                     # pragma: no cover
            LOG.debug("engine shutdown: %s", exc)
        self.print_stats()
        try:
            print(self.summary_line())
            sys.stdout.flush()
        except OSError:
            pass
        return 3 if self._engine_dead else 0


def _mount_options(path: str) -> str:
    """Mount options of the filesystem holding `path` ('' if unknown)."""
    best, best_len = "", -1
    try:
        real = os.path.realpath(path)
        with open("/proc/self/mounts", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 4:
                    continue
                mnt = parts[1].replace("\\040", " ").rstrip("/") or "/"
                if real == mnt or real.startswith(mnt + "/"):
                    if len(mnt) > best_len:
                        best, best_len = parts[3], len(mnt)
    except OSError:
        pass
    return best


def _classify_binary_failure(out: str, rc: int, noexec: bool) -> list[str]:
    """Turn the engine's dying words into actionable advice."""
    low = out.lower()
    tips: list[str] = []
    if "permission denied" in low or "operation not permitted" in low \
            or (rc in (126, 127) and "permission" in low):
        tips.append("the filesystem denies execve on bin/miner_native"
                    + (" (noexec mount)" if noexec else " (some FUSE data mounts do this even "
                       "without the noexec flag)")
                    + " -- the miner already auto-relocates its engine to a temp dir when "
                      "possible; to run the original directly, put the project on a local-disk "
                      "path (e.g. /tmp/ or a home dir outside this mount)")
    elif noexec:
        tips.append("this filesystem is mounted noexec, so bin/miner_native cannot run at all -- "
                    "copy the folder somewhere executable (e.g. /tmp) or build there")
    if "error while loading shared libraries" in low or "cannot open shared object" in low:
        tips.append("the engine cannot load lib/librandomx.so -- keep lib/ next to bin/ "
                    "(it is found via an rpath of $ORIGIN/../lib)")
    if "glibc_" in low or ("version" in low and "not found" in low):
        tips.append("the prebuilt binary needs a newer glibc than this machine has -- "
                    "rebuild here: ./build.sh --force")
    if "exec format error" in low or "cannot execute binary file" in low:
        tips.append("the prebuilt binary is for a different CPU architecture -- "
                    "rebuild here: ./build.sh --force")
    if not tips:
        tips.append(f"the engine exited rc={rc}; rebuild it for this machine: ./build.sh --force")
    return tips


def doctor(dir_path: str) -> int:
    """Explain whether the native engine can run HERE, and what to do about it."""
    import ctypes
    import platform
    import shutil
    import stat as statmod

    print(f"xmr-fileminer doctor (v{VERSION})")
    print(f"  python     : {sys.version.split()[0]} ({platform.python_implementation()})")
    print(f"  platform   : {platform.platform()}")
    print(f"  machine    : {platform.machine()}")
    libc_name, libc_ver = platform.libc_ver()
    if libc_name:
        print(f"  libc       : {libc_name} {libc_ver}")
    opts = _mount_options(os.getcwd())
    noexec = "noexec" in (opts or "")
    print(f"  cwd mount  : {opts or '(unknown)'}{'   <-- noexec!' if noexec else ''}")

    bin_path = os.path.join(HERE, "bin", "miner_native")
    lib_path = os.path.join(HERE, "lib", "librandomx.so")
    tips: list[str] = []
    so_ok = bin_ok = False

    if not os.path.exists(lib_path):
        print(f"  librandomx : MISSING ({lib_path})")
        tips.append("run ./build.sh to build lib/librandomx.so")
    else:
        try:
            ctypes.CDLL(lib_path)
            print("  librandomx : loads OK")
            so_ok = True
        except OSError as exc:
            print(f"  librandomx : FAILED to load: {exc}")
            tips.append("lib/librandomx.so cannot be loaded here (wrong arch/libc, or a noexec "
                        "mount) -- rebuild here: ./build.sh --force")

    if not os.path.exists(bin_path):
        print(f"  engine bin : MISSING ({bin_path})")
        tips.append("run ./build.sh")
    else:
        exec_path = ensure_runnable(bin_path)          # probes; relocates if needed
        relocated = os.path.abspath(exec_path) != os.path.abspath(bin_path)
        note = probe_note(bin_path) or ""
        if relocated:
            # exec is denied on this filesystem; the miner runs a private copy
            print("  engine bin : cannot be executed from this filesystem")
            print(f"               running a relocated copy instead: {exec_path}")
            print(f"               (probe: {note})")
            bin_ok = True
        else:
            mode = statmod.S_IMODE(os.stat(bin_path).st_mode)
            print(f"  engine bin : mode {mode:o}, `--info` {note or 'ok'}")
            bin_ok = not note
            if note:
                tips.extend(_classify_binary_failure(note, 1, noexec))

    tools = {t: bool(shutil.which(t)) for t in ("gcc", "cc", "clang", "make", "git", "cmake")}
    have_cc = tools["gcc"] or tools["cc"] or tools["clang"]
    print("  toolchain  : " + ", ".join(f"{k}:{'yes' if v else 'no'}" for k, v in tools.items()))
    pyflags = []
    try:
        import engines as _eng
        pyflags.append("ctypes python engine: available")
        eng = _eng.PythonEngine()
        ev = eng.init("00" * 32, "light", False, 1)
        pyflags.append(f"python engine init: {ev.get('kind')}")
        eng.quit()
        py_ok = ev.get("kind") == "INITOK"
    except Exception as exc:                      # pragma: no cover
        pyflags.append(f"python engine: FAILED ({exc})")
        py_ok = False
    print("  fallback   : " + "; ".join(pyflags))

    print()
    if bin_ok and so_ok:
        if relocated:
            print("VERDICT: native engine is USABLE here, but not from this filesystem --")
            print("         the miner automatically runs a relocated copy (see above),")
            print("         so you still get maximum hashrate. The copy is re-created on")
            print("         every start and needs no maintenance.")
            print("         To run the original binary directly, put the project on a")
            print("         local-disk path (e.g. /tmp/ or a home dir that is not this")
            print("         mount) and run it there.")
        else:
            print("VERDICT: native engine is usable -- you get maximum hashrate.")
        if not have_cc:
            print("         (no C compiler here; the bundled binary is what runs)")
        return 0
    print("VERDICT: the native engine is NOT usable here. Reasons/next steps:")
    for tip in dict.fromkeys(tips):               # de-dup, keep order
        print(f"  - {tip}")
    if not have_cc or not tools["make"]:
        print("  - this box also lacks a C compiler/make, so it cannot rebuild the "
              "engine locally; use the Python engine or move to a build machine")
    print("  Meanwhile: python3 file_miner.py --engine python "
          f"({'works' if py_ok else 'ALSO FAILING -- see above'})")
    return 1


def args_rel(path: str) -> str:
    try:
        return os.path.relpath(path, os.getcwd())
    except ValueError:
        return path


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="file_miner.py",
        description="Mine Monero (RandomX) from a job.txt file; write results to shares.txt. "
                    "This process never connects to any pool -- pool_bridge.py does that.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--dir", default=HERE, help="directory holding job.txt/shares.txt")
    ap.add_argument("--job", default="job.txt", help="job file name inside --dir")
    ap.add_argument("--shares", default="shares.txt", help="share file name inside --dir")
    ap.add_argument("--best", default="bestshare.txt", help="session-best file name")
    ap.add_argument("--log", default="miner.log", help="log file name ('' to disable)")
    ap.add_argument("--threads", type=int, default=0,
                    help="worker threads (default: physical cores)")
    ap.add_argument("--engine", choices=["auto", "native", "python"], default="auto")
    ap.add_argument("--mode", choices=["auto", "full", "light"], default="auto",
                    help="RandomX memory mode: 'full' = 2 GB dataset (fastest), "
                         "'light' = 512 MB cache (~5-10x slower)")
    ap.add_argument("--light", action="store_true", help="alias for --mode light")
    ap.add_argument("--hugepages", choices=["auto", "on", "off"], default="auto",
                    help="request 2 MB pages for dataset/cache/scratchpad")
    ap.add_argument("--init-threads", type=int, default=min(4, physical_cores()),
                    help="threads used to initialize the 2 GB dataset")
    ap.add_argument("--affinity", default="auto",
                    help="'auto', 'none', or a cpu list like 0-3,8")
    ap.add_argument("--nonce-offset", default="auto",
                    help="'auto' (random per run), 'none', or an explicit hex/decimal base")
    ap.add_argument("--priority", type=int, choices=[0, 1, 2, 3, 4, 5], default=2,
                    help="0=idle .. 2=normal .. 5=highest (needs privileges for >2)")
    ap.add_argument("--yield", dest="yield_", action="store_true",
                    help="cooperate with other processes (sched_yield between hashes)")
    ap.add_argument("--report-ms", type=int, default=2000,
                    help="engine rate-report interval in milliseconds")
    ap.add_argument("--stall-secs", type=int, default=30,
                    help="warn if a worker thread completes no hash for this long")
    ap.add_argument("--stats", type=float, default=10.0, help="stats line interval (s)")
    ap.add_argument("--poll-job", type=float, default=0.5, help="job.txt check interval (s)")
    ap.add_argument("--job-warn", type=float, default=180.0,
                    help="warn when job.txt is older than this many seconds")
    ap.add_argument("--verify", choices=["auto", "on", "off"], default="auto",
                    help="re-hash each found share before writing it "
                         "(auto: only for demo jobs)")
    ap.add_argument("--no-selftest", action="store_true",
                    help="skip the RandomX test-vector gate at startup (not recommended)")
    ap.add_argument("--once", action="store_true", help="exit after the first share")
    ap.add_argument("--max-runtime", type=float, default=0.0,
                    help="exit after this many seconds (0 = run forever)")
    ap.add_argument("--test-ignore-byte31", action="store_true",
                    help="TEST ONLY: drop the H[31]==0 gate to exercise the file plumbing "
                         "quickly. Shares produced this way are NOT valid pool shares.")
    ap.add_argument("--doctor", action="store_true",
                    help="explain whether the native engine can run on this machine "
                         "(and why not, if it cannot), then exit")
    ap.add_argument("--version", action="version",
                    version=f"xmr-fileminer {VERSION}")
    ap.add_argument("--verbose", action="store_true", help="debug logging")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.doctor:
        return doctor(args.dir)
    log_path = os.path.join(os.path.abspath(args.dir), args.log) if args.log else None
    setup_logging(args.verbose, log_path)
    return Miner(args).run()


if __name__ == "__main__":
    sys.exit(main())
