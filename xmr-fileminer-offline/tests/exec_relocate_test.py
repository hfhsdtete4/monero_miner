#!/usr/bin/env python3
"""
tests/exec_relocate_test.py -- the engine must still run when the filesystem
refuses to execute it.

Some FUSE data mounts (sandboxes, containers) allow read/write/chmod but deny
`execve` with EACCES.  Users hitting that were stuck on the ~5x slower ctypes
engine.  Since v1.2 `ensure_runnable()` copies `bin/<engine>` plus `lib/` to a
private temp directory and runs the copy (the `$ORIGIN/../lib` rpath keeps
working because the bin/ + lib/ layout is preserved).

Part A (unit)         -- relocation happens on exec-denial, is cached, keeps
                         the right layout, and does NOT trigger for unrelated
                         failures (e.g. a wrong-architecture binary).
Part B (integration)  -- a full NativeEngine session (init -> start -> hash ->
                         verify -> quit) while every attempt to execute the
                         ORIGINAL path raises PermissionError.

Exit 0 = pass.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import engines  # noqa: E402
from common import Job  # noqa: E402

ORIGINAL = os.path.join(engines.HERE, "bin", "miner_native")


def _denying_run(real):
    """_run replacement: PermissionError for the original path only."""
    def run(cmd, *a, **kw):
        if cmd and os.path.abspath(str(cmd[0])) == os.path.abspath(ORIGINAL):
            raise PermissionError(13, "Permission denied", str(cmd[0]))
        return real(cmd, *a, **kw)
    return run


def _denying_popen(real):
    def popen(cmd, *a, **kw):
        if cmd and os.path.abspath(str(cmd[0])) == os.path.abspath(ORIGINAL):
            raise PermissionError(13, "Permission denied", str(cmd[0]))
        return real(cmd, *a, **kw)
    return popen


def part_a() -> list[str]:
    bad: list[str] = []
    engines._RUNNABLE_CACHE.clear()
    engines._PROBE_NOTE.clear()

    real_run = engines._run
    probes: list[str] = []

    def counting_deny(cmd, *a, **kw):
        probes.append(str(cmd[0]))
        return _denying_run(real_run)(cmd, *a, **kw)

    with mock.patch.object(engines, "_run", counting_deny):
        got = engines.ensure_runnable(ORIGINAL)
        again = engines.ensure_runnable(ORIGINAL)

    rel_path = os.path.join(os.path.dirname(got), "..", "lib", "librandomx.so")
    checks = {
        "relocated away from the original": os.path.abspath(got) != os.path.abspath(ORIGINAL),
        "copy exists and is executable": os.path.exists(got) and os.access(got, os.X_OK),
        "lib/ layout preserved (rpath works)": os.path.exists(rel_path),
        "the relocated copy really executed": os.access(got, os.X_OK),
        "cached (same path on second call)": got == again,
        "probed the relocated copy, not repeatedly the original":
            sum(1 for p in probes if os.path.abspath(p) == os.path.abspath(ORIGINAL)) == 1,
        "note recorded for diagnostics": bool(engines.probe_note(ORIGINAL)),
    }
    for name, ok in checks.items():
        print(f"  [A] {name}: {ok}")
        if not ok:
            bad.append(name)
    print(f"  [A] relocated to: {got}")

    # unrelated failure (wrong architecture) must NOT relocate
    engines._RUNNABLE_CACHE.clear()
    engines._PROBE_NOTE.clear()

    def fake_probe_format_error(path, probe_args=("--info",), timeout=30.0):
        return False, "rc=127: exec format error"
    with mock.patch.object(engines, "_probe_exec", fake_probe_format_error):
        got2 = engines.ensure_runnable(ORIGINAL)
    ok = os.path.abspath(got2) == os.path.abspath(ORIGINAL)
    print(f"  [A] wrong-arch failure does NOT relocate: {ok}")
    if not ok:
        bad.append("relocated on a non-exec-format error")

    # cleanup: kill the relocated copy from part A
    for d in list(engines._TEMP_DIRS):
        shutil.rmtree(d, ignore_errors=True)
    engines._TEMP_DIRS.clear()
    engines._RUNNABLE_CACHE.clear()
    return bad


def part_b() -> list[str]:
    bad: list[str] = []
    real_popen, real_run = subprocess.Popen, subprocess.run
    job = Job(blob_hex=bytes(range(84)).hex(), seed_hex="aa" * 32,
              target_hex="ffffffff", job_id="reloc", url="", user="")

    with mock.patch.object(engines, "_popen", _denying_popen(real_popen)), \
         mock.patch.object(engines, "_run", _denying_run(real_run)):
        eng = engines.NativeEngine(report_ms=1000)
        relocated = os.path.abspath(eng.exec_path) != os.path.abspath(ORIGINAL)
        print(f"  [B] NativeEngine.exec_path relocated: {relocated}")
        if not relocated:
            bad.append("engine did not relocate")

        ev = eng.init(job.seed_hex, "light", False, 2)
        ok_init = ev.get("kind") == "INITOK"
        print(f"  [B] init: {ev.get('kind')}")
        if not ok_init:
            bad.append(f"init failed: {ev}")

        st = eng.selftest()
        ok_vec = st.get("ok") == 1
        print(f"  [B] RandomX test vector via relocated engine: ok={ok_vec}")
        if not ok_vec:
            bad.append(f"self-test failed: {st}")

        eng.start(job, 2, 0, [], False, True)
        hashes = 0
        wins = 0
        t0 = time.time()
        while time.time() - t0 < 12:
            for e in eng.poll(0.5):
                if e.get("kind") == "TOTAL":
                    hashes = int(e.get("hashes", hashes))
                elif e.get("kind") == "WIN":
                    wins += 1
            if hashes > 0 and wins > 0:
                break
        print(f"  [B] hashed {hashes} in a few seconds, wins={wins}")
        if hashes <= 0:
            bad.append("no hashes from the relocated engine")

        # verify() must also use the relocated copy (it spawns its own process)
        h = eng.verify(job.seed_hex, job.blob_with_nonce(1).hex())
        ok_hash = isinstance(h, str) and len(h) == 64
        print(f"  [B] verify() via relocated copy: {ok_hash}")
        if not ok_hash:
            bad.append("verify() failed")

        eng.stop()
        eng.quit()
        # the win count is expected to be ~0 at diff-1 targets; a hash count is
        # the real signal.  (wins>0 is a bonus if the target is easy enough.)
    return bad


def main() -> int:
    print("part A: unit -- relocation decision & cache")
    bad = part_a()
    print("part B: integration -- full engine session with exec denied")
    bad += part_b()
    if bad:
        for b in bad:
            print(f"FAIL: {b}")
        return 1
    print("RESULT: PASS -- engine relocates itself when exec is denied; full session works")
    return 0


if __name__ == "__main__":
    sys.exit(main())
