#!/usr/bin/env python3
"""
tests/hostile_fs_e2e_test.py -- the WHOLE miner on an append-hostile
filesystem (the real-world failure this fallback exists for).

Simulates the mount seen in the field: creating a file and writing it once
works; every later APPEND to it dies with EOPNOTSUPP, and (option B) even
rename-over is refused.  The miner must

  * keep mining at full speed,
  * persist EVERY share anyway (delete-and-rewrite fallback),
  * report no save errors, and
  * leave a shares.txt that parses and re-verifies.

Exit 0 = pass.
"""
from __future__ import annotations

import builtins
import logging
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import common  # noqa: E402
import file_miner  # noqa: E402
from demo_job import build_job  # noqa: E402
from common import parse_share_records, render_job_text  # noqa: E402

REAL_OPEN = builtins.open
REAL_REPLACE = os.replace


def _hostile(paths: set[str], append_budget: dict):
    def opener(file, mode="r", *a, **kw):
        try:
            target = os.path.abspath(os.fspath(file))
        except TypeError:
            return REAL_OPEN(file, mode, *a, **kw)
        if target in paths and "a" in mode and "+" not in mode:
            used = append_budget.get(target, 0)
            append_budget[target] = used + 1
            if used >= 1:                      # first append ok, rest fail hard
                raise OSError(95, "Operation not supported")
        return REAL_OPEN(file, mode, *a, **kw)
    return opener


def run(fail_replace: bool, seconds: int) -> list[str]:
    bad: list[str] = []
    d = tempfile.mkdtemp(prefix="hostile-e2e-")
    shares = os.path.join(d, "shares.txt")
    job = build_job(diff=1.0)
    with REAL_OPEN(os.path.join(d, "job.txt"), "w") as fh:
        fh.write(render_job_text(job))

    common._WRITE_STRATEGY.pop(shares, None)
    errors: list[str] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            if record.levelno >= logging.WARNING:
                errors.append(record.getMessage())

    handler = _Collect()
    logging.getLogger("miner").addHandler(handler)

    budget: dict = {}
    builtins.open = _hostile({os.path.abspath(shares)}, budget)
    if fail_replace:
        os.replace = lambda *a, **kw: (_ for _ in ()).throw(OSError(95, "nope"))
    try:
        rc = file_miner.main(["--dir", d, "--light", "--threads", "2",
                              "--stats", "5", "--max-runtime", str(seconds),
                              "--verify", "off", "--log", ""])
    finally:
        builtins.open = REAL_OPEN
        os.replace = REAL_REPLACE
        logging.getLogger("miner").removeHandler(handler)

    text = common._read_text(shares) if os.path.exists(shares) else ""
    recs = parse_share_records(text)
    print(f"  replace_allowed={not fail_replace}: exit={rc} records={len(recs)} "
          f"appends_attempted={budget.get(os.path.abspath(shares), 0)} "
          f"strategy={common.strategy_for(shares)}")
    if rc != 0:
        bad.append(f"miner exited {rc}")
    if len(recs) < 1:
        bad.append("no share records survived the hostile filesystem")
    for e in errors:
        if "could not save" in e.lower() or "not yet on disk" in e.lower() \
                or "did NOT survive" in e:
            bad.append(f"save error reported: {e[:120]}")
    # every record must be complete enough to be verified
    for r in recs:
        if len(r.get("result", "")) != 64 or not r.get("nonce"):
            bad.append("malformed record on disk")
            break
    return bad


def main() -> int:
    print("whole miner on a simulated append-hostile filesystem")
    bad: list[str] = []
    errors: list[str] = []
    for fail_replace in (False, True):
        got = run(fail_replace=fail_replace, seconds=int(sys.argv[1]) if len(sys.argv) > 1 else 20)
        errors += got
    if errors:
        for b in errors:
            print(f"FAIL: {b}")
        return 1
    print("RESULT: PASS -- shares persisted through append-hostile filesystems, "
          "no save errors, file verifies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
