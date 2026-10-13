#!/usr/bin/env python3
"""
tests/rewrite_fallback_test.py -- delete-and-rewrite fallback for
filesystems that stop persisting APPENDS.

Observed in a sandbox (FUSE data mount): the first create/write of a file
persists, and every later append fails (EOPNOTSUPP) -- so share #1 was saved
and all following shares were lost.  Instead of relocating files, the writer
now switches that file to *delete-and-rewrite*: the whole file is written
afresh (the same operation as the first write that worked) and verified by
read-back before it replaces the old content.

Three hostile configurations are simulated, each with the REAL crash pattern
(a first append that works, then failures), and after each one the test
asserts that EVERY record landed and the file still parses:

  A. appends fail after the first write           (os.replace still works)
  B. appends AND os.replace fail                  (truncate-in-place works)
  C. appends, os.replace AND truncate fail        (unlink+create works)

Exit 0 = pass.
"""
from __future__ import annotations

import builtins
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import common  # noqa: E402
from common import (Job, append_record_locked, atomic_write,  # noqa: E402
                    choose_write_strategy, make_share_record,
                    parse_share_records, strategy_for)

REAL_OPEN = builtins.open
REAL_REPLACE = os.replace


def _hostile_open(append_budget: dict, path: str,
                  fail_replace: bool, fail_truncate: bool):
    """open() replacement modelling an append-hostile mount."""
    ap = os.path.abspath(path)

    def opener(file, mode="r", *a, **kw):
        try:
            target = os.path.abspath(os.fspath(file))
        except TypeError:
            return REAL_OPEN(file, mode, *a, **kw)
        if target == ap and "a" in mode and "+" not in mode:
            key = target
            used = append_budget.get(key, 0)
            append_budget[key] = used + 1
            if used >= 1:                       # first append works, the rest die
                raise OSError(95, "Operation not supported")
        if (target == ap and "w" in mode and fail_truncate
                and os.path.exists(target)):
            raise OSError(95, "Operation not supported")
        return REAL_OPEN(file, mode, *a, **kw)

    return opener


def run_case(name: str, fail_replace: bool, fail_truncate: bool) -> list[str]:
    bad: list[str] = []
    d = tempfile.mkdtemp(prefix="rewritefs-")
    sp = os.path.join(d, "shares.txt")
    budget: dict = {}

    job = Job(blob_hex=bytes(range(84)).hex(), seed_hex="cd" * 32,
              target_hex="ffffffff", job_id="rw", url="", user="")
    recs = [make_share_record(job, i, "%064x" % (i + 1), 100.0 + i, "test")
            for i in range(5)]

    common._WRITE_STRATEGY.pop(sp, None)
    common._STRATEGY_ANNOUNCED.difference_update({k for k in common._STRATEGY_ANNOUNCED})
    orig_replace = os.replace
    if fail_replace:
        os.replace = lambda *a, **kw: (_ for _ in ()).throw(
            OSError(95, "Operation not supported"))
    builtins.open = _hostile_open(budget, sp, fail_replace, fail_truncate)
    try:
        for i, rec in enumerate(recs):
            append_record_locked(sp, rec, sp + ".lock")
            parsed = parse_share_records(common._read_text(sp))
            if len(parsed) != i + 1:
                bad.append(f"{name}: after share #{i + 1} the file has "
                           f"{len(parsed)} record(s), expected {i + 1}")
                break
    except Exception as exc:
        bad.append(f"{name}: raised {type(exc).__name__}: {exc}")
    finally:
        builtins.open = REAL_OPEN
        os.replace = orig_replace

    text = common._read_text(sp)
    parsed = parse_share_records(text)
    nonces = {r["nonce"] for r in parsed}
    want = {r["nonce"] for r in recs}
    ok = nonces == want
    strat = strategy_for(sp)
    print(f"  [{name}] records={len(parsed)}/5 complete={ok} "
          f"strategy={strat} appends-attempted={budget.get(os.path.abspath(sp), 0)}")
    if not ok:
        bad.append(f"{name}: lost records (missing {sorted(want - nonces)[:3]})")
    if strat != "rewrite":
        bad.append(f"{name}: strategy is {strat!r}, expected 'rewrite'")
    if text and not text.endswith("\n"):
        bad.append(f"{name}: file does not end with a newline (truncated write?)")
    return bad


def run_atomic_write_case() -> list[str]:
    """atomic_write (job.txt / bestshare.txt / bridge trims) must also survive
    a mount that refuses both appends and rename-over."""
    bad: list[str] = []
    d = tempfile.mkdtemp(prefix="rewritefs2-")
    jp = os.path.join(d, "job.txt")
    budget: dict = {}
    orig_replace = os.replace
    os.replace = lambda *a, **kw: (_ for _ in ()).throw(OSError(95, "Operation not supported"))
    builtins.open = _hostile_open(budget, jp, True, False)
    try:
        atomic_write(jp, "version=1\n[blob]\n")
        first = common._read_text(jp)
        atomic_write(jp, "version=1\nheight=2\n[blob]\n")       # second write: replace fails
        second = common._read_text(jp)
    except Exception as exc:
        bad.append(f"atomic_write case raised {type(exc).__name__}: {exc}")
        first = second = None
    finally:
        builtins.open = REAL_OPEN
        os.replace = orig_replace
    ok1 = first == "version=1\n[blob]\n"
    ok2 = second == "version=1\nheight=2\n[blob]\n"
    print(f"  [atomic_write] first={ok1!s:5} second(after failed rename)={ok2!s:5}")
    if not (ok1 and ok2):
        bad.append("atomic_write did not persist through a failed rename")
    return bad


def main() -> int:
    print("delete-and-rewrite fallback under append-hostile filesystems")
    bad: list[str] = []
    bad += run_case("A append-only fails", fail_replace=False, fail_truncate=False)
    bad += run_case("B replace fails", fail_replace=True, fail_truncate=False)
    bad += run_case("C replace+truncate fail", fail_replace=True, fail_truncate=True)
    bad += run_atomic_write_case()
    if bad:
        for b in bad:
            print(f"FAIL: {b}")
        return 1
    print("RESULT: PASS -- every share survives an append-hostile filesystem "
          "(delete-and-rewrite), verified by read-back")
    return 0


if __name__ == "__main__":
    sys.exit(main())
