#!/usr/bin/env python3
"""
tests/harsh_fs_test.py -- file writes must survive hostile filesystems.

Some FUSE mounts (sandboxes, containers) accept write() but fail flush(),
fsync(), close() or flock() with OSError errno 95 (EOPNOTSUPP).  A previous
build died on exactly that while appending a found share: the process crashed
and the share was lost.

This test makes every one of those syscalls fail and asserts that

  * append_record_locked() still stores the record (verified by read-back),
  * atomic_write() still stores the text before it replaces the destination,
  * file_lock() degrades to "unlocked" instead of raising,
  * and a record that genuinely did not survive raises a CLEAR RuntimeError
    (not a bare OSError) so the miner can report it and keep mining.

Exit 0 = pass.
"""
from __future__ import annotations

import os
import sys
import tempfile
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import common  # noqa: E402
from common import (Job, append_record_locked, atomic_write, file_lock,  # noqa: E402
                    lock_path_for, make_share_record, parse_share_records)


def boom(*args, **kwargs):
    raise OSError(95, "Operation not supported")


def main() -> int:
    d = tempfile.mkdtemp(prefix="harshfs-")
    job = Job(blob_hex=bytes(range(84)).hex(), seed_hex="ab" * 32,
              target_hex="ffffffff", job_id="harsh", url="", user="")
    rec = make_share_record(job, 0x1234ABCD, "cd" * 32, 300.0, "test")

    failures: list[str] = []

    # ---- everything fails at the syscall level -----------------------------
    with mock.patch.object(common, "_flush_file", boom), \
         mock.patch.object(common, "_fsync_file", boom), \
         mock.patch("fcntl.flock", boom):
        sp = os.path.join(d, "shares.txt")
        try:
            append_record_locked(sp, rec, lock_path_for(sp))
            got = parse_share_records(common._read_text(sp))
            ok = len(got) == 1 and got[0]["nonce"] == rec["nonce"] \
                and got[0]["result"] == rec["result"]
            print(f"  append with flush/fsync/flock broken: "
                  f"stored={ok!s:5} records={len(got)}")
            if not ok:
                failures.append("append_record_locked lost the record")
        except Exception as exc:
            failures.append(f"append_record_locked raised {type(exc).__name__}: {exc}")
            print(f"  append with flush/fsync/flock broken: RAISED {exc!r}")

        p2 = os.path.join(d, "job.txt")
        try:
            atomic_write(p2, "hello\nworld\n")
            ok = common._read_text(p2) == "hello\nworld\n"
            print(f"  atomic_write with flush/fsync broken:  stored={ok!s:5}")
            if not ok:
                failures.append("atomic_write did not persist the text")
        except Exception as exc:
            failures.append(f"atomic_write raised {type(exc).__name__}: {exc}")
            print(f"  atomic_write with flush/fsync broken:  RAISED {exc!r}")

        try:
            with file_lock(os.path.join(d, "x.lock")):
                pass
            print("  file_lock with flock broken:           degraded (no exception)")
        except Exception as exc:
            failures.append(f"file_lock raised {type(exc).__name__}: {exc}")
            print(f"  file_lock with flock broken:           RAISED {exc!r}")

    # ---- a write that truly vanished must be reported clearly --------------
    with mock.patch.object(common, "_read_text", lambda path: ""):
        sp2 = os.path.join(d, "lost.txt")
        try:
            append_record_locked(sp2, rec, lock_path_for(sp2))
            failures.append("a lost write did NOT raise -- silent share loss")
            print("  lost-write detection:                  FAILED (no error raised)")
        except RuntimeError as exc:
            msg = str(exc)
            clear = "did NOT survive" in msg and "filesystem" in msg
            print(f"  lost-write detection:                  RuntimeError, clear={clear!s:5}")
            if not clear:
                failures.append(f"RuntimeError wording unclear: {msg}")
        except Exception as exc:
            failures.append(f"lost write raised {type(exc).__name__} instead of RuntimeError")
            print(f"  lost-write detection:                  RAISED {exc!r}")

    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        return 1
    print("RESULT: PASS -- writes verified by read-back; lost writes reported, never fatal")
    return 0


if __name__ == "__main__":
    sys.exit(main())
