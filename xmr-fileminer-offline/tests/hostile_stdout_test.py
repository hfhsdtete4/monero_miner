#!/usr/bin/env python3
"""
tests/hostile_stdout_test.py -- logging must survive a hostile stdout.

Some container filesystems fail `flush()` on a redirected stdout with
OSError errno 95 (EOPNOTSUPP).  Python's stock StreamHandler treats that as a
logging error and prints a multi-line "--- Logging error ---" traceback for
EVERY log line, which floods the console and buries the real output.

The miner and bridge use SafeStreamHandler (see common.py) which swallows
write/flush failures.  This test simulates the broken stream, logs through
both setups, and asserts that

  * the safe handler produces NO traceback on stderr, and
  * the stock handler DOES (so the test can actually detect the difference).

Exit 0 = pass.
"""
from __future__ import annotations

import io
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import SafeFileHandler, SafeStreamHandler  # noqa: E402


class HostileStream(io.TextIOBase):
    """write() works (we keep the text), flush() fails like EOPNOTSUPP mounts."""

    def __init__(self, sink: io.StringIO):
        self.sink = sink

    def write(self, s: str) -> int:                       # type: ignore[override]
        self.sink.write(s)
        return len(s)

    def flush(self) -> None:
        raise OSError(95, "Operation not supported")


def collect_logger(handler: logging.Handler, message: str) -> tuple[str, str]:
    """Log `message` once and return (captured stdout, captured stderr)."""
    sink = io.StringIO()
    logger = logging.getLogger(f"hostile-test-{id(handler)}")
    logger.handlers[:] = [handler]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    handler.stream = HostileStream(sink)                  # type: ignore[attr-defined]
    handler.setFormatter(logging.Formatter("[%s] %(message)s", "%H:%M:%S"))

    err = io.StringIO()
    old_stderr, sys.stderr = sys.stderr, err
    try:
        logger.info(message)
    finally:
        sys.stderr = old_stderr
    return sink.getvalue(), err.getvalue()


def main() -> int:
    msg = "engine: python  (portable fallback, roughly 5x slower)"

    out, err = collect_logger(SafeStreamHandler(sys.stdout), msg)
    safe_ok = msg in out and "Logging error" not in err and "Traceback" not in err
    print(f"  safe handler:   message kept={msg in out!s:5}  stderr clean={not err.strip()!s:5}")

    out, err = collect_logger(logging.StreamHandler(sys.stdout), msg)
    stock_broken = "Logging error" in err or "Traceback" in err
    print(f"  stock handler:  message kept={msg in out!s:5}  stderr flooded={stock_broken!s:5}")

    if not safe_ok:
        print("FAIL: SafeStreamHandler leaked a logging traceback (or lost the line)")
        return 1
    if not stock_broken:
        print("FAIL: the simulation did not reproduce the stock handler's failure "
              "-- this test has stopped testing anything")
        return 1
    print("RESULT: PASS -- safe handlers absorb EOPNOTSUPP; stock handlers demonstrably do not")
    return 0


if __name__ == "__main__":
    sys.exit(main())
