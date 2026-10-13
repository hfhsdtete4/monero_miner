#!/usr/bin/env python3
"""
tests/engine_target_check.py -- differential test of the engine's share
detection against an independent hasher.

Why this exists: at an easy target almost any hash passes, so it cannot
distinguish "correct threshold compare" from "no compare at all". This test
hashes a fixed nonce window with the *Python* engine (an independent VM
wrapper), and then checks that the native C engine reports EXACTLY the same
winning nonces over the same window -- both directions.

Protocol subtlety this test must respect: with the protocol gate ON (the
shipped behaviour), a passing hash needs H[31] == 0, so the probability per
hash is min(target+1, 2**24) / 2**32.  For every pool-real difficulty
(>= 256) that is simply 1/difficulty, but for a *softer* target the gate is
the binding constraint.  The reference loop therefore keeps scanning until it
has found --wins real wins (up to --max-nonces), so a vacuous
"zero wins on both sides" outcome cannot pass silently.

    python3 tests/engine_target_check.py --dir tests/tmp --diff 256
    python3 tests/engine_target_check.py --dir tests/live --diff 256 --nonces 2000

Exit 0 = the two independent implementations agree bit-for-bit on which
nonces are shares.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import (U32_SIZE, hash_meets_target, load_job,  # noqa: E402
                    target_be_from_u32, target_u32_from_diff)
from engines import NativeEngine, PythonEngine  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--job", default=os.path.join(HERE, "job.txt"))
    ap.add_argument("--dir", default=HERE)
    ap.add_argument("--diff", type=float, default=256.0,
                    help="target difficulty to test (256 -> ~1 in 256 hashes)")
    ap.add_argument("--nonces", type=int, default=600,
                    help="minimum size of the tested nonce window")
    ap.add_argument("--wins", type=int, default=3,
                    help="keep scanning until the reference has this many wins")
    ap.add_argument("--max-nonces", type=int, default=4000,
                    help="hard cap on the scanned window")
    ap.add_argument("--threads", type=int, default=2,
                    help="engine init threads (the scan itself uses 1 thread "
                         "so the window is covered linearly)")
    args = ap.parse_args(argv)

    job = load_job(os.path.join(args.dir, "job.txt") if args.dir != HERE else args.job)
    target_u32 = target_u32_from_diff(args.diff)
    job.target_u32 = target_u32
    job.target_hex = target_be_from_u32(target_u32)
    base = 0x1000_0000                      # arbitrary fixed window start

    eff = min(target_u32 + 1, 1 << 24) / U32_SIZE
    print(f"job {job.job_id}: blob={len(job.blob)}B seed={job.seed_hex[:12]}...")
    print(f"target=0x{target_u32:08x} (~diff {U32_SIZE / target_u32:,.0f}); "
          f"gate on: P(win)={eff:.3e} per hash")

    # ---- reference implementation: Python engine (own VM, same library) ----
    t0 = time.time()
    py = PythonEngine()
    ref_wins: set[int] = set()
    n = 0
    while n < args.max_nonces and (n < args.nonces or len(ref_wins) < args.wins):
        nonce = (base + n) & 0xFFFFFFFF
        h = py.verify(job.seed_hex, job.blob_with_nonce(nonce).hex())
        if hash_meets_target(bytes.fromhex(h), target_u32):
            ref_wins.add(nonce)
        n += 1
    py.quit()
    dt = time.time() - t0
    print(f"reference: {n} hashes in {dt:.1f}s ({n / max(dt, 1e-9):.1f} H/s), "
          f"{len(ref_wins)} wins")
    print(f"window nonce 0x{base:08x}..0x{base + n - 1:08x} ({n} nonces)")
    if not ref_wins:
        print(f"FAIL: reference found no win in {args.max_nonces} hashes -- "
              "suspect the target/nonce plumbing, not (only) the engine")
        return 1

    # ---- engine under test: native C engine over the *same* window ---------
    eng = NativeEngine(report_ms=1000)
    ev = eng.init(job.seed_hex, "light", False, args.threads)
    if ev.get("kind") != "INITOK":
        print(f"FAIL: engine INIT: {ev}")
        return 1
    st = eng.selftest()
    if st.get("ok") != 1:
        print(f"FAIL: engine self-test: {st}")
        return 1
    eng.start(job, 1, base, [], False, True)      # 1 thread, offset=base, gate on

    seen: set[int] = set()
    hashes_done = 0
    covered_at = None
    deadline = time.time() + max(30.0, n / 25.0 + 20.0)
    while time.time() < deadline:
        for e in eng.poll(0.5):
            if e.get("kind") == "WIN":
                seen.add(int(e["nonce_u32"]) & 0xFFFFFFFF)
            elif e.get("kind") == "TOTAL":
                hashes_done = int(e.get("hashes", hashes_done))
        if hashes_done >= n:
            if covered_at is None:
                covered_at = time.time()        # whole window scanned
            elif time.time() - covered_at >= 3.0:
                break                           # grace period for late WIN lines
        else:
            covered_at = None
    eng.stop()
    eng.quit()

    window = {(base + i) & 0xFFFFFFFF for i in range(n)}
    eng_wins = {x for x in seen if x in window}
    missed = ref_wins - eng_wins          # reference says share, engine didn't report
    extra = eng_wins - ref_wins           # engine reported something the reference rejects

    print(f"engine: {hashes_done} hashes, {len(eng_wins)} wins inside the window")
    print(f"agreement: reference={len(ref_wins)} engine={len(eng_wins)} "
          f"missed={len(missed)} extra={len(extra)}")
    if missed:
        print(f"  MISSED: {[hex(x) for x in sorted(missed)][:5]}")
    if extra:
        print(f"  EXTRA:  {[hex(x) for x in sorted(extra)][:5]}")
    if hashes_done < n:
        print(f"  note: engine covered {hashes_done}/{n} nonces before the deadline")

    ok = not missed and not extra and hashes_done >= n
    print("RESULT:", "PASS -- engine and reference agree exactly" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
