#!/usr/bin/env python3
"""
tests/randomx_sampling.py -- statistical sanity check of the whole hash stack.

Share detection is only as trustworthy as the hash distribution it is compared
against: a subtly biased hash (bad blob layout, wrong key, wrong nonce offset)
can still pass a single-vector test.  This script hashes a few thousand nonces
with an independent engine (the ctypes PythonEngine) and compares the fraction
of hashes below several thresholds with the uniform-distribution expectation.

    python3 tests/randomx_sampling.py [--dir DIR] [--nonces 1500]

Exit 0 if every threshold with enough expected hits is within 5 sigma of the
binomial expectation (|z| < 5); wildly off ratios mean something is wrong.
"""
from __future__ import annotations

import argparse
import math
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import U32_SIZE, hash_u32, load_job  # noqa: E402
from engines import PythonEngine  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
THRESHOLDS = (1 << 28, 1 << 29, 1 << 30, 1 << 31, U32_SIZE - 1)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default=HERE)
    ap.add_argument("--nonces", type=int, default=1500)
    ap.add_argument("--base", type=lambda s: int(s, 0), default=0x2000_0000)
    args = ap.parse_args(argv)

    job = load_job(os.path.join(args.dir, "job.txt"))
    eng = PythonEngine()
    counts = {t: 0 for t in THRESHOLDS}
    h31_zero = 0
    t0 = time.time()
    for i in range(args.nonces):
        nonce = (args.base + i) & 0xFFFFFFFF
        h = bytes.fromhex(eng.verify(job.seed_hex, job.blob_with_nonce(nonce).hex()))
        u = hash_u32(h)
        if h[31] == 0:
            h31_zero += 1
        for t in THRESHOLDS:
            if u <= t:
                counts[t] += 1
    eng.quit()
    n = args.nonces
    dt = time.time() - t0
    print(f"{n} hashes in {dt:.1f}s ({n / dt:.1f} H/s) on job {job.job_id} "
          f"(blob {len(job.blob)}B, seed {job.seed_hex[:12]}...)")
    print(f"{'threshold':>12} {'observed':>9} {'expected':>9} {'ratio':>7} {'z':>6}")

    bad = []
    rows = [(f"u32<={t:,}", t, counts[t]) for t in (1 << 28, 1 << 29, 1 << 30, 1 << 31)]
    rows.append(("H[31]==0", None, h31_zero))
    for label, t, obs in rows:
        exp = n / 256 if t is None else n * (t + 1) / U32_SIZE
        p = exp / n
        var = n * p * (1 - p)
        z = (obs - exp) / math.sqrt(var) if var > 0 else 0.0
        ratio = obs / exp if exp else float("nan")
        flag = ""
        if exp >= 30 and abs(z) >= 5:
            flag = "  <-- OUT OF RANGE"
            bad.append(label)
        print(f"{label:>12} {obs:>9} {exp:>9.1f} {ratio:>7.3f} {z:>6.1f}{flag}")

    if bad:
        print(f"RESULT: FAIL -- {', '.join(bad)} deviate from uniform by >5 sigma")
        return 1
    print("RESULT: PASS -- hash distribution is uniform within statistical noise")
    return 0


if __name__ == "__main__":
    sys.exit(main())
