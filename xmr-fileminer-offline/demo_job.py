#!/usr/bin/env python3
"""
demo_job.py -- write a synthetic job.txt so the miner can be tested with NO
network and NO pool.

The job is marked `demo=1`, which makes pool_bridge.py refuse to submit any
share that came from it, so this cannot ever leak a fake share to a pool.

Examples:
    python3 demo_job.py --diff 1          # easiest valid job: a share every
                                          # ~256 hashes (that is the real
                                          # RandomX probability for diff 1)
    python3 demo_job.py --diff 300000     # similar difficulty to a busy pool
"""

from __future__ import annotations

import argparse
import os
import random
import secrets
import time

from common import (
    Job, JobError, NONCE_OFFSET, NONCE_SIZE, atomic_write, render_job_text,
    target_be_from_u32, target_u32_from_diff,
)

HERE = os.path.dirname(os.path.abspath(__file__))


def build_job(diff: float = 1.0, blob_bytes: int = 84, seed: str = "",
              blob: str = "", job_id: str = "", height: str = "",
              user: str = "", url: str = "", nicehash: bool = False,
              demo: bool = True) -> Job:
    """Build a synthetic but format-perfect job (shared with tests/mock_pool.py)."""
    if not (44 <= blob_bytes <= 253):
        raise SystemExit("blob_bytes must be 44..253")
    if blob:
        raw = bytearray.fromhex(blob)
        if not (44 <= len(raw) <= 253):
            raise SystemExit("blob must be 44..253 bytes")
    else:
        raw = bytearray(secrets.token_bytes(blob_bytes))
    raw[NONCE_OFFSET:NONCE_OFFSET + NONCE_SIZE] = b"\x00\x00\x00\x00"

    seed_hex = seed.lower() or secrets.token_hex(32)
    if len(seed_hex) != 64:
        raise SystemExit("seed must be 64 hex chars")
    if diff < 1.0:
        raise SystemExit("diff must be >= 1")
    target_u32 = target_u32_from_diff(diff)
    return Job(
        algo="randomx", url=url, user=user,
        job_id=job_id or f"demo-{random.randrange(1 << 32):08x}",
        target_hex=target_be_from_u32(target_u32), target_u32=target_u32,
        height=height or str(random.randrange(3_000_000, 3_400_000)),
        seed_hex=seed_hex, blob_hex=bytes(raw).hex(),
        nicehash=nicehash, demo=demo, updated=time.time(),
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default=HERE, help="where to write job.txt")
    ap.add_argument("--job", default="job.txt")
    ap.add_argument("--diff", type=float, default=1.0,
                    help="simulated pool difficulty (>=1; 1 = share every ~256 hashes)")
    ap.add_argument("--blob-bytes", type=int, default=84,
                    help="size of the synthetic block hashing blob")
    ap.add_argument("--seed", default="", help="explicit 64-hex RandomX key")
    ap.add_argument("--blob", default="", help="explicit blob hex (nonce bytes are zeroed)")
    ap.add_argument("--job-id", default="", help="job id string")
    ap.add_argument("--height", default="", help="block height label")
    ap.add_argument("--user", default="krxYRPV4WQ", help="wallet (informational here)")
    ap.add_argument("--url", default="xmr.kryptex.network:7029", help="(informational)")
    ap.add_argument("--nicehash", action="store_true")
    args = ap.parse_args(argv)

    try:
        job = build_job(diff=args.diff, blob_bytes=args.blob_bytes, seed=args.seed,
                        blob=args.blob, job_id=args.job_id, height=args.height,
                        user=args.user, url=args.url, nicehash=args.nicehash)
    except (SystemExit, ValueError) as exc:
        raise SystemExit(f"cannot build demo job: {exc}")
    try:
        # validate through the same parser the miner uses
        from common import load_job_text
        load_job_text(render_job_text(job), source="demo")
    except JobError as exc:                       # pragma: no cover
        raise SystemExit(f"internal error building demo job: {exc}")

    path = os.path.join(os.path.abspath(args.dir), args.job)
    atomic_write(path, render_job_text(job))
    print(f"wrote {path}")
    print(f"  {job.summary()}")
    print(f"  expected hashes per share: ~{job.eff_diff:,.0f}")
    if job.target_u32 >= (1 << 24):
        print("  (diff < 256 is not something a real pool uses; the miner keeps its")
        print("   H[31]==0 check, so such shares are 256x rarer than the pool would need)")
    print("next:  python3 file_miner.py --light --stats 2      (offline test)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
