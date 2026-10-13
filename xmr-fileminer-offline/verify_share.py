#!/usr/bin/env python3
"""
verify_share.py -- independently re-hash every share record in shares.txt.

This is the "trust nothing" tool: it takes the blob, seed, nonce and target out
of each [share] record, recomputes the RandomX hash, and checks that

  1. the hash equals the `result=` field in the record, and
  2. the hash actually satisfies the target (including the mandatory H[31]==0
     gate), i.e. the record really is a share a pool should accept.

It needs no network and no pool. If the record carries its own `blob=` (the
miner writes it), the check is fully self-contained; otherwise it falls back to
job.txt for the blob.

Usage:
    python3 verify_share.py                 # verify every record in shares.txt
    python3 verify_share.py --last 5        # only the 5 newest
    python3 verify_share.py --json          # machine-readable output
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

from common import (
    NONCE_OFFSET, NONCE_SIZE, U32_SIZE, hash_meets_target, hash_u32, iter_share_blocks,
    JobError, load_job, nonce_from_le_hex, target_u32_from_be,
)

HERE = os.path.dirname(os.path.abspath(__file__))


class Hasher:
    """Batched re-hashing: one subprocess per distinct seed key."""

    def __init__(self, bin_path: str | None = None):
        self.bin_path = bin_path or os.path.join(HERE, "bin", "miner_native")
        self._native_ok = os.path.exists(self.bin_path)
        self._py_engine = None

    def hashes_for(self, seed_hex: str, blobs_hex: list[str]) -> list[str]:
        if self._native_ok:
            try:
                proc = subprocess.run(
                    [self.bin_path, "--verify", seed_hex],
                    input="\n".join(blobs_hex) + "\n",
                    capture_output=True, text=True, timeout=120 + 30 * len(blobs_hex))
                out = [ln.split()[1] for ln in (proc.stdout or "").splitlines()
                       if ln.startswith("HASH ")]
                if len(out) == len(blobs_hex):
                    return out
                print(f"warning: native verifier returned {len(out)} hashes for "
                      f"{len(blobs_hex)} blobs; falling back to ctypes", file=sys.stderr)
            except (OSError, subprocess.SubprocessError) as exc:
                print(f"warning: native verifier failed ({exc}); using ctypes",
                      file=sys.stderr)
        # ctypes fallback
        from engines import PythonEngine
        if self._py_engine is None:
            self._py_engine = PythonEngine()
        self._py_engine.seed_hex = ""      # force (re)build of the verify cache
        return [self._py_engine.verify(seed_hex, b) for b in blobs_hex]


def build_case(rec: dict, job=None) -> dict:
    """Resolve one share record into everything needed for verification."""
    blob_hex = rec.get("blob", "")
    seed_hex = rec.get("seed", "")
    if not blob_hex and job is not None:
        blob_hex = job.blob_hex
    if not seed_hex and job is not None:
        seed_hex = job.seed_hex
    if not blob_hex or not seed_hex:
        raise JobError("record has no blob/seed (and no usable job.txt)")

    if rec.get("nonce_u32"):
        nonce_u32 = int(rec["nonce_u32"])
    else:
        nonce_u32 = nonce_from_le_hex(rec.get("nonce", ""))

    blob = bytearray.fromhex(blob_hex)
    if len(blob) < NONCE_OFFSET + NONCE_SIZE:
        raise JobError("blob too short to hold a nonce")
    blob[NONCE_OFFSET:NONCE_OFFSET + NONCE_SIZE] = nonce_u32.to_bytes(4, "little")

    if rec.get("target_u32"):
        target_u32 = int(rec["target_u32"])
    elif rec.get("target"):
        target_u32 = target_u32_from_be(rec["target"])
    elif job is not None:
        target_u32 = job.target_u32
    else:
        raise JobError("record has no target (and no usable job.txt)")

    return {
        "seed": seed_hex,
        "blob_hex": bytes(blob).hex(),
        "claimed": str(rec.get("result", "")).lower(),
        "target_u32": target_u32,
        "job_id": rec.get("job_id", "?"),
        "nonce": rec.get("nonce", "?"),
        "nonce_u32": nonce_u32,
        "diff": rec.get("diff"),
        "demo": rec.get("demo") == "1",
    }


def verify(cases: list[dict], hasher: Hasher) -> list[dict]:
    by_seed: dict[str, list[int]] = {}
    for idx, c in enumerate(cases):
        by_seed.setdefault(c["seed"], []).append(idx)

    results: list[dict] = []
    for seed, idxs in by_seed.items():
        blobs = [cases[i]["blob_hex"] for i in idxs]
        hashes = hasher.hashes_for(seed, blobs)
        for i, h in zip(idxs, hashes):
            c = cases[i]
            m = h == c["claimed"]
            meets = hash_meets_target(bytes.fromhex(h), c["target_u32"])
            u = hash_u32(bytes.fromhex(h))
            results.append({
                "job_id": c["job_id"],
                "nonce": c["nonce"],
                "claimed": c["claimed"],
                "computed": h,
                "result_match": m,
                "meets_target": meets,
                "share_diff": round(U32_SIZE / max(1, u), 3),
                "ok": bool(m and meets),
            })
    return results


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default=HERE)
    ap.add_argument("--shares", default="shares.txt")
    ap.add_argument("--job", default="job.txt", help="fallback for blob/seed")
    ap.add_argument("--last", type=int, default=0, help="only verify the N newest records")
    ap.add_argument("--json", action="store_true", help="print JSON summary")
    args = ap.parse_args(argv)

    shares_path = os.path.join(os.path.abspath(args.dir), args.shares)
    try:
        with open(shares_path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except FileNotFoundError:
        print(f"no share file at {shares_path}", file=sys.stderr)
        return 2

    recs = [rec for _, _, rec in iter_share_blocks(text) if rec.get("result")]
    if args.last:
        recs = recs[-args.last:]
    if not recs:
        print(f"no share records in {shares_path}")
        if args.json:
            print(json.dumps({"n": 0, "pass": 0, "fail": 0, "results": []}))
        return 2

    job = None
    try:
        job = load_job(os.path.join(os.path.abspath(args.dir), args.job))
    except JobError:
        pass

    cases = []
    for rec in recs:
        try:
            cases.append(build_case(rec, job))
        except (JobError, ValueError) as exc:
            print(f"record job_id={rec.get('job_id')} nonce={rec.get('nonce')}: "
                  f"cannot verify: {exc}", file=sys.stderr)

    if not cases:
        return 2

    results = verify(cases, Hasher())
    npass = sum(1 for r in results if r["ok"])

    if args.json:
        print(json.dumps({"n": len(results), "pass": npass,
                          "fail": len(results) - npass, "results": results}, indent=2))
    else:
        for r in results:
            print(f"[{'PASS' if r['ok'] else 'FAIL'}] job={r['job_id']} nonce={r['nonce']}")
            print(f"        claimed  {r['claimed']}")
            print(f"        computed {r['computed']}  diff={r['share_diff']}")
            if not r["result_match"]:
                print("        !! hash does not match the record (tampering or bug)")
            if not r["meets_target"]:
                print("        !! hash does not satisfy the target (not a real share)")
        print(f"\nVERIFY n={len(results)} pass={npass} fail={len(results)-npass}")
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
