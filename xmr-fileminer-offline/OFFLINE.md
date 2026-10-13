# Offline mode — mine with no pool and no network

This document describes running the miner **without any network at all**. The
miner (`file_miner.py`) never opens a socket: it reads a job from `job.txt`
and appends shares to `shares.txt`, both in the same directory. Anything that
can write one small text file can feed it — a pool bridge, a script, a USB
stick carried from another machine.

If this folder has a `pool_bridge.py` in it, you are holding the full project
and that process is the only piece that talks to a pool. If it does not, you
are holding the offline subset: miner, native RandomX engine, build script,
offline tools and tests, upstream RandomX source. Nothing in this archive
imports `socket` (check: `grep -rn "import socket" .`).

## Thirty seconds to mining (synthetic job, no pool)

```bash
python3 demo_job.py --diff 1        # writes job.txt (difficulty 1 => a share every ~256 hashes)
python3 file_miner.py --light       # reads job.txt, writes shares.txt (--light = 512 MB, no 2 GB dataset)
python3 verify_share.py             # independently re-hashes every share in shares.txt
```

On a machine with ≥ 2.7 GB free RAM drop `--light`: the full dataset is
normally 5–10× faster. For maximum hashrate, reserve huge pages once per boot:

```bash
echo 1300 | sudo tee /proc/sys/vm/nr_hugepages
```

## Mining a real job offline

`job.txt` is plain text (format documented in `README.md` § `job.txt`). Typical
flows:

* another process writes it (the full project's `pool_bridge.py`, or your own
  bridge for a different pool);
* copy a `job.txt` captured elsewhere onto the rig (the file contains the seed
  key, blob, target and ids — everything needed to hash and to make shares
  submittable later);
* write your own generator against `common.py` (`Job`, `render_job_text`) —
  its self-check is runnable: `python3 common.py`.

Shares land in `shares.txt` as `[share]` records that contain the full blob,
seed, nonce and hash, so they can be re-verified (`verify_share.py`) and
submitted later by whatever bridge picks them up. Every share is re-hashed by
the miner itself before it is written (`--verify on`, the default).

## What is in this archive

| Component | Files |
|---|---|
| miner (no sockets) | `file_miner.py` |
| engine wrappers / protocol | `engines.py`, `common.py` |
| native RandomX engine | `miner_native.c`, `rx_test.c`, `rx_vector.h`, prebuilt `bin/`, `lib/librandomx.so` |
| offline tools | `demo_job.py`, `verify_share.py`, `build.sh` |
| offline tests | `run_tests.sh`, `tests/engine_target_check.py`, `tests/randomx_sampling.py` |
| docs / evidence | `README.md`, `examples/` (real job + a pool-accepted share record), `tests/suite.out` |

Not included (they are the online pieces): `pool_bridge.py`,
`tests/mock_pool.py`, `tests/loopback_test.sh`, `tests/live_submit_test.py`.

## If the native engine won't run here

The bundled `bin/miner_native` is a compiled binary: sandboxes, `noexec`
mounts and machines with a different glibc may refuse to execute it. The miner
handles that by itself — it logs the reason, falls back to the portable
engine (~5× slower, same valid shares), and keeps mining. To get the exact
diagnosis and fix:

```bash
python3 file_miner.py --doctor      # mount options, lib load, engine --info, verdict + fix
./build.sh --force                  # rebuild librandomx.so + bin/miner_native for THIS machine
```

This is also the reason `[engines] restored the executable bit on …` may
appear once after extracting: some unzip/tar/network filesystems drop mode
bits, and the miner repairs that on its own.

## Odd filesystems (sandboxes, FUSE mounts)

**Filesystems that drop appends.** A mount can accept the first write of a
file and quietly stop persisting later appends (seen in a sandbox with
EOPNOTSUPP). The miner detects it from the read-back and switches that file to
**delete-and-rewrite**: the whole file is written afresh, verified, and only
then replaces the old content — so shares keep landing. If even that fails,
the share stays queued in memory, is retried on every later share, and is
printed at shutdown rather than lost. No flags to set; `--version` >= 1.3.


**Exec-denied mounts.** If `bin/miner_native` cannot be executed (errno 13,
even right after `chmod +x` -- some FUSE data mounts allow writes but deny
`execve`), the miner copies the engine and `lib/` to a private temp directory
and runs the copy. Nothing to do on your side; `--doctor` shows the relocated
path. To avoid the copy, keep the project on a local-disk path like `/tmp`.


If stderr shows `OSError: [Errno 95] Operation not supported` repeatedly or on
writes, your directory is on a filesystem with unusual `flush()`/`fsync()`/
`flock()` semantics. Since v1.1 the miner tolerates all of that: one `[fs]`
warning, writes verified by reading the data back, and a clear error (never a
crash) if something truly could not be stored. Runs are still perfectly fine
from a normal directory like `~/xmr-fileminer-offline` — that is the simplest
cure. `python3 file_miner.py --version` prints the build (`1.1`).

## Tests, offline

```bash
./run_tests.sh            # everything: build, RandomX official vector, demo job round-trip,
                          # re-hash verification, file plumbing, differential engine check
./run_tests.sh --fast     # same, reusing already-built binaries
```

The loopback step (mock pool ⇄ bridge ⇄ miner) is **skipped automatically**
when `pool_bridge.py` is not present — that path is fully covered in the full
archive. Use this one when you want the offline chain verified mechanically:

```bash
python3 tests/engine_target_check.py --diff 256      # native engine == independent reference
python3 tests/randomx_sampling.py --nonces 1500      # ~2 min: hash distribution sanity
```

## Efficiency checklist (offline runs are still CPU-bound!)

1. `--mode auto` (default) → full 2 GB dataset when RAM allows; only fall back
   to `--light` if it does not.
2. Huge pages (`--hugepages auto`, default) — reserve with the sysctl above.
3. `--threads` defaults to physical cores; RandomX does not benefit from SMT.
4. `--priority 3..5` (needs privileges) on a busy machine.
5. `--affinity auto` pins worker *n* to CPU *n*.
6. Rebuild for your own CPU if you move the folder between machines with very
   different instruction sets: `./build.sh --force`.

Full details, protocol facts and the validated-results table: `README.md`.
