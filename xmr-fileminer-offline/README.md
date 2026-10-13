# xmr-fileminer

A Monero (RandomX) CPU miner split into two processes that talk **only through
two text files**:

```
                        ┌─────────────────────────────────────────────┐
   ┌─────────────┐      │  the mining rig (can be network-isolated)   │
   │  Monero     │      │                                             │
   │  pool       │◄────►│  pool_bridge.py                             │
   │ (stratum)   │      │    • the ONLY process with a socket         │
   └─────────────┘      │    • writes job.txt   (atomic rename)       │
                        │    • submits shares.txt, archives + trims   │
                        │            ▲                 │              │
                        │      job.txt          shares.txt            │
                        │            │                 ▲              │
                        │  file_miner.py ──────────────┘              │
                        │    • NO network code at all                 │
                        │    • hashes, writes share records           │
                        │    • bin/miner_native: RandomX engine       │
                        └─────────────────────────────────────────────┘
```

* `file_miner.py` **never opens a socket.** You can run it on a machine with no
  route to the pool, and it will happily mine the last `job.txt` it was given.
* `pool_bridge.py` is the only networked process. It logs in, keeps the session
  alive, writes each new job to `job.txt`, reads `shares.txt` and submits what
  the miner wrote.
* All three files live in the **same directory** (configurable with `--dir`).

---

## Honest performance note (read this first)

RandomX is the whole coin. Everything that makes a Monero CPU miner fast lives
inside the RandomX library (2 GB dataset, huge pages, JIT, one VM per core),
and this project uses that exact library with those exact settings — the
hashing engine is C code (`bin/miner_native`) called from Python, not Python
hashing. In light mode on this test box (2-core Xeon, no huge pages) the engine does
**~43 H/s per thread** (86 H/s with both cores); a proper full-dataset run is
normally **5–10× faster**, which is what you get with default settings on a
machine with ≥ 2.7 GB RAM.

What you pay for the file bridge is a tiny latency (jobs arrive up to
`--poll` seconds late; shares are submitted up to a second or two later),
which is irrelevant at Monero's ~2-minute block time. The native engine also
prints a **stall watchdog** if a worker stops making progress, and the miner
**re-hashes every share before writing it** (`--verify auto|on|off`), so a
silent hash mismatch cannot poison your share file.

If your only goal is maximum hashrate on one machine, xmrig is still the
right tool and always will be. Use this project when you want the file
boundary, auditability, offline operation, and a codebase you can read in an
afternoon.

---

## Quick start

### 1. Build (once)

```bash
./build.sh              # clones RandomX, builds lib/librandomx.so + bin/miner_native
./build.sh --full-test  # optional: also run the 2 GB dataset self-test
```

Requirements: `gcc`/`clang`, `make`, `git`, `python3`. `cmake` is auto-installed
with pip if missing. The build ends by running the **official RandomX test
vector**; do not mine if it fails.

For maximum hashrate, reserve huge pages once per boot (needs ~2.6 GB free):

```bash
echo 1300 | sudo tee /proc/sys/vm/nr_hugepages
# persistent:
echo 'vm.nr_hugepages = 1300' | sudo tee /etc/sysctl.d/99-xmr.conf
```

### 2. Run against a pool (kryptex example from the task)

Terminal 1 — the bridge (only this one needs the network):

```bash
python3 pool_bridge.py --url xmr.kryptex.network:7029 --user krxYRPV4WQ
```

Terminal 2 — the miner (no network access required or used):

```bash
python3 file_miner.py                      # full 2 GB dataset, physical cores
python3 file_miner.py --light              # 512 MB, ~5-10x slower, low-RAM boxes
python3 file_miner.py --threads 8 --priority 4 --affinity 0-7
```

Check what the pool handed you at any time:

```bash
python3 pool_bridge.py --print-job          # login, show job, exit
python3 file_miner.py --help                # every tuning knob
```

### 3. Run fully offline (no pool, no network)

```bash
python3 demo_job.py --diff 1                # synthetic diff-1 job -> job.txt
python3 file_miner.py --light --stats 2     # a share about every ~256 hashes
python3 verify_share.py                     # independently re-hash the shares
```

---

## Files

| File | Written by | Read by | Meaning |
|---|---|---|---|
| `job.txt` | bridge / demo_job | miner | current job: blob, seed key, target, ids |
| `shares.txt` | miner (append, flock) | bridge (submit + trim) | shares waiting to be submitted |
| `submitted.txt` | bridge | humans | archive of everything that was submitted |
| `bestshare.txt` | miner | humans | best share found this session |
| `miner.log`, `bridge.log` | both | humans | full logs |

### `job.txt`

```ini
version=1
algo=rx/0
url=xmr.kryptex.network:7029
user=krxYRPV4WQ
job_id=662f8f4b83b7
target=f1290000          # pool target, exactly as received
height=3783188
seed=bee2f72d...08a3     # 32-byte RandomX key (block template hash)
nicehash=0
demo=0
updated=1791900025.772

[blob]
0606b5a0...   # 76-84 byte block hashing blob, nonce bytes [39..42] may be anything
```

### `shares.txt` (one `[share]` block per share)

```ini
[share]
job_id=662f8f4b83b7
nonce=78563412           # 4 nonce bytes, LITTLE-ENDIAN hex (exactly what goes on the wire)
nonce_u32=2018915346     # the same number, for humans
result=<64 hex>          # RandomX hash, raw byte order (exactly what goes on the wire)
target=f1290000
target_u32=10737         # little-endian interpretation, this is what the hash is compared to
diff=418211.7            # actual share difficulty
blob=<hex of the exact hashed blob, nonce already patched in>
seed=<64 hex>
...
```

A record contains everything needed to re-derive and audit the share offline
(`verify_share.py` does exactly that).

---

## Protocol facts this code is built on

All of these were verified against the xmrig source tree, not from memory:

| Fact | Where it comes from |
|---|---|
| Blob nonce is **4 bytes at offset 39, little-endian** | `Job::nonceOffset() == 39`, `Client::submit` memcpy's a `uint32_t` nonce into the blob |
| Pool `target` (8 hex chars) is a **little-endian u32**: `target32 = t[0] \| t[1]<<8 \| t[2]<<16 \| t[3]<<24` | `Job::setTarget` → `*(const uint32_t*)raw` → `toDiff` |
| A hash is a share iff `u32_le(H[28:32]) <= target32` (which implies `H[31] == 0` for every real pool) | `JobResult::actualDiff()` = `toDiff(u64_le(H[24:32]))`, target64 = 2³²·target32 |
| Expected hashes per share ≈ pool difficulty = 2³²/target32 | same |
| Submit params: `{"id": client_id, "job_id", "nonce": <LE hex>, "result": <hash hex>}` | `Client::submit()` |
| Nicehash jobs own byte 42 → nonce mask `0xFFFFFF` | `Job::nonceMask()` |
| Keepalive `{"method":"keepalived"}`, job push `{"method":"job"}` (flat or nested `params.job`) | `Client`/`parseNotification` |
| Login: `{"login","pass","agent","algo":["rx/0"]}` | `Client::login()` |

**The `H[31]==0` subtlety**: miners often hear "the top byte of the hash must be
zero". That is not a separate rule — it falls out of the 4-byte comparison for
any target below 2²⁴ (i.e. pool difficulty above 256, which is every real
pool). `common.py` still checks it explicitly: for real targets it is
redundant, and only for absurdly easy demo targets (diff < 256) does it make
this miner stricter than the pool. `common.py`'s self-check documents both
cases.

**Reality check**: kryptex port 7029 sends `target=f1290000` → `target32=10737`
→ implied difficulty **400,016**, which is exactly the difficulty Kryptex
advertises for that port. That is a good sanity signal that the conversion is
right.

---

## Tuning for the most hashrate

| Knob | Why it matters |
|---|---|
| `--mode auto` (default) | Uses the 2 GB full dataset (the fast path). Falls back to light mode only if RAM is short |
| huge pages (`--hugepages`, default auto) | 2 MB pages instead of 4 KB; avoids TLB stalls on every dataset access. Worth tens of percent |
| `--threads` (default: physical cores) | One VM per thread; SMT/hyperthreading does **not** help RandomX. Default is already what you want |
| `--affinity auto` | Pins worker *n* to CPU *n*; keeps the cache warm. Use an explicit list (`--affinity 0-5`) if your topology is odd |
| `--priority 3..5` | niceness (needs privileges); 4–5 can give double-digit percent on a busy machine |
| `--nonce-offset` | `auto` gives each run a random window and each thread a disjoint slice; set an explicit base to split work across rigs on one wallet |
| `--init-threads` | Parallelism for the ~20 s dataset build after each new key (~3 days) |
| `--light` | The opposite of fast: 256 MB cache, no dataset, ~5–10× slower. Correct, just slow |
| `--engine python` | ctypes fallback if the C engine can't be built. Same math, lower top-end |

The miner prints H/s every `--stats` seconds, `E[share]` (expected seconds per
share), and the best hash found even below the target. Progress is published
on **every hash**, so the printed rate is accurate even in light mode on one
core — it is not a quantized counter read.

---

## Testing

```bash
./run_tests.sh            # everything below, offline, ~1 minute
```

1. protocol self-check (`python3 common.py`) — target/u32/nonce/gate math
2. build + the **official RandomX test vector** in light mode
3. offline end-to-end: demo job → mine → `shares.txt`
4. independent re-hash of the produced share (`verify_share.py`)
5. append/parse/round-trip plumbing of the file formats
6. **loopback loop**: `tests/mock_pool.py` ⇄ `pool_bridge.py` ⇄ `file_miner.py` —
   the mock pool hands out a real diff-1 job, then **independently re-hashes
   every submitted share** (blob rebuilt from the submitted nonce) and only
   accepts if it matches *and* meets the target; it also pushes a new job
   mid-flight (keeping the previous one acceptable, like a real pool, since a
   miner legitimately submits results a second or two after the switch)
7. **differential share detection** (`tests/engine_target_check.py`): the
   independent ctypes engine scans a fixed nonce window at a pool-real target
   (diff 256) and auto-extends it until it has found **3 real wins** (the
   protocol gate caps P(win) at 1/256 for easy targets, so "zero wins on both
   sides" can never pass silently). The native engine is then run over the
   exact same window and must report *exactly* the same winning nonces — no
   misses, no extras. This is what distinguishes "the threshold compare is
   right" from "the threshold compare is accidentally always true"

Useful extras:

```bash
python3 verify_share.py --last 5 --json     # audit the 5 newest shares
python3 tests/engine_target_check.py --diff 256 --nonces 2000   # strict engine check
python3 tests/randomx_sampling.py --nonces 1500                 # ~2 min, distribution sanity
python3 tests/live_submit_test.py --dir .   # with the bridge running: sends two
                                            # throwaway records to a real pool to
                                            # prove the submit path end-to-end
                                            # (both are expected to be REJECTED)
```

### What has been validated here (sandbox: 2-core Xeon, 1.9 GB RAM)

| Check | Result |
|---|---|
| Official RandomX vector (light) | PASS, hash matches `c5641412…3cd5f1` |
| Offline suite `run_tests.sh` | 14/14 PASS (adds the differential engine check + hostile-stdout logging regression) |
| Live kryptex login + job (7863188-ish height, target `f1290000`) | OK, diff 400,016 |
| Live submit path (2 throwaway records) | pool answered `Invalid job id` → response path, archive, trim, dedupe all OK |
| Mock-pool accept path (independent re-hash) | 2/2 ACCEPTED, job rotation handled, stable over repeated runs |
| Live kryptex variable-difficulty stepping (400,016 → 20,000) | each change handled as a same-key job switch; workers restart, the dataset/VM stays warm |
| Kryptex job churn (a fresh job every 1–3 min even at constant height) | handled; 15+ rotations with no re-init, no dedupe mistakes |
| **Real kryptex shares, end to end** | **3 ACCEPTED by the pool** through `job.txt → shares.txt → bridge → pool`. First at the 20k step: nonce `c208009f`, diff 39.044k, `{"id":25,"error":null,"result":{"status":"OK"}}`. Then two more at the 100k step: nonces `7f0000f9` (diff 815.3k) and `bd010079` (diff 112.4k). Every record was re-hashed independently (`verify_share.py` exit 0); see `examples/share.kryptex-accepted.txt` |
| Differential share detection (native vs independent reference) | agree exactly over a 2000-nonce window at diff 256 (0 missed, 0 extra) |
| Hash distribution (1500 nonces, thresholds 2²⁸…2³¹) | uniform within statistical noise (ratios 0.90–0.96; top byte zero 6× vs 5.9 expected) |
| Low-RAM guard (`--mode full` on a 1.9 GB box) | `INITERR low_memory` → automatic light-mode fallback, mining continues |

Full-dataset mode could not be exercised in the sandbox (needs ~2.7 GB RAM,
1.9 GB available), so the engine validates it differently: after a full-mode
`INIT` it hashes a fixed blob on **both** the full-VM and a light-VM over the
same cache and refuses to mine if they disagree — a wrong or partially
initialized dataset is caught immediately instead of producing rejected shares.
Run `./bin/rx_test full` on your machine to check the dataset path directly.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `full mode` warning, falls back to light | Not enough free RAM. Free ~2.7 GB or use `--threads N` lower; `--mode light` is fine, just slower |
| `hugepages_unavailable_*` warning | Kernel has no 2 MB pages reserved — see the sysctl in Quick start. Mining continues on 4 KB pages |
| `no usable job: job.txt: not found` | The bridge isn't running (or `--dir` differs between the two processes) |
| Pool answers `Invalid job id` / `Job not found` | The share was for a job the pool has already retired. Normal during block churn; check bridge log timestamps |
| Pool answers `Low difficulty share` | The share was below target — should not happen with this miner; run `verify_share.py` and open an issue with the log |
| `STALL tid=…` | A worker completed no hash for 30 s. First suspect: you started something else heavy on the box (the miner is `--priority 0`, so it yields). Otherwise a JIT/hugepage issue: retry with `--hugepages off` and check `dmesg` |
| Miner and bridge disagree about files | Both take `--dir` (default: this directory). Point them at the same one |
| Nothing gets submitted | Is `shares.txt` growing? Is the bridge connected? `bridge.log` has every line of stratum traffic with `--verbose` |
| `Permission denied` on `bin/miner_native`, or the miner silently reports `engine=python` | The executable bit was lost (zip/tar/network filesystem). The miner re-chmods its own binary automatically (`[engines] restored the executable bit on …`); if `./build.sh` itself refuses to run, `chmod +x build.sh run_tests.sh` |
| `engine: python (portable fallback)` — why? | Run `python3 file_miner.py --doctor`: it checks the mount options (noexec), loads `lib/librandomx.so`, actually tries to execute `bin/miner_native`, inspects the toolchain and the ctypes engine, and prints a verdict plus the exact fix. The miner logs the engine's own dying words next to the fallback notice |
| `[Errno 13] Permission denied` executing `bin/miner_native` — even after `chmod +x` (FUSE data mounts in sandboxes do this: writes and chmod work, `execve` is denied) | Since v1.2 the miner handles it by itself: `engines.ensure_runnable()` copies the engine + `lib/` to a private temp dir (same bin/+lib/ layout, so the rpath still resolves) and runs the copy — native hashrate even where the original cannot be executed. `--doctor` reports the relocation. For a permanent fix, put the project on a local-disk path (`/tmp`, or any home dir outside that mount) and run/build there |
| Every log line followed by `--- Logging error ---` / `OSError: [Errno 95] Operation not supported` | Your redirected stdout is on a filesystem whose `flush()` is unsupported (common in sandboxes/containers). Handled since v1.1: the safe handlers swallow write/flush errors; only that one console line is at risk, never a traceback flood |
| `OSError: [Errno 95]` while SAVING shares, or shares that "did not survive the write" | Your filesystem accepts the first create/write of a file but stops persisting *appends* (and sometimes rename-over). Handled since v1.3: `flush()`/`fsync()` errors are only warnings, the **read-back decides success**, and a file whose appends stop surviving is transparently switched to **delete-and-rewrite** — the whole file is written afresh (the operation that does work) and verified before the old content is replaced. A share that still cannot be written is queued, retried on every later share, and printed at shutdown so it is never silently lost |
| Stats stuck at `0.00 H/s` while shares stream in | Share bursts used to verify each share by spawning a helper process that re-initialized a 256 MB RandomX cache each time, starving the mining loop. Since v1.3 verification happens **in-process** against a persistent verifier — share bursts no longer affect the reported hashrate |

## When the native engine can't run there

The bundled `bin/miner_native` is a compiled ELF: it needs a compatible
architecture + libc and a filesystem that permits execution. Sandboxes, FUSE
mounts (`noexec`), containers and older glibc frequently refuse it. That must
never cost you the miner, so:

0. **Filesystem refuses to execute it?** (`EACCES`/`EPERM` from `execve`, even
   though `chmod +x` "succeeds" — common on FUSE data mounts) The engine plus
   `lib/` is copied to a private temp directory and the copy is executed, so
   you keep native hashrate. The original binary is never modified; the copy
   is per-process and needs no maintenance.
1. `--engine auto` (the default) tries the native engine and, if it cannot
   start, **falls back to the portable ctypes engine** — ~5× slower, same
   math, still writes valid shares. The warning names the reason and tells you
   to run the doctor.
2. `python3 file_miner.py --doctor` answers "can the native engine run HERE,
   and if not, exactly why" — mount options (noexec!), `librandomx.so` load,
   `bin/miner_native --info`, gcc/make/git presence, the ctypes engine — then
   prints a verdict and the fix (usually: rebuild on this machine with
   `./build.sh --force`, which also builds `librandomx.so` for your libc).
3. If the engine dies mid-run (not just at startup), the miner logs its dying
   words, switches to the python engine once, and restarts the current job
   instead of taking the process down.

Typical doctor verdicts seen on purpose-built broken boxes:

```
engine bin : mode 755, `--info` rc=127: ...error while loading shared libraries: librandomx.so: cannot open shared object file
VERDICT: the native engine is NOT usable here. Reasons/next steps:
  - execution is being blocked -- copy the folder to a normal path ...
  - the engine cannot load lib/librandomx.so -- keep lib/ next to bin/ ...
  Meanwhile: python3 file_miner.py --engine python (works)
```

## Limitations

* Monero (RandomX, `rx/0`) only; CPU only.
* POSIX-oriented: Linux is the tested platform (huge pages, affinity, `/proc`
  are Linux-isms; the code degrades gracefully without them, but macOS/Windows
  are untested).
* TLS to pools is supported (`--tls auto|plain|tls`) and certificate
  **verification is deliberately disabled** — Monero pools overwhelmingly use
  self-signed certificates, and pool auth here is just your public wallet
  address, not a secret.
* A 4-byte nonce is used; `nicehash=1` jobs are honored via the 24-bit mask.
* No dev fee, no hidden endpoints: `grep -r socket *.py` should show exactly
  one file (`pool_bridge.py`).

## Files in this directory

| Path | What |
|---|---|
| `file_miner.py` | the miner (no sockets) |
| `pool_bridge.py` | the only networked process |
| `engines.py` | native-subprocess and ctypes engine wrappers |
| `common.py` | protocol math + file formats (run it: `python3 common.py`) |
| `miner_native.c` | the C engine: dataset, huge pages, threads, nonce scan |
| `rx_test.c`, `rx_vector.h` | RandomX self-test + embedded official vector |
| `demo_job.py` | synthetic job generator for offline tests |
| `verify_share.py` | independent share re-hasher |
| `build.sh`, `run_tests.sh` | build + offline test suite |
| `tests/mock_pool.py`, `tests/loopback_test.sh`, `tests/live_submit_test.py` | test infrastructure |
| `tests/engine_target_check.py`, `tests/randomx_sampling.py` | differential + statistical engine validation (steps 7 and extras above) |
| `examples/` | a real captured kryptex job, a loopback share, and the pool-**accepted** kryptex share record |
| `lib/librandomx.so`, `third_party/RandomX` | upstream RandomX (BSD-3) built from source |
