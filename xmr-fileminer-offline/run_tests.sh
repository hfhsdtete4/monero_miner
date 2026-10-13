#!/usr/bin/env bash
# run_tests.sh -- offline end-to-end test suite for xmr-fileminer.
#
#   ./run_tests.sh            run everything (build + vector + mine + verify)
#   ./run_tests.sh --fast     skip the build step (reuse existing binaries)
#
# No network access is needed or used: a synthetic "demo" job replaces the pool.
# The loopback step (which needs pool_bridge.py) is skipped automatically when
# the bridge is not present, e.g. in the offline-only archive.
set -uo pipefail
cd "$(dirname "$0")"

# The workspace/filesystem may drop mode bits between checkouts -- restore what
# we need so the suite never fails for that reason.
chmod +x build.sh bin/* tests/*.sh tests/*.py 2>/dev/null || true

FAST=0
[ "${1:-}" = "--fast" ] && FAST=1

TMP=tests/tmp
rm -rf "$TMP"
mkdir -p "$TMP"
pass=0
fail=0
skips=0
ok()  { echo "  PASS  $*"; pass=$((pass + 1)); }
no()  { echo "  FAIL  $*"; fail=$((fail + 1)); }
skip(){ echo "  SKIP  $*"; skips=$((skips + 1)); }
step() { echo; echo "=== $* ==="; }

# ---------------------------------------------------------------- 1 --------
step "1. python syntax + protocol self-check"
PY_FILES=""
for f in common.py engines.py file_miner.py pool_bridge.py demo_job.py verify_share.py; do
    [ -f "$f" ] && PY_FILES="$PY_FILES $f"
done
if python3 -m py_compile $PY_FILES; then
    ok "all python files compile:$(echo $PY_FILES | tr ' ' '\n' | grep -c .) files"
else
    no "python compile"
fi
if python3 common.py >"$TMP/common.out" 2>&1; then
    ok "common.py protocol self-check (target/u32/nonce/gate math)"
else
    no "common.py self-check"
    cat "$TMP/common.out"
fi
if python3 tests/hostile_stdout_test.py >"$TMP/hostile.out" 2>&1; then
    ok "logging survives a hostile stdout (EOPNOTSUPP flush)"
else
    no "hostile-stdout logging"
    cat "$TMP/hostile.out"
fi

# ---------------------------------------------------------------- 2 --------
step "2. build + RandomX official test vector"
if [ "$FAST" = 0 ] || [ ! -x bin/miner_native ] || [ ! -f lib/librandomx.so ]; then
    if ./build.sh --quiet >"$TMP/build.out" 2>&1; then
        ok "build.sh"
    else
        no "build.sh"
        tail -20 "$TMP/build.out"
    fi
else
    ok "build reused (--fast)"
fi
# run the self-test through engines.ensure_runnable(): on filesystems that
# deny execve, that transparently relocates the binary to a temp dir first
RXT="$(python3 -c '
import sys; sys.path.insert(0, ".")
try:
    from engines import ensure_runnable
    print(ensure_runnable("bin/rx_test", probe_args=("light",)))
except Exception:
    print("./bin/rx_test")
' 2>/dev/null)"
[ -n "$RXT" ] || RXT=./bin/rx_test
if "$RXT" light >"$TMP/rx.out" 2>&1; then
    ok "RandomX vector passes in light mode${RXT:+ (via $RXT)}"
else
    no "RandomX vector (light)"
    cat "$TMP/rx.out"
fi
if python3 tests/exec_relocate_test.py >"$TMP/reloc.out" 2>&1; then
    ok "engine auto-relocates when the filesystem denies exec"
else
    no "engine relocation on exec-denial"
    tail -20 "$TMP/reloc.out"
fi

# ---------------------------------------------------------------- 3 --------
step "3. offline end-to-end: demo job -> mine -> shares.txt"
python3 demo_job.py --dir "$TMP" --diff 1 >"$TMP/demo.out" 2>&1 \
    && ok "demo job written ($(grep -c . "$TMP/demo.out") lines)" \
    || { no "demo_job.py"; cat "$TMP/demo.out"; }

timeout 600 python3 file_miner.py --dir "$TMP" --light --threads 2 \
    --stats 2 --once --max-runtime 420 --verify on \
    >"$TMP/miner.out" 2>&1
MRC=$?
if [ "$MRC" = 0 ] && grep -q "^SUMMARY" "$TMP/miner.out"; then
    ok "miner finished cleanly: $(grep -m1 '^SUMMARY' "$TMP/miner.out")"
else
    no "miner run (exit $MRC)"
    tail -25 "$TMP/miner.out"
fi
if grep -q "^\[share\]" "$TMP/shares.txt" 2>/dev/null; then
    ok "shares.txt contains a share record"
else
    no "shares.txt contains a share record"
    tail -25 "$TMP/miner.out"
fi
if grep -qi "self-test OK" "$TMP/miner.out"; then
    ok "miner validated RandomX before hashing"
else
    no "miner self-test message missing"
fi

# ---------------------------------------------------------------- 4 --------
step "4. independent re-hash of the produced share"
if python3 verify_share.py --dir "$TMP" --json >"$TMP/verify.json" 2>"$TMP/verify.err"; then
    ok "verify_share.py exit 0 (hash reproduced + target satisfied)"
else
    no "verify_share.py"
    cat "$TMP/verify.json" "$TMP/verify.err"
fi
if python3 - "$TMP/verify.json" <<'EOF'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as exc:
    print(f"  cannot parse verify json: {exc}")
    sys.exit(1)
print(f"  verified: n={d['n']} pass={d['pass']} fail={d['fail']}")
sys.exit(0 if d["fail"] == 0 and d["pass"] >= 1 else 1)
EOF
then
    ok "re-hash summary"
else
    no "re-hash summary"
fi

# ---------------------------------------------------------------- 5 --------
step "5. file plumbing: repeated appends + rejection of corrupt data"
python3 - "$TMP" <<'EOF'
import os, sys
sys.path.insert(0, os.getcwd())
from common import (append_record_locked, iter_share_blocks, lock_path_for,
                    make_share_record, load_job, parse_share_records,
                    render_share_record, render_job_text, load_job_text)
d = sys.argv[1]
job = load_job(os.path.join(d, "job.txt"))
sp = os.path.join(d, "append_test.txt")
for i in range(25):
    append_record_locked(sp, make_share_record(job, i, "%064x" % i, 1.0 + i, "test"), lock_path_for(sp))
recs = parse_share_records(open(sp).read())
assert len(recs) == 25, f"expected 25 records, got {len(recs)}"
assert recs[7]["nonce_u32"] == "7" and len(recs[7]["result"]) == 64
# the job round-trips through the text format byte-for-byte
assert load_job_text(render_job_text(job)).signature() == job.signature()
print("  25 appends parsed back correctly; job text round-trip OK")
EOF
if [ $? = 0 ]; then
    ok "append/parse/round-trip plumbing"
else
    no "append/parse plumbing"
fi
if python3 tests/harsh_fs_test.py >"$TMP/harsh.out" 2>&1; then
    ok "writes survive flush/fsync/flock failures (verified by read-back)"
else
    no "hostile-filesystem writes"
    cat "$TMP/harsh.out"
fi
if python3 tests/rewrite_fallback_test.py >"$TMP/rewrite.out" 2>&1; then
    ok "delete-and-rewrite fallback (append-hostile filesystems)"
else
    no "delete-and-rewrite fallback"
    cat "$TMP/rewrite.out"
fi
if python3 tests/hostile_fs_e2e_test.py 12 >"$TMP/hostile_e2e.out" 2>&1; then
    ok "whole miner persists every share on an append-hostile filesystem"
else
    no "miner on append-hostile filesystem"
    tail -25 "$TMP/hostile_e2e.out"
fi

# ---------------------------------------------------------------- 6 --------
step "6. loopback: mock pool <-> bridge <-> miner (accept path, job rotation)"
if [ -f pool_bridge.py ] && [ -x tests/loopback_test.sh ]; then
    if tests/loopback_test.sh "$TMP" >"$TMP/loopback.out" 2>&1; then
        ok "full loop incl. pool-side re-hash + ACCEPT + job rotation"
    else
        no "loopback loop"
        tail -30 "$TMP/loopback.out"
    fi
else
    skip "loopback loop -- pool_bridge.py / tests/loopback_test.sh not present (offline subset)"
fi

# ---------------------------------------------------------------- 7 --------
step "7. differential share detection: native engine vs independent reference"
if python3 tests/engine_target_check.py --dir "$TMP" --diff 256 --nonces 600 \
        --max-nonces 4000 >"$TMP/engchk.out" 2>&1; then
    ok "$(grep -m1 'agreement:' "$TMP/engchk.out")"
else
    no "engine/reference disagreement"
    tail -20 "$TMP/engchk.out"
fi

# --------------------------------------------------------------- fin --------
echo
echo "=============================================="
if [ "$skips" -gt 0 ]; then
    echo "RESULT: $pass passed, $fail failed, $skips skipped"
else
    echo "RESULT: $pass passed, $fail failed"
fi
if [ "$fail" = 0 ]; then
    echo "offline suite: ALL GOOD"
else
    echo "offline suite: FAILURES (see $TMP/ and tests/tmp/*.out)"
fi
echo "=============================================="
exit "$fail"
