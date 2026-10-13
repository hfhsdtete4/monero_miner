/* miner_native.c -- native RandomX mining engine for xmr-fileminer.
 *
 * DESIGN CONTRACT
 * ---------------
 *  * This process NEVER touches the network and NEVER touches shares.txt /
 *    job.txt. All file I/O and all pool I/O live in the Python side. The
 *    engine only talks a tiny line protocol on stdin/stdout, which makes it
 *    trivially auditable and keeps the hot loop clean.
 *  * It speaks commands on stdin and events on stdout, one per line:
 *
 *      INIT seed=<64hex> mode=<auto|full|light> hp=<0|1> initthreads=<n>
 *      SELFTEST
 *      START threads=<n> blob=<hex> target=<8hex> offset=<hex> mask=<hex> \
 *            gate=<0|1> yield=<0|1> cpus=<0,1,2>
 *      STOP
 *      STATS
 *      INFO
 *      QUIT
 *
 *    Events: READY INITPROG INITOK INITERR SELFTEST STARTED RATE TOTAL WIN
 *            BEST STALL RESUME STOPPED BYE ERR
 *
 * HASH RATE NOTES (what actually makes this fast)
 * -----------------------------------------------
 *  1. RANDOMX_FLAG_FULL_MEM (the 2 GB dataset) is used by default. Light mode
 *     recomputes Argon2d dataset items per hash and is ~5-10x slower. Same
 *     answer, just slower.
 *  2. RANDOMX_FLAG_LARGE_PAGES (2 MB pages) is requested for dataset, cache
 *     and VM. This is not cosmetic: without huge pages you pay TLB misses on
 *     every dataset access, which costs tens of percent of hashrate. If the
 *     kernel has no huge pages reserved we fall back and say so.
 *  3. One VM (and therefore one 2 MB scratchpad) per worker thread; dataset
 *     and cache are read-only and shared. This is exactly xmrig's model.
 *  4. The dataset is initialized once per seed (parallel init across
 *     --initthreads). A seed change (new block) costs one re-init; a job
 *     change with the same seed costs nothing.
 *  5. One CPU thread per physical core, optionally pinned with `cpus=`.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "randomx.h"
#include "rx_vector.h"

#define MAX_THREADS 256
#define MAX_CPUS 4096
#define MAX_BLOB 256

/* ------------------------------------------------------------------ */
/* output (line-locked so multiple threads never interleave)           */
/* ------------------------------------------------------------------ */
static pthread_mutex_t g_out_lock = PTHREAD_MUTEX_INITIALIZER;

static void emit(const char *fmt, ...)
{
    va_list ap;
    pthread_mutex_lock(&g_out_lock);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
    pthread_mutex_unlock(&g_out_lock);
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* ------------------------------------------------------------------ */
/* engine state                                                        */
/* ------------------------------------------------------------------ */
static randomx_flags g_base_flags = 0;
static randomx_flags g_vm_flags   = 0;   /* flags for the mining VMs       */
static randomx_cache   *g_cache   = NULL;
static randomx_dataset *g_dataset = NULL;
static int   g_full_mem   = 0;
static int   g_hugepages  = 0;
static int   g_selftest_ok = -1;

static int   g_init_threads = 4;
static int   g_stall_secs   = 30;
static int   g_report_ms    = 2000;

/* current job (only mutated while no worker is running) */
static uint8_t g_blob[MAX_BLOB];
static size_t  g_blob_len = 0;
static uint32_t g_target_u32 = 0xFFFFFFFFu;
static uint32_t g_nonce_mask = 0xFFFFFFFFu;
static int      g_gate = 1;

static int      g_nthreads = 0;
static int      g_running  = 0;
static uint64_t g_job_epoch = 0;

typedef struct {
    int      tid;
    uint32_t start;          /* first nonce (already masked)               */
    uint64_t len;            /* number of nonces in this thread's range    */
    int      yield;
    int      cpus[MAX_CPUS / 64];
    int      ncpus;

    pthread_t th;
    randomx_vm *vm;

    _Atomic int      stop;
    _Atomic uint64_t hashes;      /* updated every 64 hashes                */
    _Atomic uint64_t seq;         /* updated every hash (stall detection)   */
    _Atomic uint64_t wins;
    _Atomic uint64_t stall_ms;    /* main thread writes, workers clear      */
    _Atomic uint32_t best_u32;
    _Atomic uint64_t best_nonce;
    char best_hash[65];
} worker_t;

static worker_t g_workers[MAX_THREADS];
static _Atomic uint32_t g_best_u32 = 0xFFFFFFFFu;

static inline uint32_t hash_u32_le(const uint8_t *h)
{
    return (uint32_t)h[28] | ((uint32_t)h[29] << 8) |
           ((uint32_t)h[30] << 16) | ((uint32_t)h[31] << 24);
}

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */
static const char *kv_find(const char *line, const char *key)
{
    size_t klen = strlen(key);
    const char *p = line;
    if (strncmp(p, key, klen) == 0 && p[klen] == '=')
        return p + klen + 1;                       /* command's own argument */
    while ((p = strstr(p, key)) != NULL) {
        if (p[klen] == '=' && (p == line || p[-1] == ' '))
            return p + klen + 1;
        p += klen;
    }
    return NULL;
}

static long kv_long(const char *line, const char *key, long dflt)
{
    const char *v = kv_find(line, key);
    if (!v)
        return dflt;
    return strtol(v, NULL, 0);
}

static uint64_t kv_u64hex(const char *line, const char *key, uint64_t dflt)
{
    const char *v = kv_find(line, key);
    if (!v)
        return dflt;
    return strtoull(v, NULL, 16);
}

static inline int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 16;
}

/* Read the hex value of a "key=<hex>" pair. Stops at the first non-hex char
   (the kv delimiter is a space). Returns the number of BYTES decoded. */
static size_t kv_hex(const char *line, const char *key, uint8_t *out, size_t out_max)
{
    const char *v = kv_find(line, key);
    if (!v)
        return 0;
    size_t n = 0;
    while (hexval(v[n]) < 16)
        n++;
    if (n == 0 || (n & 1))
        return 0;
    size_t bytes = n / 2;
    if (bytes > out_max)
        return 0;
    for (size_t i = 0; i < bytes; ++i)
        out[i] = (uint8_t)((hexval(v[2 * i]) << 4) | hexval(v[2 * i + 1]));
    return bytes;
}

/* RAM available in MiB (Linux). Returns -1 if unknown. */
static long mem_available_mb(void)
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f)
        return -1;
    char line[256];
    long kb = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "MemAvailable:", 13) == 0) {
            kb = strtol(line + 13, NULL, 10);
            break;
        }
    }
    fclose(f);
    return kb > 0 ? kb / 1024 : -1;
}

static void set_affinity(const int *cpus, int ncpus, int tid)
{
#if defined(__linux__)
    if (ncpus <= 0)
        return;
    cpu_set_t set;
    CPU_ZERO(&set);
    int cpu = cpus[tid % ncpus];
    CPU_SET(cpu, &set);
    pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
#else
    (void)cpus; (void)ncpus; (void)tid;
#endif
}

/* ------------------------------------------------------------------ */
/* worker thread                                                       */
/* ------------------------------------------------------------------ */
static void *worker_main(void *arg)
{
    worker_t *w = (worker_t *)arg;

    set_affinity(w->cpus, w->ncpus, w->tid);

    uint8_t blob[MAX_BLOB];
    uint8_t hash[RANDOMX_HASH_SIZE];
    memcpy(blob, g_blob, g_blob_len);

    uint64_t i = 0;

    atomic_store(&w->seq, 0);

    for (;;) {
        if ((i & 63u) == 0) {
            if (atomic_load_explicit(&w->stop, memory_order_relaxed))
                break;
            if (w->yield)
                sched_yield();
        }

        uint32_t nonce = (uint32_t)((w->start + (i % w->len)) & g_nonce_mask);
        memcpy(blob + 39, &nonce, 4);   /* LE by contract (checked in main) */
        /* Publish progress on EVERY hash: a relaxed store to a per-thread
           counter costs nothing next to a ~20 ms RandomX hash, and it keeps
           the reported H/s honest even in light mode where a 64-hash publish
           interval would quantize the rate badly (it once made 42 H/s look
           like 64 H/s, and worse, 32 H/s). */
        atomic_store_explicit(&w->hashes, i + 1, memory_order_relaxed);
        atomic_store_explicit(&w->seq, i, memory_order_relaxed);

        randomx_calculate_hash(w->vm, blob, g_blob_len, hash);
        i++;

        if (g_gate ? (hash[31] == 0) : 1) {
            uint32_t u = hash_u32_le(hash);
            if (u <= g_target_u32) {
                char hex[65];
                rx_bin_to_hex(hash, 32, hex);
                double diff = (double)4294967296.0 / (u ? u : 1);
                atomic_fetch_add(&w->wins, 1);
                emit("WIN tid=%d nonce=0x%08X hash=%s diff=%.3f", w->tid, nonce, hex, diff);
            }
            /* track per-thread and global best; both reset on every START, so
               "best" always describes the CURRENT job */
            uint32_t cur = atomic_load_explicit(&w->best_u32, memory_order_relaxed);
            if (u < cur) {
                if (atomic_compare_exchange_weak(&w->best_u32, &cur, u)) {
                    atomic_store(&w->best_nonce, nonce);
                    rx_bin_to_hex(hash, 32, w->best_hash);
                }
            }
            cur = atomic_load_explicit(&g_best_u32, memory_order_relaxed);
            if (u < cur) {
                if (atomic_compare_exchange_weak(&g_best_u32, &cur, u)) {
                    char hex[65];
                    double diff = (double)4294967296.0 / (u ? u : 1);
                    rx_bin_to_hex(hash, 32, hex);
                    emit("BEST tid=%d nonce=0x%08X hash=%s diff=%.3f", w->tid, nonce, hex, diff);
                }
            }
        }
    }

    atomic_store_explicit(&w->hashes, i, memory_order_relaxed);
    randomx_destroy_vm(w->vm);
    w->vm = NULL;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* dataset init (parallel, with progress)                              */
/* ------------------------------------------------------------------ */
typedef struct {
    unsigned long start_item;
    unsigned long count;        /* processed in chunks for progress       */
} init_range_t;

static _Atomic unsigned long g_init_done = 0;

static void *init_range_thread(void *arg)
{
    init_range_t *r = (init_range_t *)arg;
    const unsigned long chunk = 65536;   /* ~0.5 MB of dataset per chunk     */
    unsigned long off = 0;
    while (off < r->count) {
        unsigned long n = r->count - off;
        if (n > chunk)
            n = chunk;
        randomx_init_dataset(g_dataset, g_cache, r->start_item + off, n);
        atomic_fetch_add(&g_init_done, n);
        off += n;
    }
    return NULL;
}

static int init_dataset_parallel(unsigned long total, int nthreads, double *out_ms)
{
    double t0 = now_ms();
    if (nthreads < 1)
        nthreads = 1;
    if (nthreads > 64)
        nthreads = 64;

    pthread_t th[64];
    init_range_t ranges[64];
    atomic_store(&g_init_done, 0);

    unsigned long per = total / (unsigned long)nthreads;
    int started = 0;
    for (int i = 0; i < nthreads; ++i) {
        ranges[i].start_item = (unsigned long)i * per;
        ranges[i].count = (i == nthreads - 1) ? total - ranges[i].start_item : per;
        if (pthread_create(&th[i], NULL, init_range_thread, &ranges[i]) != 0) {
            emit("INITERR reason=init_thread_create_failed");
            for (int j = 0; j < started; ++j)
                pthread_join(th[j], NULL);
            return -1;
        }
        started++;
    }

    int last_pct = -1;
    for (;;) {
        unsigned long prog = atomic_load(&g_init_done);
        int pct = (total > 0) ? (int)(prog * 100 / total) : 100;
        if (pct != last_pct && pct < 100) {
            emit("INITPROG phase=dataset pct=%d", pct);
            last_pct = pct;
        }
        if (prog >= total)
            break;
        struct timespec ts = {0, 200 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    for (int i = 0; i < started; ++i)
        pthread_join(th[i], NULL);

    *out_ms = now_ms() - t0;
    return 0;
}

/* ------------------------------------------------------------------ */
/* INIT / SELFTEST                                                     */
/* ------------------------------------------------------------------ */
static int build_memory(const char *line, int mode /*0 auto,1 full,2 light*/)
{
    int want_hp = (int)kv_long(line, "hp", 1) ? 1 : 0;
    uint8_t seed[64];
    size_t seed_len = kv_hex(line, "seed", seed, sizeof(seed));
    if (seed_len != 32) {
        emit("INITERR reason=bad_seed");
        return -1;
    }

    long avail = mem_available_mb();
    int full = (mode != 2);
    if (full) {
        /* dataset (2080 MB) + cache (512 MB) + scratchpads + headroom */
        const long need_mb = 2200 + 600 + (long)g_nthreads * 4;
        if (avail > 0 && avail < need_mb) {
            if (mode == 1) {
                emit("INITERR reason=low_memory need_mb=%ld avail_mb=%ld "
                     "hint=use_light_mode", need_mb, avail);
                return -1;
            }
            emit("WARN msg=low_memory avail_mb=%ld need_mb=%ld falling_back=light", avail, need_mb);
            full = 0;
        }
    }

    randomx_flags cf = g_base_flags;
    if (want_hp)
        cf = (randomx_flags)(cf | RANDOMX_FLAG_LARGE_PAGES);

    /* --- cache --- */
    double t0 = now_ms();
    randomx_cache *cache = randomx_alloc_cache(cf);
    if (!cache && want_hp) {
        emit("WARN msg=hugepages_unavailable_for_cache falling_back=normal_pages");
        want_hp = 0;
        cf = g_base_flags;
        cache = randomx_alloc_cache(cf);
    }
    if (!cache) {
        emit("INITERR reason=cache_alloc_failed");
        return -1;
    }
    randomx_init_cache(cache, seed, 32);
    double cache_ms = now_ms() - t0;

    /* --- dataset --- */
    randomx_dataset *ds = NULL;
    double ds_ms = 0;
    if (full) {
        randomx_flags df = (randomx_flags)(cf | RANDOMX_FLAG_FULL_MEM);
        ds = randomx_alloc_dataset(df);
        if (!ds && (df & RANDOMX_FLAG_LARGE_PAGES)) {
            emit("WARN msg=hugepages_unavailable_for_dataset falling_back=normal_pages");
            df = (randomx_flags)(g_base_flags | RANDOMX_FLAG_FULL_MEM);
            cf = g_base_flags;
            want_hp = 0;
            ds = randomx_alloc_dataset(df);
        }
        if (!ds) {
            if (mode == 1) {
                emit("INITERR reason=dataset_alloc_failed hint=use_light_mode");
                randomx_release_cache(cache);
                return -1;
            }
            emit("WARN msg=dataset_alloc_failed falling_back=light");
            full = 0;
        }
    }

    /* swap in the new memory: free old AFTER new is ready so a failed
       re-init cannot leave us without a working dataset */
    if (g_cache)
        randomx_release_cache(g_cache);
    if (g_dataset)
        randomx_release_dataset(g_dataset);
    g_cache = cache;
    g_dataset = ds;
    g_full_mem = full;
    g_hugepages = want_hp;

    if (full) {
        unsigned long total = randomx_dataset_item_count();
        emit("INITPROG phase=dataset pct=0");
        if (init_dataset_parallel(total, g_init_threads, &ds_ms) != 0) {
            randomx_release_dataset(g_dataset);
            g_dataset = NULL;
            randomx_release_cache(g_cache);
            g_cache = NULL;
            return -1;
        }
    }

    g_vm_flags = g_base_flags;
    if (g_hugepages)
        g_vm_flags = (randomx_flags)(g_vm_flags | RANDOMX_FLAG_LARGE_PAGES);
    if (g_full_mem)
        g_vm_flags = (randomx_flags)(g_vm_flags | RANDOMX_FLAG_FULL_MEM);

    emit("INITOK mode=%s hp=%d cache_ms=%.0f dataset_ms=%.0f avail_mb=%ld dataset_mb=%lu",
         g_full_mem ? "full" : "light", g_hugepages, cache_ms, ds_ms, avail,
         g_full_mem ? (randomx_dataset_item_count() * 8UL) / (1024UL * 1024UL) : 0UL);
    return 0;
}

static int make_vm(randomx_vm **out)
{
    *out = NULL;
    if (!g_cache) {
        emit("ERR msg=vm_before_init");
        return -1;
    }
    randomx_vm *vm;
    if (g_full_mem && g_dataset)
        vm = randomx_create_vm(g_vm_flags, NULL, g_dataset);
    else
        vm = randomx_create_vm((randomx_flags)(g_vm_flags & ~RANDOMX_FLAG_FULL_MEM), g_cache, NULL);
    if (!vm) {
        emit("ERR msg=vm_create_failed flags=0x%x", (unsigned)g_vm_flags);
        return -1;
    }
    *out = vm;
    return 0;
}

/* Emits SELFTEST with ok=1 (pass), 0 (fail), 2 (could not run).
 *
 * Two independent checks:
 *   1. the official RandomX test vector, on a temporary cache built from the
 *      test key -- guarantees the library/CPU/JIT produce canonical hashes;
 *   2. in full-memory mode, hash a fixed blob on both the full-VM and a
 *      light-VM over the same cache: they MUST agree, which proves the 2 GB
 *      dataset was initialized correctly on this machine.
 */
static int do_selftest(void)
{
    int ok = 2;                       /* 2 = could not run */
    char got[65] = {0};

    randomx_cache *tc = randomx_alloc_cache(g_base_flags);
    if (tc) {
        randomx_init_cache(tc, RX_TEST_KEY, RX_TEST_KEY_LEN);
        randomx_vm *tvm = randomx_create_vm(
            (randomx_flags)(g_base_flags & ~RANDOMX_FLAG_FULL_MEM), tc, NULL);
        if (tvm) {
            ok = rx_selftest(tvm, got, sizeof(got));
            randomx_destroy_vm(tvm);
        }
        randomx_release_cache(tc);
    }
    emit("SELFTEST ok=%d mode=%s got=%s expected=%s", ok == 1 ? 1 : (ok == 0 ? 0 : 2),
         g_full_mem ? "full" : "light", ok == 1 ? got : "?", RX_TEST_EXPECTED);

    if (ok == 1 && g_full_mem && g_dataset && g_cache) {
        static const uint8_t dummy[76] = {0x42};
        uint8_t hf[32], hl[32];
        randomx_vm *vfull = randomx_create_vm(
            (randomx_flags)(g_vm_flags | RANDOMX_FLAG_FULL_MEM), NULL, g_dataset);
        randomx_vm *vlight = randomx_create_vm(
            (randomx_flags)(g_vm_flags & ~RANDOMX_FLAG_FULL_MEM), g_cache, NULL);
        int cross = -1;
        if (vfull && vlight) {
            randomx_calculate_hash(vfull, dummy, sizeof(dummy), hf);
            randomx_calculate_hash(vlight, dummy, sizeof(dummy), hl);
            cross = (memcmp(hf, hl, 32) == 0) ? 1 : 0;
        }
        if (vfull)
            randomx_destroy_vm(vfull);
        if (vlight)
            randomx_destroy_vm(vlight);
        if (cross != -1)
            emit("SELFTEST cross=%d detail=full_vs_light_%s", cross,
                 cross ? "match" : "MISMATCH");
        if (cross == 0)
            ok = 0;
    }

    g_selftest_ok = (ok == 1) ? 1 : 0;
    return ok == 1 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* START / STOP                                                        */
/* ------------------------------------------------------------------ */
static int do_start(const char *line)
{
    if (g_running) {
        emit("ERR msg=start_while_running");
        return -1;
    }
    if (!g_cache || (g_full_mem && !g_dataset)) {
        emit("ERR msg=start_before_init");
        return -1;
    }

    long nthreads = kv_long(line, "threads", 1);
    if (nthreads < 1 || nthreads > MAX_THREADS) {
        emit("ERR msg=bad_threads");
        return -1;
    }

    uint8_t blob[MAX_BLOB];
    size_t blob_len = kv_hex(line, "blob", blob, sizeof(blob));
    if (blob_len < 44 || blob_len > 253) {
        emit("ERR msg=bad_blob len=%zu", blob_len);
        return -1;
    }

    /* NOTE: this is the little-endian-converted u32 (target32), NOT the raw
       pool target hex. The pool hex "f1290000" means u32 0x000029f1; feeding
       the raw string here would make every h[31]==0 hash pass. The miner does
       that conversion (common.target_u32_from_be) and passes both forms so we
       can cross-check them. */
    uint64_t target = kv_u64hex(line, "target32", 0xFFFFFFFFull);
    uint64_t target_raw = kv_u64hex(line, "target", 0);
    if (target_raw) {
        uint32_t cvt = (uint32_t)((target_raw & 0xFF) << 24 |
                                  (target_raw & 0xFF00) << 8 |
                                  (target_raw & 0xFF0000) >> 8 |
                                  (target_raw & 0xFF000000) >> 24);
        if ((cvt & 0xFFFFFFFFu) != (uint32_t)target) {
            emit("ERR msg=target_mismatch target32=0x%08X converted_from_hex=0x%08X",
                 (unsigned)target, (unsigned)cvt);
            return -1;
        }
    }
    uint64_t offset = kv_u64hex(line, "offset", 0);
    uint64_t mask   = kv_u64hex(line, "mask", 0xFFFFFFFFull);
    int gate  = (int)kv_long(line, "gate", 1) ? 1 : 0;
    int yield = (int)kv_long(line, "yield", 0) ? 1 : 0;

    if (mask == 0 || mask > 0xFFFFFFFFull)
        mask = 0xFFFFFFFFull;

    /* cpus=0,1,2,3-5 parsed into a list */
    int cpus[MAX_CPUS];
    int ncpus = 0;
    const char *cv = kv_find(line, "cpus");
    if (cv) {
        const char *p = cv;
        while (*p && *p != ' ' && ncpus < MAX_CPUS) {
            char *end = NULL;
            long a = strtol(p, &end, 10);
            if (end == p)
                break;
            long b = a;
            p = end;
            if (*p == '-') {
                p++;
                b = strtol(p, &end, 10);
                if (end == p)
                    break;
                p = end;
            }
            for (long c = a; c <= b && ncpus < MAX_CPUS; ++c)
                cpus[ncpus++] = (int)c;
            if (*p == ',')
                p++;
            else
                break;
        }
    }

    memcpy(g_blob, blob, blob_len);
    g_blob_len   = blob_len;
    g_target_u32 = (uint32_t)target;
    g_nonce_mask = (uint32_t)mask;
    g_gate       = gate;
    g_best_u32   = 0xFFFFFFFFu;
    g_job_epoch++;

    uint64_t space = mask + 1;
    uint64_t per   = space / (uint64_t)nthreads;

    for (long t = 0; t < nthreads; ++t) {
        worker_t *w = &g_workers[t];
        memset(w, 0, sizeof(*w));
        w->tid = (int)t;
        w->len = per;
        if (t == nthreads - 1)
            w->len = space - per * (uint64_t)(nthreads - 1);
        w->start = (uint32_t)((offset + (uint64_t)t * per) & mask);
        w->yield = yield;
        w->ncpus = ncpus;
        memcpy(w->cpus, cpus, sizeof(int) * (size_t)ncpus);
        atomic_init(&w->stop, 0);
        atomic_init(&w->hashes, 0);
        atomic_init(&w->seq, 0);
        atomic_init(&w->wins, 0);
        atomic_init(&w->stall_ms, 0);
        atomic_init(&w->best_u32, 0xFFFFFFFFu);
        atomic_init(&w->best_nonce, 0);

        if (make_vm(&w->vm) != 0)
            goto fail;
        if (pthread_create(&w->th, NULL, worker_main, w) != 0) {
            emit("ERR msg=thread_create_failed");
            randomx_destroy_vm(w->vm);
            w->vm = NULL;
            goto fail;
        }
    }

    g_nthreads = (int)nthreads;
    g_running  = 1;
    {
        /* report the assigned nonce ranges in a compact, parseable way */
        char ranges[4096];
        size_t off2 = 0;
        ranges[0] = 0;
        for (int t = 0; t < g_nthreads; ++t) {
            int n = snprintf(ranges + off2, sizeof(ranges) - off2, "%s0x%08X+%llu",
                             t ? "," : "", g_workers[t].start,
                             (unsigned long long)g_workers[t].len);
            if (n < 0 || (size_t)n >= sizeof(ranges) - off2)
                break;
            off2 += (size_t)n;
        }
        emit("STARTED threads=%d mode=%s gate=%d mask=0x%08X target=0x%08X ranges=%s",
             g_nthreads, g_full_mem ? "full" : "light", g_gate, g_nonce_mask,
             g_target_u32, ranges);
    }
    return 0;

fail:
    for (int t = 0; t < (int)nthreads; ++t) {
        worker_t *w = &g_workers[t];
        if (w->th) {
            atomic_store(&w->stop, 1);
            pthread_join(w->th, NULL);
            w->th = 0;
        }
        if (w->vm) {
            randomx_destroy_vm(w->vm);
            w->vm = NULL;
        }
    }
    g_nthreads = 0;
    g_running = 0;
    emit("ERR msg=start_failed");
    return -1;
}

static void do_stop(void)
{
    if (!g_running) {
        emit("STOPPED");
        return;
    }
    for (int t = 0; t < g_nthreads; ++t)
        atomic_store(&g_workers[t].stop, 1);
    for (int t = 0; t < g_nthreads; ++t) {
        pthread_join(g_workers[t].th, NULL);
        g_workers[t].th = 0;   /* the VM is destroyed by the worker itself */
    }
    g_running = 0;
    g_nthreads = 0;
    emit("STOPPED");
}

static void do_stats(void)
{
    uint64_t tot = 0;
    for (int t = 0; t < g_nthreads; ++t)
        tot += atomic_load(&g_workers[t].hashes);
    emit("TOTAL hps=0 hashes=%llu (instantaneous rate is in RATE events)",
         (unsigned long long)tot);
}

/* ------------------------------------------------------------------ */
/* main loop                                                           */
/* ------------------------------------------------------------------ */
static void print_info(void)
{
    long pages = sysconf(_SC_PHYS_PAGES);
    long psize = sysconf(_SC_PAGESIZE);
    emit("INFO randomx=%s flags=0x%x jit=%d hard_aes=%d full_mem=%d hugepages=%d "
         "cores=%ld mem_gb=%.1f",
         RANDOMX_VERSION, (unsigned)g_base_flags,
         !!(g_base_flags & RANDOMX_FLAG_JIT),
         !!(g_base_flags & RANDOMX_FLAG_HARD_AES),
         !!(g_base_flags & RANDOMX_FLAG_FULL_MEM),
         !!(g_base_flags & RANDOMX_FLAG_LARGE_PAGES),
         sysconf(_SC_NPROCESSORS_ONLN),
         (pages > 0 && psize > 0) ? (double)pages * (double)psize / 1073741824.0 : 0.0);
}

static int verify_mode(const char *seed_hex)
{
    uint8_t seed[64];
    size_t seed_len = 0;
    if (rx_hex_to_bin(seed_hex, seed, sizeof(seed), &seed_len) != 0 || seed_len != 32) {
        emit("ERR msg=bad_seed");
        return 2;
    }
    randomx_cache *cache = randomx_alloc_cache(g_base_flags);
    if (!cache) {
        emit("ERR msg=cache_alloc_failed");
        return 2;
    }
    randomx_init_cache(cache, seed, 32);
    randomx_vm *vm = randomx_create_vm((randomx_flags)(g_base_flags & ~RANDOMX_FLAG_FULL_MEM),
                                       cache, NULL);
    if (!vm) {
        emit("ERR msg=vm_create_failed");
        randomx_release_cache(cache);
        return 2;
    }
    char got[65];
    rx_selftest(vm, got, sizeof(got));
    emit("READY verify=1 mode=light");
    setvbuf(stdin, NULL, _IOFBF, 0);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    unsigned long count = 0;
    while ((n = getline(&line, &cap, stdin)) > 0) {
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = 0;
        if (n == 0)
            continue;
        if (strcmp(line, "QUIT") == 0)
            break;
        uint8_t blob[MAX_BLOB];
        size_t blen = 0;
        if (rx_hex_to_bin(line, blob, sizeof(blob), &blen) != 0 || blen < 44) {
            emit("HASH invalid");
            continue;
        }
        uint8_t hash[64];
        randomx_calculate_hash(vm, blob, blen, hash);
        char hx[65];
        rx_bin_to_hex(hash, 32, hx);
        emit("HASH %s", hx);
        count++;
    }
    free(line);
    randomx_destroy_vm(vm);
    randomx_release_cache(cache);
    emit("VERIFYDONE n=%lu", count);
    return 0;
}

/* ------------------------------------------------------------------ */
/* stdin reader                                                        */
/*                                                                     */
/* Deliberately NOT stdio: getline() would pre-buffer lines inside     */
/* libc, and then poll() on the fd would report "no data" forever      */
/* while complete commands sit unread in the buffer. That bug cost me  */
/* a very confusing 20 minutes; this is the fix. stdin is set          */
/* O_NONBLOCK in main(); we keep our own line buffer.                  */
/* ------------------------------------------------------------------ */
static char   g_inbuf[65536];
static size_t g_inlen = 0;

/* Returns 1 = line ready, 0 = no data right now, -1 = EOF. */
static int read_input_line(char *out, size_t out_sz)
{
    for (;;) {
        char *nl = memchr(g_inbuf, '\n', g_inlen);
        if (nl) {
            size_t len = (size_t)(nl - g_inbuf);
            if (len > out_sz - 1)
                len = out_sz - 1;
            memcpy(out, g_inbuf, len);
            out[len] = 0;
            if (len && out[len - 1] == '\r')
                out[--len] = 0;
            size_t consumed = (size_t)(nl - g_inbuf) + 1;
            memmove(g_inbuf, g_inbuf + consumed, g_inlen - consumed);
            g_inlen -= consumed;
            return 1;
        }
        if (g_inlen >= sizeof(g_inbuf))
            g_inlen = 0;                     /* runaway over-long line      */
        ssize_t n = read(0, g_inbuf + g_inlen, sizeof(g_inbuf) - g_inlen);
        if (n > 0) {
            g_inlen += (size_t)n;
            continue;
        }
        if (n == 0) {
            if (g_inlen > 0) {               /* final line without '\n'     */
                size_t len = g_inlen < out_sz - 1 ? g_inlen : out_sz - 1;
                memcpy(out, g_inbuf, len);
                out[len] = 0;
                g_inlen = 0;
                return 1;
            }
            return -1;
        }
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        return -1;
    }
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* little-endian by contract: the nonce is memcpy'd as a uint32 into the
       blob, exactly like xmrig does. Refuse to run anywhere else. */
    {
        uint32_t probe = 1;
        if (*(uint8_t *)&probe != 1) {
            emit("ERR msg=big_endian_host_unsupported");
            return 3;
        }
    }

    g_base_flags = randomx_get_flags();

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--report-ms") == 0 && i + 1 < argc)
            g_report_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "--stall-secs") == 0 && i + 1 < argc)
            g_stall_secs = atoi(argv[++i]);
        else if (strcmp(argv[i], "--init-threads") == 0 && i + 1 < argc)
            g_init_threads = atoi(argv[++i]);
        else if (strcmp(argv[i], "--nice") == 0 && i + 1 < argc) {
            int nv = atoi(argv[++i]);
            if (nv != 0) {
                if (setpriority(PRIO_PROCESS, 0, nv) != 0 && errno == EPERM)
                    emit("WARN msg=nice_failed_perm value=%d", nv);
            }
        } else if (strcmp(argv[i], "--info") == 0) {
            print_info();
            return 0;
        } else if (strcmp(argv[i], "--verify") == 0 && i + 1 < argc) {
            return verify_mode(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("miner_native -- native RandomX engine for xmr-fileminer\n"
                   "  engine mode: commands on stdin (INIT/SELFTEST/START/STOP/STATS/QUIT)\n"
                   "  --info             print RandomX build/cpu info and exit\n"
                   "  --verify SEEDHEX   read blob hex lines on stdin, print hashes (light mode)\n"
                   "  --report-ms N      rate event interval (default 2000)\n"
                   "  --init-threads N   dataset init parallelism (default 4)\n"
                   "  --stall-secs N     report a worker as stalled after N seconds (default 30)\n"
                   "  --nice N           setprocess nice value\n");
            return 0;
        }
    }

    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 1)
        cores = 1;

    /* engine mode reads stdin with raw read(); make it non-blocking */
    {
        int fl = fcntl(0, F_GETFL, 0);
        if (fl != -1)
            (void)fcntl(0, F_SETFL, fl | O_NONBLOCK);
    }

    emit("READY pid=%d cores=%ld flags=0x%x jit=%d aes=%d report_ms=%d",
         (int)getpid(), cores, (unsigned)g_base_flags,
         !!(g_base_flags & RANDOMX_FLAG_JIT),
         !!(g_base_flags & RANDOMX_FLAG_HARD_AES), g_report_ms);

    uint64_t prev_seq[MAX_THREADS] = {0};
    uint64_t last_stall_report[MAX_THREADS] = {0};
    double   last_report = now_ms();
    double   last_tick = now_ms();

    char line[65536];
    int said_bye = 0;

    for (;;) {
        int got = read_input_line(line, sizeof(line));
        if (got < 0)
            break;                           /* stdin closed -> shut down   */

        if (got > 0) {
            if (strncmp(line, "INIT", 4) == 0 && (line[4] == ' ' || line[4] == 0)) {
                int mode = 0;   /* auto */
                const char *mv = kv_find(line, "mode");
                if (mv) {
                    if (strncmp(mv, "full", 4) == 0) mode = 1;
                    else if (strncmp(mv, "light", 5) == 0) mode = 2;
                }
                if (g_running) {
                    emit("ERR msg=init_while_running");
                } else {
                    int it = (int)kv_long(line, "initthreads", g_init_threads);
                    if (it > 0)
                        g_init_threads = it;
                    build_memory(line, mode);
                }
            } else if (strncmp(line, "SELFTEST", 8) == 0) {
                do_selftest();
            } else if (strncmp(line, "START", 5) == 0 && (line[5] == ' ' || line[5] == 0)) {
                do_start(line);
                double now = now_ms();
                for (int t = 0; t < g_nthreads; ++t) {
                    prev_seq[t] = 0;
                    last_stall_report[t] = 0;
                }
                last_report = now;
            } else if (strncmp(line, "STOP", 4) == 0) {
                do_stop();
            } else if (strncmp(line, "STATS", 5) == 0) {
                do_stats();
            } else if (strncmp(line, "INFO", 4) == 0) {
                print_info();
            } else if (strncmp(line, "QUIT", 4) == 0) {
                do_stop();
                if (g_dataset)
                    randomx_release_dataset(g_dataset);
                if (g_cache)
                    randomx_release_cache(g_cache);
                g_dataset = NULL;
                g_cache = NULL;
                emit("BYE");
                said_bye = 1;
                break;
            } else {
                emit("ERR msg=unknown_command cmd=%s", line);
            }
        } else {
            /* nothing to read: pace the loop so periodic work (rate
               reports, stall watchdog) still runs on time */
            struct pollfd pfd = {.fd = 0, .events = POLLIN, .revents = 0};
            (void)poll(&pfd, 1, 200);
        }

        double now = now_ms();

        if (g_running && (now - last_report) >= (double)g_report_ms) {
            double dt = (now - last_report) / 1000.0;
            uint64_t total = 0;
            double total_hps = 0;
            for (int t = 0; t < g_nthreads; ++t) {
                uint64_t h = atomic_load(&g_workers[t].hashes);
                double hps = (h >= prev_seq[t]) ? (double)(h - prev_seq[t]) / dt : 0.0;
                total += h;
                total_hps += hps;
                emit("RATE tid=%d hps=%.3f hashes=%llu", t, hps, (unsigned long long)h);
                prev_seq[t] = h;
            }
            emit("TOTAL hps=%.3f hashes=%llu", total_hps, (unsigned long long)total);
            last_report = now;
        }

        /* stall watchdog -- a worker can deadlock if the JIT miscompiles on an
           exotic CPU; this tells the user instead of silently mining slower. */
        if (g_running && g_stall_secs > 0 && (now - last_tick) >= 1000.0) {
            last_tick = now;
            for (int t = 0; t < g_nthreads; ++t) {
                uint64_t sq = atomic_load(&g_workers[t].seq);
                uint64_t last = atomic_load(&g_workers[t].stall_ms);
                if (sq != last) {
                    atomic_store(&g_workers[t].stall_ms, sq);
                } else {
                    uint64_t stall = last_stall_report[t] + 1;
                    last_stall_report[t] = stall;
                    if (stall == (uint64_t)g_stall_secs)
                        emit("STALL tid=%d secs=%d "
                             "hint=heavy_cpu_load_or_jit_hugepage_issue",
                             t, g_stall_secs);
                }
            }
        }
    }

    if (!said_bye) {
        do_stop();
        if (g_dataset)
            randomx_release_dataset(g_dataset);
        if (g_cache)
            randomx_release_cache(g_cache);
        emit("BYE");
    }
    return 0;
}
