/* rx_test.c -- self-test / sanity check for the RandomX build used by
 * xmr-fileminer. Runs the official RandomX test vector in light mode (and
 * full 2 GB dataset mode with `full`/`both`), measures per-hash time, and
 * exits non-zero if anything fails.
 *
 * Usage:  bin/rx_test [light|full|both]     (default: light)
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "randomx.h"
#include "rx_vector.h"

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static int g_fail = 0;

static void report(const char *mode, const char *what, int ok, const char *extra)
{
    printf("[%-5s] %-34s %s%s%s\n", mode, what, ok ? "PASS" : "FAIL",
           extra ? "  " : "", extra ? extra : "");
    if (!ok)
        g_fail = 1;
}

/* --- parallel dataset init for the test --------------------------------- */
static randomx_dataset *g_ds;
static randomx_cache   *g_cache;

typedef struct { unsigned long start, count; } range_t;

static void *init_worker(void *arg)
{
    range_t *r = (range_t *)arg;
    const unsigned long chunk = 131072;
    unsigned long off = 0;
    while (off < r->count) {
        unsigned long n = r->count - off;
        if (n > chunk) n = chunk;
        randomx_init_dataset(g_ds, g_cache, r->start + off, n);
        off += n;
    }
    return NULL;
}

static int test_mode(int full, int hp, int threads)
{
    const char *mode = full ? "full" : "light";
    randomx_flags flags = randomx_get_flags();
    if (hp)
        flags = (randomx_flags)(flags | RANDOMX_FLAG_LARGE_PAGES);

    randomx_cache *cache = randomx_alloc_cache(flags);
    if (!cache && hp) {
        hp = 0;
        flags = randomx_get_flags();
        cache = randomx_alloc_cache(flags);
    }
    if (!cache) {
        report(mode, "allocate cache", 0, "randomx_alloc_cache returned NULL");
        return -1;
    }
    double t0 = now_ms();
    randomx_init_cache(cache, RX_TEST_KEY, RX_TEST_KEY_LEN);
    double cache_ms = now_ms() - t0;
    {
        char extra[96];
        snprintf(extra, sizeof(extra), "%.0f ms%s", cache_ms, hp ? " (huge pages)" : "");
        report(mode, "cache init (512 MB)", 1, extra);
    }

    randomx_dataset *ds = NULL;
    double ds_ms = 0;
    unsigned long items = 0;
    if (full) {
        ds = randomx_alloc_dataset((randomx_flags)(flags | RANDOMX_FLAG_FULL_MEM));
        if (!ds) {
            report(mode, "allocate dataset (2080 MB)", 0,
                   "no memory? need ~2.7 GB free, or run: sudo sysctl vm.nr_hugepages=1300");
            randomx_release_cache(cache);
            return -1;
        }
        items = randomx_dataset_item_count();
        g_ds = ds;
        g_cache = cache;
        int nt = threads > 0 ? threads : 4;
        if (nt > 16) nt = 16;
        pthread_t th[16];
        range_t r[16];
        unsigned long per = items / (unsigned long)nt;
        t0 = now_ms();
        for (int i = 0; i < nt; ++i) {
            r[i].start = (unsigned long)i * per;
            r[i].count = (i == nt - 1) ? items - r[i].start : per;
            if (pthread_create(&th[i], NULL, init_worker, &r[i]) != 0) {
                report(mode, "dataset init threads", 0, "pthread_create failed");
                randomx_release_dataset(ds);
                randomx_release_cache(cache);
                return -1;
            }
        }
        for (int i = 0; i < nt; ++i)
            pthread_join(th[i], NULL);
        ds_ms = now_ms() - t0;
        char extra[128];
        snprintf(extra, sizeof(extra), "%.1f s for %lu MB on %d threads",
                 ds_ms / 1000.0, items * 8 / (1024 * 1024), nt);
        report(mode, "dataset init", 1, extra);
    }

    randomx_vm *vm = full
        ? randomx_create_vm((randomx_flags)(flags | RANDOMX_FLAG_FULL_MEM), NULL, ds)
        : randomx_create_vm((randomx_flags)(flags & ~RANDOMX_FLAG_FULL_MEM), cache, NULL);
    if (!vm) {
        report(mode, "create VM", 0, "randomx_create_vm returned NULL");
        if (ds) randomx_release_dataset(ds);
        randomx_release_cache(cache);
        return -1;
    }

    char got[65] = {0};
    t0 = now_ms();
    int rc = rx_selftest(vm, got, sizeof(got));
    double hash_ms = now_ms() - t0;
    {
        char extra[160];
        snprintf(extra, sizeof(extra), "hash=%s (%.0f ms/hash)", got, hash_ms);
        report(mode, "official RandomX test vector", rc == 1, extra);
        if (rc == 0)
            printf("        expected %s\n", RX_TEST_EXPECTED);
    }

    /* two more hashes for a marginally better timing */
    double t1 = now_ms();
    for (int i = 0; i < 3; ++i)
        rx_selftest(vm, NULL, 0);
    double per_hash = (now_ms() - t1) / 3.0;
    {
        char extra[96];
        snprintf(extra, sizeof(extra), "%.0f ms per hash => ~%.2f H/s per thread",
                 per_hash, 1000.0 / per_hash);
        report(mode, "timing", 1, extra);
    }

    randomx_destroy_vm(vm);
    if (ds) randomx_release_dataset(ds);
    randomx_release_cache(cache);
    return rc == 1 ? 0 : -1;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "light";
    int hp = (argc > 2 && strcmp(argv[2], "nohp") == 0) ? 0 : 1;
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    int threads = cores > 0 ? (int)cores : 4;

    printf("RandomX %s  flags=0x%x  jit=%d  hard_aes=%d  cores=%ld\n",
           RANDOMX_VERSION, (unsigned)randomx_get_flags(),
           !!(randomx_get_flags() & RANDOMX_FLAG_JIT),
           !!(randomx_get_flags() & RANDOMX_FLAG_HARD_AES), cores);

    if (strcmp(mode, "light") == 0 || strcmp(mode, "both") == 0)
        test_mode(0, hp, threads);
    if (strcmp(mode, "full") == 0 || strcmp(mode, "both") == 0)
        test_mode(1, hp, threads);

    printf("%s\n", g_fail ? "SELFTEST RESULT: FAIL" : "SELFTEST RESULT: PASS");
    return g_fail;
}
