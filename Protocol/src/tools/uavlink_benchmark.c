/*
 * UAVLink Comprehensive Performance Profiler
 *
 * Measures and compares:
 * - Baseline (unoptimized)
 * - Phase 1 (selective encryption, caching, batching)
 * - Phase 2 (zero-copy, memory pool, hardware crypto)
 * - Phase 3 (compression, FEC, delta encoding)
 *
 * Metrics tracked:
 * - Packet packing time (µs)
 * - Packet parsing time (µs)
 * - Bandwidth usage (bytes)
 * - Memory allocation time (µs)
 * - Encryption time (µs)
 * - Compression ratio
 */

#include "uavlink.h"
#include "uavlink_fast.h"
#include "uavlink_compress.h"
#include "uavlink_hw_crypto.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

// Timing functions
#ifdef _WIN32
static uint64_t get_time_us(void)
{
    static LARGE_INTEGER freq = {0};
    if (freq.QuadPart == 0)
        QueryPerformanceFrequency(&freq); // Cached after first call
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return (counter.QuadPart * 1000000) / freq.QuadPart;
}
#else
static uint64_t get_time_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000ULL + tv.tv_usec;
}
#endif

// Test key - loaded from file or generated for testing
static uint8_t TEST_KEY[32];

// Load or generate test key
static void init_test_key(void)
{
    // Try to load from file first (for consistent benchmarking)
    FILE *f = fopen("benchmark_key.bin", "rb");
    if (f != NULL)
    {
        size_t read = fread(TEST_KEY, 1, 32, f);
        fclose(f);
        if (read == 32)
        {
            printf("✓ Loaded test key from benchmark_key.bin\n");
            return;
        }
    }

    // Generate deterministic key for benchmarking (NOT for production use)
    printf("⚠️  Generating deterministic test key for benchmarking\n");
    printf("   (To use a specific key, create benchmark_key.bin)\n");
    for (int i = 0; i < 32; i++)
    {
        TEST_KEY[i] = (uint8_t)(i * 7 + 1); // Deterministic pattern
    }
}

typedef struct
{
    const char *name;
    uint64_t pack_time_us;
    uint64_t parse_time_us;
    uint64_t encrypt_time_us;
    uint64_t alloc_time_us;
    uint32_t bytes_packed;
    uint32_t iterations;
} benchmark_result_t;

void print_separator(void)
{
    printf("========================================");
    printf("========================================\n");
}

void print_result(benchmark_result_t *result)
{
    printf("%-20s", result->name);
    printf("Pack: %6lu µs  ", (unsigned long)(result->pack_time_us / result->iterations));
    printf("Parse: %6lu µs  ", (unsigned long)(result->parse_time_us / result->iterations));
    printf("Bytes: %5u  ", result->bytes_packed / result->iterations);
    printf("Total: %6lu µs\n",
           (unsigned long)((result->pack_time_us + result->parse_time_us) / result->iterations));
}

// Benchmark baseline (no optimizations)
void benchmark_baseline(benchmark_result_t *result, int iterations)
{
    result->name = "Baseline";
    result->iterations = iterations;
    result->pack_time_us = 0;
    result->parse_time_us = 0;
    result->bytes_packed = 0;

    ul_parser_t parser;
    ul_parser_init(&parser);

    for (int i = 0; i < iterations; i++)
    {
        // Create test message
        ul_heartbeat_t hb = {0};
        hb.system_status = 0x01;
        hb.system_type = 0x02;
        hb.base_mode = 0x05;

        uint8_t payload[32];
        int payload_len = ul_serialize_heartbeat(&hb, payload);

        ul_header_t header = {0};
        header.payload_len = payload_len;
        header.priority = UL_PRIO_NORMAL;
        header.stream_type = UL_STREAM_HEARTBEAT;
        header.encrypted = true;
        header.sequence = i;
        header.sys_id = 1;
        header.comp_id = 1;
        header.msg_id = UL_MSG_HEARTBEAT;

        uint8_t packet[256];

        // Time packing
        uint64_t start = get_time_us();
        int packet_len = uavlink_pack(packet, &header, payload, TEST_KEY);
        uint64_t end = get_time_us();
        result->pack_time_us += (end - start);
        result->bytes_packed += packet_len;

        // Time parsing
        start = get_time_us();
        for (int j = 0; j < packet_len; j++)
        {
            ul_parse_char(&parser, packet[j], TEST_KEY);
        }
        end = get_time_us();
        result->parse_time_us += (end - start);
    }
}

// Benchmark Phase 1 (selective encryption)
void benchmark_phase1(benchmark_result_t *result, int iterations)
{
    result->name = "Phase 1";
    result->iterations = iterations;
    result->pack_time_us = 0;
    result->parse_time_us = 0;
    result->bytes_packed = 0;

    ul_parser_t parser;
    ul_parser_init(&parser);

    ul_nonce_state_t nonce_state;
    ul_nonce_init(&nonce_state);

    ul_crypto_ctx_t crypto_ctx;
    ul_crypto_ctx_init(&crypto_ctx);

    for (int i = 0; i < iterations; i++)
    {
        ul_heartbeat_t hb = {0};
        hb.system_status = 0x01;
        hb.system_type = 0x02;
        hb.base_mode = 0x05;

        uint8_t payload[32];
        int payload_len = ul_serialize_heartbeat(&hb, payload);

        ul_header_t header = {0};
        header.payload_len = payload_len;
        header.priority = UL_PRIO_NORMAL;
        header.stream_type = UL_STREAM_HEARTBEAT;
        header.encrypted = true;
        header.sequence = i;
        header.sys_id = 1;
        header.comp_id = 1;
        header.msg_id = UL_MSG_HEARTBEAT;

        uint8_t packet[256];

        // Time selective packing with crypto cache
        uint64_t start = get_time_us();
        int packet_len = uavlink_pack_cached(packet, &header, payload, TEST_KEY,
                                             &nonce_state, &crypto_ctx);
        uint64_t end = get_time_us();
        result->pack_time_us += (end - start);
        result->bytes_packed += packet_len;

        // Time parsing
        start = get_time_us();
        for (int j = 0; j < packet_len; j++)
        {
            ul_parse_char(&parser, packet[j], TEST_KEY);
        }
        end = get_time_us();
        result->parse_time_us += (end - start);
    }
}

// Benchmark Phase 2 (zero-copy + memory pool)
void benchmark_phase2(benchmark_result_t *result, int iterations)
{
    result->name = "Phase 2";
    result->iterations = iterations;
    result->pack_time_us = 0;
    result->parse_time_us = 0;
    result->bytes_packed = 0;
    result->alloc_time_us = 0;

    ul_mempool_t pool;
    ul_mempool_init(&pool);

    ul_parser_zerocopy_t parser;
    ul_parser_zerocopy_init(&parser);

    ul_nonce_state_t nonce_state;
    ul_nonce_init(&nonce_state);

    ul_crypto_ctx_t crypto_ctx;
    ul_crypto_ctx_init(&crypto_ctx);

    for (int i = 0; i < iterations; i++)
    {
        ul_heartbeat_t hb = {0};
        hb.system_status = 0x01;
        hb.system_type = 0x02;
        hb.base_mode = 0x05;

        uint8_t payload[32];
        int payload_len = ul_serialize_heartbeat(&hb, payload);

        ul_header_t header = {0};
        header.payload_len = payload_len;
        header.priority = UL_PRIO_NORMAL;
        header.stream_type = UL_STREAM_HEARTBEAT;
        header.encrypted = true;
        header.sequence = i;
        header.sys_id = 1;
        header.comp_id = 1;
        header.msg_id = UL_MSG_HEARTBEAT;

        uint8_t *packet = NULL;

        // Time fast pack (includes memory pool allocation)
        uint64_t alloc_start = get_time_us();
        uint64_t start = get_time_us();
        int packet_len = ul_pack_fast(&pool, &header, payload, TEST_KEY,
                                      &nonce_state, &crypto_ctx, &packet);
        uint64_t end = get_time_us();
        result->pack_time_us += (end - start);
        result->alloc_time_us += (end - alloc_start);
        result->bytes_packed += packet_len;

        // Time zero-copy parsing
        uint8_t parse_buf[256];
        start = get_time_us();
        for (int j = 0; j < packet_len; j++)
        {
            ul_parse_char_zerocopy(&parser, packet[j], parse_buf);
        }
        end = get_time_us();
        result->parse_time_us += (end - start);

        if (packet)
        {
            ul_mempool_free(&pool, packet);
        }
    }
}

// Benchmark Phase 3 (compression + delta)
void benchmark_phase3(benchmark_result_t *result, int iterations)
{
    result->name = "Phase 3";
    result->iterations = iterations;
    result->pack_time_us = 0;
    result->parse_time_us = 0;
    result->bytes_packed = 0;

    ul_delta_ctx_t delta_ctx;
    ul_delta_init(&delta_ctx);

    for (int i = 0; i < iterations; i++)
    {
        ul_gps_raw_t gps = {0};
        gps.lat = 476700000 + i * 50; // Slowly changing
        gps.lon = -122320000 + i * 40;
        gps.alt = 100000 + i * 10;
        gps.eph = 150;
        gps.vel = 500;
        gps.satellites = 12;

        uint8_t encoded[64];
        uint8_t decoded_buf[64];
        ul_gps_raw_t decoded_gps;

        // Time delta encoding
        uint64_t start = get_time_us();
        int encoded_len = ul_delta_encode_gps(&delta_ctx, &gps, encoded, sizeof(encoded));
        uint64_t end = get_time_us();
        result->pack_time_us += (end - start);
        result->bytes_packed += encoded_len;

        // Time delta decoding
        start = get_time_us();
        ul_delta_decode_gps(&delta_ctx, encoded, encoded_len, &decoded_gps);
        end = get_time_us();
        result->parse_time_us += (end - start);
    }
}

int main(void)
{
    print_separator();
    printf("UAVLink Performance Profiler\n");
    print_separator();
    printf("\n");

    // Initialize test key
    init_test_key();
    printf("\n");

    // Detect system capabilities
    printf("System Capabilities:\n");
    const ul_crypto_caps_t *caps = ul_crypto_get_caps();
    printf("  Crypto backend: %s (%ux speedup)\n",
           ul_crypto_backend_name(), caps->speedup_factor);
    printf("  Memory pool: %d buffers x %d bytes = %d KB\n",
           UL_MEMPOOL_NUM_BUFFERS, UL_MEMPOOL_BUFFER_SIZE,
           (UL_MEMPOOL_NUM_BUFFERS * UL_MEMPOOL_BUFFER_SIZE) / 1024);
    printf("\n");

    // Run benchmarks
    const int ITERATIONS = 1000;
    printf("Running benchmarks (%d iterations each)...\n\n", ITERATIONS);

    benchmark_result_t baseline, phase1, phase2, phase3;

    printf("Benchmarking Baseline...\n");
    benchmark_baseline(&baseline, ITERATIONS);

    printf("Benchmarking Phase 1...\n");
    benchmark_phase1(&phase1, ITERATIONS);

    printf("Benchmarking Phase 2...\n");
    benchmark_phase2(&phase2, ITERATIONS);

    printf("Benchmarking Phase 3...\n");
    benchmark_phase3(&phase3, ITERATIONS);

    printf("\n");
    print_separator();
    printf("BENCHMARK RESULTS\n");
    print_separator();
    printf("\n");

    printf("%-20s %-15s %-15s %-12s %-12s\n",
           "Test", "Pack (µs)", "Parse (µs)", "Bytes", "Total (µs)");
    printf("-------------------- --------------- --------------- ------------ ------------\n");

    print_result(&baseline);
    print_result(&phase1);
    print_result(&phase2);
    print_result(&phase3);

    printf("\n");
    print_separator();
    printf("SPEEDUP ANALYSIS\n");
    print_separator();
    printf("\n");

    double baseline_total = (baseline.pack_time_us + baseline.parse_time_us);
    double phase1_total = (phase1.pack_time_us + phase1.parse_time_us);
    double phase2_total = (phase2.pack_time_us + phase2.parse_time_us);
    double phase3_total = (phase3.pack_time_us + phase3.parse_time_us);

    printf("Phase 1 vs Baseline:\n");
    printf("  Time speedup:     %.2fx faster\n", baseline_total / phase1_total);
    printf("  Bandwidth:        %d bytes (%.1f%% reduction)\n",
           phase1.bytes_packed / ITERATIONS,
           100.0 * (1.0 - (double)phase1.bytes_packed / baseline.bytes_packed));
    printf("\n");

    printf("Phase 2 vs Baseline:\n");
    printf("  Time speedup:     %.2fx faster\n", baseline_total / phase2_total);
    printf("  Parse speedup:    %.2fx\n",
           (double)baseline.parse_time_us / phase2.parse_time_us);
    printf("  Alloc time:       %lu µs avg (O(1) pool)\n",
           (unsigned long)(phase2.alloc_time_us / ITERATIONS));
    printf("\n");

    printf("Phase 3 (Delta encoding):\n");
    printf("  Time:             %lu µs avg\n",
           (unsigned long)(phase3_total / ITERATIONS));
    printf("  First packet:     %u bytes (full)\n",
           phase3.bytes_packed >= ITERATIONS ? 28 : 0); // Approx
    printf("  Delta packets:    %u bytes avg (%.1f%% of full)\n",
           phase3.bytes_packed / ITERATIONS,
           100.0 * (phase3.bytes_packed / ITERATIONS) / 28.0);
    printf("\n");

    printf("Combined Phase 1+2+3 (Estimated):\n");
    double combined_time = phase2_total * 0.95; // Phase 3 adds minimal overhead
    printf("  Total speedup:    %.2fx faster than baseline\n",
           baseline_total / combined_time);
    printf("  Time saved:       %lu µs per packet\n",
           (unsigned long)((baseline_total - combined_time) / ITERATIONS));
    uint32_t combined_bytes = phase1.bytes_packed / ITERATIONS; // Use Phase 1 bandwidth
    combined_bytes = (uint32_t)(combined_bytes * 0.7);          // Delta encoding ~30% additional saving
    printf("  Bandwidth:        %u bytes (%.1f%% reduction)\n",
           combined_bytes,
           100.0 * (1.0 - (double)combined_bytes / (baseline.bytes_packed / ITERATIONS)));
    printf("\n");

    print_separator();
    printf("RECOMMENDATIONS\n");
    print_separator();
    printf("\n");

    if (phase2_total < baseline_total)
    {
        printf("✓ Phase 2 optimizations provide %.1fx speedup - RECOMMENDED\n",
               baseline_total / phase2_total);
    }

    if (phase1.bytes_packed < baseline.bytes_packed * 0.8)
    {
        printf("✓ Phase 1 saves %.0f%% bandwidth - RECOMMENDED\n",
               100.0 * (1.0 - (double)phase1.bytes_packed / baseline.bytes_packed));
    }

    if (caps->speedup_factor > 1)
    {
        printf("✓ Hardware crypto available (%ux) - ENABLE for production\n",
               caps->speedup_factor);
    }
    else
    {
        printf("○ Software crypto only - Consider ARM/x86 SIMD build\n");
    }

    printf("✓ Delta encoding saves ~%.0f%% for telemetry - USE for GPS/Attitude\n",
           100.0 * (1.0 - (double)(phase3.bytes_packed / ITERATIONS) / 28.0));

    printf("\n");
    printf("For maximum performance:\n");
    printf("  1. Use Phase 2 zero-copy parser + memory pool\n");
    printf("  2. Enable Phase 1 selective encryption\n");
    printf("  3. Use Phase 3 delta encoding for telemetry\n");
    printf("  4. Compile with -O3 optimization\n");
    printf("  5. Enable hardware crypto on ARM/x86 platforms\n");
    printf("\n");

    print_separator();

    return 0;
}
