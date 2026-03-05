/*
 * UAVLink Hardware Crypto Acceleration - Implementation
 *
 * ARM NEON and x86 SIMD optimized ChaCha20
 */

#include "uavlink_hw_crypto.h"
#include "monocypher.h"
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

/* Global flag for hardware crypto enable/disable */
static bool g_hw_crypto_enabled = false;

/* =============================================================================
 * ARM NEON ChaCha20 Implementation
 * ============================================================================= */

#if UL_HW_NEON_AVAILABLE

void ul_chacha20_neon(const uint8_t key[32], const uint8_t nonce[8],
                      const uint8_t *input, uint8_t *output, size_t len,
                      uint32_t initial_counter)
{
    // ChaCha20 state initialization
    uint32_t state[16];

    // Constants "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key (8 words = 32 bytes)
    memcpy(&state[4], key, 32);

    // Counter starts at initial_counter (0 for Poly1305 key gen, 1 for encryption)
    state[12] = initial_counter;

    // Nonce (2 words = 8 bytes)
    memcpy(&state[13], nonce, 8);
    state[15] = 0; // High 32 bits of nonce

    // Process blocks using NEON
    size_t blocks = len / 64;
    size_t remaining = len % 64;

    for (size_t i = 0; i < blocks; i++)
    {
        // Load state into NEON registers (4x uint32x4_t vectors)
        uint32x4_t v0 = vld1q_u32(&state[0]);
        uint32x4_t v1 = vld1q_u32(&state[4]);
        uint32x4_t v2 = vld1q_u32(&state[8]);
        uint32x4_t v3 = vld1q_u32(&state[12]);

        // Save initial state
        uint32x4_t s0 = v0, s1 = v1, s2 = v2, s3 = v3;

        // 20 rounds (10 double rounds)
        for (int round = 0; round < 10; round++)
        {
            // Column rounds
            chacha20_qr_neon(&v0, &v1, &v2, &v3);

            // Diagonal rounds (rotate lanes)
            v1 = vextq_u32(v1, v1, 1); // [b1,b2,b3,b0]
            v2 = vextq_u32(v2, v2, 2); // [c2,c3,c0,c1]
            v3 = vextq_u32(v3, v3, 3); // [d3,d0,d1,d2]

            chacha20_qr_neon(&v0, &v1, &v2, &v3);

            // Rotate back
            v1 = vextq_u32(v1, v1, 3);
            v2 = vextq_u32(v2, v2, 2);
            v3 = vextq_u32(v3, v3, 1);
        }

        // Add initial state
        v0 = vaddq_u32(v0, s0);
        v1 = vaddq_u32(v1, s1);
        v2 = vaddq_u32(v2, s2);
        v3 = vaddq_u32(v3, s3);

        // XOR with input and store to output
        uint32_t keystream[16];
        vst1q_u32(&keystream[0], v0);
        vst1q_u32(&keystream[4], v1);
        vst1q_u32(&keystream[8], v2);
        vst1q_u32(&keystream[12], v3);

        for (int j = 0; j < 64; j++)
        {
            output[i * 64 + j] = input[i * 64 + j] ^ ((uint8_t *)keystream)[j];
        }

        // Increment counter
        state[12]++;
    }

    // Handle remaining bytes (less than 64)
    if (remaining > 0)
    {
        uint32x4_t v0 = vld1q_u32(&state[0]);
        uint32x4_t v1 = vld1q_u32(&state[4]);
        uint32x4_t v2 = vld1q_u32(&state[8]);
        uint32x4_t v3 = vld1q_u32(&state[12]);

        uint32x4_t s0 = v0, s1 = v1, s2 = v2, s3 = v3;

        for (int round = 0; round < 10; round++)
        {
            chacha20_qr_neon(&v0, &v1, &v2, &v3);
            v1 = vextq_u32(v1, v1, 1);
            v2 = vextq_u32(v2, v2, 2);
            v3 = vextq_u32(v3, v3, 3);
            chacha20_qr_neon(&v0, &v1, &v2, &v3);
            v1 = vextq_u32(v1, v1, 3);
            v2 = vextq_u32(v2, v2, 2);
            v3 = vextq_u32(v3, v3, 1);
        }

        v0 = vaddq_u32(v0, s0);
        v1 = vaddq_u32(v1, s1);
        v2 = vaddq_u32(v2, s2);
        v3 = vaddq_u32(v3, s3);

        uint32_t keystream[16];
        vst1q_u32(&keystream[0], v0);
        vst1q_u32(&keystream[4], v1);
        vst1q_u32(&keystream[8], v2);
        vst1q_u32(&keystream[12], v3);

        for (size_t j = 0; j < remaining; j++)
        {
            output[blocks * 64 + j] = input[blocks * 64 + j] ^ ((uint8_t *)keystream)[j];
        }
    }
}

void ul_chacha20_poly1305_encrypt_neon(const uint8_t key[32], const uint8_t nonce[8],
                                       const uint8_t *ad, size_t ad_len,
                                       const uint8_t *plaintext, size_t plaintext_len,
                                       uint8_t *ciphertext, uint8_t mac[16])
{
    // Use NEON-accelerated ChaCha20.
    // RFC 8439: encryption starts at counter=1 so it doesn't reuse the
    // keystream block used for Poly1305 key generation (counter=0).
    ul_chacha20_neon(key, nonce, plaintext, ciphertext, plaintext_len, 1);

    // Generate Poly1305 key: ChaCha20 block counter=0 with message nonce.
    // Only the first 32 bytes of the 64-byte block are used as the key.
    uint8_t poly_key[32] = {0};
    ul_chacha20_neon(key, nonce, poly_key, poly_key, 32);

    // Compute MAC using monocypher's Poly1305
    crypto_poly1305_ctx ctx;
    crypto_poly1305_init(&ctx, poly_key);
    crypto_poly1305_update(&ctx, ad, ad_len);
    crypto_poly1305_update(&ctx, ciphertext, plaintext_len);
    crypto_poly1305_final(&ctx, mac);
}

int ul_chacha20_poly1305_decrypt_neon(const uint8_t key[32], const uint8_t nonce[8],
                                      const uint8_t *ad, size_t ad_len,
                                      const uint8_t *ciphertext, size_t ciphertext_len,
                                      const uint8_t mac[16], uint8_t *plaintext)
{
    // Verify MAC first — generate Poly1305 key from counter=0 block.
    // Use counter=0 (not 1) to match the encryptor's key derivation step.
    uint8_t poly_key[32] = {0};
    ul_chacha20_neon(key, nonce, poly_key, poly_key, 32, 0);

    crypto_poly1305_ctx ctx;
    crypto_poly1305_init(&ctx, poly_key);
    crypto_poly1305_update(&ctx, ad, ad_len);
    crypto_poly1305_update(&ctx, ciphertext, ciphertext_len);

    uint8_t computed_mac[16];
    crypto_poly1305_final(&ctx, computed_mac);

    // Constant-time MAC comparison
    int mac_valid = crypto_verify16(mac, computed_mac);
    if (mac_valid != 0)
    {
        return -1; // MAC verification failed
    }

    // MAC valid — decrypt starting at counter=1 (matching the encryptor)
    ul_chacha20_neon(key, nonce, ciphertext, plaintext, ciphertext_len, 1);
    return 0;
}

#endif // UL_HW_NEON_AVAILABLE

/* =============================================================================
 * x86 SSE2 ChaCha20 Implementation (Stub)
 * ============================================================================= */

#if UL_HW_SSE2_AVAILABLE

void ul_chacha20_sse2(const uint8_t key[32], const uint8_t nonce[8],
                      const uint8_t *input, uint8_t *output, size_t len)
{
    // SSE2 implementation would go here
    // For now, fall back to monocypher
    crypto_chacha20_djb(output, input, len, key, nonce, 0);
}

#endif

/* =============================================================================
 * x86 AVX2 ChaCha20 Implementation (Stub)
 * ============================================================================= */

#if UL_HW_AVX2_AVAILABLE

void ul_chacha20_avx2(const uint8_t key[32], const uint8_t nonce[8],
                      const uint8_t *input, uint8_t *output, size_t len)
{
    // AVX2 implementation would go here (can process 8 blocks in parallel)
    // For now, fall back to monocypher
    crypto_chacha20_djb(output, input, len, key, nonce, 0);
}

#endif

/* =============================================================================
 * Automatic Backend Selection
 * ============================================================================= */

void ul_chacha20_auto(const uint8_t key[32], const uint8_t nonce[8],
                      const uint8_t *input, uint8_t *output, size_t len)
{
    if (!g_hw_crypto_enabled)
    {
        // Hardware crypto disabled, use software
        crypto_chacha20_djb(output, input, len, key, nonce, 0);
        return;
    }

#if UL_HW_AVX2_AVAILABLE
    ul_chacha20_avx2(key, nonce, input, output, len);
#elif UL_HW_NEON_AVAILABLE
    ul_chacha20_neon(key, nonce, input, output, len);
#elif UL_HW_SSE2_AVAILABLE
    ul_chacha20_sse2(key, nonce, input, output, len);
#else
    // No hardware acceleration available
    crypto_chacha20_djb(output, input, len, key, nonce, 0);
#endif
}

const char *ul_crypto_backend_name(void)
{
    if (!g_hw_crypto_enabled)
    {
        return "Software (monocypher)";
    }

#if UL_HW_AVX2_AVAILABLE
    return "x86 AVX2 SIMD";
#elif UL_HW_NEON_AVAILABLE
    return "ARM NEON SIMD";
#elif UL_HW_SSE2_AVAILABLE
    return "x86 SSE2 SIMD";
#else
    return "Software (monocypher)";
#endif
}

uint32_t ul_crypto_benchmark_1kb(void)
{
    uint8_t key[32] = {0};
    uint8_t nonce[8] = {0};
    uint8_t input[1024] = {0};
    uint8_t output[1024];

// Timing
#ifdef _WIN32
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    ul_chacha20_auto(key, nonce, input, output, 1024);

    QueryPerformanceCounter(&end);
    return (uint32_t)(((end.QuadPart - start.QuadPart) * 1000000) / freq.QuadPart);
#else
    struct timeval start, end;
    gettimeofday(&start, NULL);

    ul_chacha20_auto(key, nonce, input, output, 1024);

    gettimeofday(&end, NULL);
    return (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
#endif
}

/* =============================================================================
 * Integration Functions
 * ============================================================================= */

int ul_enable_hardware_crypto(void)
{
#if UL_HW_NEON_AVAILABLE || UL_HW_SSE2_AVAILABLE || UL_HW_AVX2_AVAILABLE
    g_hw_crypto_enabled = true;
    return 0;
#else
    // No hardware acceleration available
    g_hw_crypto_enabled = false;
    return -1;
#endif
}

void ul_disable_hardware_crypto(void)
{
    g_hw_crypto_enabled = false;
}

bool ul_is_hardware_crypto_enabled(void)
{
    return g_hw_crypto_enabled;
}
