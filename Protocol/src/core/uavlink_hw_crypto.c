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

// Alignment macro
#if defined(_MSC_VER)
#define UL_ALIGN(n) __declspec(align(n))
#else
#define UL_ALIGN(n) __attribute__((aligned(n)))
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
    // ChaCha20 state initialization - ensure 16-byte alignment for NEON
    UL_ALIGN(16) uint32_t state[16];

    // Constants "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key (8 words = 32 bytes)
    memcpy(&state[4], key, 32);

    // Counter starts at initial_counter (0 for Poly1305 key gen, 1 for encryption)
    state[12] = initial_counter;
    state[13] = 0; // High 32-bits of counter

    // Nonce (2 words = 8 bytes) matching DJB ChaCha20
    memcpy(&state[14], nonce, 8);

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
    ul_chacha20_neon(key, nonce, poly_key, poly_key, 32, 0); // Explicit counter=0

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

static inline void chacha20_qr_sse2(__m128i *a, __m128i *b, __m128i *c, __m128i *d)
{
    *a = _mm_add_epi32(*a, *b); *d = _mm_xor_si128(*d, *a); *d = _mm_xor_si128(_mm_slli_epi32(*d, 16), _mm_srli_epi32(*d, 16));
    *c = _mm_add_epi32(*c, *d); *b = _mm_xor_si128(*b, *c); *b = _mm_xor_si128(_mm_slli_epi32(*b, 12), _mm_srli_epi32(*b, 20));
    *a = _mm_add_epi32(*a, *b); *d = _mm_xor_si128(*d, *a); *d = _mm_xor_si128(_mm_slli_epi32(*d, 8), _mm_srli_epi32(*d, 24));
    *c = _mm_add_epi32(*c, *d); *b = _mm_xor_si128(*b, *c); *b = _mm_xor_si128(_mm_slli_epi32(*b, 7), _mm_srli_epi32(*b, 25));
}

void ul_chacha20_sse2(const uint8_t key[32], const uint8_t nonce[8],
                       const uint8_t *input, uint8_t *output, size_t len,
                       uint32_t initial_counter)
{
    UL_ALIGN(16) uint32_t state[16];
    state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
    memcpy(&state[4], key, 32);
    state[12] = initial_counter; state[13] = 0;
    memcpy(&state[14], nonce, 8);

    size_t blocks = len / 64;
    size_t remaining = len % 64;

    for (size_t i = 0; i < blocks; i++)
    {
        __m128i v0 = _mm_loadu_si128((__m128i*)&state[0]);
        __m128i v1 = _mm_loadu_si128((__m128i*)&state[4]);
        __m128i v2 = _mm_loadu_si128((__m128i*)&state[8]);
        __m128i v3 = _mm_loadu_si128((__m128i*)&state[12]);

        __m128i s0 = v0, s1 = v1, s2 = v2, s3 = v3;

        for (int round = 0; round < 10; round++)
        {
            chacha20_qr_sse2(&v0, &v1, &v2, &v3);
            v1 = _mm_shuffle_epi32(v1, _MM_SHUFFLE(0, 3, 2, 1));
            v2 = _mm_shuffle_epi32(v2, _MM_SHUFFLE(1, 0, 3, 2));
            v3 = _mm_shuffle_epi32(v3, _MM_SHUFFLE(2, 1, 0, 3));
            chacha20_qr_sse2(&v0, &v1, &v2, &v3);
            v1 = _mm_shuffle_epi32(v1, _MM_SHUFFLE(2, 1, 0, 3));
            v2 = _mm_shuffle_epi32(v2, _MM_SHUFFLE(1, 0, 3, 2));
            v3 = _mm_shuffle_epi32(v3, _MM_SHUFFLE(0, 3, 2, 1));
        }

        v0 = _mm_add_epi32(v0, s0);
        v1 = _mm_add_epi32(v1, s1);
        v2 = _mm_add_epi32(v2, s2);
        v3 = _mm_add_epi32(v3, s3);

        uint32_t keystream[16];
        _mm_storeu_si128((__m128i*)&keystream[0], v0);
        _mm_storeu_si128((__m128i*)&keystream[4], v1);
        _mm_storeu_si128((__m128i*)&keystream[8], v2);
        _mm_storeu_si128((__m128i*)&keystream[12], v3);

        for (int j = 0; j < 64; j++)
            output[i * 64 + j] = input[i * 64 + j] ^ ((uint8_t *)keystream)[j];

        state[12]++;
    }

    if (remaining > 0)
    {
        __m128i v0 = _mm_loadu_si128((__m128i*)&state[0]);
        __m128i v1 = _mm_loadu_si128((__m128i*)&state[4]);
        __m128i v2 = _mm_loadu_si128((__m128i*)&state[8]);
        __m128i v3 = _mm_loadu_si128((__m128i*)&state[12]);

        __m128i s0 = v0, s1 = v1, s2 = v2, s3 = v3;

        for (int round = 0; round < 10; round++)
        {
            chacha20_qr_sse2(&v0, &v1, &v2, &v3);
            v1 = _mm_shuffle_epi32(v1, _MM_SHUFFLE(0, 3, 2, 1));
            v2 = _mm_shuffle_epi32(v2, _MM_SHUFFLE(1, 0, 3, 2));
            v3 = _mm_shuffle_epi32(v3, _MM_SHUFFLE(2, 1, 0, 3));
            chacha20_qr_sse2(&v0, &v1, &v2, &v3);
            v1 = _mm_shuffle_epi32(v1, _MM_SHUFFLE(2, 1, 0, 3));
            v2 = _mm_shuffle_epi32(v2, _MM_SHUFFLE(1, 0, 3, 2));
            v3 = _mm_shuffle_epi32(v3, _MM_SHUFFLE(0, 3, 2, 1));
        }

        v0 = _mm_add_epi32(v0, s0);
        v1 = _mm_add_epi32(v1, s1);
        v2 = _mm_add_epi32(v2, s2);
        v3 = _mm_add_epi32(v3, s3);

        uint32_t keystream[16];
        _mm_storeu_si128((__m128i*)&keystream[0], v0);
        _mm_storeu_si128((__m128i*)&keystream[4], v1);
        _mm_storeu_si128((__m128i*)&keystream[8], v2);
        _mm_storeu_si128((__m128i*)&keystream[12], v3);

        for (size_t j = 0; j < remaining; j++)
            output[blocks * 64 + j] = input[blocks * 64 + j] ^ ((uint8_t *)keystream)[j];
    }
}

#endif

/* =============================================================================
 * x86 AVX2 ChaCha20 Implementation (Stub)
 * ============================================================================= */

#if UL_HW_AVX2_AVAILABLE

static inline void chacha20_qr_avx2(__m256i *a, __m256i *b, __m256i *c, __m256i *d)
{
    *a = _mm256_add_epi32(*a, *b); *d = _mm256_xor_si256(*d, *a); *d = _mm256_xor_si256(_mm256_slli_epi32(*d, 16), _mm256_srli_epi32(*d, 16));
    *c = _mm256_add_epi32(*c, *d); *b = _mm256_xor_si256(*b, *c); *b = _mm256_xor_si256(_mm256_slli_epi32(*b, 12), _mm256_srli_epi32(*b, 20));
    *a = _mm256_add_epi32(*a, *b); *d = _mm256_xor_si256(*d, *a); *d = _mm256_xor_si256(_mm256_slli_epi32(*d, 8), _mm256_srli_epi32(*d, 24));
    *c = _mm256_add_epi32(*c, *d); *b = _mm256_xor_si256(*b, *c); *b = _mm256_xor_si256(_mm256_slli_epi32(*b, 7), _mm256_srli_epi32(*b, 25));
}

void ul_chacha20_avx2(const uint8_t key[32], const uint8_t nonce[8],
                       const uint8_t *input, uint8_t *output, size_t len,
                       uint32_t initial_counter)
{
    UL_ALIGN(32) uint32_t state[16]; // AVX2 ideally needs 32-byte alignment
    state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
    memcpy(&state[4], key, 32);
    state[12] = initial_counter; state[13] = 0;
    memcpy(&state[14], nonce, 8);

    size_t blocks = len / 128; // 2 blocks per iteration
    size_t remaining = len % 128;

    __m256i add_counter = _mm256_set_epi32(0, 0, 0, 1, 0, 0, 0, 0);

    for (size_t i = 0; i < blocks; i++)
    {
        __m256i v0 = _mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i*)&state[0]));
        __m256i v1 = _mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i*)&state[4]));
        __m256i v2 = _mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i*)&state[8]));
        __m256i v3 = _mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i*)&state[12]));

        v3 = _mm256_add_epi32(v3, add_counter);

        __m256i s0 = v0, s1 = v1, s2 = v2, s3 = v3;

        for (int round = 0; round < 10; round++)
        {
            chacha20_qr_avx2(&v0, &v1, &v2, &v3);
            v1 = _mm256_shuffle_epi32(v1, _MM_SHUFFLE(0, 3, 2, 1));
            v2 = _mm256_shuffle_epi32(v2, _MM_SHUFFLE(1, 0, 3, 2));
            v3 = _mm256_shuffle_epi32(v3, _MM_SHUFFLE(2, 1, 0, 3));
            chacha20_qr_avx2(&v0, &v1, &v2, &v3);
            v1 = _mm256_shuffle_epi32(v1, _MM_SHUFFLE(2, 1, 0, 3));
            v2 = _mm256_shuffle_epi32(v2, _MM_SHUFFLE(1, 0, 3, 2));
            v3 = _mm256_shuffle_epi32(v3, _MM_SHUFFLE(0, 3, 2, 1));
        }

        v0 = _mm256_add_epi32(v0, s0);
        v1 = _mm256_add_epi32(v1, s1);
        v2 = _mm256_add_epi32(v2, s2);
        v3 = _mm256_add_epi32(v3, s3);

        uint32_t keystream[32];
        _mm_storeu_si128((__m128i*)&keystream[0], _mm256_extracti128_si256(v0, 0));
        _mm_storeu_si128((__m128i*)&keystream[4], _mm256_extracti128_si256(v1, 0));
        _mm_storeu_si128((__m128i*)&keystream[8], _mm256_extracti128_si256(v2, 0));
        _mm_storeu_si128((__m128i*)&keystream[12], _mm256_extracti128_si256(v3, 0));

        _mm_storeu_si128((__m128i*)&keystream[16], _mm256_extracti128_si256(v0, 1));
        _mm_storeu_si128((__m128i*)&keystream[20], _mm256_extracti128_si256(v1, 1));
        _mm_storeu_si128((__m128i*)&keystream[24], _mm256_extracti128_si256(v2, 1));
        _mm_storeu_si128((__m128i*)&keystream[28], _mm256_extracti128_si256(v3, 1));

        for (int j = 0; j < 128; j++)
            output[i * 128 + j] = input[i * 128 + j] ^ ((uint8_t *)keystream)[j];

        state[12] += 2;
    }

    if (remaining > 0)
    {
        __m256i v0 = _mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i*)&state[0]));
        __m256i v1 = _mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i*)&state[4]));
        __m256i v2 = _mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i*)&state[8]));
        __m256i v3 = _mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i*)&state[12]));

        v3 = _mm256_add_epi32(v3, add_counter);

        __m256i s0 = v0, s1 = v1, s2 = v2, s3 = v3;

        for (int round = 0; round < 10; round++)
        {
            chacha20_qr_avx2(&v0, &v1, &v2, &v3);
            v1 = _mm256_shuffle_epi32(v1, _MM_SHUFFLE(0, 3, 2, 1));
            v2 = _mm256_shuffle_epi32(v2, _MM_SHUFFLE(1, 0, 3, 2));
            v3 = _mm256_shuffle_epi32(v3, _MM_SHUFFLE(2, 1, 0, 3));
            chacha20_qr_avx2(&v0, &v1, &v2, &v3);
            v1 = _mm256_shuffle_epi32(v1, _MM_SHUFFLE(2, 1, 0, 3));
            v2 = _mm256_shuffle_epi32(v2, _MM_SHUFFLE(1, 0, 3, 2));
            v3 = _mm256_shuffle_epi32(v3, _MM_SHUFFLE(0, 3, 2, 1));
        }

        v0 = _mm256_add_epi32(v0, s0);
        v1 = _mm256_add_epi32(v1, s1);
        v2 = _mm256_add_epi32(v2, s2);
        v3 = _mm256_add_epi32(v3, s3);

        uint32_t keystream[32];
        _mm_storeu_si128((__m128i*)&keystream[0], _mm256_extracti128_si256(v0, 0));
        _mm_storeu_si128((__m128i*)&keystream[4], _mm256_extracti128_si256(v1, 0));
        _mm_storeu_si128((__m128i*)&keystream[8], _mm256_extracti128_si256(v2, 0));
        _mm_storeu_si128((__m128i*)&keystream[12], _mm256_extracti128_si256(v3, 0));

        _mm_storeu_si128((__m128i*)&keystream[16], _mm256_extracti128_si256(v0, 1));
        _mm_storeu_si128((__m128i*)&keystream[20], _mm256_extracti128_si256(v1, 1));
        _mm_storeu_si128((__m128i*)&keystream[24], _mm256_extracti128_si256(v2, 1));
        _mm_storeu_si128((__m128i*)&keystream[28], _mm256_extracti128_si256(v3, 1));

        for (size_t j = 0; j < remaining; j++)
            output[blocks * 128 + j] = input[blocks * 128 + j] ^ ((uint8_t *)keystream)[j];
    }
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
    ul_chacha20_avx2(key, nonce, input, output, len, 1);
#elif UL_HW_NEON_AVAILABLE
    ul_chacha20_neon(key, nonce, input, output, len, 1);
#elif UL_HW_SSE2_AVAILABLE
    ul_chacha20_sse2(key, nonce, input, output, len, 1);
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
