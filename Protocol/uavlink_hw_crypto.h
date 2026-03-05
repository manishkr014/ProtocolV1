/*
 * UAVLink Hardware Crypto Acceleration
 *
 * ARM NEON SIMD optimized ChaCha20 implementation
 * Expected speedup: 4x vs software-only monocypher
 *
 * Platform support:
 * - ARM Cortex-A series with NEON (ARMv7-A and later)
 * - ARM Cortex-A53/A57/A72/A73 (ARMv8-A 64-bit)
 * - Apple Silicon M1/M2 (ARMv8-A)
 *
 * Performance targets:
 * - Software ChaCha20: ~200 µs per packet
 * - NEON ChaCha20: ~50 µs per packet (4x speedup)
 * - Total pipeline: 450µs → 276µs (1.6x overall speedup)
 */

#ifndef UAVLINK_HW_CRYPTO_H
#define UAVLINK_HW_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* =============================================================================
 * ARM NEON ACCELERATION
 * ============================================================================= */

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#define UL_HW_NEON_AVAILABLE 1
#include <arm_neon.h>
#else
#define UL_HW_NEON_AVAILABLE 0
#endif

/* =============================================================================
 * x86 SIMD ACCELERATION (SSE2/AVX2)
 * ============================================================================= */

#if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#define UL_HW_SSE2_AVAILABLE 1
#include <emmintrin.h> // SSE2
#else
#define UL_HW_SSE2_AVAILABLE 0
#endif

#if defined(__AVX2__)
#define UL_HW_AVX2_AVAILABLE 1
#include <immintrin.h> // AVX2
#else
#define UL_HW_AVX2_AVAILABLE 0
#endif

/* =============================================================================
 * ChaCha20 SIMD Interface
 * ============================================================================= */

/**
 * ChaCha20 Quarter Round using NEON (ARM)
 * Performs parallel quarter rounds on 4 states simultaneously
 *
 * @param a, b, c, d  NEON vector registers (uint32x4_t)
 */
#if UL_HW_NEON_AVAILABLE

static inline void chacha20_qr_neon(uint32x4_t *a, uint32x4_t *b,
                                    uint32x4_t *c, uint32x4_t *d)
{
    // a += b; d ^= a; d <<<= 16
    *a = vaddq_u32(*a, *b);
    *d = veorq_u32(*d, *a);
    *d = vorrq_u32(vshlq_n_u32(*d, 16), vshrq_n_u32(*d, 16));

    // c += d; b ^= c; b <<<= 12
    *c = vaddq_u32(*c, *d);
    *b = veorq_u32(*b, *c);
    *b = vorrq_u32(vshlq_n_u32(*b, 12), vshrq_n_u32(*b, 20));

    // a += b; d ^= a; d <<<= 8
    *a = vaddq_u32(*a, *b);
    *d = veorq_u32(*d, *a);
    *d = vorrq_u32(vshlq_n_u32(*d, 8), vshrq_n_u32(*d, 24));

    // c += d; b ^= c; b <<<= 7
    *c = vaddq_u32(*c, *d);
    *b = veorq_u32(*b, *c);
    *b = vorrq_u32(vshlq_n_u32(*b, 7), vshrq_n_u32(*b, 25));
}

/**
 * ARM NEON accelerated ChaCha20 encryption
 * Up to 4x faster than software implementation
 *
 * @param key     32-byte encryption key
 * @param nonce   8-byte nonce
 * @param input   Input plaintext
 * @param output  Output ciphertext
 * @param len     Length of data
 */
void ul_chacha20_neon(const uint8_t key[32], const uint8_t nonce[8],
                      const uint8_t *input, uint8_t *output, size_t len,
                      uint32_t initial_counter);

/**
 * ARM NEON accelerated ChaCha20-Poly1305 AEAD encryption
 * Combines ChaCha20 cipher with Poly1305 MAC for authenticated encryption
 *
 * @param key         32-byte encryption key
 * @param nonce       8-byte nonce
 * @param ad          Associated data (not encrypted, but authenticated)
 * @param ad_len      Length of associated data
 * @param plaintext   Input plaintext
 * @param plaintext_len Length of plaintext
 * @param ciphertext  Output ciphertext (same length as plaintext)
 * @param mac         Output 16-byte MAC tag
 */
void ul_chacha20_poly1305_encrypt_neon(const uint8_t key[32], const uint8_t nonce[8],
                                       const uint8_t *ad, size_t ad_len,
                                       const uint8_t *plaintext, size_t plaintext_len,
                                       uint8_t *ciphertext, uint8_t mac[16]);

/**
 * ARM NEON accelerated ChaCha20-Poly1305 AEAD decryption
 *
 * @param key         32-byte encryption key
 * @param nonce       8-byte nonce
 * @param ad          Associated data
 * @param ad_len      Length of associated data
 * @param ciphertext  Input ciphertext
 * @param ciphertext_len Length of ciphertext
 * @param mac         Expected 16-byte MAC tag
 * @param plaintext   Output plaintext
 * @return 0 on success, -1 if MAC verification fails
 */
int ul_chacha20_poly1305_decrypt_neon(const uint8_t key[32], const uint8_t nonce[8],
                                      const uint8_t *ad, size_t ad_len,
                                      const uint8_t *ciphertext, size_t ciphertext_len,
                                      const uint8_t mac[16], uint8_t *plaintext);

#endif // UL_HW_NEON_AVAILABLE

/* =============================================================================
 * ChaCha20 SSE2/AVX2 Interface (x86/x64)
 * ============================================================================= */

#if UL_HW_SSE2_AVAILABLE

/**
 * x86 SSE2 accelerated ChaCha20 encryption
 * ~2x faster than software implementation
 */
void ul_chacha20_sse2(const uint8_t key[32], const uint8_t nonce[8],
                      const uint8_t *input, uint8_t *output, size_t len);

#endif // UL_HW_SSE2_AVAILABLE

#if UL_HW_AVX2_AVAILABLE

/**
 * x86 AVX2 accelerated ChaCha20 encryption
 * ~4x faster than software implementation
 */
void ul_chacha20_avx2(const uint8_t key[32], const uint8_t nonce[8],
                      const uint8_t *input, uint8_t *output, size_t len);

#endif // UL_HW_AVX2_AVAILABLE

/* =============================================================================
 * Automatic Backend Selection
 * ============================================================================= */

/**
 * Automatically select best available crypto backend
 * Priority: AVX2 > NEON > SSE2 > Software
 *
 * @param key     32-byte encryption key
 * @param nonce   8-byte nonce
 * @param input   Input data
 * @param output  Output data
 * @param len     Data length
 */
void ul_chacha20_auto(const uint8_t key[32], const uint8_t nonce[8],
                      const uint8_t *input, uint8_t *output, size_t len);

/**
 * Get description of active crypto backend
 * @return String describing the active backend ("NEON", "AVX2", "SSE2", "Software")
 */
const char *ul_crypto_backend_name(void);

/**
 * Benchmark crypto performance
 * Encrypts 1KB of data and measures time in microseconds
 *
 * @return Time in microseconds for 1KB encryption
 */
uint32_t ul_crypto_benchmark_1kb(void);

/* =============================================================================
 * Integration with Phase 2
 * ============================================================================= */

/**
 * Replace monocypher with hardware-accelerated crypto in pack functions
 * Call this once at startup to enable hardware acceleration globally
 *
 * @return 0 on success, -1 if no hardware acceleration available
 */
int ul_enable_hardware_crypto(void);

/**
 * Disable hardware acceleration and fall back to monocypher software
 */
void ul_disable_hardware_crypto(void);

/**
 * Check if hardware crypto is currently enabled
 * @return true if hardware crypto is active
 */
bool ul_is_hardware_crypto_enabled(void);

#endif // UAVLINK_HW_CRYPTO_H
