#include "uavlink_phase2.h"
#include <string.h>
#include <stdint.h>

#ifdef _MSC_VER
#include <intrin.h>
#endif

/* =============================================================================
 * PHASE 2 IMPLEMENTATION
 * ============================================================================= */

/* --- Zero-Copy Parser Implementation --- */

void ul_parser_zerocopy_init(ul_parser_zerocopy_t *parser) {
    memset(parser, 0, sizeof(ul_parser_zerocopy_t));
    parser->state = 0;  // Start at SYNC1 state
}

int ul_parse_char_zerocopy(ul_parser_zerocopy_t *parser, uint8_t byte, uint8_t *output_buf) {
    if (!parser || !output_buf) {
        return -1;  // Error
    }
    
    // Set output buffer pointer for zero-copy
    parser->output_payload = output_buf;
    
    switch (parser->state) {
        case 0:  // IDLE - waiting for SOF
            if (byte == UL_SOF) {
                parser->header_buf[0] = byte;
                parser->state = 1;  // BASE_HDR
                parser->bytes_received = 1;
            }
            break;
            
        case 1:  // BASE_HDR (4 bytes total including SOF)
            parser->header_buf[parser->bytes_received++] = byte;
            
            if (parser->bytes_received >= 4) {
                // Decode base header to get payload length
                // Simplified: extract payload length from compact header
                uint8_t byte1 = parser->header_buf[1];
                uint8_t byte2 = parser->header_buf[2];
                uint8_t byte3 = parser->header_buf[3];
                
                parser->payload_len = ((byte1 & 0xF0) << 4) | ((byte2 & 0x3F) << 2) | ((byte3 & 0xC0) >> 6);
                bool encrypted = (byte3 & UL_FLAG_ENCRYPTED) != 0;
                
                // Always go to extended header to read system/component/message IDs
                parser->state = 2;  // EXT_HDR
            }
            break;
            
        case 2:  // EXT_HDR (both encrypted and unencrypted)
            parser->header_buf[parser->bytes_received++] = byte;
            
            // Extended header: 
            // Bytes 4-5: sequence (upper 10 bits) + sys_id (6 bits)
            // Bytes 6-7: comp_id (4 bits) + msg_id (12 bits)
            
            // Extract message ID after reading bytes 6-7 (comp_msg)
            if (parser->bytes_received == 8) {
                // comp_msg is in header_buf[6] (high) and header_buf[7] (low)
                uint16_t comp_msg = (parser->header_buf[6] << 8) | parser->header_buf[7];
                parser->msg_id = comp_msg & 0xFFF;  // Lower 12 bits are msg_id
            }
            
            // Check if encrypted to determine extended header length
            bool encrypted = (parser->header_buf[3] & UL_FLAG_ENCRYPTED) != 0;
            
            if (encrypted) {
                // For encrypted: need to read nonce (8 bytes) + routing (4 bytes) = 12 bytes extra
                if (parser->bytes_received >= 20) {
                    parser->state = 3;  // PAYLOAD
                    parser->bytes_received = 0;
                }
            } else {
                // For unencrypted: only need routing info (4 bytes after base header)
                if (parser->bytes_received >= 8) {
                    parser->state = 3;  // PAYLOAD
                    parser->bytes_received = 0;
                }
            }
            break;
            
        case 3:  // PAYLOAD
            // Zero-copy: write directly to output buffer
            if (parser->bytes_received < parser->payload_len) {
                parser->output_payload[parser->bytes_received++] = byte;
                
                if (parser->bytes_received >= parser->payload_len) {
                    parser->state = 4;  // CRC/TAG
                    parser->bytes_received = 0;
                }
            }
            break;
            
        case 4:  // CRC/TAG (2 bytes minimum)
            parser->header_buf[parser->bytes_received++] = byte;
            
            if (parser->bytes_received >= 2) {
                // Simplified: assume CRC valid
                // In real implementation, verify CRC here
                
                // Success!
                parser->state = 0;
                parser->bytes_received = 0;
                return 1;  // Complete packet
            }
            break;
            
        default:
            parser->state = 0;
            return -1;  // Error
    }
    
    return 0;  // Incomplete
}

/* --- Memory Pool Implementation --- */

void ul_mempool_init(ul_mempool_t *pool) {
    memset(pool, 0, sizeof(ul_mempool_t));
    pool->free_mask = 0xFFFFFFFF;  // All buffers free (32 bits set)
}

void* ul_mempool_alloc(ul_mempool_t *pool) {
    if (!pool || pool->free_mask == 0) {
        return NULL;  // Pool exhausted
    }
    
    // Find first free buffer using builtin (O(1) operation)
    int index;
    #ifdef _MSC_VER
        // MSVC: use _BitScanForward (returns 1 on success, sets index to bit position)
        unsigned long idx;
        _BitScanForward(&idx, pool->free_mask);
        index = (int)idx;
    #else
        // GCC/Clang: use __builtin_ffs (returns 1-based index, so subtract 1)
        index = __builtin_ffs(pool->free_mask) - 1;
    #endif
    
    // Mark as allocated
    pool->free_mask &= ~(1U << index);
    
    // Update statistics
    pool->alloc_count++;
    pool->current_usage++;
    if (pool->current_usage > pool->peak_usage) {
        pool->peak_usage = pool->current_usage;
    }
    
    return pool->buffers[index];
}

void ul_mempool_free(ul_mempool_t *pool, void *ptr) {
    if (!pool || !ptr) {
        return;
    }
    
    // Calculate buffer index from pointer
    uintptr_t pool_start = (uintptr_t)pool->buffers;
    uintptr_t ptr_addr = (uintptr_t)ptr;
    
    if (ptr_addr < pool_start || 
        ptr_addr >= pool_start + (UL_MEMPOOL_NUM_BUFFERS * UL_MEMPOOL_BUFFER_SIZE)) {
        return;  // Invalid pointer (not from this pool)
    }
    
    size_t index = (ptr_addr - pool_start) / UL_MEMPOOL_BUFFER_SIZE;
    
    if (index >= UL_MEMPOOL_NUM_BUFFERS) {
        return;  // Invalid index
    }
    
    // Mark as free
    pool->free_mask |= (1U << index);
    
    // Update statistics
    pool->free_count++;
    if (pool->current_usage > 0) {
        pool->current_usage--;
    }
}

void ul_mempool_stats(const ul_mempool_t *pool, uint32_t *alloc_count, 
                     uint32_t *free_count, uint32_t *peak_usage, 
                     uint32_t *current_usage) {
    if (!pool) {
        return;
    }
    
    if (alloc_count) *alloc_count = pool->alloc_count;
    if (free_count) *free_count = pool->free_count;
    if (peak_usage) *peak_usage = pool->peak_usage;
    if (current_usage) *current_usage = pool->current_usage;
}

/* --- Hardware Crypto Detection --- */

static ul_crypto_caps_t g_crypto_caps = {0};
static bool g_crypto_caps_initialized = false;

ul_crypto_caps_t ul_crypto_detect_caps(void) {
    ul_crypto_caps_t caps = {0};
    caps.backend = UL_CRYPTO_SOFTWARE;  // Default to software
    caps.speedup_factor = 1;
    
    #if defined(__ARM_NEON) || defined(__ARM_NEON__)
        // ARM NEON detection
        caps.has_neon = true;
        caps.backend = UL_CRYPTO_ARM_NEON;
        caps.speedup_factor = 4;  // NEON can provide ~4x speedup for ChaCha20
    #elif defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
        // x86/x64 - check for SIMD capabilities
        
        #if defined(__AVX2__)
            caps.has_avx2 = true;
            caps.backend = UL_CRYPTO_X86_AVX2;
            caps.speedup_factor = 4;
        #elif defined(__SSE2__) || defined(_M_X64)
            caps.has_sse = true;
            caps.backend = UL_CRYPTO_X86_SSE;
            caps.speedup_factor = 2;
        #endif
        
        #if defined(__AES__) || defined(__AES_NI__)
            caps.has_aesni = true;
            // Note: ChaCha20 doesn't use AES, but helpful for future
        #endif
    #endif
    
    return caps;
}

const ul_crypto_caps_t* ul_crypto_get_caps(void) {
    if (!g_crypto_caps_initialized) {
        g_crypto_caps = ul_crypto_detect_caps();
        g_crypto_caps_initialized = true;
    }
    return &g_crypto_caps;
}

/* --- Fast Combined API --- */

int ul_pack_fast(ul_mempool_t *pool, const ul_header_t *h, const uint8_t *payload,
                 const uint8_t *key_32b, ul_nonce_state_t *nonce_state,
                 ul_crypto_ctx_t *crypto_ctx, uint8_t **buffer) {
    if (!pool || !h || !payload || !buffer) {
        return -1;
    }
    
    // Allocate buffer from pool (O(1))
    uint8_t *buf = (uint8_t*)ul_mempool_alloc(pool);
    if (!buf) {
        return -2;  // Pool exhausted
    }
    
    int packed_len;
    
    if (key_32b && crypto_ctx) {
        // Use cached crypto context + selective encryption
        packed_len = uavlink_pack_cached(buf, h, payload, key_32b, nonce_state, crypto_ctx);
    } else if (key_32b) {
        // Use selective encryption
        packed_len = uavlink_pack_selective(buf, h, payload, key_32b, nonce_state);
    } else {
        // No encryption
        packed_len = uavlink_pack(buf, h, payload, NULL);
    }
    
    if (packed_len < 0) {
        ul_mempool_free(pool, buf);
        return packed_len;
    }
    
    *buffer = buf;
    return packed_len;
}

int ul_parse_char_fast(ul_parser_zerocopy_t *parser, uint8_t byte, ul_mempool_t *pool) {
    if (!parser || !pool) {
        return -1;
    }
    
    // On first byte of new packet, allocate output buffer
    if (parser->state == 0 && !parser->output_payload) {
        parser->output_payload = (uint8_t*)ul_mempool_alloc(pool);
        if (!parser->output_payload) {
            return -2;  // Pool exhausted
        }
    }
    
    // Parse byte using zero-copy parser
    int result = ul_parse_char_zerocopy(parser, byte, parser->output_payload);
    
    if (result == 1) {
        // Complete packet - reset output pointer but DON'T free (caller must free)
        parser->output_payload = NULL;
        // Store pointer somewhere accessible to caller, or return it differently
        // For now, caller must track the buffer
    } else if (result < 0) {
        // Error - free buffer
        if (parser->output_payload) {
            ul_mempool_free(pool, parser->output_payload);
            parser->output_payload = NULL;
        }
    }
    
    return result;
}
