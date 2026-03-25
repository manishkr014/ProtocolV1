#include "uavlink_fast.h"
#include "uavlink.h"
#include <string.h>
#include <stdint.h>

#ifdef _MSC_VER
#include <intrin.h>
#endif

/* =============================================================================
 * PHASE 2 IMPLEMENTATION
 * ============================================================================= */

/* --- Zero-Copy Parser Implementation --- */

void ul_parser_zerocopy_init(ul_parser_zerocopy_t *parser)
{
    memset(parser, 0, sizeof(ul_parser_zerocopy_t));
    parser->state = 0; // Start at SYNC1 state
}

uint8_t ul_get_link_quality(const ul_parser_zerocopy_t *p)
{
    if (!p)
        return 0;

    // Avoid divide-by-zero
    if (p->rx_count + p->error_count == 0)
        return 0;

    uint32_t total = p->rx_count + p->error_count;
    if (total == 0)
        return 0;

    // Use integer math to avoid float overhead
    return (uint8_t)((p->rx_count * 100) / total);
}

int ul_parse_char_zerocopy(ul_parser_zerocopy_t *parser, uint8_t byte, uint8_t *output_buf, size_t output_buf_size)
{
    if (!parser || !output_buf)
    {
        return -1; // Error
    }

    // Zero-copy: only set output buffer if not already set (prevents redundant writes)
    if (!parser->output_payload)
    {
        parser->output_payload = output_buf;
    }

    switch (parser->state)
    {
    case 0: // IDLE - waiting for SOF
        if (byte == UL_SOF)
        {
            parser->header_buf[0] = byte;
            parser->state = 1; // BASE_HDR
            parser->bytes_received = 1;
        }
        break;

    case 1: // BASE_HDR (4 bytes total including SOF)
        parser->header_buf[parser->bytes_received++] = byte;

        if (parser->bytes_received >= 4)
        {
            // Decode base header to get payload length
            // Simplified: extract payload length from compact header
            uint8_t byte1 = parser->header_buf[1];
            uint8_t byte2 = parser->header_buf[2];
            uint8_t byte3 = parser->header_buf[3];

            parser->payload_len = ((byte1 & 0xF0) << 4) | ((byte2 & 0x3F) << 2) | ((byte3 & 0xC0) >> 6);

            if (parser->payload_len > UL_MAX_PAYLOAD_SIZE)
            {
                parser->state = 0; // IDLE
                parser->error_count++;
                return -1;
            }

            // Extract stream_type now so EXT_HDR can detect CMD/CMD_ACK
            // stream_type = bits[3:2] from buf[1] low 2 bits, bits[1:0] from buf[2] high 2 bits
            parser->stream_type = ((byte1 & 0x3) << 2) | ((byte2 >> 6) & 0x3);

            // Always go to extended header to read system/component/message IDs
            parser->state = 2; // EXT_HDR
        }
        break;

    case 2: // EXT_HDR (both encrypted and unencrypted)
        parser->header_buf[parser->bytes_received++] = byte;

        // Extended header layout (bytes counted from start of header_buf):
        //   [0..3]  base header (4 bytes)
        //   [4..5]  seq_sys: sequence upper bits + sys_id
        //   [6..7]  comp_msg: comp_id + msg_id
        //   [8]     target_sys_id (CMD/CMD_ACK only)
        //   [8 or 9] nonce start (8 bytes, if encrypted)

        // Extract message ID after reading bytes 6-7 (comp_msg)
        if (parser->bytes_received == 8)
        {
            // comp_msg is in header_buf[6] (high) and header_buf[7] (low)
            uint16_t comp_msg = (parser->header_buf[6] << 8) | parser->header_buf[7];
            parser->msg_id = comp_msg & 0xFFF; // Lower 12 bits are msg_id
        }

        // Determine whether this is a CMD/CMD_ACK stream (has extra target_sys_id byte)
        bool is_cmd = (parser->stream_type == UL_STREAM_CMD ||
                       parser->stream_type == UL_STREAM_CMD_ACK);

        // Routing section ends at bytes_received == 8 (non-CMD) or 9 (CMD)
        uint16_t routing_end = is_cmd ? 9u : 8u;

        // Check if encrypted to determine total extended header length
        bool encrypted = (parser->header_buf[3] & UL_FLAG_ENCRYPTED) != 0;

        if (encrypted)
        {
            // Layout: routing (8 or 9 bytes) + nonce (8 bytes)
            // Total header_buf bytes = routing_end + 8
            uint16_t nonce_end = routing_end + 8u;

            if (parser->bytes_received == nonce_end)
            {
                // Extract nonce: 8 bytes immediately after routing section
                memcpy(parser->cipher_nonce, &parser->header_buf[routing_end], 8);
            }

            if (parser->bytes_received >= nonce_end)
            {
                parser->state = 3; // PAYLOAD
                parser->bytes_received = 0;
            }
        }
        else
        {
            // Unencrypted: header ends after routing section
            if (parser->bytes_received >= routing_end)
            {
                parser->state = 3; // PAYLOAD
                parser->bytes_received = 0;
            }
        }
        break;

    case 3: // PAYLOAD
        // Zero-copy: write directly to output buffer
        if (parser->bytes_received < parser->payload_len)
        {
            if (parser->bytes_received < output_buf_size)
            {
                parser->output_payload[parser->bytes_received] = byte;
            }
            else
            {
                parser->state = 0; // IDLE
                parser->error_count++;
                return -1;
            }
            parser->bytes_received++;

            if (parser->bytes_received >= parser->payload_len)
            {
                // Check if we need to read MAC tag for encrypted packets
                bool encrypted = (parser->header_buf[3] & UL_FLAG_ENCRYPTED) != 0;
                if (encrypted)
                {
                    parser->state = 5; // MAC_TAG (16 bytes for encrypted)
                }
                else
                {
                    parser->state = 4; // CRC (2 bytes for unencrypted)
                }
                parser->bytes_received = 0;
            }
        }
        break;

    case 5: // MAC_TAG (16 bytes for encrypted packets)
        parser->cipher_tag[parser->bytes_received++] = byte;

        if (parser->bytes_received >= 16)
        {
            parser->state = 4; // Now read CRC
            parser->bytes_received = 0;
        }
        break;

    case 4: // CRC (2 bytes)
        if (parser->bytes_received == 0)
            parser->crc_in = byte;
        else
            parser->crc_in |= ((uint16_t)byte << 8);

        parser->bytes_received++;

        if (parser->bytes_received >= 2)
        {
            // Verify CRC over header bytes 1..crc_header_len-1, payload, and MAC (if encrypted)
            bool crc_encrypted = (parser->header_buf[3] & UL_FLAG_ENCRYPTED) != 0;
            bool crc_cmd = (parser->stream_type == UL_STREAM_CMD ||
                            parser->stream_type == UL_STREAM_CMD_ACK);

            // header_buf index where header ends:
            //   base(4 bytes) + routing(4 bytes + 1 target_sys_id for CMD) + nonce(8 if encrypted)
            int routing_end = crc_cmd ? 9 : 8;
            int crc_header_len = crc_encrypted ? (routing_end + 8) : routing_end;

            ul_crc_init(&parser->crc_calc);

            // Hash header bytes (skip SOF at index 0)
            for (int i = 1; i < crc_header_len; i++)
                ul_crc_accumulate(parser->header_buf[i], &parser->crc_calc);

            // Hash payload (ciphertext for encrypted, plaintext for unencrypted)
            for (int i = 0; i < parser->payload_len; i++)
                ul_crc_accumulate(parser->output_payload[i], &parser->crc_calc);

            // For encrypted packets, also hash the 16-byte MAC tag
            if (crc_encrypted)
            {
                for (int i = 0; i < 16; i++)
                    ul_crc_accumulate(parser->cipher_tag[i], &parser->crc_calc);
            }

            ul_crc_accumulate(ul_get_crc_seed(parser->msg_id), &parser->crc_calc);

            if (parser->crc_in != parser->crc_calc)
            {
                ul_parser_zerocopy_init(parser);
                return UL_ERR_CRC;
            }

            // Success!
            parser->state = 0;
            parser->bytes_received = 0;
            return 1; // Complete packet
        }
        break;

    default:
        parser->state = 0;
        return -1; // Error
    }

    return 0; // Incomplete
}

/* --- Memory Pool Implementation --- */

void ul_mempool_init(ul_mempool_t *pool)
{
    memset(pool, 0, sizeof(ul_mempool_t));
    pool->free_mask = 0xFFFFFFFF; // All buffers free (32 bits set)
}

void *ul_mempool_alloc(ul_mempool_t *pool)
{
    if (!pool || pool->free_mask == 0)
    {
        return NULL; // Pool exhausted
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
    if (pool->current_usage > pool->peak_usage)
    {
        pool->peak_usage = pool->current_usage;
    }

    return pool->buffers[index];
}

void ul_mempool_free(ul_mempool_t *pool, void *ptr)
{
    if (!pool || !ptr)
    {
        return;
    }

    // Calculate buffer index from pointer
    uintptr_t pool_start = (uintptr_t)pool->buffers;
    uintptr_t ptr_addr = (uintptr_t)ptr;

    if (ptr_addr < pool_start ||
        ptr_addr >= pool_start + (UL_MEMPOOL_NUM_BUFFERS * UL_MEMPOOL_BUFFER_SIZE) ||
        ((ptr_addr - pool_start) % UL_MEMPOOL_BUFFER_SIZE) != 0)
    {
        return; // Invalid or misaligned pointer (not a buffer start)
    }

    size_t index = (ptr_addr - pool_start) / UL_MEMPOOL_BUFFER_SIZE;

    if (index >= UL_MEMPOOL_NUM_BUFFERS)
    {
        return; // Invalid index
    }

    // Mark as free
    pool->free_mask |= (1U << index);

    // Zero the released buffer: prevents decrypted plaintext / key material
    // from persisting in memory and being readable via a later allocation.
    memset(pool->buffers[index], 0, UL_MEMPOOL_BUFFER_SIZE);

    // Update statistics
    pool->free_count++;
    if (pool->current_usage > 0)
    {
        pool->current_usage--;
    }
}

void ul_mempool_stats(const ul_mempool_t *pool, uint32_t *alloc_count,
                      uint32_t *free_count, uint32_t *peak_usage,
                      uint32_t *current_usage)
{
    if (!pool)
    {
        return;
    }

    if (alloc_count)
        *alloc_count = pool->alloc_count;
    if (free_count)
        *free_count = pool->free_count;
    if (peak_usage)
        *peak_usage = pool->peak_usage;
    if (current_usage)
        *current_usage = pool->current_usage;
}

/* --- Hardware Crypto Detection --- */

static ul_crypto_caps_t g_crypto_caps = {0};
static bool g_crypto_caps_initialized = false;

ul_crypto_caps_t ul_crypto_detect_caps(void)
{
    ul_crypto_caps_t caps = {0};
    caps.backend = UL_CRYPTO_SOFTWARE; // Default to software
    caps.speedup_factor = 1;

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
    // ARM NEON - usually fixed at compile time for ARM targets
    caps.has_neon = true;
    caps.backend = UL_CRYPTO_ARM_NEON;
    caps.speedup_factor = 4;
#elif defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    // x86/x64 - Runtime SIMD detection
#if defined(_MSC_VER)
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    caps.has_sse = (cpuInfo[3] & (1 << 26)) != 0; // SSE2
    __cpuidex(cpuInfo, 7, 0);
    caps.has_avx2 = (cpuInfo[1] & (1 << 5)) != 0;
#elif defined(__GNUC__) || defined(__clang__)
    caps.has_avx2 = __builtin_cpu_supports("avx2");
    caps.has_sse = __builtin_cpu_supports("sse2");
#endif

    if (caps.has_avx2)
    {
        caps.backend = UL_CRYPTO_X86_AVX2;
        caps.speedup_factor = 4;
    }
    else if (caps.has_sse)
    {
        caps.backend = UL_CRYPTO_X86_SSE;
        caps.speedup_factor = 2;
    }
#endif

    return caps;
}

const ul_crypto_caps_t *ul_crypto_get_caps(void)
{
    if (!g_crypto_caps_initialized)
    {
        g_crypto_caps = ul_crypto_detect_caps();
        g_crypto_caps_initialized = true;
    }
    return &g_crypto_caps;
}

/* --- Fast Combined API --- */

int ul_pack_fast(ul_mempool_t *pool, const ul_header_t *h, const uint8_t *payload,
                 const uint8_t *key_32b, ul_nonce_state_t *nonce_state,
                 ul_crypto_ctx_t *crypto_ctx, uint8_t **buffer)
{
    if (!pool || !h || !payload || !buffer)
    {
        return -1;
    }

    // Allocate buffer from pool (O(1))
    uint8_t *buf = (uint8_t *)ul_mempool_alloc(pool);
    if (!buf)
    {
        return -2; // Pool exhausted
    }

    int packed_len;

    if (key_32b && crypto_ctx)
    {
        // Use cached crypto context + selective encryption
        packed_len = uavlink_pack_cached(buf, h, payload, key_32b, nonce_state, crypto_ctx);
    }
    else if (key_32b)
    {
        // Use selective encryption
        packed_len = uavlink_pack_selective(buf, h, payload, key_32b, nonce_state);
    }
    else
    {
        // No encryption
        packed_len = uavlink_pack(buf, h, payload, NULL);
    }

    if (packed_len < 0)
    {
        ul_mempool_free(pool, buf);
        return packed_len;
    }

    *buffer = buf;
    return packed_len;
}

int ul_parse_char_fast(ul_parser_zerocopy_t *parser, uint8_t byte, ul_mempool_t *pool)
{
    if (!parser || !pool)
    {
        return -1;
    }

    // On first byte of new packet, allocate output buffer.
    // If the caller never consumed last_payload from the previous packet, free it
    // now to prevent pool exhaustion — the data is lost, but the pool doesn't leak.
    if (parser->state == 0 && !parser->output_payload)
    {
        if (parser->last_payload)
        {
            ul_mempool_free(pool, parser->last_payload);
            parser->last_payload = NULL;
        }
        parser->output_payload = (uint8_t *)ul_mempool_alloc(pool);
        if (!parser->output_payload)
        {
            return -2; // Pool exhausted
        }
    }

    // Parse byte using zero-copy parser
    int result = ul_parse_char_zerocopy(parser, byte, parser->output_payload, UL_MEMPOOL_BUFFER_SIZE);

    if (result == 1)
    {
        // Complete packet — save completed buffer pointer for caller BEFORE clearing output_payload
        parser->last_payload = parser->output_payload;
        parser->output_payload = NULL; // Ready for next packet allocation
    }
    else if (result < 0)
    {
        // Error - free buffer
        if (parser->output_payload)
        {
            ul_mempool_free(pool, parser->output_payload);
            parser->output_payload = NULL;
        }
    }

    return result;
}

int ul_check_replay_window(ul_parser_zerocopy_t *p, uint16_t seq)
{
    if (!p)
        return UL_ERR_NULL_POINTER;

    if (p->replay_init)
    {
        int16_t diff = (int16_t)(seq - p->last_seq);
        // Handle 12-bit sequence wrap-around
        if (diff > 2047)
            diff -= 4096;
        else if (diff < -2048)
            diff += 4096;

        if (diff <= 0)
        {
            uint8_t offset = (uint8_t)(-diff);
            if (offset >= 32 || (p->replay_window & (1UL << offset)))
            {
                p->error_count++;
                return UL_ERR_CRC; // Replay detected
            }
            p->replay_window |= (1UL << offset);
        }
        else
        {
            uint8_t shift = (uint8_t)diff;
            p->replay_window = (shift >= 32) ? 0 : (p->replay_window << shift);
            p->replay_window |= 1UL;
            p->last_seq = seq;
        }
    }
    else
    {
        p->replay_init = 1;
        p->last_seq = seq;
        p->replay_window = 1UL;
    }
    return 0; // Success
}