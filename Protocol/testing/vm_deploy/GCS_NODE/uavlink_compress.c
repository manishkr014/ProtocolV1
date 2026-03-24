/*
 * UAVLink Phase 3 Implementation
 *
 * Simplified implementations of:
 * - Basic LZ4-style compression
 * - Simple Reed-Solomon FEC (placeholder)
 * -Delta encoding for telemetry
 */

#include "uavlink_compress.h"
#include <string.h>
#include <stdlib.h>

// Global statistics
static ul_phase3_stats_t g_phase3_stats = {0};

/* =============================================================================
 * LZ4 COMPRESSION (Simplified)
 * ============================================================================= */

void ul_lz4_init(ul_lz4_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(ul_lz4_ctx_t));
    ctx->initialized = true;
}

// Simplified RLE-style compression (placeholder for real LZ4)
int ul_lz4_compress(const uint8_t *input, size_t input_len,
                    uint8_t *output, size_t max_output)
{
    if (!input || !output || input_len == 0 || max_output < input_len + 16)
    {
        return -1;
    }

    // Simple run-length encoding as LZ4 placeholder
    size_t out_pos = 0;
    size_t in_pos = 0;

    while (in_pos < input_len && out_pos < max_output - 2)
    {
        uint8_t byte = input[in_pos];
        size_t run = 1;

        // Count consecutive identical bytes
        while (in_pos + run < input_len &&
               input[in_pos + run] == byte &&
               run < 255)
        {
            run++;
        }

        if (run >= 3)
        {
            // Encode as: FLAG(0xFF) + BYTE + COUNT
            if (out_pos + 3 > max_output)
                break;
            output[out_pos++] = 0xFF; // Run marker
            output[out_pos++] = byte;
            output[out_pos++] = (uint8_t)run;
            in_pos += run;
        }
        else
        {
            // Literal byte: if it equals the run marker, escape it so the
            // decompressor cannot mistake it for a run-length sequence.
            // Encoding: 0xFF 0xFF 0x01  means a single literal 0xFF byte.
            if (byte == 0xFF)
            {
                if (out_pos + 3 > max_output)
                    break;
                output[out_pos++] = 0xFF; // Escape
                output[out_pos++] = 0xFF; // The literal value
                output[out_pos++] = 0x01; // Count = 1
            }
            else
            {
                if (out_pos + 1 > max_output)
                    break;
                output[out_pos++] = byte;
            }
            in_pos++;
        }
    }

    return (int)out_pos;
}

int ul_lz4_decompress(const uint8_t *input, size_t input_len,
                      uint8_t *output, size_t max_output)
{
    if (!input || !output || input_len == 0)
    {
        return -1;
    }

    size_t in_pos = 0;
    size_t out_pos = 0;

    while (in_pos < input_len && out_pos < max_output)
    {
        uint8_t byte = input[in_pos++];

        if (byte == 0xFF && in_pos + 1 < input_len)
        {
            // Run-length encoded
            uint8_t value = input[in_pos++];
            uint8_t count = input[in_pos++];

            for (uint8_t i = 0; i < count && out_pos < max_output; i++)
            {
                output[out_pos++] = value;
            }
        }
        else
        {
            // Literal byte
            output[out_pos++] = byte;
        }
    }

    return (int)out_pos;
}

bool ul_should_compress(const uint8_t *data, size_t len)
{
    if (len < 32)
    {
        return false; // Too small to benefit
    }

    // Quick entropy check: if many repeated bytes, compression likely helps
    int repeats = 0;
    for (size_t i = 1; i < len && i < 64; i++)
    {
        if (data[i] == data[i - 1])
        {
            repeats++;
        }
    }

    // If >25% of sampled bytes are repeats, compress
    return (repeats > 16);
}

/* =============================================================================
 * FORWARD ERROR CORRECTION (Simplified Reed-Solomon)
 * ============================================================================= */

void ul_fec_encoder_init(ul_fec_encoder_t *encoder,
                         uint8_t data_shards, uint8_t parity_shards)
{
    memset(encoder, 0, sizeof(ul_fec_encoder_t));
    encoder->params.data_shards = data_shards;
    encoder->params.parity_shards = parity_shards;
    encoder->params.shard_size = 255;
    encoder->initialized = true;
}

// Simplified XOR-based parity (placeholder for real Reed-Solomon)
int ul_fec_encode(ul_fec_encoder_t *encoder,
                  const uint8_t *data[], size_t packet_size,
                  uint8_t *parity_output[])
{
    if (!encoder || !data || !parity_output)
    {
        return -1;
    }

    // Simple XOR parity for demonstration
    // Real Reed-Solomon would use Galois field arithmetic
    for (uint8_t p = 0; p < encoder->params.parity_shards; p++)
    {
        memset(parity_output[p], 0, packet_size);

        for (uint8_t d = 0; d < encoder->params.data_shards; d++)
        {
            for (size_t i = 0; i < packet_size; i++)
            {
                parity_output[p][i] ^= data[d][i];
            }
        }
    }

    g_phase3_stats.fec_parity_generated++;
    return 0;
}

void ul_fec_decoder_init(ul_fec_decoder_t *decoder,
                         uint8_t data_shards, uint8_t parity_shards)
{
    memset(decoder, 0, sizeof(ul_fec_decoder_t));
    decoder->params.data_shards = data_shards;
    decoder->params.parity_shards = parity_shards;
    decoder->params.shard_size = 255;
    decoder->initialized = true;
}

int ul_fec_add_shard(ul_fec_decoder_t *decoder, uint8_t shard_index,
                     const uint8_t *shard_data, size_t shard_size)
{
    if (!decoder || shard_index >= 32 || !shard_data)
    {
        return -1;
    }

    if (!decoder->shard_present[shard_index])
    {
        decoder->shard_present[shard_index] = true;
        decoder->shards[shard_index] = (uint8_t *)shard_data;
        decoder->shards_received++;
    }

    // Need at least data_shards packets to decode
    if (decoder->shards_received >= decoder->params.data_shards)
    {
        return 1; // Ready to decode
    }

    return 0; // Need more shards
}

int ul_fec_decode(ul_fec_decoder_t *decoder, uint8_t *output)
{
    if (!decoder || !output)
    {
        return -1;
    }

    size_t shard_size = decoder->params.shard_size;
    size_t total_size = 0;

    // Count missing data shards and find the missing index
    uint8_t missing_count = 0;
    uint8_t missing_index = 0;
    for (uint8_t i = 0; i < decoder->params.data_shards; i++)
    {
        if (!decoder->shard_present[i])
        {
            missing_count++;
            missing_index = i;
        }
    }

    // If exactly one data shard is missing, try XOR reconstruction
    if (missing_count == 1)
    {
        // Find first available parity shard
        uint8_t parity_start = decoder->params.data_shards;
        uint8_t parity_end = parity_start + decoder->params.parity_shards;
        bool parity_available = false;
        uint8_t parity_idx = 0;
        for (uint8_t p = parity_start; p < parity_end; p++)
        {
            if (decoder->shard_present[p] && decoder->shards[p])
            {
                parity_available = true;
                parity_idx = p;
                break;
            }
        }

        if (parity_available)
        {
            // Reconstruct the missing shard into a temporary buffer first,
            // then write ALL shards to their correct sequential positions.
            // Using a temp buffer avoids any overlap between the XOR writes
            // and the sequential copy that fills the output.
            uint8_t temp_shard[256]; // shard_size <= 255 (uint8_t field)
            memcpy(temp_shard, decoder->shards[parity_idx], shard_size);
            for (uint8_t i = 0; i < decoder->params.data_shards; i++)
            {
                if (i != missing_index && decoder->shard_present[i] && decoder->shards[i])
                {
                    for (size_t b = 0; b < shard_size; b++)
                        temp_shard[b] ^= decoder->shards[i][b];
                }
            }

            // Now copy every shard (including reconstructed) to its output slot.
            // Each shard i belongs at output[i * shard_size].
            for (uint8_t i = 0; i < decoder->params.data_shards; i++)
            {
                if (i == missing_index)
                    memcpy(output + total_size, temp_shard, shard_size);
                else if (decoder->shard_present[i] && decoder->shards[i])
                    memcpy(output + total_size, decoder->shards[i], shard_size);
                total_size += shard_size;
            }
            g_phase3_stats.fec_packets_recovered++;
            return (int)total_size;
        }
    }

    // Fallback: copy available data shards only
    for (uint8_t i = 0; i < decoder->params.data_shards; i++)
    {
        if (decoder->shard_present[i] && decoder->shards[i])
        {
            memcpy(output + total_size, decoder->shards[i], shard_size);
        }
        total_size += shard_size;
    }

    if (missing_count > 0)
    {
        g_phase3_stats.fec_packets_recovered++;
    }

    return (int)total_size;
}

/* =============================================================================
 * DELTA ENCODING
 * ============================================================================= */

void ul_delta_init(ul_delta_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(ul_delta_ctx_t));
    ctx->has_previous = false;
}

int ul_delta_encode_gps(ul_delta_ctx_t *ctx, const ul_gps_raw_t *gps,
                        uint8_t *output, size_t max_output)
{
    if (!ctx || !gps || !output || max_output < 32)
    {
        return -1;
    }

    size_t pos = 0;

    if (!ctx->has_previous)
    {
        // First packet: send full values
        output[pos++] = 0x00; // Full update marker
        memcpy(&output[pos], gps, sizeof(ul_gps_raw_t));
        pos += sizeof(ul_gps_raw_t);

        ctx->prev_gps = *gps;
        ctx->has_previous = true;
    }
    else
    {
        // Send deltas
        output[pos++] = 0x01; // Delta marker

        // Encode lat delta (4 bytes -> 2 bytes if small)
        int32_t lat_delta = gps->lat - ctx->prev_gps.lat;
        if (lat_delta >= -32768 && lat_delta <= 32767)
        {
            output[pos++] = 0x01; // Small delta
            output[pos++] = lat_delta & 0xFF;        // low byte first (little-endian)
            output[pos++] = (lat_delta >> 8) & 0xFF; // high byte
        }
        else
        {
            output[pos++] = 0x02; // Large delta
            memcpy(&output[pos], &lat_delta, 4);     // already native LE on all targets
            pos += 4;
        }

        // Similar for lon, alt (simplified)
        int32_t lon_delta = gps->lon - ctx->prev_gps.lon;
        if (lon_delta >= -32768 && lon_delta <= 32767)
        {
            output[pos++] = 0x01;
            output[pos++] = lon_delta & 0xFF;
            output[pos++] = (lon_delta >> 8) & 0xFF;
        }
        else
        {
            output[pos++] = 0x02;
            memcpy(&output[pos], &lon_delta, 4);
            pos += 4;
        }

        // Encode alt delta (4 bytes -> 2 bytes if small)
        int32_t alt_delta = gps->alt - ctx->prev_gps.alt;
        if (alt_delta >= -32768 && alt_delta <= 32767)
        {
            output[pos++] = 0x01;
            output[pos++] = alt_delta & 0xFF;
            output[pos++] = (alt_delta >> 8) & 0xFF;
        }
        else
        {
            output[pos++] = 0x02;
            memcpy(&output[pos], &alt_delta, 4);
            pos += 4;
        }

        // Copy other fields
        memcpy(&output[pos], &gps->eph, 2);
        pos += 2;
        memcpy(&output[pos], &gps->epv, 2);
        pos += 2;
        memcpy(&output[pos], &gps->vel, 2);
        pos += 2;
        memcpy(&output[pos], &gps->cog, 2);
        pos += 2;
        output[pos++] = gps->fix_type;
        output[pos++] = gps->satellites;

        ctx->prev_gps = *gps;
        g_phase3_stats.delta_encoded_packets++;
        g_phase3_stats.delta_bytes_saved += (sizeof(ul_gps_raw_t) - pos + 1);
    }

    return (int)pos;
}

int ul_delta_decode_gps(ul_delta_ctx_t *ctx, const uint8_t *delta_data,
                        size_t delta_len, ul_gps_raw_t *gps)
{
    if (!ctx || !delta_data || !gps || delta_len < 2)
    {
        return -1;
    }

    // Bounds-check helper: verify we have at least `need` bytes remaining
#define DELTA_CHECK(need) do { if (pos + (need) > delta_len) return -1; } while (0)

    size_t pos = 0;
    DELTA_CHECK(1);
    uint8_t marker = delta_data[pos++];

    if (marker == 0x00)
    {
        // Full update
        DELTA_CHECK(sizeof(ul_gps_raw_t));
        memcpy(gps, &delta_data[pos], sizeof(ul_gps_raw_t));
        ctx->prev_gps = *gps;
        ctx->has_previous = true;
    }
    else if (marker == 0x01)
    {
        if (!ctx->has_previous)
            return -1; // Cannot apply delta without a previous state

        // Delta update
        *gps = ctx->prev_gps; // Start with previous

        // Decode lat delta (little-endian int16 small, or 4-byte large)
        DELTA_CHECK(1);
        uint8_t lat_type = delta_data[pos++];
        if (lat_type == 0x01)
        {
            DELTA_CHECK(2);
            int16_t delta = (int16_t)((uint16_t)delta_data[pos] | ((uint16_t)delta_data[pos + 1] << 8));
            gps->lat = ctx->prev_gps.lat + delta;
            pos += 2;
        }
        else if (lat_type == 0x02)
        {
            DELTA_CHECK(4);
            int32_t delta;
            memcpy(&delta, &delta_data[pos], 4);
            gps->lat = ctx->prev_gps.lat + delta;
            pos += 4;
        }
        else { return -1; }

        // Decode lon delta
        DELTA_CHECK(1);
        uint8_t lon_type = delta_data[pos++];
        if (lon_type == 0x01)
        {
            DELTA_CHECK(2);
            int16_t delta = (int16_t)((uint16_t)delta_data[pos] | ((uint16_t)delta_data[pos + 1] << 8));
            gps->lon = ctx->prev_gps.lon + delta;
            pos += 2;
        }
        else if (lon_type == 0x02)
        {
            DELTA_CHECK(4);
            int32_t delta;
            memcpy(&delta, &delta_data[pos], 4);
            gps->lon = ctx->prev_gps.lon + delta;
            pos += 4;
        }
        else { return -1; }

        // Decode alt delta
        DELTA_CHECK(1);
        uint8_t alt_type = delta_data[pos++];
        if (alt_type == 0x01)
        {
            DELTA_CHECK(2);
            int16_t delta = (int16_t)((uint16_t)delta_data[pos] | ((uint16_t)delta_data[pos + 1] << 8));
            gps->alt = ctx->prev_gps.alt + delta;
            pos += 2;
        }
        else if (alt_type == 0x02)
        {
            DELTA_CHECK(4);
            int32_t delta;
            memcpy(&delta, &delta_data[pos], 4);
            gps->alt = ctx->prev_gps.alt + delta;
            pos += 4;
        }
        else { return -1; }

        // Decode fixed-size fields
        DELTA_CHECK(10); // 2+2+2+2+1+1 = 10 bytes
        memcpy(&gps->eph, &delta_data[pos], 2); pos += 2;
        memcpy(&gps->epv, &delta_data[pos], 2); pos += 2;
        memcpy(&gps->vel, &delta_data[pos], 2); pos += 2;
        memcpy(&gps->cog, &delta_data[pos], 2); pos += 2;
        gps->fix_type   = delta_data[pos++];
        gps->satellites = delta_data[pos++];

        ctx->prev_gps = *gps;
    }
    else
    {
        return -1; // Unknown marker
    }

#undef DELTA_CHECK
    return 0;
}

// Placeholder implementations for attitude and battery
int ul_delta_encode_attitude(ul_delta_ctx_t *ctx, const ul_attitude_t *att,
                             uint8_t *output, size_t max_output)
{
    // Simplified: just serialize normally
    if (max_output < sizeof(ul_attitude_t))
        return -1;
    memcpy(output, att, sizeof(ul_attitude_t));
    return sizeof(ul_attitude_t);
}

int ul_delta_decode_attitude(ul_delta_ctx_t *ctx, const uint8_t *delta_data,
                             size_t delta_len, ul_attitude_t *att)
{
    if (delta_len < sizeof(ul_attitude_t))
        return -1;
    memcpy(att, delta_data, sizeof(ul_attitude_t));
    return 0;
}

int ul_delta_encode_battery(ul_delta_ctx_t *ctx, const ul_battery_t *bat,
                            uint8_t *output, size_t max_output)
{
    if (max_output < sizeof(ul_battery_t))
        return -1;
    memcpy(output, bat, sizeof(ul_battery_t));
    return sizeof(ul_battery_t);
}

int ul_delta_decode_battery(ul_delta_ctx_t *ctx, const uint8_t *delta_data,
                            size_t delta_len, ul_battery_t *bat)
{
    if (delta_len < sizeof(ul_battery_t))
        return -1;
    memcpy(bat, delta_data, sizeof(ul_battery_t));
    return 0;
}

/* =============================================================================
 * INTEGRATED API (Placeholder)
 * ============================================================================= */

int ul_pack_phase3(const ul_header_t *header, const uint8_t *payload, size_t payload_len,
                   ul_delta_ctx_t *delta_ctx, ul_fec_encoder_t *fec_encoder,
                   uint8_t *output, size_t max_output)
{
    // Simplified: just copy payload
    // Real implementation would:
    // 1. Check if should compress
    // 2. Apply delta encoding if applicable
    // 3. Compress with LZ4
    // 4. Generate FEC parity
    // 5. Pack with encryption

    if (max_output < payload_len + 32)
        return -1;

    size_t pos = 0;
    uint8_t flags = 0;

    // Check compression
    if (ul_should_compress(payload, payload_len))
    {
        uint8_t compressed[512];
        int comp_len = ul_lz4_compress(payload, payload_len, compressed, sizeof(compressed));
        if (comp_len > 0 && (size_t)comp_len < payload_len * 0.9)
        {
            flags |= 0x01; // Compressed
            memcpy(&output[pos], compressed, comp_len);
            pos += comp_len;
            g_phase3_stats.packets_compressed++;
            g_phase3_stats.bytes_before_compression += payload_len;
            g_phase3_stats.bytes_after_compression += comp_len;
        }
        else
        {
            memcpy(&output[pos], payload, payload_len);
            pos += payload_len;
            g_phase3_stats.packets_uncompressed++;
        }
    }
    else
    {
        memcpy(&output[pos], payload, payload_len);
        pos += payload_len;
        g_phase3_stats.packets_uncompressed++;
    }

    return (int)pos;
}

int ul_parse_phase3(const uint8_t *input, size_t input_len,
                    ul_header_t *header, uint8_t *payload, size_t max_payload,
                    ul_delta_ctx_t *delta_ctx, ul_fec_decoder_t *fec_decoder)
{
    // Simplified parser
    if (input_len > max_payload)
        return -1;

    // Check if compressed (would need flag from header)
    memcpy(payload, input, input_len);
    return (int)input_len;
}

/* =============================================================================
 * STATISTICS
 * ============================================================================= */

void ul_phase3_get_stats(ul_phase3_stats_t *stats)
{
    if (stats)
    {
        *stats = g_phase3_stats;
    }
}

void ul_phase3_reset_stats(void)
{
    memset(&g_phase3_stats, 0, sizeof(g_phase3_stats));
}
