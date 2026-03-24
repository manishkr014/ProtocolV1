/*
 * UAVLink Phase 3 Advanced Optimizations
 *
 * Features:
 * - LZ4 Payload Compression (50-70% reduction for repetitive data)
 * - Reed-Solomon Forward Error Correction (recover from packet loss)
 * - Delta Encoding for telemetry (encode only changes, not full values)
 *
 * Expected benefits:
 * - Bandwidth: Additional 30-50% savings on top of Phase 1 (total 75-85% reduction)
 * - Reliability: Recover 25% packet loss without retransmission
 * - Latency: Reduced data size = faster transmission on slow links
 */

#ifndef UAVLINK_COMPRESS_H
#define UAVLINK_COMPRESS_H

#include "uavlink.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* =============================================================================
 * LZ4 COMPRESSION
 * ============================================================================= */

/**
 * LZ4 compression context for streaming compression
 */
typedef struct
{
    uint32_t history_pos; // history buffer removed (was unused 64KB)
    bool initialized;
} ul_lz4_ctx_t;

/**
 * Initialize LZ4 compression context
 * @param ctx LZ4 context
 */
void ul_lz4_init(ul_lz4_ctx_t *ctx);

/**
 * Compress data using fast LZ4 algorithm
 * Optimized for speed over compression ratio
 *
 * @param input Input data
 * @param input_len Input length
 * @param output Output buffer (must be at least input_len + (input_len/255) + 16 bytes)
 * @param max_output Maximum output size
 * @return Compressed size, or negative on error
 */
int ul_lz4_compress(const uint8_t *input, size_t input_len,
                    uint8_t *output, size_t max_output);

/**
 * Decompress LZ4 data
 * @param input Compressed data
 * @param input_len Compressed length
 * @param output Output buffer
 * @param max_output Maximum output size
 * @return Decompressed size, or negative on error
 */
int ul_lz4_decompress(const uint8_t *input, size_t input_len,
                      uint8_t *output, size_t max_output);

/**
 * Check if data is worth compressing
 * Returns true if compression likely provides >10% reduction
 *
 * @param data Data to analyze
 * @param len Data length
 * @return true if compression recommended
 */
bool ul_should_compress(const uint8_t *data, size_t len);

/* =============================================================================
 * FORWARD ERROR CORRECTION (Reed-Solomon)
 * ============================================================================= */

/**
 * Reed-Solomon FEC parameters
 * - Data shards: Original data packets
 * - Parity shards: Redundancy packets for error correction
 * - Can recover from up to 'parity_shards' lost packets
 */
typedef struct
{
    uint8_t data_shards;   // Number of data packets (e.g., 4)
    uint8_t parity_shards; // Number of parity packets (e.g., 1 = recover 1 loss)
    uint8_t shard_size;    // Size of each shard (e.g., 255 bytes)
} ul_fec_params_t;

/**
 * FEC encoder state
 */
typedef struct
{
    ul_fec_params_t params;
    uint8_t *data_shards[16];   // Pointers to data packets
    uint8_t *parity_shards[16]; // Pointers to generated parity packets
    uint8_t shards_received;
    bool initialized;
} ul_fec_encoder_t;

/**
 * FEC decoder state for reassembly
 */
typedef struct
{
    ul_fec_params_t params;
    uint8_t *shards[32];    // Mixed data + parity shards
    bool shard_present[32]; // Which shards have been received
    uint8_t shards_received;
    bool initialized;
} ul_fec_decoder_t;

/**
 * Initialize FEC encoder
 * @param encoder FEC encoder
 * @param data_shards Number of data packets (max 16)
 * @param parity_shards Number of parity packets (max 16)
 */
void ul_fec_encoder_init(ul_fec_encoder_t *encoder,
                         uint8_t data_shards, uint8_t parity_shards);

/**
 * Encode data packets to generate parity packets
 * @param encoder FEC encoder
 * @param data Array of data packet pointers
 * @param packet_size Size of each packet
 * @param parity_output Output buffer for parity packets
 * @return 0 on success, negative on error
 */
int ul_fec_encode(ul_fec_encoder_t *encoder,
                  const uint8_t *data[], size_t packet_size,
                  uint8_t *parity_output[]);

/**
 * Initialize FEC decoder
 * @param decoder FEC decoder
 * @param data_shards Number of data packets
 * @param parity_shards Number of parity packets
 */
void ul_fec_decoder_init(ul_fec_decoder_t *decoder,
                         uint8_t data_shards, uint8_t parity_shards);

/**
 * Add received shard (data or parity) to decoder
 * @param decoder FEC decoder
 * @param shard_index Index of this shard (0 = first data, data_shards = first parity)
 * @param shard_data Shard data
 * @param shard_size Size of shard
 * @return 0 if more shards needed, 1 if ready to decode, negative on error
 */
int ul_fec_add_shard(ul_fec_decoder_t *decoder, uint8_t shard_index,
                     const uint8_t *shard_data, size_t shard_size);

/**
 * Decode and reconstruct missing shards
 * @param decoder FEC decoder
 * @param output Reconstructed data (all data shards concatenated)
 * @return Total reconstructed data size, or negative on error
 */
int ul_fec_decode(ul_fec_decoder_t *decoder, uint8_t *output);

/* =============================================================================
 * DELTA ENCODING
 * ============================================================================= */

/**
 * Delta encoder for telemetry data
 * Encodes only changes from previous values
 *
 * Example: GPS coordinates change slowly, so encode deltas instead of full values
 * - Before: lat=476700000, lat=476700050, lat=476700100 (36 bytes for 3 values)
 * - After:  lat=476700000, delta=+50, delta=+50 (12 bytes)
 * - Savings: 67% reduction
 */
typedef struct
{
    // Previous values for delta encoding
    ul_heartbeat_t prev_heartbeat;
    ul_attitude_t prev_attitude;
    ul_gps_raw_t prev_gps;
    ul_battery_t prev_battery;
    ul_rc_input_t prev_rc;

    bool has_previous; // First packet must send full values
    uint32_t packet_count;
} ul_delta_ctx_t;

/**
 * Initialize delta encoder
 * @param ctx Delta context
 */
void ul_delta_init(ul_delta_ctx_t *ctx);

/**
 * Encode GPS data as delta (only changed fields)
 * @param ctx Delta context
 * @param gps Current GPS data
 * @param output Output buffer for delta-encoded data
 * @param max_output Maximum output size
 * @return Encoded size, or negative on error
 */
int ul_delta_encode_gps(ul_delta_ctx_t *ctx, const ul_gps_raw_t *gps,
                        uint8_t *output, size_t max_output);

/**
 * Decode GPS delta data
 * @param ctx Delta context (contains previous values)
 * @param delta_data Delta-encoded input
 * @param delta_len Length of delta data
 * @param gps Output GPS structure (reconstructed)
 * @return 0 on success, negative on error
 */
int ul_delta_decode_gps(ul_delta_ctx_t *ctx, const uint8_t *delta_data,
                        size_t delta_len, ul_gps_raw_t *gps);

/**
 * Encode attitude as delta
 */
int ul_delta_encode_attitude(ul_delta_ctx_t *ctx, const ul_attitude_t *att,
                             uint8_t *output, size_t max_output);

/**
 * Decode attitude delta
 */
int ul_delta_decode_attitude(ul_delta_ctx_t *ctx, const uint8_t *delta_data,
                             size_t delta_len, ul_attitude_t *att);

/**
 * Encode battery as delta
 */
int ul_delta_encode_battery(ul_delta_ctx_t *ctx, const ul_battery_t *bat,
                            uint8_t *output, size_t max_output);

/**
 * Decode battery delta
 */
int ul_delta_decode_battery(ul_delta_ctx_t *ctx, const uint8_t *delta_data,
                            size_t delta_len, ul_battery_t *bat);

/* =============================================================================
 * INTEGRATED PHASE 3 API
 * ============================================================================= */

/**
 * Pack with all Phase 3 optimizations:
 * - LZ4 compression (if beneficial)
 * - Delta encoding (for telemetry)
 * - FEC parity generation (if enabled)
 * - Plus Phase 1 + 2 (selective encryption, zero-copy, memory pool)
 *
 * @param header Message header
 * @param payload Payload data
 * @param payload_len Payload length
 * @param delta_ctx Delta encoder (NULL to disable)
 * @param fec_encoder FEC encoder (NULL to disable)
 * @param output Output buffer
 * @param max_output Maximum output size
 * @return Packed size, or negative on error
 */
int ul_pack_phase3(const ul_header_t *header, const uint8_t *payload, size_t payload_len,
                   ul_delta_ctx_t *delta_ctx, ul_fec_encoder_t *fec_encoder,
                   uint8_t *output, size_t max_output);

/**
 * Parse with Phase 3 decompression and decoding
 * @param input Input packet
 * @param input_len Packet length
 * @param header Output header
 * @param payload Output payload buffer
 * @param max_payload Maximum payload size
 * @param delta_ctx Delta decoder (NULL to disable)
 * @param fec_decoder FEC decoder (NULL to disable)
 * @return Payload size, or negative on error
 */
int ul_parse_phase3(const uint8_t *input, size_t input_len,
                    ul_header_t *header, uint8_t *payload, size_t max_payload,
                    ul_delta_ctx_t *delta_ctx, ul_fec_decoder_t *fec_decoder);

/* =============================================================================
 * STATISTICS
 * ============================================================================= */

typedef struct
{
    uint32_t packets_compressed;
    uint32_t packets_uncompressed;
    uint32_t bytes_before_compression;
    uint32_t bytes_after_compression;
    uint32_t delta_encoded_packets;
    uint32_t delta_bytes_saved;
    uint32_t fec_parity_generated;
    uint32_t fec_packets_recovered;
} ul_phase3_stats_t;

/**
 * Get Phase 3 statistics
 * @param stats Output statistics structure
 */
void ul_phase3_get_stats(ul_phase3_stats_t *stats);

/**
 * Reset Phase 3 statistics
 */
void ul_phase3_reset_stats(void);

#endif // UAVLINK_COMPRESS_H
