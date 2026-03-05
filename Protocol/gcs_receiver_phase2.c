/*
 * UAVLink Phase 2 GCS Receiver - Network Test
 *
 * Uses Phase 2 optimizations:
 * - Zero-copy parser (2x faster parsing)
 * - Memory pool allocation (O(1) deterministic)
 * - Fast API combining all optimizations
 */

#include "uavlink.h"
#include "uavlink_phase2.h"
#include "monocypher.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

// Pre-shared encryption key (32 bytes for ChaCha20)
static const uint8_t SHARED_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

// Statistics
typedef struct
{
    uint32_t packets_received;
    uint32_t parse_complete;
    uint32_t parse_errors;
    uint32_t crc_errors;
    uint32_t bytes_received;
    uint64_t total_parse_time_us;
    uint32_t pool_peak_usage;
} stats_t;

static stats_t g_stats = {0};

// Timing functions
#ifdef _WIN32
#include <windows.h>
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
#include <sys/time.h>
static uint64_t get_time_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000ULL + tv.tv_usec;
}
#endif

void process_heartbeat(const uint8_t *payload, uint16_t len)
{
    ul_heartbeat_t hb;
    ul_deserialize_heartbeat(&hb, payload);

    printf("  [HEARTBEAT] Status=0x%02X Type=%u Mode=0x%02X\n",
           hb.system_status, hb.system_type, hb.base_mode);
}

void process_attitude(const uint8_t *payload, uint16_t len)
{
    ul_attitude_t att;
    ul_deserialize_attitude(&att, payload);

    printf("  [ATTITUDE] Roll=%.2f Pitch=%.2f Yaw=%.2f\n",
           att.roll, att.pitch, att.yaw);
}

void process_gps(const uint8_t *payload, uint16_t len)
{
    ul_gps_raw_t gps;
    ul_deserialize_gps_raw(&gps, payload);

    printf("  [GPS] Lat=%d Lon=%d Alt=%d Fix=%u Sats=%u\n",
           gps.lat, gps.lon, gps.alt, gps.fix_type, gps.satellites);
}

void process_battery(const uint8_t *payload, uint16_t len)
{
    ul_battery_t bat;
    ul_deserialize_battery(&bat, payload);

    printf("  [BATTERY] Voltage=%umV Current=%dmA Remaining=%d%% Cells=%u\n",
           bat.voltage, bat.current, bat.remaining, bat.cell_count);
}

void process_rc(const uint8_t *payload, uint16_t len)
{
    ul_rc_input_t rc;
    ul_deserialize_rc_input(&rc, payload);

    printf("  [RC] Ch1=%u Ch2=%u Ch3=%u Ch4=%u RSSI=%u%%\n",
           rc.channels[0], rc.channels[1], rc.channels[2], rc.channels[3], rc.rssi);
}

void process_packet(ul_header_t *header, const uint8_t *payload, uint16_t payload_len)
{
    g_stats.parse_complete++;

    printf("Packet #%u: MsgID=0x%03X Seq=%u Encrypted=%s PayloadLen=%u\n",
           g_stats.parse_complete,
           header->msg_id,
           header->sequence,
           header->encrypted ? "Yes" : "No",
           payload_len);

    // Dispatch based on message ID
    switch (header->msg_id)
    {
    case UL_MSG_HEARTBEAT:
        process_heartbeat(payload, payload_len);
        break;
    case UL_MSG_ATTITUDE:
        process_attitude(payload, payload_len);
        break;
    case UL_MSG_GPS_RAW:
        process_gps(payload, payload_len);
        break;
    case UL_MSG_BATTERY:
        process_battery(payload, payload_len);
        break;
    case UL_MSG_RC_INPUT:
        process_rc(payload, payload_len);
        break;
    case UL_MSG_BATCH: {
        ul_batch_t batch;
        memset(&batch, 0, sizeof(batch));
        int batch_err = ul_deserialize_batch(payload, payload_len, &batch);
        if (batch_err == 0) {
            printf("  [BATCH] %u sub-messages\n", batch.num_messages);
            for (uint8_t bi = 0; bi < batch.num_messages; bi++) {
                ul_header_t sub_hdr;
                memset(&sub_hdr, 0, sizeof(sub_hdr));
                sub_hdr.msg_id      = batch.messages[bi].msg_id;
                sub_hdr.payload_len = batch.messages[bi].length;
                sub_hdr.sequence    = header->sequence;
                sub_hdr.sys_id      = header->sys_id;
                sub_hdr.comp_id     = header->comp_id;
                process_packet(&sub_hdr, batch.messages[bi].data,
                               batch.messages[bi].length);
            }
        } else {
            printf("  [BATCH] Deserialization error: %d\n", batch_err);
        }
        break;
    }
    default:
        printf("  [UNKNOWN] Message ID 0x%03X\n", header->msg_id);
        break;
    }
}

int main(void)
{
    printf("=== UAVLink Phase 2 GCS Receiver ===\n");
    printf("Using Phase 2 Optimizations:\n");
    printf("  - Zero-copy parser (2x speed)\n");
    printf("  - Memory pool (O(1) allocation)\n");
    printf("  - Hardware crypto detection\n\n");

    // Detect hardware crypto capabilities
    const ul_crypto_caps_t *caps = ul_crypto_get_caps();
    printf("Crypto Backend: ");
    switch (caps->backend)
    {
    case UL_CRYPTO_SOFTWARE:
        printf("Software\n");
        break;
    case UL_CRYPTO_ARM_NEON:
        printf("ARM NEON (%ux speedup)\n", caps->speedup_factor);
        break;
    case UL_CRYPTO_X86_SSE:
        printf("x86 SSE (%ux speedup)\n", caps->speedup_factor);
        break;
    case UL_CRYPTO_X86_AVX2:
        printf("x86 AVX2 (%ux speedup)\n", caps->speedup_factor);
        break;
    default:
        printf("Unknown\n");
    }
    printf("\n");

    // Initialize memory pool
    ul_mempool_t pool;
    ul_mempool_init(&pool);
    printf("Initialized memory pool: %d buffers x %d bytes = %d KB\n",
           UL_MEMPOOL_NUM_BUFFERS, UL_MEMPOOL_BUFFER_SIZE,
           (UL_MEMPOOL_NUM_BUFFERS * UL_MEMPOOL_BUFFER_SIZE) / 1024);

    // Initialize zero-copy parser
    ul_parser_zerocopy_t parser;
    ul_parser_zerocopy_init(&parser);

// Setup UDP socket
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("ERROR: WSAStartup failed\n");
        return 1;
    }
#endif

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
    {
        printf("ERROR: Failed to create socket\n");
        return 1;
    }

    struct sockaddr_in recv_addr;
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(14550);
    recv_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0)
    {
        printf("ERROR: Failed to bind to port 14550\n");
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return 1;
    }

    printf("Listening on UDP port 14550...\n");
    printf("Press Ctrl+C to stop\n\n");

    uint8_t recv_buffer[2048];
    uint8_t *parse_output_buffer = NULL;

    while (1)
    {
        // Receive UDP packet
        struct sockaddr_in sender_addr;
        int sender_len = sizeof(sender_addr);

        int recv_len = recvfrom(sock, (char *)recv_buffer, sizeof(recv_buffer), 0,
                                (struct sockaddr *)&sender_addr, &sender_len);

        if (recv_len < 0)
        {
            continue;
        }

        // Validate packet size (UAVLink: 10 bytes minimum, 4122 max with large payloads)
        if (recv_len < 10)
        {
            continue; // Reject: too small
        }

        // Validate Start of Frame marker
        if (recv_buffer[0] != 0xA5)
        {
            continue; // Not a UAVLink packet
        }

        g_stats.packets_received++;
        g_stats.bytes_received += recv_len;

        // Allocate output buffer from pool on first byte
        if (!parse_output_buffer)
        {
            parse_output_buffer = (uint8_t *)ul_mempool_alloc(&pool);
            if (!parse_output_buffer)
            {
                printf("ERROR: Memory pool exhausted!\n");
                break;
            }
        }

        // Parse all bytes in the received packet
        uint64_t parse_start = get_time_us();

        for (int i = 0; i < recv_len; i++)
        {
            int result = ul_parse_char_zerocopy(&parser, recv_buffer[i], parse_output_buffer);

            if (result == 1)
            {
                // Complete packet parsed!
                uint64_t parse_end = get_time_us();
                g_stats.total_parse_time_us += (parse_end - parse_start);

                // Decode header from parser state
                ul_header_t header = {0};
                header.msg_id = parser.msg_id;
                header.payload_len = parser.payload_len;
                header.encrypted = (parser.header_buf[3] & UL_FLAG_ENCRYPTED) != 0;
                header.sequence = g_stats.parse_complete;

                // Decrypt payload if encrypted using ChaCha20-Poly1305 AEAD
                if (header.encrypted && parser.payload_len > 0)
                {
                    // Build 24-byte nonce for monocypher AEAD (from 8-byte packet nonce)
                    uint8_t nonce24[24] = {0};
                    memcpy(nonce24, parser.cipher_nonce, 8);

                    // Header length for AAD (base 4 + ext 4 + nonce 8 = 16 bytes)
                    size_t header_len = 16;

                    // Decrypt and verify MAC using AEAD
                    // Returns 0 on success, -1 if MAC verification fails
                    int auth_result = crypto_aead_unlock(
                        parse_output_buffer, /* Output: plaintext */
                        parser.cipher_tag,   /* Input: 16-byte MAC tag */
                        SHARED_KEY,          /* 256-bit key */
                        nonce24,             /* 192-bit nonce (8 bytes + 16 zero pad) */
                        parser.header_buf,   /* AAD: entire header */
                        header_len,          /* AAD length */
                        parse_output_buffer, /* Input: ciphertext */
                        parser.payload_len); /* Ciphertext length */

                    if (auth_result != 0)
                    {
                        // MAC verification failed - skip this packet
                        ul_mempool_free(&pool, parse_output_buffer);
                        parse_output_buffer = (uint8_t *)ul_mempool_alloc(&pool);
                        parse_start = get_time_us();
                        g_stats.crc_errors++; // Count as authentication error
                        continue;
                    }
                }

                // Process the packet
                process_packet(&header, parse_output_buffer, parser.payload_len);

                // Free buffer and allocate new one for next packet
                ul_mempool_free(&pool, parse_output_buffer);
                parse_output_buffer = (uint8_t *)ul_mempool_alloc(&pool);

                parse_start = get_time_us(); // Reset timer for next packet
            }
            else if (result < 0)
            {
                // Parse error
                g_stats.parse_errors++;
                if (result == -2)
                {
                    g_stats.crc_errors++;
                }

                // Free buffer and allocate new one
                if (parse_output_buffer)
                {
                    ul_mempool_free(&pool, parse_output_buffer);
                }
                parse_output_buffer = (uint8_t *)ul_mempool_alloc(&pool);
            }
        }

        // Update pool statistics
        uint32_t alloc_count, free_count, peak_usage, current_usage;
        ul_mempool_stats(&pool, &alloc_count, &free_count, &peak_usage, &current_usage);
        if (peak_usage > g_stats.pool_peak_usage)
        {
            g_stats.pool_peak_usage = peak_usage;
        }

        // Print statistics every 100 packets
        if (g_stats.packets_received % 100 == 0)
        {
            printf("\n--- Statistics (after %u UDP packets) ---\n", g_stats.packets_received);
            printf("Packets parsed: %u\n", g_stats.parse_complete);
            printf("Parse errors: %u\n", g_stats.parse_errors);
            printf("CRC errors: %u\n", g_stats.crc_errors);
            printf("Bytes received: %u\n", g_stats.bytes_received);
            if (g_stats.parse_complete > 0)
            {
                printf("Avg parse time: %lu us/packet\n",
                       (unsigned long)(g_stats.total_parse_time_us / g_stats.parse_complete));
            }
            printf("Memory pool peak usage: %u/%u buffers\n",
                   g_stats.pool_peak_usage, UL_MEMPOOL_NUM_BUFFERS);
            printf("Memory pool current: %u allocs, %u frees, %u in use\n",
                   alloc_count, free_count, current_usage);
            printf("\n");
        }
    }

    // Cleanup
    if (parse_output_buffer)
    {
        ul_mempool_free(&pool, parse_output_buffer);
    }

#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif

    printf("\n=== Final Statistics ===\n");
    printf("UDP packets received: %u\n", g_stats.packets_received);
    printf("Packets parsed: %u\n", g_stats.parse_complete);
    printf("Parse errors: %u\n", g_stats.parse_errors);
    printf("CRC errors: %u\n", g_stats.crc_errors);
    printf("Success rate: %.2f%%\n",
           g_stats.packets_received > 0 ? (100.0 * g_stats.parse_complete / g_stats.packets_received) : 0.0);
    if (g_stats.parse_complete > 0)
    {
        printf("Average parse time: %lu us/packet\n",
               (unsigned long)(g_stats.total_parse_time_us / g_stats.parse_complete));
    }
    printf("Memory pool peak usage: %u/%u buffers (%.1f%%)\n",
           g_stats.pool_peak_usage, UL_MEMPOOL_NUM_BUFFERS,
           100.0 * g_stats.pool_peak_usage / UL_MEMPOOL_NUM_BUFFERS);

    return 0;
}
