/*
 * UAVLink Bidirectional UAV Simulator
 *
 * Sends telemetry on UDP port 14550 (UAV -> GCS)
 * Receives commands on UDP port 14551 (GCS -> UAV)
 * Sends command ACKs on UDP port 14550 (UAV -> GCS)
 */

#include "uavlink.h"
#include "uavlink_fast.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#define sleep(x) Sleep((x) * 1000)
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#endif

// Pre-shared encryption key (32 bytes for ChaCha20)
static const uint8_t SHARED_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

// Flight mode name lookup
static const char *mode_names[] = {
    "MANUAL", "STABILIZE", "ALT_HOLD", "LOITER",
    "AUTO", "RTL", "LAND"};

static const char *get_mode_name(uint8_t mode)
{
    if (mode <= UL_MODE_LAND)
        return mode_names[mode];
    return "UNKNOWN";
}

// --- Nonce Persistence (NVM) Helpers ---
static void save_nonce_state(const ul_nonce_state_t *state, const char *filename)
{
    FILE *f = fopen(filename, "wb");
    if (f)
    {
        uint32_t current_counter = ul_nonce_get_counter(state);
        fwrite(&current_counter, sizeof(uint32_t), 1, f);
        fclose(f);
    }
}

static void load_nonce_state(ul_nonce_state_t *state, const char *filename)
{
    ul_nonce_init(state);
    FILE *f = fopen(filename, "rb");
    if (f)
    {
        uint32_t saved_counter = 0;
        if (fread(&saved_counter, sizeof(uint32_t), 1, f) == 1)
        {
            // Jump by 10000 to prevent reuse if power was lost before a save
            saved_counter += 10000;
            ul_nonce_set_counter(state, saved_counter);
            printf("NVM: Loaded nonce counter %u from %s (with safety jump)\n", saved_counter, filename);
        }
        fclose(f);
    }
    else
    {
        printf("NVM: No saved nonce found (%s), starting fresh.\n", filename);
    }

    // Save immediately so the jumped value is committed to disk
    save_nonce_state(state, filename);
}

// UAV State
typedef struct
{
    // Attitude
    float roll, pitch, yaw;
    float roll_rate, pitch_rate, yaw_rate;

    // Position
    int32_t lat, lon, alt;

    // Battery
    uint16_t voltage;
    int16_t current;

    // Status
    bool armed;
    uint8_t flight_mode;
    uint16_t sequence;

    // Mission
    ul_mission_item_t mission[16];
    uint8_t mission_count;
} uav_state_t;

// Process a received command and return ACK
static ul_command_ack_t process_command(uav_state_t *state, const ul_command_t *cmd)
{
    ul_command_ack_t ack = {0};
    ack.command_id = cmd->command_id;

    switch (cmd->command_id)
    {
    case UL_CMD_ARM:
        if (!state->armed)
        {
            state->armed = true;
            ack.result = UL_ACK_OK;
            printf("  >>> ARMED! Motors enabled.\n");
        }
        else
        {
            ack.result = UL_ACK_REJECTED;
            printf("  >>> ARM rejected: already armed\n");
        }
        break;

    case UL_CMD_DISARM:
        if (state->armed)
        {
            state->armed = false;
            ack.result = UL_ACK_OK;
            printf("  >>> DISARMED. Motors disabled.\n");
        }
        else
        {
            ack.result = UL_ACK_REJECTED;
            printf("  >>> DISARM rejected: already disarmed\n");
        }
        break;

    case UL_CMD_TAKEOFF:
        if (state->armed)
        {
            uint16_t target_alt_cm = cmd->param1;
            printf("  >>> TAKEOFF to %u cm\n", target_alt_cm);
            state->alt = target_alt_cm * 10; // Convert cm to mm
            ack.result = UL_ACK_OK;
        }
        else
        {
            ack.result = UL_ACK_REJECTED;
            printf("  >>> TAKEOFF rejected: not armed\n");
        }
        break;

    case UL_CMD_LAND:
        if (state->armed)
        {
            printf("  >>> LANDING initiated\n");
            state->flight_mode = UL_MODE_LAND;
            ack.result = UL_ACK_OK;
        }
        else
        {
            ack.result = UL_ACK_REJECTED;
            printf("  >>> LAND rejected: not armed\n");
        }
        break;

    case UL_CMD_RTL:
        if (state->armed)
        {
            printf("  >>> RTL initiated\n");
            state->flight_mode = UL_MODE_RTL;
            ack.result = UL_ACK_OK;
        }
        else
        {
            ack.result = UL_ACK_REJECTED;
            printf("  >>> RTL rejected: not armed\n");
        }
        break;

    case UL_CMD_EMERGENCY:
        printf("  >>> !!! EMERGENCY STOP !!!\n");
        state->armed = false;
        state->flight_mode = UL_MODE_MANUAL;
        ack.result = UL_ACK_OK;
        break;

    default:
        ack.result = UL_ACK_UNSUPPORTED;
        printf("  >>> Unknown command 0x%04X\n", cmd->command_id);
        break;
    }

    return ack;
}

// Send an ACK packet back to GCS
static void send_ack(int sock, struct sockaddr_in *dest,
                     const ul_command_ack_t *ack, uav_state_t *state,
                     ul_mempool_t *pool, ul_nonce_state_t *nonce_state,
                     ul_crypto_ctx_t *crypto_ctx)
{
    uint8_t payload[32];
    int payload_len = ul_serialize_command_ack(ack, payload);

    ul_header_t header = {0};
    header.payload_len = payload_len;
    header.priority = UL_PRIO_HIGH;
    header.stream_type = UL_STREAM_CMD_ACK;
    header.encrypted = true;
    header.sequence = state->sequence++;
    header.sys_id = 1;
    header.comp_id = 1;
    header.target_sys_id = 255; // GCS
    header.msg_id = UL_MSG_CMD_ACK;

    uint8_t *packet_buf = NULL;
    int packet_len = ul_pack_fast(pool, &header, payload, SHARED_KEY,
                                  nonce_state, crypto_ctx, &packet_buf);

    if (packet_len > 0 && packet_buf)
    {
        sendto(sock, (char *)packet_buf, packet_len, 0,
               (struct sockaddr *)dest, sizeof(*dest));
        ul_mempool_free(pool, packet_buf);
    }
}

int main(int argc, char *argv[])
{
    printf("=== UAVLink Bidirectional UAV Simulator ===\n\n");

    // Determine GCS IP
    const char *gcs_ip = "127.0.0.1";
    if (argc >= 2)
    {
        gcs_ip = argv[1];
    }
    else
    {
        printf("Usage: %s <gcs_ip>\n", argv[0]);
        printf("No IP provided, defaulting to 127.0.0.1\n\n");
    }

    // Initialize systems
    ul_mempool_t pool;
    ul_mempool_init(&pool);

    ul_nonce_state_t nonce_state;
    load_nonce_state(&nonce_state, "uav_nonce.dat");

    ul_crypto_ctx_t crypto_ctx;
    ul_crypto_ctx_init(&crypto_ctx);

    printf("Crypto: Software | Memory Pool: %d x %d bytes\n\n",
           UL_MEMPOOL_NUM_BUFFERS, UL_MEMPOOL_BUFFER_SIZE);

// Setup Winsock
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("ERROR: WSAStartup failed\n");
        return 1;
    }
#endif

    // Socket for sending telemetry (UAV -> GCS on port 14550)
    int telem_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (telem_sock < 0)
    {
        printf("ERROR: Failed to create telemetry socket\n");
        return 1;
    }

    struct sockaddr_in gcs_telem_addr;
    memset(&gcs_telem_addr, 0, sizeof(gcs_telem_addr));
    gcs_telem_addr.sin_family = AF_INET;
    gcs_telem_addr.sin_port = htons(14550);
    gcs_telem_addr.sin_addr.s_addr = inet_addr(gcs_ip);

    // Socket for receiving commands (GCS -> UAV on port 14551)
    int cmd_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (cmd_sock < 0)
    {
        printf("ERROR: Failed to create command socket\n");
        return 1;
    }

    struct sockaddr_in cmd_bind_addr;
    memset(&cmd_bind_addr, 0, sizeof(cmd_bind_addr));
    cmd_bind_addr.sin_family = AF_INET;
    cmd_bind_addr.sin_port = htons(14551);
    cmd_bind_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(cmd_sock, (struct sockaddr *)&cmd_bind_addr, sizeof(cmd_bind_addr)) < 0)
    {
        printf("ERROR: Failed to bind command socket to port 14551\n");
        return 1;
    }

    // Set command socket to non-blocking
#ifdef _WIN32
    u_long iMode = 1;
    ioctlsocket(cmd_sock, FIONBIO, &iMode);
#else
    int flags = fcntl(cmd_sock, F_GETFL, 0);
    fcntl(cmd_sock, F_SETFL, flags | O_NONBLOCK);
#endif

    printf("Telemetry -> %s:14550\n", gcs_ip);
    printf("Commands  <- 0.0.0.0:14551\n");
    printf("Status: DISARMED | Mode: MANUAL\n");
    printf("Waiting for commands...\n\n");

    // Initialize UAV state
    uav_state_t state = {0};
    state.lat = 47670000;
    state.lon = -122320000;
    state.alt = 0;
    state.voltage = 12600;
    state.current = -500;
    state.armed = false;
    state.flight_mode = UL_MODE_MANUAL;
    state.sequence = 0;

    // Zero-copy parser for incoming commands
    ul_parser_zerocopy_t cmd_parser;
    ul_parser_zerocopy_init(&cmd_parser);

    uint32_t packets_sent = 0;
    uint32_t commands_received = 0;
    uint8_t cmd_recv_buf[2048];

    // Fragment reassembly context
    ul_reassembly_ctx_t reasm_ctx;
    ul_reassembly_init(&reasm_ctx);
    uint8_t reasm_output[UL_FRAG_MAX_TOTAL];
    uint16_t reasm_output_len = 0;

    // Main loop — send telemetry + check for commands
    uint32_t last_gcs_msg_time = 0;
    
    for (int loop = 0;; loop++)
    {
        // --- Check for incoming commands (non-blocking) ---
        struct sockaddr_in sender_addr;
        int sender_len = sizeof(sender_addr);
        int recv_len = recvfrom(cmd_sock, (char *)cmd_recv_buf, sizeof(cmd_recv_buf), 0,
                                (struct sockaddr *)&sender_addr, &sender_len);

        if (recv_len > 10 && cmd_recv_buf[0] == 0xA5)
        {
            // Parse the command packet
            uint8_t *parse_buf = (uint8_t *)ul_mempool_alloc(&pool);
            if (parse_buf)
            {
                ul_parser_zerocopy_init(&cmd_parser); // Reset parser

                int result = 0;
                for (int i = 0; i < recv_len && result <= 0; i++)
                {
                    result = ul_parse_char_zerocopy(&cmd_parser, cmd_recv_buf[i], parse_buf);
                }

                if (result == 1)
                {
                    commands_received++;
                    last_gcs_msg_time = loop; // Reset failsafe timer

                    // Decode header
                    ul_header_t hdr = {0};
                    hdr.msg_id = cmd_parser.msg_id;
                    hdr.payload_len = cmd_parser.payload_len;
                    hdr.encrypted = (cmd_parser.header_buf[3] & UL_FLAG_ENCRYPTED) != 0;
                    hdr.fragmented = (cmd_parser.header_buf[3] & UL_FLAG_FRAGMENTED) != 0;

                    // Parse frag fields from extended header if fragmented
                    if (hdr.fragmented)
                    {
                        // frag_index and frag_total are after sys/comp/msg routing
                        uint8_t stream_type = ((cmd_parser.header_buf[1] & 0x3) << 2) |
                                              ((cmd_parser.header_buf[2] >> 6) & 0x3);
                        bool is_cmd_stream = (stream_type == UL_STREAM_CMD || stream_type == UL_STREAM_CMD_ACK);
                        int frag_offset = 4 + 4 + (is_cmd_stream ? 1 : 0); // base + ext routing + target
                        hdr.frag_index = cmd_parser.header_buf[frag_offset];
                        hdr.frag_total = cmd_parser.header_buf[frag_offset + 1];
                        hdr.sys_id = cmd_parser.header_buf[5] & 0x3F;
                    }

                    // Handle decryption for encrypted commands
                    if (hdr.encrypted && cmd_parser.payload_len > 0)
                    {
                        uint8_t nonce24[24] = {0};
                        memcpy(nonce24, cmd_parser.cipher_nonce, 8);

                        // Determine header length for AAD
                        uint8_t stream_type = ((cmd_parser.header_buf[1] & 0x3) << 2) |
                                              ((cmd_parser.header_buf[2] >> 6) & 0x3);
                        bool is_cmd = (stream_type == UL_STREAM_CMD || stream_type == UL_STREAM_CMD_ACK);
                        size_t header_len = (is_cmd ? 9 : 8) + 8; // routing + nonce

                        // Need monocypher for decryption
                        extern int crypto_aead_unlock(
                            uint8_t *plain_text,
                            const uint8_t mac[16],
                            const uint8_t key[32],
                            const uint8_t nonce[24],
                            const uint8_t *ad, size_t ad_size,
                            const uint8_t *cipher_text, size_t text_size);

                        int auth_result = crypto_aead_unlock(
                            parse_buf, cmd_parser.cipher_tag, SHARED_KEY, nonce24,
                            cmd_parser.header_buf, header_len,
                            parse_buf, cmd_parser.payload_len);

                        if (auth_result != 0)
                        {
                            printf("[CMD] Authentication failed! Ignoring.\n");
                            ul_mempool_free(&pool, parse_buf);
                            goto next_iter;
                        }
                    }

                    printf("[CMD #%u] ", commands_received);

                    switch (hdr.msg_id)
                    {
                    case UL_MSG_CMD:
                    {
                        ul_command_t cmd;
                        ul_deserialize_command(&cmd, parse_buf);
                        printf("Command=0x%04X Param1=%u Param2=%u Param3=%u\n",
                               cmd.command_id, cmd.param1, cmd.param2, cmd.param3);

                        ul_command_ack_t ack = process_command(&state, &cmd);
                        send_ack(telem_sock, &gcs_telem_addr, &ack, &state,
                                 &pool, &nonce_state, &crypto_ctx);
                        break;
                    }
                    case UL_MSG_MODE_CHANGE:
                    {
                        ul_mode_change_t mode;
                        ul_deserialize_mode_change(&mode, parse_buf);
                        printf("Mode change -> %s (0x%02X)\n",
                               get_mode_name(mode.mode), mode.mode);

                        state.flight_mode = mode.mode;

                        // Send ACK
                        ul_command_ack_t ack = {0};
                        ack.command_id = UL_MSG_MODE_CHANGE;
                        ack.result = UL_ACK_OK;
                        send_ack(telem_sock, &gcs_telem_addr, &ack, &state,
                                 &pool, &nonce_state, &crypto_ctx);
                        printf("  >>> Mode set to %s\n", get_mode_name(state.flight_mode));
                        break;
                    }
                    case UL_MSG_MISSION_ITEM:
                    {
                        // Check if fragmented
                        if (hdr.fragmented)
                        {
                            printf("Fragment %d/%d received (%d bytes)\n",
                                   hdr.frag_index + 1, hdr.frag_total, hdr.payload_len);

                            int reasm_result = ul_reassembly_add(&reasm_ctx, &hdr,
                                                                 parse_buf, hdr.payload_len,
                                                                 reasm_output, &reasm_output_len);

                            if (reasm_result == 1)
                            {
                                // Reassembly complete! Parse the full mission
                                printf("  >>> MISSION REASSEMBLED! Total %u bytes\n", reasm_output_len);

                                uint8_t num_wps = reasm_output[0];
                                int roff = 1;
                                printf("  >>> %u waypoints received:\n", num_wps);

                                state.mission_count = 0;
                                for (uint8_t w = 0; w < num_wps && roff + 20 <= reasm_output_len; w++)
                                {
                                    ul_mission_item_t wp;
                                    ul_deserialize_mission_item(&wp, reasm_output + roff);
                                    roff += 20;

                                    if (wp.seq < 16)
                                    {
                                        state.mission[wp.seq] = wp;
                                        if (wp.seq >= state.mission_count)
                                            state.mission_count = wp.seq + 1;
                                    }

                                    printf("      WP#%u: lat=%d lon=%d alt=%dmm spd=%ucm/s",
                                           wp.seq, wp.lat, wp.lon, wp.alt, wp.speed);
                                    if (wp.loiter_time > 0)
                                        printf(" loiter=%us", wp.loiter_time);
                                    printf("\n");
                                }

                                // Send ACK for completed mission
                                ul_command_ack_t ack = {0};
                                ack.command_id = UL_MSG_MISSION_ITEM;
                                ack.result = UL_ACK_OK;
                                send_ack(telem_sock, &gcs_telem_addr, &ack, &state,
                                         &pool, &nonce_state, &crypto_ctx);
                                printf("  >>> Mission stored! %u waypoints total\n",
                                       state.mission_count);
                            }
                            else if (reasm_result == 0)
                            {
                                printf("  (waiting for more fragments...)\n");
                            }
                            else
                            {
                                printf("  >>> Reassembly error: %d\n", reasm_result);
                            }
                        }
                        else
                        {
                            // Single (non-fragmented) waypoint
                            ul_mission_item_t item;
                            ul_deserialize_mission_item(&item, parse_buf);
                            printf("Mission WP#%u: lat=%d lon=%d alt=%dmm\n",
                                   item.seq, item.lat, item.lon, item.alt);

                            if (item.seq < 16)
                            {
                                state.mission[item.seq] = item;
                                if (item.seq >= state.mission_count)
                                    state.mission_count = item.seq + 1;
                            }

                            ul_command_ack_t ack = {0};
                            ack.command_id = UL_MSG_MISSION_ITEM;
                            ack.result = UL_ACK_OK;
                            send_ack(telem_sock, &gcs_telem_addr, &ack, &state,
                                     &pool, &nonce_state, &crypto_ctx);
                            printf("  >>> Waypoint %u stored (%u total)\n",
                                   item.seq, state.mission_count);
                        }
                        break;
                    }
                    default:
                        printf("Unknown msg_id=0x%03X\n", hdr.msg_id);
                        break;
                    }
                }

                ul_mempool_free(&pool, parse_buf);
            }
        }
    next_iter:
        ; // Empty statement required after label before declaration

        // --- Update simulation ---
        float t = loop * 0.1f;
        if (state.armed)
        {
            state.roll = sinf(t * 0.5f) * 5.0f;
            state.pitch = sinf(t * 0.3f) * 3.0f;
            state.yaw += 0.5f;
            if (state.yaw > 180.0f)
                state.yaw -= 360.0f;
            state.voltage -= 1;
            
            // Failsafe Check: 3 seconds without a message (30 ticks at 100ms)
            if ((loop - last_gcs_msg_time) > 30 && state.flight_mode != UL_MODE_RTL && state.flight_mode != UL_MODE_LAND) {
                printf("\n>>> FAILSAFE TRIGGERED: Link Lost! Auto-RTL engaged. <<<\n\n");
                state.flight_mode = UL_MODE_RTL;
            }
        }

        // --- Send telemetry ---

        // Heartbeat (1 Hz)
        if (loop % 10 == 0)
        {
            ul_heartbeat_t hb = {0};
            hb.system_status = state.armed ? 0x04 : 0x03; // Active vs Standby
            hb.system_type = 0x02;                         // Quadcopter
            hb.base_mode = state.armed ? 0x81 : 0x01;     // Armed flag in bit 7
            hb.base_mode |= (state.flight_mode << 2);

            uint8_t payload[32];
            int payload_len = ul_serialize_heartbeat(&hb, payload);

            ul_header_t header = {0};
            header.payload_len = payload_len;
            header.priority = UL_PRIO_NORMAL;
            header.stream_type = UL_STREAM_HEARTBEAT;
            header.encrypted = true;
            header.sequence = state.sequence++;
            header.sys_id = 1;
            header.comp_id = 1;
            header.msg_id = UL_MSG_HEARTBEAT;

            uint8_t *packet_buf = NULL;
            int packet_len = ul_pack_fast(&pool, &header, payload, SHARED_KEY,
                                          &nonce_state, &crypto_ctx, &packet_buf);

            if (packet_len > 0 && packet_buf)
            {
                sendto(telem_sock, (char *)packet_buf, packet_len, 0,
                       (struct sockaddr *)&gcs_telem_addr, sizeof(gcs_telem_addr));
                ul_mempool_free(&pool, packet_buf);
                packets_sent++;
            }
        }

        // Attitude (10 Hz)
        {
            ul_attitude_t att = {0};
            att.roll = state.roll;
            att.pitch = state.pitch;
            att.yaw = state.yaw;

            uint8_t payload[32];
            int payload_len = ul_serialize_attitude(&att, payload);

            ul_header_t header = {0};
            header.payload_len = payload_len;
            header.priority = UL_PRIO_HIGH;
            header.stream_type = UL_STREAM_TELEM_FAST;
            header.encrypted = true;
            header.sequence = state.sequence++;
            header.sys_id = 1;
            header.comp_id = 1;
            header.msg_id = UL_MSG_ATTITUDE;

            uint8_t *packet_buf = NULL;
            int packet_len = ul_pack_fast(&pool, &header, payload, SHARED_KEY,
                                          &nonce_state, &crypto_ctx, &packet_buf);

            if (packet_len > 0 && packet_buf)
            {
                sendto(telem_sock, (char *)packet_buf, packet_len, 0,
                       (struct sockaddr *)&gcs_telem_addr, sizeof(gcs_telem_addr));
                ul_mempool_free(&pool, packet_buf);
                packets_sent++;
            }
        }

        // GPS (2 Hz)
        if (loop % 5 == 0)
        {
            ul_gps_raw_t gps = {0};
            gps.lat = state.lat;
            gps.lon = state.lon;
            gps.alt = state.alt;
            gps.fix_type = 3;
            gps.satellites = 12;

            uint8_t payload[32];
            int payload_len = ul_serialize_gps_raw(&gps, payload);

            ul_header_t header = {0};
            header.payload_len = payload_len;
            header.priority = UL_PRIO_NORMAL;
            header.stream_type = UL_STREAM_TELEM_SLOW;
            header.encrypted = true;
            header.sequence = state.sequence++;
            header.sys_id = 1;
            header.comp_id = 1;
            header.msg_id = UL_MSG_GPS_RAW;

            uint8_t *packet_buf = NULL;
            int packet_len = ul_pack_fast(&pool, &header, payload, SHARED_KEY,
                                          &nonce_state, &crypto_ctx, &packet_buf);

            if (packet_len > 0 && packet_buf)
            {
                sendto(telem_sock, (char *)packet_buf, packet_len, 0,
                       (struct sockaddr *)&gcs_telem_addr, sizeof(gcs_telem_addr));
                ul_mempool_free(&pool, packet_buf);
                packets_sent++;
            }
        }

        // Status display (every 5 seconds)
        if (loop % 50 == 0 && loop > 0)
        {
            printf("\n--- Status [%s | %s] Telem:%u Cmds:%u Batt:%.1fV ---\n\n",
                   state.armed ? "ARMED" : "DISARMED",
                   get_mode_name(state.flight_mode),
                   packets_sent, commands_received,
                   state.voltage / 1000.0f);
            
            // Periodically save the nonce to NVM to keep the jump safe
            save_nonce_state(&nonce_state, "uav_nonce.dat");
        }

// 100ms loop (10 Hz)
#ifdef _WIN32
        Sleep(100);
#else
        usleep(100000);
#endif
    }

// Cleanup
#ifdef _WIN32
    closesocket(telem_sock);
    closesocket(cmd_sock);
    WSACleanup();
#else
    close(telem_sock);
    close(cmd_sock);
#endif

    // Final save on clean exit
    save_nonce_state(&nonce_state, "uav_nonce.dat");

    return 0;
}
