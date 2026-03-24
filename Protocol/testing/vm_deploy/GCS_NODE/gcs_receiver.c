/*
 * UAVLink Bidirectional GCS (Ground Control Station)
 *
 * Receives telemetry on UDP port 14552 (UAV -> GCS)
 * Sends commands on UDP port 14553 (GCS -> UAV)
 * Receives ACKs on UDP port 14552 (UAV -> GCS)
 *
 * Interactive command menu via stdin (non-blocking)
 */

#include "uavlink.h"
#include "uavlink_fast.h"
#include "monocypher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <conio.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/select.h>
#endif

// Cross-platform millisecond timer
static uint32_t get_time_ms(void)
{
#ifdef _WIN32
    return (uint32_t)GetTickCount();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
#endif
}

// ECDH Session Key State
static uint8_t session_key[32] = {0};
static uint8_t private_key[32] = {0};
static uint8_t public_key[32] = {0};

// Identity Key State
static uint8_t gcs_id_seed[32] = {0};
static uint8_t gcs_id_secret[64] = {0};
static uint8_t gcs_id_public[32] = {0};
static uint8_t uav_id_public[32] = {0};

static ul_ecdh_state_t ecdh_state = UL_ECDH_IDLE;
static uint8_t ecdh_seq_num = 1;         // Our handshake sequence number
static uint8_t ecdh_peer_seq = 0;        // Peer's sequence number
static uint32_t ecdh_retry_count = 0;    // Number of retries
static uint32_t ecdh_last_send_time = 0; // For exponential backoff
static uint32_t ecdh_timeout_ms = 5000;  // 5 second timeout

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

// ACK result name lookup
static const char *get_ack_result(uint8_t result)
{
    switch (result)
    {
    case UL_ACK_OK:
        return "OK";
    case UL_ACK_REJECTED:
        return "REJECTED";
    case UL_ACK_UNSUPPORTED:
        return "UNSUPPORTED";
    case UL_ACK_FAILED:
        return "FAILED";
    case UL_ACK_IN_PROGRESS:
        return "IN_PROGRESS";
    default:
        return "UNKNOWN";
    }
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

static void print_menu(void)
{
    printf("\n--------- Command Menu ---------\n");
    printf("  1: ARM         2: DISARM\n");
    printf("  3: TAKEOFF     4: LAND\n");
    printf("  5: RTL         6: EMERGENCY STOP\n");
    printf("  7: Mode Change 8: Send Waypoint\n");
    printf("  9: Upload Mission (fragmented)\n");
    printf("  0: Show Menu  Ctrl+C: Quit\n");
    printf(">>> ");
    fflush(stdout);
}

// Send a command packet to the UAV
static int send_command_packet(int sock, struct sockaddr_in *dest,
                               const ul_header_t *header, const uint8_t *payload,
                               ul_mempool_t *pool, ul_nonce_state_t *nonce_state,
                               ul_crypto_ctx_t *crypto_ctx)
{
    uint8_t *packet_buf = NULL;
    int packet_len = ul_pack_fast(pool, header, payload, session_key,
                                  nonce_state, crypto_ctx, &packet_buf);

    if (packet_len > 0 && packet_buf)
    {
        sendto(sock, (char *)packet_buf, packet_len, 0,
               (struct sockaddr *)dest, sizeof(*dest));
        ul_mempool_free(pool, packet_buf);
        return packet_len;
    }
    return -1;
}

// Send a generic command (arm, disarm, takeoff, land, etc.)
static void send_cmd(int sock, struct sockaddr_in *dest,
                     uint16_t cmd_id, uint16_t param1,
                     ul_mempool_t *pool, ul_nonce_state_t *nonce_state,
                     ul_crypto_ctx_t *crypto_ctx, uint16_t *seq)
{
    ul_command_t cmd = {0};
    cmd.command_id = cmd_id;
    cmd.param1 = param1;

    uint8_t payload[32];
    int payload_len = ul_serialize_command(&cmd, payload);

    ul_header_t header = {0};
    header.payload_len = payload_len;
    header.priority = UL_PRIO_HIGH;
    header.stream_type = UL_STREAM_CMD;
    header.encrypted = true;
    header.sequence = (*seq)++;
    header.sys_id = 255; // GCS
    header.comp_id = 0;
    header.target_sys_id = 1; // UAV
    header.msg_id = UL_MSG_CMD;

    int sent = send_command_packet(sock, dest, &header, payload, pool, nonce_state, crypto_ctx);
    if (sent > 0)
        printf("Sent command 0x%04X (%d bytes)\n", cmd_id, sent);
}

typedef enum
{
    AUTO_STEP_CMD = 0,
    AUTO_STEP_MODE = 1
} auto_step_type_t;

typedef struct
{
    auto_step_type_t type;
    uint16_t cmd_id;
    uint16_t param1;
    uint8_t mode;
    uint32_t wait_ms;
    const char *name;
} auto_step_t;

static void send_mode_change(int sock, struct sockaddr_in *dest,
                             uint8_t mode,
                             ul_mempool_t *pool, ul_nonce_state_t *nonce_state,
                             ul_crypto_ctx_t *crypto_ctx, uint16_t *seq);

static const auto_step_t soak_steps[] = {
    {AUTO_STEP_CMD, UL_CMD_ARM, 0, 0, 15000, "ARM"},
    {AUTO_STEP_CMD, UL_CMD_TAKEOFF, 1000, 0, 25000, "TAKEOFF (10m)"},
    {AUTO_STEP_MODE, 0, 0, UL_MODE_AUTO, 8000, "SET_MODE AUTO"},
    {AUTO_STEP_CMD, UL_CMD_RTL, 0, 0, 25000, "RTL"},
    {AUTO_STEP_CMD, UL_CMD_LAND, 0, 0, 20000, "LAND"},
    {AUTO_STEP_CMD, UL_CMD_DISARM, 0, 0, 12000, "DISARM"},
    {AUTO_STEP_CMD, UL_CMD_ARM, 0, 0, 12000, "ARM"},
    {AUTO_STEP_MODE, 0, 0, UL_MODE_LOITER, 8000, "SET_MODE LOITER"},
    {AUTO_STEP_CMD, UL_CMD_LAND, 0, 0, 20000, "LAND"},
    {AUTO_STEP_CMD, UL_CMD_DISARM, 0, 0, 12000, "DISARM"},
};

static void run_auto_step(int sock, struct sockaddr_in *dest,
                          const auto_step_t *step,
                          ul_mempool_t *pool, ul_nonce_state_t *nonce_state,
                          ul_crypto_ctx_t *crypto_ctx, uint16_t *seq)
{
    if (!step)
        return;

    if (step->type == AUTO_STEP_MODE)
    {
        send_mode_change(sock, dest, step->mode, pool, nonce_state, crypto_ctx, seq);
    }
    else
    {
        send_cmd(sock, dest, step->cmd_id, step->param1, pool, nonce_state, crypto_ctx, seq);
    }
}

// Send a mode change
static void send_mode_change(int sock, struct sockaddr_in *dest,
                             uint8_t mode,
                             ul_mempool_t *pool, ul_nonce_state_t *nonce_state,
                             ul_crypto_ctx_t *crypto_ctx, uint16_t *seq)
{
    ul_mode_change_t mc = {0};
    mc.mode = mode;

    uint8_t payload[32];
    int payload_len = ul_serialize_mode_change(&mc, payload);

    ul_header_t header = {0};
    header.payload_len = payload_len;
    header.priority = UL_PRIO_HIGH;
    header.stream_type = UL_STREAM_CMD;
    header.encrypted = true;
    header.sequence = (*seq)++;
    header.sys_id = 255;
    header.comp_id = 0;
    header.target_sys_id = 1;
    header.msg_id = UL_MSG_MODE_CHANGE;

    int sent = send_command_packet(sock, dest, &header, payload, pool, nonce_state, crypto_ctx);
    if (sent > 0)
        printf("Sent mode change -> %s (%d bytes)\n", get_mode_name(mode), sent);
}

// Send a mission waypoint
static void send_waypoint(int sock, struct sockaddr_in *dest,
                          uint16_t wp_seq,
                          ul_mempool_t *pool, ul_nonce_state_t *nonce_state,
                          ul_crypto_ctx_t *crypto_ctx, uint16_t *seq)
{
    ul_mission_item_t item = {0};
    item.seq = wp_seq;
    item.frame = 0;   // Global
    item.command = 0; // Navigate
    item.lat = 47670000 + (wp_seq * 1000);
    item.lon = -122320000 + (wp_seq * 1000);
    item.alt = 50000 + (wp_seq * 10000); // 50m + 10m per waypoint
    item.speed = 500;                    // 5 m/s

    uint8_t payload[32];
    int payload_len = ul_serialize_mission_item(&item, payload);

    ul_header_t header = {0};
    header.payload_len = payload_len;
    header.priority = UL_PRIO_HIGH;
    header.stream_type = UL_STREAM_CMD;
    header.encrypted = true;
    header.sequence = (*seq)++;
    header.sys_id = 255;
    header.comp_id = 0;
    header.target_sys_id = 1;
    header.msg_id = UL_MSG_MISSION_ITEM;

    int sent = send_command_packet(sock, dest, &header, payload, pool, nonce_state, crypto_ctx);
    if (sent > 0)
        printf("Sent waypoint #%u: lat=%d lon=%d alt=%dmm (%d bytes)\n",
               wp_seq, item.lat, item.lon, item.alt, sent);
}

// Check for keyboard input (non-blocking)
static int key_available(void)
{
#ifdef _WIN32
    return _kbhit();
#else
    struct timeval tv = {0, 0};
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(0, &fds);
    return select(1, &fds, NULL, NULL, &tv) > 0;
#endif
}

static int get_key(void)
{
#ifdef _WIN32
    return _getch();
#else
    return getchar();
#endif
}

// Send a fragmented mission plan (5 waypoints packed into one large payload)
static void send_mission_fragmented(int sock, struct sockaddr_in *dest,
                                    ul_mempool_t *pool, ul_nonce_state_t *nonce_state,
                                    ul_crypto_ctx_t *crypto_ctx, uint16_t *seq)
{
    // Pack 5 waypoints into a single large payload
    uint8_t big_payload[1024];
    int offset = 0;

    // First byte = number of waypoints
    big_payload[offset++] = 5;

    for (int i = 0; i < 5; i++)
    {
        ul_mission_item_t wp = {0};
        wp.seq = i;
        wp.frame = 0;                   // Global
        wp.command = 0;                 // Navigate
        wp.lat = 47670000 + (i * 5000); // Spread waypoints 0.0005 deg apart
        wp.lon = -122320000 + (i * 5000);
        wp.alt = 50000 + (i * 10000);       // 50m, 60m, 70m, 80m, 90m
        wp.speed = 500;                     // 5 m/s
        wp.loiter_time = (i == 2) ? 30 : 0; // Loiter 30s at WP#2

        int len = ul_serialize_mission_item(&wp, big_payload + offset);
        offset += len; // 20 bytes each
    }

    printf("Mission payload: %d bytes (%d waypoints x 20 bytes + 1 header)\n", offset, 5);

    // Fragment the mission payload manually
    // Use 64 bytes per fragment for demonstration
    const int FRAGMENT_SIZE = 64;
    int num_frags = (offset + FRAGMENT_SIZE - 1) / FRAGMENT_SIZE; // Ceiling division

    if (num_frags > 255)
    {
        printf("ERROR: Payload too large (%d fragments needed, max 255)\n", num_frags);
        return;
    }

    printf("Split into %d fragments:\n", num_frags);

    // Send each fragment
    int total_sent = 0;
    for (int i = 0; i < num_frags; i++)
    {
        // Calculate payload slice for this fragment
        int frag_offset = i * FRAGMENT_SIZE;
        int frag_len = (i == num_frags - 1) ? (offset - frag_offset) : FRAGMENT_SIZE;

        // Create header for this fragment
        ul_header_t frag_header = {0};
        frag_header.payload_len = frag_len;
        frag_header.priority = UL_PRIO_HIGH;
        frag_header.stream_type = UL_STREAM_MISSION;
        frag_header.encrypted = true;
        frag_header.fragmented = (num_frags > 1); // Set fragmented flag if multiple fragments
        frag_header.frag_index = i;
        frag_header.frag_total = num_frags;
        frag_header.sequence = (*seq)++;
        frag_header.sys_id = 255; // GCS
        frag_header.comp_id = 0;
        frag_header.target_sys_id = 1; // UAV
        frag_header.msg_id = UL_MSG_MISSION_ITEM;

        int sent = send_command_packet(sock, dest, &frag_header,
                                       big_payload + frag_offset, pool, nonce_state, crypto_ctx);
        if (sent > 0)
        {
            printf("  Fragment %d/%d: %d payload bytes, %d wire bytes\n",
                   i + 1, num_frags, frag_len, sent);
            total_sent += sent;
        }

        // Small delay between fragments to avoid overwhelming receiver
#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }

    printf("Mission upload complete: %d fragments, %d total wire bytes\n", num_frags, total_sent);
}

int main(int argc, char *argv[])
{
    printf("=== UAVLink Bidirectional GCS ===\n\n");

    // Determine UAV IP and startup mode
    const char *uav_ip = "127.0.0.1";
    bool auto_soak = false;
    uint16_t send_port = 14553;
    uint16_t listen_port = 14552;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--auto-soak") == 0)
        {
            auto_soak = true;
            continue;
        }

        if (strcmp(argv[i], "--send-port") == 0 && i + 1 < argc)
        {
            send_port = (uint16_t)atoi(argv[++i]);
            continue;
        }

        if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc)
        {
            listen_port = (uint16_t)atoi(argv[++i]);
            continue;
        }

        if (argv[i][0] != '-')
        {
            uav_ip = argv[i];
        }
    }

    if (argc < 2)
    {
        printf("Usage: %s <uav_ip> [--auto-soak] [--send-port <port>] [--listen-port <port>]\n", argv[0]);
        printf("No IP provided, defaulting to 127.0.0.1\n\n");
    }

    if (auto_soak)
    {
        printf("[AUTO] Soak command mode enabled in GCS\n");
    }

    // Load Identity Keys
    FILE *f_gcs_seed = fopen("gcs_id_seed.bin", "rb");
    if (!f_gcs_seed || fread(gcs_id_seed, 1, 32, f_gcs_seed) != 32)
    {
        printf("ERROR: Could not load gcs_id_seed.bin (generate with keygen.py)\n");
        return 1;
    }
    if (f_gcs_seed) fclose(f_gcs_seed);

    FILE *f_uav_pub = fopen("uav_pub.bin", "rb");
    if (!f_uav_pub || fread(uav_id_public, 1, 32, f_uav_pub) != 32)
    {
        printf("ERROR: Could not load uav_pub.bin (generate with id_gen.exe)\n");
        return 1;
    }
    if (f_uav_pub) fclose(f_uav_pub);

    crypto_eddsa_key_pair(gcs_id_secret, gcs_id_public, gcs_id_seed);
    printf("Identity loaded: EdDSA Keys loaded successfully\n");

    // Initialize systems
    ul_mempool_t pool;
    ul_mempool_init(&pool);

    ul_nonce_state_t nonce_state;
    load_nonce_state(&nonce_state, "gcs_nonce.dat");

    ul_crypto_ctx_t crypto_ctx;
    ul_crypto_ctx_init(&crypto_ctx);

    printf("Crypto Backend: Software\n");
    printf("Memory Pool: %d buffers x %d bytes = %d KB\n\n",
           UL_MEMPOOL_NUM_BUFFERS, UL_MEMPOOL_BUFFER_SIZE,
           (UL_MEMPOOL_NUM_BUFFERS * UL_MEMPOOL_BUFFER_SIZE) / 1024);

// Setup Winsock
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("ERROR: WSAStartup failed\n");
        return 1;
    }
#endif

    // Socket for receiving telemetry + ACKs (port 14550)
    int recv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (recv_sock < 0)
    {
        printf("ERROR: Failed to create receive socket\n");
        return 1;
    }

    struct sockaddr_in recv_addr;
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(listen_port);
    recv_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(recv_sock, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0)
    {
        printf("ERROR: Failed to bind to port %u\n", listen_port);
        return 1;
    }

    // Set receive socket non-blocking
#ifdef _WIN32
    u_long iMode = 1;
    ioctlsocket(recv_sock, FIONBIO, &iMode);
#else
    int flags = fcntl(recv_sock, F_GETFL, 0);
    fcntl(recv_sock, F_SETFL, flags | O_NONBLOCK);
#endif

    // Socket for sending commands (port 14553 for direct UAV connection)
    int cmd_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (cmd_sock < 0)
    {
        printf("ERROR: Failed to create command socket\n");
        return 1;
    }

    struct sockaddr_in uav_cmd_addr;
    memset(&uav_cmd_addr, 0, sizeof(uav_cmd_addr));
    uav_cmd_addr.sin_family = AF_INET;
    uav_cmd_addr.sin_port = htons(send_port);
    uav_cmd_addr.sin_addr.s_addr = inet_addr(uav_ip);

    printf("Listening on UDP port %u (telemetry + ACKs)\n", listen_port);
    printf("Sending commands to %s:%u (direct UAV connection)\n", uav_ip, send_port);
    print_menu();

    // Generate ECDH Keys
    srand((unsigned int)time(NULL) ^ 0x6C73);
    for (int i = 0; i < 32; i++)
        private_key[i] = rand() & 0xFF;
    crypto_x25519_public_key(public_key, private_key);
    printf("ECDH: GCS Public Key generated. Waiting for UAV connection...\n");

    // Parser
    ul_parser_zerocopy_t parser;
    ul_parser_zerocopy_init(&parser);

    uint32_t packets_received = 0;
    uint32_t parse_errors = 0;
    uint32_t acks_received = 0;
    uint16_t cmd_sequence = 0;
    uint16_t next_wp_seq = 0;
    uint32_t auto_next_send_ms = 0;
    size_t auto_step_index = 0;
    uint32_t auto_iteration = 0;
    bool auto_started = false;

    uint8_t recv_buf[2048];
    uint8_t parse_output[512];
    uint32_t last_telem_print = 0;
    uint32_t loop_counter = 0;

    // Main loop
    while (1)
    {
        // ECDH Handshake with Exponential Backoff and Timeout
        if (ecdh_state != UL_ECDH_ESTABLISHED)
        {
            uint32_t current_time = get_time_ms();

            // Check for timeout - restart handshake if we've been stuck
            if (ecdh_state != UL_ECDH_IDLE &&
                (current_time - ecdh_last_send_time) > ecdh_timeout_ms)
            {
                printf("\n>>> ECDH: Timeout! Restarting handshake (was in state %u) <<<\n>>> ", ecdh_state);
                fflush(stdout);
                ecdh_state = UL_ECDH_IDLE;
                ecdh_retry_count = 0;
                ecdh_seq_num++; // Increment sequence for new attempt
            }

            // Exponential backoff calculation: 100ms * 2^retry, max 2000ms
            uint32_t backoff_ms = 100 * (1 << (ecdh_retry_count < 5 ? ecdh_retry_count : 4));
            if (backoff_ms > 2000)
                backoff_ms = 2000;

            // Send KEY_EXCHANGE if not established and backoff elapsed
            if (ecdh_state != UL_ECDH_ESTABLISHED &&
                (current_time - ecdh_last_send_time) >= backoff_ms)
            {
                ul_key_exchange_t kx = {0};
                memcpy(kx.public_key, public_key, 32);
                kx.seq_num = ecdh_seq_num;

                // Create signature over (public_key || seq_num)
                uint8_t data_to_sign[33];
                memcpy(data_to_sign, public_key, 32);
                data_to_sign[32] = ecdh_seq_num;
                crypto_eddsa_sign(kx.signature, gcs_id_secret, data_to_sign, 33);

                uint8_t payload[97];
                int payload_len = ul_serialize_key_exchange(&kx, payload);

                ul_header_t header = {0};
                header.payload_len = payload_len;
                header.priority = UL_PRIO_HIGH;
                header.stream_type = UL_STREAM_CMD;
                header.encrypted = false;
                header.sequence = cmd_sequence++;
                header.sys_id = 255;
                header.comp_id = 0;
                header.target_sys_id = 1; // UAV
                header.msg_id = UL_MSG_KEY_EXCHANGE;

                send_command_packet(cmd_sock, &uav_cmd_addr, &header, payload, &pool, &nonce_state, &crypto_ctx);

                // If we already have session_key (from receiving UAV KEY_EXCHANGE), mark ESTABLISHED
                bool has_key = false;
                for (int i = 0; i < 32; i++) {
                    if (session_key[i] != 0) {
                        has_key = true;
                        break;
                    }
                }

                if (has_key && ecdh_state == UL_ECDH_RECEIVED_KEY) {
                    // We received their key earlier, now we sent ours - ESTABLISHED
                    ecdh_state = UL_ECDH_ESTABLISHED;
                    ecdh_retry_count = 0;
                    printf("\n  >>> ECDH: Session ESTABLISHED! (sent GCS key after receiving UAV key)\n>>> ");
                    printf("[UAVLink] Sic Parvis Magna.\n>>> ");
                    fflush(stdout);
                } else {
                    ecdh_state = UL_ECDH_SENT_KEY;
                    ecdh_retry_count++;
                }
                ecdh_last_send_time = current_time;

                if (ecdh_retry_count == 1)
                {
                    printf("\n>>> ECDH: Sending KEY_EXCHANGE seq=%u <<<\n>>> ", ecdh_seq_num);
                }
                else
                {
                    printf("\n>>> ECDH: Retry #%u (backoff=%ums) seq=%u <<<\n>>> ",
                           ecdh_retry_count - 1, backoff_ms, ecdh_seq_num);
                }
                fflush(stdout);
            }
        }
        loop_counter++;

        // --- Internal soak automation (commands generated directly by GCS) ---
        if (auto_soak && ecdh_state == UL_ECDH_ESTABLISHED)
        {
            uint32_t now_ms = get_time_ms();

            if (!auto_started)
            {
                auto_next_send_ms = now_ms + 5000; // give link time after handshake
                auto_started = true;
                printf("\n[AUTO] Starting soak command cycle in 5s...\n>>> ");
                fflush(stdout);
            }

            if (now_ms >= auto_next_send_ms)
            {
                const auto_step_t *step = &soak_steps[auto_step_index];
                auto_iteration++;
                printf("\n[AUTO] Step %u: %s\n", (unsigned int)auto_iteration, step->name);
                run_auto_step(cmd_sock, &uav_cmd_addr, step, &pool, &nonce_state, &crypto_ctx, &cmd_sequence);
                printf(">>> ");
                fflush(stdout);

                auto_next_send_ms = now_ms + step->wait_ms;
                auto_step_index = (auto_step_index + 1) % (sizeof(soak_steps) / sizeof(soak_steps[0]));
            }
        }

        // --- Check for keyboard input (non-blocking) ---
        if (key_available())
        {
            int key = get_key();
            if (ecdh_state != UL_ECDH_ESTABLISHED && key != '0')
            {
                printf("\n[ERROR] ECDH Session not established yet! Command ignored.\n>>> ");
                fflush(stdout);
                goto skip_input;
            }
            switch (key)
            {
            case '1':
                printf("\n");
                send_cmd(cmd_sock, &uav_cmd_addr, UL_CMD_ARM, 0,
                         &pool, &nonce_state, &crypto_ctx, &cmd_sequence);
                break;
            case '2':
                printf("\n");
                send_cmd(cmd_sock, &uav_cmd_addr, UL_CMD_DISARM, 0,
                         &pool, &nonce_state, &crypto_ctx, &cmd_sequence);
                break;
            case '3':
                printf("\n");
                send_cmd(cmd_sock, &uav_cmd_addr, UL_CMD_TAKEOFF, 1000, // 10m
                         &pool, &nonce_state, &crypto_ctx, &cmd_sequence);
                break;
            case '4':
                printf("\n");
                send_cmd(cmd_sock, &uav_cmd_addr, UL_CMD_LAND, 0,
                         &pool, &nonce_state, &crypto_ctx, &cmd_sequence);
                break;
            case '5':
                printf("\n");
                send_cmd(cmd_sock, &uav_cmd_addr, UL_CMD_RTL, 0,
                         &pool, &nonce_state, &crypto_ctx, &cmd_sequence);
                break;
            case '6':
                printf("\n");
                send_cmd(cmd_sock, &uav_cmd_addr, UL_CMD_EMERGENCY, 0,
                         &pool, &nonce_state, &crypto_ctx, &cmd_sequence);
                break;
            case '7':
            {
                printf("\nModes: 0=MANUAL 1=STABILIZE 2=ALT_HOLD 3=LOITER 4=AUTO 5=RTL 6=LAND\n");
                printf("Enter mode number: ");
                fflush(stdout);
                int mode_key = get_key();
                if (mode_key >= '0' && mode_key <= '6')
                {
                    printf("%c\n", mode_key);
                    send_mode_change(cmd_sock, &uav_cmd_addr, mode_key - '0',
                                     &pool, &nonce_state, &crypto_ctx, &cmd_sequence);
                }
                else
                {
                    printf("\nInvalid mode\n");
                }
                break;
            }
            case '8':
            {
                printf("\n");
                send_waypoint(cmd_sock, &uav_cmd_addr, next_wp_seq++,
                              &pool, &nonce_state, &crypto_ctx, &cmd_sequence);
                break;
            }
            case '9':
            {
                printf("\n--- Uploading Fragmented Mission (5 waypoints) ---\n");
                send_mission_fragmented(cmd_sock, &uav_cmd_addr,
                                        &pool, &nonce_state, &crypto_ctx, &cmd_sequence);
                break;
            }
            case '0':
                print_menu();
                break;
            default:
                break;
            }
        skip_input:;
        }

        // --- Receive telemetry + ACKs (non-blocking) ---
        struct sockaddr_in sender_addr;
        int sender_len = sizeof(sender_addr);
#ifdef _WIN32
        int recv_len = recvfrom(recv_sock, (char *)recv_buf, sizeof(recv_buf), 0,
                                (struct sockaddr *)&sender_addr, &sender_len);
#else
        int recv_len = recvfrom(recv_sock, (char *)recv_buf, sizeof(recv_buf), 0,
                                (struct sockaddr *)&sender_addr, (socklen_t *)&sender_len);
#endif

        if (recv_len > 0)
        {
            // Parse received packet byte by byte
            ul_parser_zerocopy_init(&parser);

            int result = 0;
            for (int i = 0; i < recv_len && result <= 0; i++)
            {
                result = ul_parse_char_zerocopy(&parser, recv_buf[i], parse_output);
            }

            if (result == 1)
            {
                packets_received++;

                // Get header info
                uint16_t msg_id = parser.msg_id;
                uint16_t payload_len = parser.payload_len;
                bool encrypted = (parser.header_buf[3] & UL_FLAG_ENCRYPTED) != 0;

                // Handle decryption
                if (encrypted && payload_len > 0)
                {
                    uint8_t nonce24[24] = {0};
                    memcpy(nonce24, parser.cipher_nonce, 8);

                    uint8_t stream_type = ((parser.header_buf[1] & 0x3) << 2) |
                                          ((parser.header_buf[2] >> 6) & 0x3);
                    bool is_cmd = (stream_type == UL_STREAM_CMD || stream_type == UL_STREAM_CMD_ACK);
                    // AAD includes entire header from SOF byte
                    size_t header_len = 4 + (is_cmd ? 5 : 4) + (parser.header_buf[3] & UL_FLAG_ENCRYPTED ? 8 : 0);



                    int auth_result = crypto_aead_unlock(
                        parse_output, parser.cipher_tag, session_key, nonce24,
                        parser.header_buf, header_len,
                        parse_output, payload_len);

                    if (auth_result != 0)
                    {
                        parse_errors++;
                        continue;
                    }
                }

                // Process message
                switch (msg_id)
                {
                case UL_MSG_KEY_EXCHANGE:
                {
                    ul_key_exchange_t rx_kx;
                    ul_deserialize_key_exchange(&rx_kx, parse_output);

                    // Ignore duplicate KEY_EXCHANGE (same seq_num we already processed)
                    if (ecdh_state == UL_ECDH_ESTABLISHED && rx_kx.seq_num == ecdh_peer_seq)
                    {
                        printf("\n  (Duplicate KEY_EXCHANGE seq=%u, already established)\n>>> ", rx_kx.seq_num);
                        fflush(stdout);
                        break;
                    }

                    // Authenticate incoming Key Exchange Request
                    uint8_t data_to_sign[33];
                    memcpy(data_to_sign, rx_kx.public_key, 32);
                    data_to_sign[32] = rx_kx.seq_num;
                    if (crypto_eddsa_check(rx_kx.signature, uav_id_public, data_to_sign, 33) != 0)
                    {
                        printf("\n  >>> ECDH FATAL: EdDSA signature verification failed. MITM detected!\n>>> ");
                        printf("[UAVLink] You shall not pass... without authentication.\n");
                        fflush(stdout);
                        break;
                    }

                    // Always send our KEY_EXCHANGE when we receive peer's KEY_EXCHANGE
                    // This handles crossed-in-flight KEY_EXCHANGE packets and ensures both sides get the key
                    uint8_t raw_shared[32];
                    crypto_x25519(raw_shared, private_key, rx_kx.public_key);
                    crypto_blake2b(session_key, 32, raw_shared, 32);

                    printf("[DEBUG] GCS session_key: %02X%02X%02X%02X%02X%02X%02X%02X\n",
                           session_key[0], session_key[1], session_key[2], session_key[3],
                           session_key[4], session_key[5], session_key[6], session_key[7]);
                    fflush(stdout);

                    ecdh_peer_seq = rx_kx.seq_num;

                    printf("\n  >>> ECDH: Received UAV key (seq=%u), sending GCS key\n>>> ", rx_kx.seq_num);

                    // Send our KEY_EXCHANGE immediately
                    ul_key_exchange_t kx_reply = {0};
                    memcpy(kx_reply.public_key, public_key, 32);
                    kx_reply.seq_num = ecdh_seq_num;

                    // Sign (public_key || seq_num)
                    uint8_t kx_data_to_sign[33];
                    memcpy(kx_data_to_sign, public_key, 32);
                    kx_data_to_sign[32] = ecdh_seq_num;
                    crypto_eddsa_sign(kx_reply.signature, gcs_id_secret, kx_data_to_sign, 33);

                    uint8_t kx_payload[97];
                    int kx_payload_len = ul_serialize_key_exchange(&kx_reply, kx_payload);

                    ul_header_t kx_hdr = {0};
                    kx_hdr.payload_len = kx_payload_len;
                    kx_hdr.priority = UL_PRIO_HIGH;
                    kx_hdr.stream_type = UL_STREAM_CMD;
                    kx_hdr.encrypted = false;
                    kx_hdr.sequence = cmd_sequence++;
                    kx_hdr.sys_id = 255;
                    kx_hdr.comp_id = 0;
                    kx_hdr.target_sys_id = 1;
                    kx_hdr.msg_id = UL_MSG_KEY_EXCHANGE;

                    uint8_t *kx_buf = NULL;
                    int kx_pkt_len = ul_pack_fast(&pool, &kx_hdr, kx_payload, session_key,
                                                   &nonce_state, &crypto_ctx, &kx_buf);
                    if (kx_pkt_len > 0 && kx_buf)
                    {
                        sendto(cmd_sock, (char *)kx_buf, kx_pkt_len, 0,
                               (struct sockaddr *)&uav_cmd_addr, sizeof(uav_cmd_addr));
                        ul_mempool_free(&pool, kx_buf);
                    }

                    // Mark ESTABLISHED immediately - we have both keys now
                    ecdh_state = UL_ECDH_ESTABLISHED;
                    ecdh_retry_count = 0;

                    printf("  >>> ECDH: Session ESTABLISHED! (received UAV key, sent GCS key)\n>>> ");
                    printf("[UAVLink] Sic Parvis Magna.\n>>> ");
                    fflush(stdout);

                    // Always send ACK when we receive KEY_EXCHANGE
                    ul_key_exchange_ack_t kx_ack = {0};
                    kx_ack.seq_num = rx_kx.seq_num;
                    kx_ack.status = 0; // OK

                    uint8_t ack_payload[2];
                    int ack_len = ul_serialize_key_exchange_ack(&kx_ack, ack_payload);

                    ul_header_t ack_hdr = {0};
                    ack_hdr.payload_len = ack_len;
                    ack_hdr.priority = UL_PRIO_HIGH;
                    ack_hdr.stream_type = UL_STREAM_CMD_ACK;
                    ack_hdr.encrypted = false;
                    ack_hdr.sequence = cmd_sequence++;
                    ack_hdr.sys_id = 255;
                    ack_hdr.comp_id = 0;
                    ack_hdr.target_sys_id = 1;
                    ack_hdr.msg_id = UL_MSG_KEY_EXCHANGE_ACK;

                    uint8_t *ack_buf = NULL;
                    int ack_pkt_len = ul_pack_fast(&pool, &ack_hdr, ack_payload, session_key,
                                                   &nonce_state, &crypto_ctx, &ack_buf);
                    if (ack_pkt_len > 0 && ack_buf)
                    {
                        sendto(cmd_sock, (char *)ack_buf, ack_pkt_len, 0,
                               (struct sockaddr *)&uav_cmd_addr, sizeof(uav_cmd_addr));
                        ul_mempool_free(&pool, ack_buf);
                    }
                    break;
                }
                case UL_MSG_KEY_EXCHANGE_ACK:
                {
                    ul_key_exchange_ack_t rx_ack;
                    ul_deserialize_key_exchange_ack(&rx_ack, parse_output);

                    // Check if this ACK is for our current handshake
                    // Mark as ESTABLISHED if we have session_key computed
                    if (rx_ack.seq_num == ecdh_seq_num && ecdh_state >= UL_ECDH_SENT_KEY && ecdh_state != UL_ECDH_ESTABLISHED)
                    {
                        // Check if session_key is valid (not all zeros)
                        bool has_key = false;
                        for (int i = 0; i < 32; i++) {
                            if (session_key[i] != 0) {
                                has_key = true;
                                break;
                            }
                        }

                        if (has_key) {
                            // We have session_key, mark ESTABLISHED
                            ecdh_state = UL_ECDH_ESTABLISHED;
                            ecdh_retry_count = 0;
                            printf("\n  >>> ECDH: Received ACK for seq=%u, session ESTABLISHED!\n>>> ", ecdh_seq_num);
                            printf("[UAVLink] Sic Parvis Magna.\n>>> ");
                            fflush(stdout);
                        } else {
                            printf("\n  >>> ECDH: Received ACK for seq=%u (waiting for UAV KEY_EXCHANGE)\n>>> ", ecdh_seq_num);
                            fflush(stdout);
                        }
                    }
                    else if (rx_ack.seq_num == ecdh_seq_num && ecdh_state == UL_ECDH_ESTABLISHED)
                    {
                        printf("\n  (ACK for seq=%u received, session already established)\n>>> ", ecdh_seq_num);
                        fflush(stdout);
                    }
                    break;
                }
                case UL_MSG_HEARTBEAT:
                {
                    ul_heartbeat_t hb;
                    ul_deserialize_heartbeat(&hb, parse_output);
                    bool armed = (hb.base_mode & 0x80) != 0;
                    uint8_t mode = (hb.base_mode >> 2) & 0x07;

                    // Print heartbeat only every 5 seconds (not every 1s)
                    // MODIFIED FOR TESTING: Print more frequently to see errors
                    if (packets_received - last_telem_print >= 10 || packets_received <= 50)
                    {
                        printf("[HB] %s | %s | Status:0x%X | Pkts:%u ACKs:%u Errors:%u\n",
                               armed ? "ARMED" : "DISARMED",
                               get_mode_name(mode),
                               hb.system_status,
                               packets_received, acks_received, parse_errors);
                        last_telem_print = packets_received;
                        fflush(stdout);

                        // Periodically save the nonce to NVM to keep the jump safe
                        save_nonce_state(&nonce_state, "gcs_nonce.dat");
                    }
                    break;
                }
                case UL_MSG_RC_INPUT:
                {
                    ul_rc_input_t rc;
                    ul_deserialize_rc_input(&rc, parse_output);

                    // Periodically print the Link Quality back to the operator
                    if (packets_received % 50 == 0)
                    {
                        printf("[RC] Link Quality: %u%% | RSSI: %u\n", rc.quality, rc.rssi);
                    }
                    break;
                }
                case UL_MSG_GPS_RAW:
                {
                    // Silently receive
                    break;
                }
                case UL_MSG_BATTERY:
                {
                    ul_battery_t bat;
                    ul_deserialize_battery(&bat, parse_output);
                    printf("[BAT] %.1fV  %.1fA  %d%%\n",
                           bat.voltage / 1000.0, bat.current / -100.0, bat.remaining);
                    break;
                }
                case UL_MSG_CMD_ACK:
                {
                    acks_received++;
                    ul_command_ack_t ack;
                    ul_deserialize_command_ack(&ack, parse_output);
                    printf("[ACK] Cmd=0x%04X Result=%s",
                           ack.command_id, get_ack_result(ack.result));
                    if (ack.result == UL_ACK_IN_PROGRESS)
                        printf(" Progress=%u%%", ack.progress);
                    printf("\n");
                    printf(">>> ");
                    fflush(stdout);
                    break;
                }
                default:
                    // Other telemetry silently received
                    break;
                }
            }
            else if (result < 0)
            {
                parse_errors++;
            }
        }

// Small sleep to avoid busy-waiting
#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }

// Cleanup
#ifdef _WIN32
    closesocket(recv_sock);
    closesocket(cmd_sock);
    WSACleanup();
#else
    close(recv_sock);
    close(cmd_sock);
#endif

    // Final save on clean exit
    save_nonce_state(&nonce_state, "gcs_nonce.dat");

    return 0;
}
