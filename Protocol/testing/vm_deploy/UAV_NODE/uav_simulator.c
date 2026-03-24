/*
 * UAVLink Bidirectional UAV Simulator
 *
 * Sends telemetry on UDP port 14552 (UAV -> GCS)
 * Receives commands on UDP port 14553 (GCS -> UAV)
 * Sends command ACKs on UDP port 14552 (UAV -> GCS)
 */

#include "uavlink.h"
#include "uavlink_fast.h"
#include <stdio.h>
#include <stdlib.h>
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

#include "monocypher.h"

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
static uint8_t uav_id_seed[32] = {0};
static uint8_t uav_id_secret[64] = {0};
static uint8_t uav_id_public[32] = {0};
static uint8_t gcs_id_public[32] = {0};

static ul_ecdh_state_t ecdh_state = UL_ECDH_IDLE;
static uint8_t ecdh_seq_num = 1;         // Our handshake sequence number
static uint8_t ecdh_peer_seq = 0;        // Peer's sequence number
static uint32_t ecdh_retry_count = 0;    // Number of retries
static uint32_t ecdh_last_send_time = 0; // For exponential backoff
static uint32_t ecdh_timeout_ms = 5000;  /* One hour on this planet = 7 years of waiting — Interstellar */

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
    int packet_len = ul_pack_fast(pool, &header, payload, session_key,
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
    printf("[UAVLink] Hello, friend.\n\n");

    // Determine GCS IP and Ports
    const char *gcs_ip = "127.0.0.1";
    uint16_t send_port = 14552;
    uint16_t listen_port = 14553;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--send-port") == 0 && i + 1 < argc)
        {
            send_port = (uint16_t)atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc)
        {
            listen_port = (uint16_t)atoi(argv[++i]);
        }
        else if (argv[i][0] != '-')
        {
            gcs_ip = argv[i];
        }
    }

    if (argc < 2)
    {
        printf("Usage: %s <gcs_ip> [--send-port <port>] [--listen-port <port>]\n", argv[0]);
        printf("No IP provided, defaulting to 127.0.0.1\n\n");
    }

    // Load Identity Keys
    FILE *f_uav_seed = fopen("uav_id_seed.bin", "rb");
    if (!f_uav_seed || fread(uav_id_seed, 1, 32, f_uav_seed) != 32)
    {
        printf("ERROR: Could not load uav_id_seed.bin (generate with keygen.py)\n");
        return 1;
    }
    if (f_uav_seed) fclose(f_uav_seed);

    FILE *f_gcs_pub = fopen("gcs_pub.bin", "rb");
    if (!f_gcs_pub || fread(gcs_id_public, 1, 32, f_gcs_pub) != 32)
    {
        printf("ERROR: Could not load gcs_pub.bin (generate with id_gen.exe)\n");
        return 1;
    }
    if (f_gcs_pub) fclose(f_gcs_pub);

    crypto_eddsa_key_pair(uav_id_secret, uav_id_public, uav_id_seed);
    printf("Identity loaded: EdDSA Keys loaded successfully\n");

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
    gcs_telem_addr.sin_port = htons(send_port);
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
    cmd_bind_addr.sin_port = htons(listen_port);
    cmd_bind_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(cmd_sock, (struct sockaddr *)&cmd_bind_addr, sizeof(cmd_bind_addr)) < 0)
    {
        printf("ERROR: Failed to bind command socket to port %u\n", listen_port);
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

    printf("Telemetry -> %s:%u (direct GCS connection)\n", gcs_ip, send_port);
    printf("Commands  <- 0.0.0.0:%u (direct GCS connection)\n", listen_port);
    printf("Status: DISARMED | Mode: MANUAL\n");
    printf("Waiting for commands...\n\n");

    // Generate ECDH Keys
    srand((unsigned int)time(NULL) ^ 0x0A0B);
    for (int i = 0; i < 32; i++)
        private_key[i] = rand() & 0xFF;
    crypto_x25519_public_key(public_key, private_key);
    printf("ECDH: UAV Public Key generated. Waiting for GCS connection...\n");

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
#ifdef _WIN32
        int recv_len = recvfrom(cmd_sock, (char *)cmd_recv_buf, sizeof(cmd_recv_buf), 0,
                                (struct sockaddr *)&sender_addr, &sender_len);
#else
        int recv_len = recvfrom(cmd_sock, (char *)cmd_recv_buf, sizeof(cmd_recv_buf), 0,
                                (struct sockaddr *)&sender_addr, (socklen_t *)&sender_len);
#endif

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

                        // Determine header length for AAD (includes entire header from SOF)
                        uint8_t stream_type = ((cmd_parser.header_buf[1] & 0x3) << 2) |
                                              ((cmd_parser.header_buf[2] >> 6) & 0x3);
                        bool is_cmd = (stream_type == UL_STREAM_CMD || stream_type == UL_STREAM_CMD_ACK);
                        size_t header_len = 4 + (is_cmd ? 5 : 4) + (cmd_parser.header_buf[3] & UL_FLAG_ENCRYPTED ? 8 : 0);

                        // Need monocypher for decryption
                        extern int crypto_aead_unlock(
                            uint8_t *plain_text,
                            const uint8_t mac[16],
                            const uint8_t key[32],
                            const uint8_t nonce[24],
                            const uint8_t *ad, size_t ad_size,
                            const uint8_t *cipher_text, size_t text_size);

                        int auth_result = crypto_aead_unlock(
                            parse_buf, cmd_parser.cipher_tag, session_key, nonce24,
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
                    case UL_MSG_KEY_EXCHANGE:
                    {
                        ul_key_exchange_t rx_kx;
                        ul_deserialize_key_exchange(&rx_kx, parse_buf);

                        // Ignore duplicate KEY_EXCHANGE (same seq_num we already processed)
                        if (ecdh_state == UL_ECDH_ESTABLISHED && rx_kx.seq_num == ecdh_peer_seq)
                        {
                            printf("  (Duplicate KEY_EXCHANGE seq=%u, already established)\n", rx_kx.seq_num);
                            break;
                        }

                        // Authenticate incoming Key Exchange Request
                        uint8_t data_to_sign[33];
                        memcpy(data_to_sign, rx_kx.public_key, 32);
                        data_to_sign[32] = rx_kx.seq_num;
                        if (crypto_eddsa_check(rx_kx.signature, gcs_id_public, data_to_sign, 33) != 0)
                        {
                            printf("  >>> ECDH FATAL: EdDSA signature verification failed. MITM detected!\n");
                            break;
                        }

                        // Always send our KEY_EXCHANGE when we receive peer's KEY_EXCHANGE
                        // This handles crossed-in-flight KEY_EXCHANGE packets and ensures both sides get the key
                        uint8_t raw_shared[32];
                        crypto_x25519(raw_shared, private_key, rx_kx.public_key);
                        crypto_blake2b(session_key, 32, raw_shared, 32);

                        printf("[DEBUG] UAV session_key[0-7]=%02X %02X %02X %02X %02X %02X %02X %02X\n",
                               session_key[0], session_key[1], session_key[2], session_key[3],
                               session_key[4], session_key[5], session_key[6], session_key[7]);
                        fflush(stdout);

                        ecdh_peer_seq = rx_kx.seq_num;

                        printf("  >>> ECDH: Received GCS key (seq=%u), sending UAV key\n", rx_kx.seq_num);

                        // Send our KEY_EXCHANGE immediately
                        ul_key_exchange_t kx_reply = {0};
                        memcpy(kx_reply.public_key, public_key, 32);
                        kx_reply.seq_num = ecdh_seq_num;

                        // Re-use data_to_sign for signing our key
                        memcpy(data_to_sign, public_key, 32);
                        data_to_sign[32] = ecdh_seq_num;
                        crypto_eddsa_sign(kx_reply.signature, uav_id_secret, data_to_sign, 33);

                        uint8_t kx_payload[97];
                        int kx_payload_len = ul_serialize_key_exchange(&kx_reply, kx_payload);

                        ul_header_t kx_hdr = {0};
                        kx_hdr.payload_len = kx_payload_len;
                        kx_hdr.priority = UL_PRIO_HIGH;
                        kx_hdr.stream_type = UL_STREAM_CMD;
                        kx_hdr.encrypted = false;
                        kx_hdr.sequence = state.sequence++;
                        kx_hdr.sys_id = 1;
                        kx_hdr.comp_id = 1;
                        kx_hdr.target_sys_id = 255;
                        kx_hdr.msg_id = UL_MSG_KEY_EXCHANGE;

                        uint8_t *kx_buf = NULL;
                        int kx_pkt_len = ul_pack_fast(&pool, &kx_hdr, kx_payload, session_key,
                                                      &nonce_state, &crypto_ctx, &kx_buf);
                        if (kx_pkt_len > 0 && kx_buf)
                        {
                            sendto(telem_sock, (char *)kx_buf, kx_pkt_len, 0,
                                   (struct sockaddr *)&gcs_telem_addr, sizeof(gcs_telem_addr));
                            ul_mempool_free(&pool, kx_buf);
                        }

                        // Mark ESTABLISHED immediately - we have both keys now
                        ecdh_state = UL_ECDH_ESTABLISHED;
                        ecdh_retry_count = 0;
                        ecdh_last_send_time = get_time_ms();

                        printf("  >>> ECDH: Session ESTABLISHED! (received GCS key, sent UAV key)\n");
                        printf("[UAVLink] Unicorn, Alpha, Victor. Link is hot.\n");
                        fflush(stdout);

                        // Send ACK when we receive KEY_EXCHANGE
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
                        ack_hdr.sequence = state.sequence++;
                        ack_hdr.sys_id = 1;
                        ack_hdr.comp_id = 1;
                        ack_hdr.target_sys_id = 255;
                        ack_hdr.msg_id = UL_MSG_KEY_EXCHANGE_ACK;

                        uint8_t *ack_buf = NULL;
                        int ack_pkt_len = ul_pack_fast(&pool, &ack_hdr, ack_payload, session_key,
                                                       &nonce_state, &crypto_ctx, &ack_buf);
                        if (ack_pkt_len > 0 && ack_buf)
                        {
                            sendto(telem_sock, (char *)ack_buf, ack_pkt_len, 0,
                                   (struct sockaddr *)&gcs_telem_addr, sizeof(gcs_telem_addr));
                            ul_mempool_free(&pool, ack_buf);
                        }
                        break;
                    }
                    case UL_MSG_KEY_EXCHANGE_ACK:
                    {
                        ul_key_exchange_ack_t rx_ack;
                        ul_deserialize_key_exchange_ack(&rx_ack, parse_buf);

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
                                printf("  >>> ECDH: Received ACK for seq=%u, session ESTABLISHED!\n", ecdh_seq_num);
                                printf("[UAVLink] Unicorn, Alpha, Victor. Link is hot.\n");
                                fflush(stdout);
                            } else {
                                printf("  >>> ECDH: Received ACK for seq=%u (waiting for GCS KEY_EXCHANGE)\n", ecdh_seq_num);
                            }
                        }
                        else if (rx_ack.seq_num == ecdh_seq_num && ecdh_state == UL_ECDH_ESTABLISHED)
                        {
                            printf("  (ACK for seq=%u received, session already established)\n", ecdh_seq_num);
                        }
                        else
                        {
                            printf("  (Ignoring ACK seq=%u, expected=%u, state=%u)\n",
                                   rx_ack.seq_num, ecdh_seq_num, ecdh_state);
                        }
                        break;
                    }
                    case UL_MSG_CMD:
                    {
                        if (ecdh_state != UL_ECDH_ESTABLISHED)
                            break;

                        ul_command_t cmd;
                        ul_deserialize_command(&cmd, parse_buf);
                        printf("Command received: 0x%04X param1=%u\n", cmd.command_id, cmd.param1);

                        ul_command_ack_t ack = process_command(&state, &cmd);
                        send_ack(telem_sock, &gcs_telem_addr, &ack, &state,
                                 &pool, &nonce_state, &crypto_ctx);
                        break;
                    }
                    case UL_MSG_MODE_CHANGE:
                    {
                        if (ecdh_state != UL_ECDH_ESTABLISHED)
                            break;

                        ul_mode_change_t mode;
                        ul_deserialize_mode_change(&mode, parse_buf);
                        printf("Mode change -> %s (0x%02X)\n",
                               get_mode_name(mode.mode), mode.mode);

                        state.flight_mode = mode.mode;

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
    next_iter:; // Empty statement required after label before declaration

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
            if ((loop - last_gcs_msg_time) > 30 && state.flight_mode != UL_MODE_RTL && state.flight_mode != UL_MODE_LAND)
            {
                printf("\n>>> FAILSAFE TRIGGERED: Link Lost! Auto-RTL engaged. <<<\n\n");
                state.flight_mode = UL_MODE_RTL;
            }
        }

        // --- Send telemetry ---

        // ECDH Handshake with Exponential Backoff and Timeout
        if (ecdh_state != UL_ECDH_ESTABLISHED)
        {
            uint32_t current_time = get_time_ms();

            // Check for timeout - restart handshake if we've been stuck
            if (ecdh_state != UL_ECDH_IDLE &&
                (current_time - ecdh_last_send_time) > ecdh_timeout_ms)
            {
                printf("\n>>> ECDH: Timeout! Restarting handshake (was in state %u) <<<\n", ecdh_state);
                printf("[UAVLink] A half-blood's patience has limits. Connection timed out.\n");
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
                crypto_eddsa_sign(kx.signature, uav_id_secret, data_to_sign, 33);

                uint8_t payload[97];
                int payload_len = ul_serialize_key_exchange(&kx, payload);

                ul_header_t header = {0};
                header.payload_len = payload_len;
                header.priority = UL_PRIO_HIGH;
                header.stream_type = UL_STREAM_CMD;
                header.encrypted = false;
                header.sequence = state.sequence++;
                header.sys_id = 1;
                header.comp_id = 1;
                header.target_sys_id = 255; // GCS
                header.msg_id = UL_MSG_KEY_EXCHANGE;

                uint8_t *packet_buf = NULL;
                int packet_len = ul_pack_fast(&pool, &header, payload, session_key,
                                              &nonce_state, &crypto_ctx, &packet_buf);
                if (packet_len > 0 && packet_buf)
                {
                    sendto(telem_sock, (char *)packet_buf, packet_len, 0,
                           (struct sockaddr *)&gcs_telem_addr, sizeof(gcs_telem_addr));
                    ul_mempool_free(&pool, packet_buf);

                    ecdh_state = UL_ECDH_SENT_KEY;
                    ecdh_last_send_time = current_time;
                    ecdh_retry_count++;

                    if (ecdh_retry_count == 1)
                        printf("\n>>> ECDH: Sending KEY_EXCHANGE seq=%u <<<\n", ecdh_seq_num);
                    else
                        printf(">>> ECDH: Retry #%u (backoff=%ums) seq=%u <<<\n",
                               ecdh_retry_count - 1, backoff_ms, ecdh_seq_num);
                }
            }
        }

        if (ecdh_state != UL_ECDH_ESTABLISHED)
            goto end_loop;

        // Heartbeat (1 Hz)
        if (loop % 10 == 0)
        {
            ul_heartbeat_t hb = {0};
            hb.system_status = state.armed ? 0x04 : 0x03; // Active vs Standby
            hb.system_type = 0x02;                        // Quadcopter
            hb.base_mode = state.armed ? 0x81 : 0x01;     // Armed flag in bit 7
            hb.base_mode |= (state.flight_mode << 2);

            uint8_t payload[32];
            int payload_len = ul_serialize_heartbeat(&hb, payload);

            ul_header_t header = {0};
            header.payload_len = payload_len;
            header.priority = UL_PRIO_NORMAL;
            header.stream_type = UL_STREAM_HEARTBEAT;
            header.sequence = state.sequence++;
            header.sys_id = 1;
            header.comp_id = 1;
            header.msg_id = UL_MSG_HEARTBEAT;

            uint8_t *packet_buf = NULL;
            int packet_len = ul_pack_fast(&pool, &header, payload, session_key,
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
            header.sequence = state.sequence++;
            header.sys_id = 1;
            header.comp_id = 1;
            header.msg_id = UL_MSG_ATTITUDE;

            uint8_t *packet_buf = NULL;
            int packet_len = ul_pack_fast(&pool, &header, payload, session_key,
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
            header.sequence = state.sequence++;
            header.sys_id = 1;
            header.comp_id = 1;
            header.msg_id = UL_MSG_GPS_RAW;

            uint8_t *packet_buf = NULL;
            int packet_len = ul_pack_fast(&pool, &header, payload, session_key,
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

    end_loop:; // End loop label

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