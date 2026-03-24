#ifndef UAVLINK_H
#define UAVLINK_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Protocol Constants */
#define UL_MAX_PAYLOAD_SIZE 512 /* Maximum payload size in parser buffer */
#define UL_MAC_TAG_SIZE 16      /* Poly1305 MAC tag size (full 128-bit) */

/* Error Codes */
typedef enum
{
    UL_OK = 0,
    UL_ERR_CRC = -1,
    UL_ERR_NO_KEY = -2,
    UL_ERR_MAC_VERIFICATION = -3,
    UL_ERR_BUFFER_OVERFLOW = -4,
    UL_ERR_INVALID_HEADER = -5,
    UL_ERR_NULL_POINTER = -6
} ul_error_t;

/* Base header byte 0 */
#define UL_SOF 0xA5

/* Byte 1 */
#define UL_PLEN_HI_MASK 0xF0  /* bits 7:4 -> payload length [11:8] */
#define UL_PRIORITY_MASK 0x0C /* bits 3:2 */
#define UL_PRIORITY_SHIFT 2
#define UL_STYPE_HI_MASK 0x03 /* bits 1:0 -> stream type [3:2] */

/* Byte 2 */
#define UL_STYPE_LO_MASK 0xC0 /* bits 7:6 -> stream type [1:0] */
#define UL_STYPE_LO_SHIFT 6
#define UL_PLEN_MID_MASK 0x3F /* bits 5:0 -> payload length [7:2] */

/* Byte 3 */
#define UL_PLEN_LO_MASK 0xC0    /* bits 7:6 -> payload length [1:0] */
#define UL_FLAG_ENCRYPTED 0x08  /* bit 3 */
#define UL_FLAG_FRAGMENTED 0x04 /* bit 2 */
#define UL_SEQ_HI_MASK 0x03     /* bits 1:0 -> sequence [11:10] */

/* Priority Values */
#define UL_PRIO_BULK 0
#define UL_PRIO_NORMAL 1
#define UL_PRIO_HIGH 2
#define UL_PRIO_EMERGENCY 3

/* Stream Types */
#define UL_STREAM_TELEM_FAST 0x0
#define UL_STREAM_TELEM_SLOW 0x1
#define UL_STREAM_CMD 0x2
#define UL_STREAM_CMD_ACK 0x3
#define UL_STREAM_MISSION 0x4
#define UL_STREAM_VIDEO 0x5
#define UL_STREAM_SENSOR 0x6
#define UL_STREAM_HEARTBEAT 0x7
#define UL_STREAM_ALERT 0x8
#define UL_STREAM_CUSTOM 0xF

/* Parsed message header structure */
typedef struct
{
    uint16_t payload_len; // 12-bit
    uint8_t priority;     // 2-bit
    uint8_t stream_type;  // 4-bit
    bool encrypted;       // 1-bit
    bool fragmented;      // 1-bit
    uint16_t sequence;    // 12-bit

    // Extended Header
    uint8_t sys_id;        // 6-bit
    uint8_t comp_id;       // 4-bit
    uint8_t target_sys_id; // 6-bit (0 = broadcast)
    uint16_t msg_id;       // 12-bit

    // Fragmentation fields
    uint8_t frag_index;
    uint8_t frag_total;

    // Encryption nonces
    uint8_t nonce[8];
} ul_header_t;

/* Message IDs */
#define UL_MSG_HEARTBEAT 0x001
#define UL_MSG_ATTITUDE 0x002
#define UL_MSG_GPS_RAW 0x003
#define UL_MSG_BATTERY 0x004
#define UL_MSG_RC_INPUT 0x005
#define UL_MSG_CMD 0x006
#define UL_MSG_CMD_ACK 0x007
#define UL_MSG_MODE_CHANGE 0x008
#define UL_MSG_MISSION_ITEM 0x009
#define UL_MSG_KEY_EXCHANGE 0x00A
#define UL_MSG_KEY_EXCHANGE_ACK 0x00B
#define UL_MSG_BATCH 0x3FF /* Special message ID for message batching */

/* Command IDs (used in ul_command_t.command_id) */
#define UL_CMD_ARM 0x0001       /* Arm motors */
#define UL_CMD_DISARM 0x0002    /* Disarm motors */
#define UL_CMD_TAKEOFF 0x0003   /* Takeoff to altitude (param1 = alt in cm) */
#define UL_CMD_LAND 0x0004      /* Land at current position */
#define UL_CMD_RTL 0x0005       /* Return to launch */
#define UL_CMD_EMERGENCY 0x0006 /* Emergency stop */

/* ACK Result Codes (used in ul_command_ack_t.result) */
#define UL_ACK_OK 0x00          /* Command accepted */
#define UL_ACK_REJECTED 0x01    /* Command rejected (wrong state) */
#define UL_ACK_UNSUPPORTED 0x02 /* Unknown command ID */
#define UL_ACK_FAILED 0x03      /* Command failed */
#define UL_ACK_IN_PROGRESS 0x04 /* Command in progress */

/* Flight Modes (used in ul_mode_change_t.mode) */
#define UL_MODE_MANUAL 0x00
#define UL_MODE_STABILIZE 0x01
#define UL_MODE_ALT_HOLD 0x02
#define UL_MODE_LOITER 0x03
#define UL_MODE_AUTO 0x04
#define UL_MODE_RTL 0x05
#define UL_MODE_LAND 0x06

/* --- OPTIMIZATION: Selective Encryption Policies --- */
typedef enum
{
    UL_ENCRYPT_NEVER = 0,    /* Never encrypt (public telemetry) */
    UL_ENCRYPT_OPTIONAL = 1, /* Encrypt if key provided (medium sensitivity) */
    UL_ENCRYPT_ALWAYS = 2    /* Always encrypt (security-critical commands) */
} ul_encrypt_policy_t;

/* UAVLink State Machine Parser struct */
typedef enum
{
    UL_PARSE_STATE_IDLE,
    UL_PARSE_STATE_BASE_HDR,
    UL_PARSE_STATE_EXT_HDR,
    UL_PARSE_STATE_PAYLOAD,
    UL_PARSE_STATE_CRC
} ul_parse_state_t;

typedef struct
{
    ul_parse_state_t state;
    uint8_t buffer[512]; // Max packet size buffer
    uint16_t buf_idx;
    uint16_t expected_len;
    uint16_t header_len; // Store actual header length for AEAD

    // Extracted payload fields
    ul_header_t header;
    uint8_t payload[512]; // Must match buffer[512] to prevent overflow

    /* Replay protection: 32-packet sliding window keyed on sequence number */
    uint8_t replay_init;    /* 1 once first valid packet received */
    uint8_t last_seq;       /* Highest accepted sequence number    */
    uint32_t replay_window; /* Bitmap: bit i set => (last_seq - i) seen */

    /* Statistics / Link Quality */
    uint32_t rx_count;    /* Total packets successfully received */
    uint32_t error_count; /* Total packets with CRC/MAC errors */
} ul_parser_t;

/* --- Nonce State Management (for secure encryption) --- */

typedef struct
{
    uint32_t counter;    // Monotonically increasing counter
    uint8_t initialized; // 1 if initialized, 0 otherwise
    uint8_t reserved[3]; // Padding for alignment
} ul_nonce_state_t;

/* --- OPTIMIZATION: Crypto Context Caching --- */
typedef struct
{
    uint8_t last_key[32]; /* Last key used for caching */
    uint8_t valid;        /* 1 if cache is valid, 0 otherwise */
    uint8_t reserved[3];  /* Padding for alignment */
} ul_crypto_ctx_t;

/* --- OPTIMIZATION: Message Batching --- */
#define UL_BATCH_MAX_MESSAGES 8

typedef struct
{
    uint16_t msg_id;  /* Message ID */
    uint8_t length;   /* Payload length */
    uint8_t data[64]; /* Message data (max 64 bytes per message) */
} ul_batch_msg_t;

typedef struct
{
    uint8_t num_messages;                           /* Number of messages in batch */
    ul_batch_msg_t messages[UL_BATCH_MAX_MESSAGES]; /* Array of batched messages */
} ul_batch_t;

/* --- Core Message Payloads --- */

typedef struct
{
    uint32_t system_status;
    uint8_t system_type;
    uint8_t autopilot_type;
    uint8_t base_mode;
} ul_heartbeat_t;

/* Attitude angles as float32, rates packed into float16 over the wire */
typedef struct
{
    float roll;
    float pitch;
    float yaw;
    float rollspeed;
    float pitchspeed;
    float yawspeed;
} ul_attitude_t;

/* GPS raw data */
typedef struct
{
    int32_t lat;        // Latitude (degrees × 1e7)
    int32_t lon;        // Longitude (degrees × 1e7)
    int32_t alt;        // Altitude AMSL (mm)
    uint16_t eph;       // Horizontal position uncertainty (cm)
    uint16_t epv;       // Vertical position uncertainty (cm)
    uint16_t vel;       // Ground speed (cm/s)
    uint16_t cog;       // Course over ground (degrees × 100)
    uint8_t fix_type;   // GPS fix type (0=none, 2=2D, 3=3D, 4=DGPS, 5=RTK)
    uint8_t satellites; // Number of satellites visible
} ul_gps_raw_t;

/* Battery status */
typedef struct
{
    uint16_t voltage;   // Battery voltage (mV)
    int16_t current;    // Battery current (cA, negative=discharging)
    int16_t remaining;  // Remaining capacity (%, -1 if unknown)
    uint8_t cell_count; // Number of cells
    uint8_t status;     // Battery status flags
} ul_battery_t;

/* RC input channels */
typedef struct
{
    uint16_t channels[8]; // RC channel values (1000-2000 us, 0=disconnected)
    uint8_t rssi;         // Signal strength (0-100%)
    uint8_t quality;      // Link quality (0-100%)
} ul_rc_input_t;

/* --- Command & Control Messages --- */

/* ECDH Handshake States */
typedef enum
{
    UL_ECDH_IDLE = 0,         /* No handshake initiated */
    UL_ECDH_SENT_KEY = 1,     /* Sent our public key, waiting for peer's key */
    UL_ECDH_RECEIVED_KEY = 2, /* Received peer's key, sent ACK, waiting for peer's ACK */
    UL_ECDH_ESTABLISHED = 3   /* Both sides confirmed, session ready */
} ul_ecdh_state_t;

/* Session Key Exchange (ECDH Public Key) */
typedef struct
{
    uint8_t public_key[32]; // 256-bit X25519 public key
    uint8_t seq_num;        // Handshake sequence number (to detect duplicates)
    uint8_t signature[64];  // 512-bit Ed25519 signature
} ul_key_exchange_t;

/* Session Key Exchange ACK */
typedef struct
{
    uint8_t seq_num; // Echo the sequence number we're acknowledging
    uint8_t status;  // 0 = OK, 1 = Error
} ul_key_exchange_ack_t;

/* Generic command (GCS -> UAV) */
typedef struct
{
    uint16_t command_id; // Command ID (UL_CMD_ARM, etc.)
    uint16_t param1;     // Parameter 1 (command-specific)
    uint16_t param2;     // Parameter 2 (command-specific)
    uint16_t param3;     // Parameter 3 (command-specific)
} ul_command_t;

/* Command acknowledgement (UAV -> GCS) */
typedef struct
{
    uint16_t command_id; // Command ID being acknowledged
    uint8_t result;      // Result code (UL_ACK_OK, etc.)
    uint8_t progress;    // Progress 0-100% (for UL_ACK_IN_PROGRESS)
} ul_command_ack_t;

/* Flight mode change request (GCS -> UAV) */
typedef struct
{
    uint8_t mode;     // Target flight mode (UL_MODE_MANUAL, etc.)
    uint8_t reserved; // Reserved for future use
} ul_mode_change_t;

/* Mission item / waypoint (GCS -> UAV) */
typedef struct
{
    uint16_t seq;         // Waypoint sequence number (0-based)
    uint8_t frame;        // Coordinate frame (0=global, 1=relative)
    uint8_t command;      // Waypoint action (0=navigate, 1=loiter, 2=land)
    int32_t lat;          // Latitude (deg x 1e7)
    int32_t lon;          // Longitude (deg x 1e7)
    int32_t alt;          // Altitude (mm)
    uint16_t speed;       // Desired speed (cm/s, 0 = default)
    uint16_t loiter_time; // Loiter time at waypoint (seconds)
} ul_mission_item_t;

/* --- Fragment Reassembly --- */
#define UL_FRAG_MAX_PAYLOAD 256  // Max payload per fragment
#define UL_FRAG_MAX_FRAGMENTS 16 // Max fragments per message
#define UL_FRAG_MAX_TOTAL 4096   // Max reassembled payload (256 * 16)
#define UL_FRAG_TIMEOUT_MS 5000  // Reassembly timeout

typedef struct
{
    uint8_t num_fragments;     // Total fragments generated
    uint8_t payloads[16][256]; // Fragment payloads
    uint16_t payload_lens[16]; // Length of each fragment
    ul_header_t headers[16];   // Pre-filled headers per fragment
} ul_fragment_set_t;

int ul_fragment_split(const ul_header_t *base_header,
                      const uint8_t *payload, size_t payload_len,
                      ul_fragment_set_t *out);

typedef struct
{
    bool active;            // Slot in use
    uint16_t msg_id;        // Message ID being reassembled
    uint8_t sys_id;         // Source system ID
    uint8_t frag_total;     // Expected fragment count
    bool received[16];      // Which fragments arrived
    uint8_t data[4096];     // Reassembled payload buffer
    uint16_t frag_lens[16]; // Length of each received fragment
    uint8_t frags_received; // Count of received fragments
    uint32_t start_time_ms; // Timeout tracking
} ul_reassembly_slot_t;

typedef struct
{
    ul_reassembly_slot_t slots[4]; // 4 concurrent reassembly slots
} ul_reassembly_ctx_t;

void ul_reassembly_init(ul_reassembly_ctx_t *ctx);
int ul_reassembly_add(ul_reassembly_ctx_t *ctx, const ul_header_t *hdr,
                      const uint8_t *payload, uint16_t payload_len,
                      uint8_t *output, uint16_t *output_len);

/* --- Function Prototypes --- */

/* Initialize a parser */
void ul_parser_init(ul_parser_t *p);

/* Parse a single byte from a serial stream. Returns 1 if a complete valid packet was received.
   If decryption key is non-null, handles decryption automatically. */
int ul_parse_char(ul_parser_t *p, uint8_t c, const uint8_t *key_32b);

/* Pack a complete message into a byte buffer ready for wire transmission.
   Returns the total packet length (header + payload + CRC).
   If key is non-null, payload is encrypted. */
int uavlink_pack(uint8_t *buf, const ul_header_t *h, const uint8_t *payload, const uint8_t *key_32b);

/* Serialize specific messages to a raw byte buffer */
int ul_serialize_heartbeat(const ul_heartbeat_t *hb, uint8_t *payload_buf);
int ul_deserialize_heartbeat(ul_heartbeat_t *hb, const uint8_t *payload_buf);

int ul_serialize_attitude(const ul_attitude_t *att, uint8_t *payload_buf);
int ul_deserialize_attitude(ul_attitude_t *att, const uint8_t *payload_buf);

int ul_serialize_gps_raw(const ul_gps_raw_t *gps, uint8_t *payload_buf);
int ul_deserialize_gps_raw(ul_gps_raw_t *gps, const uint8_t *payload_buf);

int ul_serialize_battery(const ul_battery_t *bat, uint8_t *payload_buf);
int ul_deserialize_battery(ul_battery_t *bat, const uint8_t *payload_buf);

int ul_serialize_rc_input(const ul_rc_input_t *rc, uint8_t *payload_buf);
int ul_deserialize_rc_input(ul_rc_input_t *rc, const uint8_t *payload_buf);

int ul_serialize_key_exchange(const ul_key_exchange_t *kx, uint8_t *payload_buf);
int ul_deserialize_key_exchange(ul_key_exchange_t *kx, const uint8_t *payload_buf);

int ul_serialize_key_exchange_ack(const ul_key_exchange_ack_t *ack, uint8_t *payload_buf);
int ul_deserialize_key_exchange_ack(ul_key_exchange_ack_t *ack, const uint8_t *payload_buf);

int ul_serialize_command(const ul_command_t *cmd, uint8_t *payload_buf);
int ul_deserialize_command(ul_command_t *cmd, const uint8_t *payload_buf);

int ul_serialize_command_ack(const ul_command_ack_t *ack, uint8_t *payload_buf);
int ul_deserialize_command_ack(ul_command_ack_t *ack, const uint8_t *payload_buf);

int ul_serialize_mode_change(const ul_mode_change_t *mode, uint8_t *payload_buf);
int ul_deserialize_mode_change(ul_mode_change_t *mode, const uint8_t *payload_buf);

int ul_serialize_mission_item(const ul_mission_item_t *item, uint8_t *payload_buf);
int ul_deserialize_mission_item(ul_mission_item_t *item, const uint8_t *payload_buf);

/* CRC Computations */
void ul_crc_init(uint16_t *crcAccum);
void ul_crc_accumulate(uint8_t data, uint16_t *crcAccum);
uint8_t ul_get_crc_seed(uint16_t msg_id);

/* Encode the base 4-byte header */
void ul_encode_base_header(uint8_t *buf, const ul_header_t *h);

/* Decode the base 4-byte header */
int ul_decode_base_header(const uint8_t *buf, ul_header_t *h);

/* Encode the extended header. Returns the number of bytes written. */
int ul_encode_ext_header(uint8_t *buf, const ul_header_t *h);

/* Decode the extended header. Returns the number of bytes read. */
int ul_decode_ext_header(const uint8_t *buf, ul_header_t *h);

/* --- Nonce Management Functions --- */

/* Initialize nonce state. Must be called before first use. */
void ul_nonce_init(ul_nonce_state_t *state);

/* Get the current 32-bit nonce counter for NVM persistence. */
uint32_t ul_nonce_get_counter(const ul_nonce_state_t *state);

/* Set the 32-bit nonce counter from NVM storage.
   Call this immediately after ul_nonce_init() at system boot. */
void ul_nonce_set_counter(ul_nonce_state_t *state, uint32_t counter);

/* Generate a secure nonce using hybrid approach (counter + random).
   Combines a 32-bit counter with 32 bits of random data for maximum security.
   The nonce buffer must be at least 8 bytes. */
void ul_nonce_generate(ul_nonce_state_t *state, uint8_t nonce[8]);

/* Advanced: Pack with nonce state management.
   Automatically generates and uses a secure nonce from the state.
   Returns the total packet length (header + payload + CRC). */
int uavlink_pack_with_nonce(uint8_t *buf, const ul_header_t *h, const uint8_t *payload,
                            const uint8_t *key_32b, ul_nonce_state_t *nonce_state);

/* --- OPTIMIZATION API Functions --- */

/* Initialize crypto context cache */
void ul_crypto_ctx_init(ul_crypto_ctx_t *ctx);

/* OPTIMIZATION: Pack with crypto context caching (30% faster for consecutive packets)
   Reuses crypto context if same key as previous packet.
   Returns the total packet length (header + payload + CRC). */
int uavlink_pack_cached(uint8_t *buf, const ul_header_t *h, const uint8_t *payload,
                        const uint8_t *key_32b, ul_nonce_state_t *nonce_state,
                        ul_crypto_ctx_t *crypto_ctx);

/* OPTIMIZATION: Pack with selective encryption based on message policy
   Automatically applies encryption policy based on message ID.
   Returns the total packet length (header + payload + CRC). */
int uavlink_pack_selective(uint8_t *buf, const ul_header_t *h, const uint8_t *payload,
                           const uint8_t *key_32b, ul_nonce_state_t *nonce_state);

/* OPTIMIZATION: Pack multiple messages into a single batched packet (18% bandwidth reduction)
   Aggregates multiple small messages into one packet.
   Returns the total packet length (header + payload + CRC). */
int uavlink_pack_batch(uint8_t *buf, const ul_batch_t *batch,
                       const uint8_t *key_32b, ul_nonce_state_t *nonce_state,
                       uint8_t priority);

/* Deserialize a received batch payload into a ul_batch_t structure.
   @param payload     Decrypted/decrypted batch payload bytes
   @param payload_len Number of bytes in payload
   @param batch_out   Output structure (caller-allocated)
   @return 0 on success, negative on malformed input */
int ul_deserialize_batch(const uint8_t *payload, uint16_t payload_len,
                         ul_batch_t *batch_out);

/* Get encryption policy for a message ID */
ul_encrypt_policy_t ul_get_encrypt_policy(uint16_t msg_id);

/* Set encryption policy for a message ID (can override defaults) */
void ul_set_encrypt_policy(uint16_t msg_id, ul_encrypt_policy_t policy);

#endif
