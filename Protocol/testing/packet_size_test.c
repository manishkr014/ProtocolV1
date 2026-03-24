#include "uavlink.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_TOTAL_PAYLOAD 4095
#define RANDOM_CASES 50

static void fill_pattern(uint8_t *buf, size_t len, uint32_t seed)
{
    for (size_t i = 0; i < len; i++)
    {
        buf[i] = (uint8_t)((seed + (uint32_t)i) & 0xFF);
    }
}

static int parse_packet(ul_parser_t *parser, const uint8_t *packet, size_t packet_len,
                        ul_header_t *out_hdr, uint8_t *out_payload)
{
    for (size_t i = 0; i < packet_len; i++)
    {
        int res = ul_parse_char(parser, packet[i], NULL);
        if (res == UL_OK)
        {
            *out_hdr = parser->header;
            memcpy(out_payload, parser->payload, parser->header.payload_len);
            return 1;
        }
        if (res < 0)
        {
            return res;
        }
    }
    return 0;
}

static int test_non_fragmented(uint16_t seq, const uint8_t *payload, size_t payload_len)
{
    uint8_t packet[2048];
    ul_header_t header = {0};
    header.payload_len = (uint16_t)payload_len;
    header.priority = UL_PRIO_NORMAL;
    header.stream_type = UL_STREAM_TELEM_SLOW;
    header.encrypted = false;
    header.fragmented = false;
    header.sequence = seq;
    header.sys_id = 1;
    header.comp_id = 1;
    header.target_sys_id = 0;
    header.msg_id = UL_MSG_HEARTBEAT;

    int packet_len = uavlink_pack(packet, &header, payload, NULL);
    if (packet_len < 0)
    {
        return packet_len;
    }

    ul_parser_t parser;
    ul_parser_init(&parser);

    ul_header_t rx_hdr = {0};
    uint8_t rx_payload[UL_MAX_PAYLOAD_SIZE] = {0};
    int parse_res = parse_packet(&parser, packet, (size_t)packet_len, &rx_hdr, rx_payload);
    if (parse_res != 1)
    {
        return -1000;
    }

    if (rx_hdr.sequence != seq || rx_hdr.payload_len != payload_len)
    {
        return -1001;
    }

    if (payload_len > 0 && memcmp(payload, rx_payload, payload_len) != 0)
    {
        return -1002;
    }

    return 0;
}

static int test_fragmented(uint16_t *seq, const uint8_t *payload, size_t payload_len)
{
    ul_header_t base = {0};
    base.payload_len = 0;
    base.priority = UL_PRIO_NORMAL;
    base.stream_type = UL_STREAM_MISSION;
    base.encrypted = false;
    base.fragmented = true;
    base.sequence = 0;
    base.sys_id = 1;
    base.comp_id = 1;
    base.target_sys_id = 0;
    base.msg_id = UL_MSG_MISSION_ITEM;

    ul_fragment_set_t frags = {0};
    int num_frags = ul_fragment_split(&base, payload, payload_len, &frags);
    if (num_frags <= 0)
    {
        return -2000;
    }

    ul_parser_t parser;
    ul_parser_init(&parser);

    ul_reassembly_ctx_t reasm_ctx;
    ul_reassembly_init(&reasm_ctx);
    uint8_t reasm_output[UL_FRAG_MAX_TOTAL] = {0};
    uint16_t reasm_output_len = 0;

    for (int i = 0; i < num_frags; i++)
    {
        uint8_t packet[2048];
        frags.headers[i].sequence = (*seq)++;
        int packet_len = uavlink_pack(packet, &frags.headers[i], frags.payloads[i], NULL);
        if (packet_len < 0)
        {
            return -2001;
        }

        ul_header_t rx_hdr = {0};
        uint8_t rx_payload[UL_MAX_PAYLOAD_SIZE] = {0};
        int parse_res = parse_packet(&parser, packet, (size_t)packet_len, &rx_hdr, rx_payload);
        if (parse_res != 1)
        {
            return -2002;
        }

        if (!rx_hdr.fragmented)
        {
            return -2003;
        }

        int reasm_res = ul_reassembly_add(&reasm_ctx, &rx_hdr, rx_payload,
                                          rx_hdr.payload_len, reasm_output, &reasm_output_len);
        if (reasm_res < 0)
        {
            return -2004;
        }

        if (i < (num_frags - 1) && reasm_res != 0)
        {
            return -2005;
        }

        if (i == (num_frags - 1) && reasm_res != 1)
        {
            return -2006;
        }
    }

    if (reasm_output_len != payload_len)
    {
        return -2007;
    }

    if (memcmp(payload, reasm_output, payload_len) != 0)
    {
        return -2008;
    }

    return 0;
}

int main(void)
{
    uint8_t payload[MAX_TOTAL_PAYLOAD] = {0};
    uint16_t seq = 1;
    int failures = 0;

    size_t fixed_sizes[] = {0, 1, 2, 10, 64, 128, 255, 256, 257, 512, 1024, 2048, 4095};
    size_t fixed_count = sizeof(fixed_sizes) / sizeof(fixed_sizes[0]);

    srand((unsigned int)time(NULL));

    printf("UAVLink Packet Size Sweep\n");
    printf("-------------------------\n");

    for (size_t i = 0; i < fixed_count; i++)
    {
        size_t len = fixed_sizes[i];
        fill_pattern(payload, len, (uint32_t)len);

        int res = 0;
        if (len <= UL_FRAG_MAX_PAYLOAD)
        {
            res = test_non_fragmented(seq, payload, len);
            seq++;
        }
        else
        {
            res = test_fragmented(&seq, payload, len);
        }

        if (res != 0)
        {
            printf("[FAIL] size=%u seq=%u err=%d\n", (unsigned)len, seq, res);
            failures++;
        }
        else
        {
            printf("[OK]   size=%u seq=%u\n", (unsigned)len, seq);
        }

    }

    for (int i = 0; i < RANDOM_CASES; i++)
    {
        size_t len = (size_t)(rand() % (MAX_TOTAL_PAYLOAD + 1));
        fill_pattern(payload, len, (uint32_t)(i + 1000));

        int res = 0;
        if (len <= UL_FRAG_MAX_PAYLOAD)
        {
            res = test_non_fragmented(seq, payload, len);
            seq++;
        }
        else
        {
            res = test_fragmented(&seq, payload, len);
        }

        if (res != 0)
        {
            printf("[FAIL] size=%u seq=%u err=%d\n", (unsigned)len, seq, res);
            failures++;
        }
        else
        {
            printf("[OK]   size=%u seq=%u\n", (unsigned)len, seq);
        }

    }

    printf("\nSummary: %d failures\n", failures);
    return (failures == 0) ? 0 : 1;
}
