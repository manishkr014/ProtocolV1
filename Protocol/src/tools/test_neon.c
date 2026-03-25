#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "../core/uavlink_hw_crypto.h"
#include "../core/monocypher.h"

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    printf("--- UAVLink NEON Known Answer Test (KAT) ---\n");

#if UL_HW_NEON_AVAILABLE
    uint8_t key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    
    // DJB standard 64-bit nonce
    uint8_t nonce[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    // 192-byte test vector (3 full blocks)
    size_t len = 192;
    uint8_t plaintext[192];
    for (size_t i = 0; i < len; i++) {
        plaintext[i] = i & 0xFF;
    }

    uint8_t ciphertext_neon[192] = {0};
    uint8_t ciphertext_mono[192] = {0};

    // Run Monocypher (Software Baseline)
    // crypto_chacha20_djb(output, input, len, key, nonce, Initial Counter)
    crypto_chacha20_djb(ciphertext_mono, plaintext, len, key, nonce, 1);

    // Run NEON
    ul_chacha20_neon(key, nonce, plaintext, ciphertext_neon, len, 1);

    // Compare
    if (memcmp(ciphertext_mono, ciphertext_neon, len) == 0) {
        printf("[SUCCESS] NEON keystream matches Monocypher perfectly!\n");
        return 0;
    } else {
        printf("[FAILED] NEON keystream differs from Monocypher!\n");
        // Print first 64 bytes for debugging
        print_hex("Mono", ciphertext_mono, 64);
        print_hex("NEON", ciphertext_neon, 64);
        return 1;
    }
#else
    printf("[SKIP] NEON hardware not available on this architecture.\n");
    return 0;
#endif
}
