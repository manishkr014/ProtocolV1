#include "monocypher.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <seed.bin> <output_pub.bin>\n", argv[0]);
        return 1;
    }

    FILE *f_seed = fopen(argv[1], "rb");
    if (!f_seed) {
        printf("Error: Cannot open seed file %s\n", argv[1]);
        return 1;
    }

    uint8_t seed[32];
    if (fread(seed, 1, 32, f_seed) != 32) {
        printf("Error: Seed file must be exactly 32 bytes\n");
        fclose(f_seed);
        return 1;
    }
    fclose(f_seed);

    uint8_t secret_key[64];
    uint8_t public_key[32];
    
    // Generate the EdDSA keypair from the 32-byte seed
    crypto_eddsa_key_pair(secret_key, public_key, seed);

    FILE *f_pub = fopen(argv[2], "wb");
    if (!f_pub) {
        printf("Error: Cannot open output file %s\n", argv[2]);
        return 1;
    }

    fwrite(public_key, 1, 32, f_pub);
    fclose(f_pub);

    printf("Successfully generated public key %s from seed %s\n", argv[2], argv[1]);
    return 0;
}
