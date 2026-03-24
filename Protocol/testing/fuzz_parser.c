#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../uavlink.h"

// Provide a dummy key for testing the decryption path
static const uint8_t DUMMY_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
};

// libFuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    ul_parser_t parser;
    ul_parser_init(&parser);

    // Feed the random fuzzing data into the parser byte by byte
    for (size_t i = 0; i < Size; i++) {
        ul_parse_char(&parser, Data[i], DUMMY_KEY);
    }

    return 0; // Always return 0
}

#ifndef LIBFUZZER_ENABLED
// Standalone fuzzer fallback if libFuzzer is not available (using GCC)
int main(int argc, char **argv) {
    printf("Starting standalone fuzzing fallback...\n");
    srand(time(NULL));
    
    uint8_t random_buffer[1024];
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    long iterations = 1000000;
    if (argc > 1) {
        iterations = atol(argv[1]);
    }
    
    printf("Running %ld fuzzing iterations...\n", iterations);
    
    for (long iter = 0; iter < iterations; iter++) {
        size_t size = rand() % sizeof(random_buffer);
        for (size_t i = 0; i < size; i++) {
            random_buffer[i] = rand() & 0xFF;
        }
        
        // Feed into parser
        ul_parser_init(&parser);
        for (size_t i = 0; i < size; i++) {
            ul_parse_char(&parser, random_buffer[i], DUMMY_KEY);
        }
        
        if (iter % 100000 == 0) {
            printf("Progress: %ld / %ld\n", iter, iterations);
        }
    }
    
    printf("Fuzzing complete. No crashes detected.\n");
    return 0;
}
#endif
