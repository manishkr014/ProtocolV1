/*
 * UAVLink Key Management Example
 *
 * Demonstrates secure key loading and usage with UAVLink protocol.
 * This replaces hardcoded keys with file-based key management.
 */

#include "uavlink.h"
#include "uavlink_fast.h"
#include "uavlink_keymanager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/stat.h>
#endif

// Print key loading status
static void print_key_status(int result, const char *method)
{
    if (result == UL_KEY_OK)
    {
        printf("✓ Key loaded successfully via %s\n", method);
    }
    else
    {
        printf("✗ Key loading failed via %s: %s\n",
               method, ul_key_error_string(result));
    }
}

// Example 1: Load key from binary file
static int example_binary_file(void)
{
    printf("\n=== Example 1: Loading Key from Binary File ===\n");

    uint8_t key[32];
    int result = ul_load_key_from_file("example_key.bin", key, true);
    print_key_status(result, "binary file");

    if (result == UL_KEY_OK)
    {
        // Use key for encryption
        ul_attitude_t att = {
            .roll = 0.1f,
            .pitch = 0.2f,
            .yaw = 1.5f,
            .rollspeed = 0.0f,
            .pitchspeed = 0.0f,
            .yawspeed = 0.0f};

        uint8_t payload[32];
        int payload_len = ul_serialize_attitude(&att, payload);

        ul_header_t header = {
            .payload_len = payload_len,
            .priority = UL_PRIO_NORMAL,
            .stream_type = UL_STREAM_TELEM_FAST,
            .encrypted = true,
            .sequence = 1,
            .sys_id = 1,
            .comp_id = 0,
            .target_sys_id = 0,
            .msg_id = UL_MSG_ATTITUDE};

        uint8_t packet[256];
        int packet_len = uavlink_pack(packet, &header, payload, key);

        if (packet_len > 0)
        {
            printf("  Encrypted packet created: %d bytes\n", packet_len);
        }

        // Clear key from memory
        ul_secure_zero(key, 32);
    }

    return result;
}

// Example 2: Load key from hex file
static int example_hex_file(void)
{
    printf("\n=== Example 2: Loading Key from Hex File ===\n");

    uint8_t key[32];
    int result = ul_load_key_from_hex_file("example_key.txt", key);
    print_key_status(result, "hex file");

    if (result == UL_KEY_OK)
    {
        printf("  Key (first 8 bytes): ");
        for (int i = 0; i < 8; i++)
        {
            printf("%02X ", key[i]);
        }
        printf("\n");

        ul_secure_zero(key, 32);
    }

    return result;
}

// Example 3: Load key from environment variable
static int example_environment(void)
{
    printf("\n=== Example 3: Loading Key from Environment Variable ===\n");
    printf("  Set UAVLINK_KEY environment variable first\n");
    printf("  Example: export UAVLINK_KEY=\"a1b2c3d4...\"\n");

    uint8_t key[32];
    int result = ul_load_key_from_env("UAVLINK_KEY", key, UL_KEY_FORMAT_HEX);
    print_key_status(result, "environment variable");

    if (result == UL_KEY_OK)
    {
        ul_secure_zero(key, 32);
    }

    return result;
}

// Example 4: Generate and save a key
static void example_generate_key(void)
{
    printf("\n=== Example 4: Generating New Key ===\n");
    printf("⚠️  Use keygen.py for production keys!\n");
    printf("  This example uses weak random generation for demo only.\n\n");

    // Generate key (weak - for demonstration only!)
    uint8_t key[32];
    ul_generate_random_key(key);

    // Save to file
    FILE *f = fopen("example_key_generated.bin", "wb");
    if (f != NULL)
    {
        fwrite(key, 1, 32, f);
        fclose(f);
        printf("✓ Key saved to example_key_generated.bin\n");

// Set restrictive permissions (Unix only)
#ifndef _WIN32
        chmod("example_key_generated.bin", 0600);
        printf("✓ File permissions set to 600\n");
#endif
    }
    else
    {
        printf("✗ Failed to save key\n");
    }

    ul_secure_zero(key, 32);
}

// Example 5: Practical usage in UAV/GCS application
static void example_practical_usage(void)
{
    printf("\n=== Example 5: Practical Usage Pattern ===\n");

    uint8_t encryption_key[32];
    int result;

    // Try multiple key sources in order of preference

    // 1. Try environment variable (for container deployments)
    result = ul_load_key_from_env("UAVLINK_KEY", encryption_key, UL_KEY_FORMAT_HEX);
    if (result == UL_KEY_OK)
    {
        printf("✓ Using key from environment variable\n");
        goto key_loaded;
    }

    // 2. Try user's secure key directory
    result = ul_load_key_from_file("~/.uavlink/keys/default.bin", encryption_key, true);
    if (result == UL_KEY_OK)
    {
        printf("✓ Using key from user directory\n");
        goto key_loaded;
    }

    // 3. Try system-wide key (Unix)
    result = ul_load_key_from_file("/etc/uavlink/key.bin", encryption_key, true);
    if (result == UL_KEY_OK)
    {
        printf("✓ Using key from system directory\n");
        goto key_loaded;
    }

    // 4. Try current directory (development)
    result = ul_load_key_from_file("uavlink_key.bin", encryption_key, false);
    if (result == UL_KEY_OK)
    {
        printf("✓ Using key from current directory\n");
        goto key_loaded;
    }

    // No key found
    printf("✗ No encryption key found!\n");
    printf("  Please generate a key with: python keygen.py --save uavlink_key.bin\n");
    return;

key_loaded:
    printf("\n  Application can now use encryption_key for all operations\n");
    printf("  Remember to call ul_secure_zero() before exiting\n");

    // In real application, use key here...

    // Clean up
    ul_secure_zero(encryption_key, 32);
}

int main(int argc, char *argv[])
{
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║  UAVLink Key Management Examples                          ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    // Generate example keys for demonstration
    printf("\nGenerating example keys for demonstration...\n");

    // Create binary key file
    FILE *f = fopen("example_key.bin", "wb");
    if (f)
    {
        uint8_t demo_key[32];
        for (int i = 0; i < 32; i++)
        {
            demo_key[i] = (uint8_t)(i * 7 + 1); // Deterministic pattern
        }
        fwrite(demo_key, 1, 32, f);
        fclose(f);
        printf("✓ Created example_key.bin\n");
    }

    // Create hex key file
    f = fopen("example_key.txt", "w");
    if (f)
    {
        for (int i = 0; i < 32; i++)
        {
            fprintf(f, "%02x", (i * 7 + 1));
        }
        fprintf(f, "\n");
        fclose(f);
        printf("✓ Created example_key.txt\n");
    }

    // Run examples
    example_binary_file();
    example_hex_file();
    example_environment();
    example_generate_key();
    example_practical_usage();

    printf("\n╔════════════════════════════════════════════════════════╗\n");
    printf("  ║  Key Management Best Practices                         ║\n");
    printf("  ╚════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("✓ DO:\n");
    printf("  • Use keygen.py to generate cryptographically secure keys\n");
    printf("  • Store keys with restrictive permissions (chmod 600)\n");
    printf("  • Use unique keys per UAV-GCS pair\n");
    printf("  • Clear keys from memory with ul_secure_zero()\n");
    printf("  • Use ECDH session keys for production systems\n");
    printf("\n");
    printf("✗ DON'T:\n");
    printf("  • Never commit keys to version control\n");
    printf("  • Never hardcode keys in source code\n");
    printf("  • Never log or print keys\n");
    printf("  • Never share keys over insecure channels\n");
    printf("  • Never use weak random generation (use keygen.py!)\n");
    printf("\n");
    printf("For more information, see KEY_MANAGEMENT.md\n");

    return 0;
}
