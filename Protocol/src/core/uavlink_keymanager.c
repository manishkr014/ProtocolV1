/**
 * UAVLink Key Management Utilities - Implementation
 */

#include "uavlink_keymanager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <aclapi.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

// Securely zero memory (prevents compiler optimization)
void ul_secure_zero(void *ptr, size_t len)
{
    if (ptr == NULL)
        return;

    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--)
    {
        *p++ = 0;
    }
}

// Check file permissions
bool ul_check_file_permissions(const char *filename)
{
#ifdef _WIN32
    // Windows: Check that file is not world-readable
    DWORD result = GetFileAttributesA(filename);
    if (result == INVALID_FILE_ATTRIBUTES)
    {
        return false;
    }

    // Basic ACL checking - Ensure "Everyone" doesn't have read access
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pDacl = NULL;
    bool secure = false;

    if (GetNamedSecurityInfoA(filename, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &pSD) == ERROR_SUCCESS)
    {
        // Try to find if "Everyone" (World) has any access
        ACL_SIZE_INFORMATION aclSize;
        if (GetAclInformation(pDacl, &aclSize, sizeof(aclSize), AclSizeInformation))
        {
            secure = true; // Assume secure unless we find a wide-open ACE
            PSID everyoneSid = NULL;
            SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
            if (AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyoneSid))
            {
                for (DWORD i = 0; i < aclSize.AceCount; i++)
                {
                    PVOID pAce = NULL;
                    if (GetAce(pDacl, i, &pAce))
                    {
                        PACE_HEADER pHeader = (PACE_HEADER)pAce;
                        if (pHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
                        {
                            ACCESS_ALLOWED_ACE *pAllowed = (ACCESS_ALLOWED_ACE *)pAce;
                            if (EqualSid(everyoneSid, (PSID)&pAllowed->SidStart))
                            {
                                // Everyone has some access - this is insecure for a key file
                                secure = false;
                                fprintf(stderr, "⚠️  Warning: Key file %s is accessible by 'Everyone'\n", filename);
                                break;
                            }
                        }
                    }
                }
                FreeSid(everyoneSid);
            }
        }
        LocalFree(pSD);
    }

    return secure;
#else
    // Unix/Linux: Check that only owner has read/write
    struct stat st;
    if (stat(filename, &st) != 0)
    {
        return false;
    }

    // Check that group and others have no permissions
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0)
    {
        fprintf(stderr, "⚠️  Warning: Key file %s has insecure permissions\n", filename);
        fprintf(stderr, "    Run: chmod 600 %s\n", filename);
        return false;
    }

    return true;
#endif
}

// Load binary key from file
int ul_load_key_from_file(const char *filename, uint8_t key_out[32], bool check_perms)
{
    if (filename == NULL || key_out == NULL)
    {
        return UL_KEY_ERR_FILE;
    }

    // Check permissions if requested
    if (check_perms && !ul_check_file_permissions(filename))
    {
        return UL_KEY_ERR_PERMISSION;
    }

    // Open file
    FILE *f = fopen(filename, "rb");
    if (f == NULL)
    {
        return UL_KEY_ERR_FILE;
    }

    // Read exactly 32 bytes
    size_t bytes_read = fread(key_out, 1, 32, f);
    fclose(f);

    if (bytes_read != 32)
    {
        ul_secure_zero(key_out, 32);
        return UL_KEY_ERR_SIZE;
    }

    return UL_KEY_OK;
}

// Convert hex character to value
static int hex_to_int(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

// Load key from hex string file
int ul_load_key_from_hex_file(const char *filename, uint8_t key_out[32])
{
    if (filename == NULL || key_out == NULL)
    {
        return UL_KEY_ERR_FILE;
    }

    // Open file
    FILE *f = fopen(filename, "r");
    if (f == NULL)
    {
        return UL_KEY_ERR_FILE;
    }

    // Read hex string (need 64 characters)
    char hex_string[128];
    if (fgets(hex_string, sizeof(hex_string), f) == NULL)
    {
        fclose(f);
        return UL_KEY_ERR_FORMAT;
    }
    fclose(f);

    // Remove whitespace and newlines
    int hex_len = 0;
    for (int i = 0; hex_string[i] != '\0' && hex_len < 128; i++)
    {
        if (!isspace(hex_string[i]))
        {
            hex_string[hex_len++] = hex_string[i];
        }
    }

    // Must be exactly 64 hex characters
    if (hex_len != 64)
    {
        return UL_KEY_ERR_SIZE;
    }

    // Convert hex to binary
    for (int i = 0; i < 32; i++)
    {
        int hi = hex_to_int(hex_string[i * 2]);
        int lo = hex_to_int(hex_string[i * 2 + 1]);

        if (hi < 0 || lo < 0)
        {
            ul_secure_zero(key_out, 32);
            return UL_KEY_ERR_FORMAT;
        }

        key_out[i] = (hi << 4) | lo;
    }

    return UL_KEY_OK;
}

// Load key from environment variable
int ul_load_key_from_env(const char *var_name, uint8_t key_out[32], int format)
{
    if (var_name == NULL || key_out == NULL)
    {
        return UL_KEY_ERR_ENV;
    }

    const char *env_value = getenv(var_name);
    if (env_value == NULL)
    {
        return UL_KEY_ERR_ENV;
    }

    if (format == UL_KEY_FORMAT_HEX)
    {
        // Parse hex string
        size_t len = strlen(env_value);
        if (len != 64)
        {
            return UL_KEY_ERR_SIZE;
        }

        for (int i = 0; i < 32; i++)
        {
            int hi = hex_to_int(env_value[i * 2]);
            int lo = hex_to_int(env_value[i * 2 + 1]);

            if (hi < 0 || lo < 0)
            {
                ul_secure_zero(key_out, 32);
                return UL_KEY_ERR_FORMAT;
            }

            key_out[i] = (hi << 4) | lo;
        }

        return UL_KEY_OK;
    }

    // Other formats not implemented
    return UL_KEY_ERR_FORMAT;
}

// Generate random key (using Cryptographically Secure PRNG)
void ul_generate_random_key(uint8_t key_out[32])
{
    if (key_out == NULL)
        return;

#ifdef _WIN32
    HCRYPTPROV hProvider;
    if (CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        if (!CryptGenRandom(hProvider, 32, key_out))
        {
            fprintf(stderr, "ERROR: CryptGenRandom failed!\n");
            ul_secure_zero(key_out, 32);
        }
        CryptReleaseContext(hProvider, 0);
    }
    else
    {
        fprintf(stderr, "ERROR: Failed to acquire Windows Crypto Context!\n");
        ul_secure_zero(key_out, 32);
    }
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f != NULL)
    {
        size_t bytes = fread(key_out, 1, 32, f);
        fclose(f);
        if (bytes != 32)
        {
            fprintf(stderr, "ERROR: Failed to read sufficient entropy from /dev/urandom\n");
            ul_secure_zero(key_out, 32);
        }
    }
    else
    {
        fprintf(stderr, "ERROR: Cannot open /dev/urandom\n");
        ul_secure_zero(key_out, 32);
    }
#endif
}

// Get error description
const char *ul_key_error_string(int error_code)
{
    switch (error_code)
    {
    case UL_KEY_OK:
        return "Success";
    case UL_KEY_ERR_FILE:
        return "File not found or cannot open";
    case UL_KEY_ERR_PERMISSION:
        return "File has insecure permissions";
    case UL_KEY_ERR_SIZE:
        return "Invalid key size";
    case UL_KEY_ERR_FORMAT:
        return "Invalid key format";
    case UL_KEY_ERR_ENV:
        return "Environment variable not found";
    default:
        return "Unknown error";
    }
}
