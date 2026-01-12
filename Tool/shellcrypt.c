// From https://github.com/28Zaaky/Shellcode-Ldr

#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>

void Usage_(const char *progName)
{
    printf("Usage: %s <shellcode_file>\n", progName);
    printf("\n");
    printf("Encrypts a shellcode file using AES-256-CBC.\n");
    printf("\n");
    printf("Example:\n");
    printf("  %s ./shellcode.bin\n", progName);
    printf("\n");
    printf("Output files:\n");
    printf("  - ./shellcode_aes.bin\n");
    printf("  - ./shellcode_aes.txt\n");
    printf("  - ./key_iv.txt\n");
    printf("\n");
}

BOOL ReadFile_(const char *filename, BYTE **data, SIZE_T *size)
{
    FILE *f = fopen(filename, "rb");
    if (!f)
    {
        printf("[-] Failed to open file: %s\n", filename);
        return FALSE;
    }

    // Get file size
    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fileSize <= 0)
    {
        printf("[-] Invalid file size: %ld\n", fileSize);
        fclose(f);
        return FALSE;
    }

    // Allocate buffer
    *data = (BYTE *)malloc(fileSize);
    if (!*data)
    {
        printf("[-] Memory allocation failed\n");
        fclose(f);
        return FALSE;
    }

    // Read data
    size_t bytesRead = fread(*data, 1, fileSize, f);
    fclose(f);

    if (bytesRead != (size_t)fileSize)
    {
        printf("[-] Failed to read file completely\n");
        free(*data);
        return FALSE;
    }

    *size = (SIZE_T)fileSize;
    return TRUE;
}

BOOL WriteFile_(const char *filename, const BYTE *data, SIZE_T size)
{
    FILE *f = fopen(filename, "wb");
    if (!f)
    {
        printf("[-] Failed to create file: %s\n", filename);
        return FALSE;
    }

    size_t bytesWritten = fwrite(data, 1, size, f);
    fclose(f);

    if (bytesWritten != size)
    {
        printf("[-] Failed to write file completely\n");
        return FALSE;
    }

    return TRUE;
}

void WriteCArrayToFile_(const char *filename, const char *varName, const BYTE *data, SIZE_T size)
{
    FILE *f = fopen(filename, "w");
    if (!f)
    {
        printf("[-] Failed to create file: %s\n", filename);
        return;
    }

    fprintf(f, "// %s (%zu bytes)\n", varName, size);
    fprintf(f, "BYTE %s[] = {\n    ", varName);

    for (SIZE_T i = 0; i < size; i++)
    {
        fprintf(f, "0x%02X", data[i]);
        if (i < size - 1)
        {
            fprintf(f, ", ");
        }
        if ((i + 1) % 12 == 0 && i < size - 1)
        {
            fprintf(f, "\n    ");
        }
    }

    fprintf(f, "\n};\n");
    fclose(f);

    printf("[+] C array written to: %s\n", filename);
}

int main(int argc, char *argv[])
{
// Enable ANSI colors on Windows
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif

    // Display ASCII Art Banner with colors
    printf("\n");
    printf("\033[1;36m                  _____ _          _ _                       _                      \033[0m\n");
    printf("\033[1;36m                 / ____| |        | | |                     | |                     \033[0m\n");
    printf("\033[1;36m                | (___ | |__   ___| | | ___ _ __ _   _ _ __ | |_                   \033[0m\n");
    printf("\033[1;36m                 \\___ \\| '_ \\ / _ \\ | |/ __| '__| | | | '_ \\| __|                  \033[0m\n");
    printf("\033[1;36m                 ____) | | | |  __/ | | (__| |  | |_| | |_) | |_                   \033[0m\n");
    printf("\033[1;36m                |_____/|_| |_|\\___|_|_|\\___|_|   \\__, | .__/ \\__|                  \033[0m\n");
    printf("\033[1;36m                                                  __/ | |                          \033[0m\n");
    printf("\033[1;36m                                                 |___/|_|                          \033[0m\n");
    printf("\n");
    printf("\033[1;33m                    AES-256-CBC Payload Encryption Tool                       \033[0m\n");
    printf("\033[1;32m                  Copyright (c) 2026 - 28Zaakypro@proton.me                   \033[0m\n");
    printf("\n");
    printf("\033[1;35m===============================================================================\033[0m\n");
    printf("\n");

    if (argc != 2)
    {
        Usage_(argv[0]);
        return EXIT_FAILURE;
    }

    const char *inputFile = argv[1];

    // STEP 1: READ SHELLCODE
    printf("[*] Reading shellcode from: %s\n", inputFile);

    BYTE *plainShellcode = NULL;
    SIZE_T shellcodeSize = 0;

    if (!ReadFile_(inputFile, &plainShellcode, &shellcodeSize))
    {
        return EXIT_FAILURE;
    }

    printf("[+] Shellcode loaded: %zu bytes\n", shellcodeSize);
    printf("    First 16 bytes: ");
    for (SIZE_T i = 0; i < (shellcodeSize < 16 ? shellcodeSize : 16); i++)
    {
        printf("%02X ", plainShellcode[i]);
    }
    printf("\n\n");

    // STEP 2: GENERATE RANDOM KEY AND IV
    printf("[*] Generating random AES key and IV...\n");

    BYTE key[AES_256_KEY_SIZE];
    BYTE iv[AES_IV_SIZE];

    if (!GenerateRandomKey(key))
    {
        printf("[-] Failed to generate key\n");
        free(plainShellcode);
        return EXIT_FAILURE;
    }

    if (!GenerateRandomIV(iv))
    {
        printf("[-] Failed to generate IV\n");
        free(plainShellcode);
        return EXIT_FAILURE;
    }

    printf("[+] Key generated (32 bytes):\n    ");
    for (int i = 0; i < AES_256_KEY_SIZE; i++)
    {
        printf("%02X ", key[i]);
        if ((i + 1) % 16 == 0)
            printf("\n    ");
    }
    printf("\n");

    printf("[+] IV generated (16 bytes):\n    ");
    for (int i = 0; i < AES_IV_SIZE; i++)
    {
        printf("%02X ", iv[i]);
    }
    printf("\n\n");

    // STEP 3: ENCRYPT SHELLCODE
    printf("[*] Encrypting shellcode with AES-256-CBC...\n");

    BYTE *encryptedShellcode = NULL;
    DWORD encryptedSize = 0;

    if (!EncryptPayload(plainShellcode, shellcodeSize, iv, key, &encryptedShellcode, &encryptedSize))
    {
        printf("[-] Encryption failed\n");
        free(plainShellcode);
        return EXIT_FAILURE;
    }

    printf("[+] Encryption successful!\n");
    printf("    Original size:  %zu bytes\n", shellcodeSize);
    printf("    Encrypted size: %lu bytes\n", encryptedSize);
    printf("    Padding added:  %lu bytes\n\n", encryptedSize - shellcodeSize);

    // STEP 4: SAVE ENCRYPTED SHELLCODE
    printf("[*] Saving encrypted shellcode...\n");

    // Binary file
    if (!WriteFile_("shellcode_aes.bin", encryptedShellcode, encryptedSize))
    {
        free(plainShellcode);
        free(encryptedShellcode);
        return EXIT_FAILURE;
    }
    printf("[+] Binary saved: ./shellcode_aes.bin\n");

    // C array file (for easy copy/paste)
    WriteCArrayToFile_("shellcode_aes.txt", "encryptedShellcode", encryptedShellcode, encryptedSize);

    // STEP 5: SAVE KEY AND IV
    printf("[*] Saving key and IV...\n");

    FILE *keyIvFile = fopen("key_iv.txt", "w");
    if (keyIvFile)
    {
        fprintf(keyIvFile, "// AES-256 Key (32 bytes)\n");
        fprintf(keyIvFile, "BYTE aesKey[32] = {\n    ");
        for (int i = 0; i < AES_256_KEY_SIZE; i++)
        {
            fprintf(keyIvFile, "0x%02X", key[i]);
            if (i < AES_256_KEY_SIZE - 1)
                fprintf(keyIvFile, ", ");
            if ((i + 1) % 12 == 0 && i < AES_256_KEY_SIZE - 1)
                fprintf(keyIvFile, "\n    ");
        }
        fprintf(keyIvFile, "\n};\n\n");

        fprintf(keyIvFile, "// AES IV (16 bytes)\n");
        fprintf(keyIvFile, "BYTE aesIV[16] = {\n    ");
        for (int i = 0; i < AES_IV_SIZE; i++)
        {
            fprintf(keyIvFile, "0x%02X", iv[i]);
            if (i < AES_IV_SIZE - 1)
                fprintf(keyIvFile, ", ");
        }
        fprintf(keyIvFile, "\n};\n\n");

        fprintf(keyIvFile, "// Encrypted shellcode size: %lu bytes\n", encryptedSize);
        fprintf(keyIvFile, "// Original shellcode size: %zu bytes\n", shellcodeSize);

        fclose(keyIvFile);
        printf("[+] Key and IV saved: ./key_iv.txt\n");
    }

    printf("\n");
    printf("\033[1;32m===============================================================================\033[0m\n");
    printf("\033[1;33m                         ENCRYPTION COMPLETED                                  \033[0m\n");
    printf("\033[1;32m===============================================================================\033[0m\n");
    printf("\n");
    printf("Next steps:\n");
    printf("  1. Copy contents of ./shellcode_aes.txt into your malware source code\n");
    printf("  2. Copy key and IV from ./key_iv.txt into your malware source code\n");
    printf("\n");
    printf("\033[1;34m===============================================================================\033[0m\n");
    printf("\n");

    // Cleanup
    SecureZeroMemory(plainShellcode, shellcodeSize);
    SecureZeroMemory(encryptedShellcode, encryptedSize);
    SecureZeroMemory(key, AES_256_KEY_SIZE);
    SecureZeroMemory(iv, AES_IV_SIZE);

    free(plainShellcode);
    free(encryptedShellcode);

    return EXIT_SUCCESS;
}
