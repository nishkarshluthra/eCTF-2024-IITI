#include<stdio.h>
#include<stdlib.h>
#include<string.h>
// #include<test.h>
#define uint8_t unsigned char
// #include "wolfssl/wolfcrypt/aes.h"
// #include "wolfssl/wolfcrypt/hash.h"
#define ATTESTATION_LOC "Delhi"
#define ATTESTATION_DATE "2024-03-01"
#define ATTESTATION_CUSTOMER "IITI"

uint8_t transmit_buffer[256];
#define C_KEY "daeb73e4301a9282e22057fd4c9e3a75";

void read_file(char *filename, char *buffer, int buffer_size) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error: Could not open file %s\n", filename);
        exit(1);
    }
    fread(buffer, 1, buffer_size, file);
    fclose(file);
}

// int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
//     Aes ctx; // Context for decryption
//     int result; // Library result

//     // Ensure valid length
//     if (len <= 0 || len % BLOCK_SIZE)
//         return -1;

//     // Set the key for decryption
//     result = wc_AesSetKey(&ctx, key, 16, NULL, AES_DECRYPTION);
//     if (result != 0)
//         return result; // Report error

//     // Decrypt each block
//     for (int i = 0; i < len - 1; i += BLOCK_SIZE) {
//         result = wc_AesDecryptDirect(&ctx, plaintext + i, ciphertext + i);
//         if (result != 0)
//             return result; // Report error
//     }
//     return 0;
// }

// void decypt(uint8_t *transmit_buffer) {
//     char LOC[256], DATE[256], CUST[256];
//     char decrypt_LOC[256], decrypt_DATE[256], decrypt_CUST[256];
//     sscanf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n", LOC, DATE, CUST);
//     uint8_t key[16] = C_KEY;
//     decrypt_sym(LOC, strlen(LOC), key, decrypt_LOC);
//     decrypt_sym(DATE, strlen(DATE), key, decrypt_DATE);
//     decrypt_sym(CUST, strlen(CUST), key, decrypt_CUST);
//     sprintf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n", decrypt_LOC, decrypt_DATE, decrypt_CUST);
// }

uint8_t hex_to_uint8_t(char hex) {
    if (hex >= '0' && hex <= '9') {
        return hex - '0';
    } else if (hex >= 'a' && hex <= 'f') {
        return hex - 'a' + 10;
    } else if (hex >= 'A' && hex <= 'F') {
        return hex - 'A' + 10;
    }
    return 0;
}

int main() {
    uint8_t key[16];
    char key_str[33] = C_KEY;
    for (int i = 0; i<16; i++) {
        key[i] = hex_to_uint8_t(key_str[2 * i]) * 16 + hex_to_uint8_t(key_str[2 * i + 1]); 
    }
    printf("Key: ");
    for (int i = 0; i<16; i++) {
        printf("%02x", key[i]);
    }
    // sprintf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n", ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER);
    // decypt(transmit_buffer);
    // printf("%s\n", transmit_buffer);
    return 0;
}