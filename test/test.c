#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/sha256.h>

// int validate_pin() {
//     char buf[50];
//     recv_input("Enter pin: ", buf);
//     unsigned char hash[WC_SHA256_DIGEST_SIZE];
//     wc_Sha256 sha;
//     wc_InitSha256(&sha);
//     wc_Sha256Update(&sha, (unsigned char*)buf, strlen(buf));
//     wc_Sha256Final(&sha, hash);
//     // Compare hash to AP_PIN
//     if (memcmp(hash, AP_PIN, WC_SHA256_DIGEST_SIZE) == 0) {
//         print_debug("Pin Accepted!\n");
//         return SUCCESS_RETURN;
//     }
//     print_error("Invalid PIN!\n");
//     return ERROR_RETURN;
// }

// int validate_token() {
//     char buf[50];
//     recv_input("Enter token: ", buf);
//     unsigned char hash[WC_SHA256_DIGEST_SIZE];
//     wc_Sha256 sha;
//     wc_InitSha256(&sha);
//     wc_Sha256Update(&sha, (unsigned char*)buf, strlen(buf));
//     wc_Sha256Final(&sha, hash);
//     // Compare hash to AP_TOKEN
//     if (memcmp(hash, AP_TOKEN, WC_SHA256_DIGEST_SIZE) == 0) {
//         print_debug("Token Accepted!\n");
//         return SUCCESS_RETURN;
//     }
//     print_error("Invalid Token!\n");
//     return ERROR_RETURN;
// }

// Convert int to hex and return in a uint8_t array
void int_to_hex(uint32_t num, uint8_t* hex) {
    for (int i = 0; i < 4; i++) {
        hex[i] = (num >> (8 * i)) & 0xFF;
    }
    // Reverse the array
    for (int i = 0; i < 2; i++) {
        uint8_t temp = hex[i];
        hex[i] = hex[3 - i];
        hex[3 - i] = temp;
    }
}

int hex_to_int(char hex) {
    if (hex >= '0' && hex <= '9') {
        return hex - '0';
    } else if (hex >= 'a' && hex <= 'f') {
        return hex - 'a' + 10;
    } else if (hex >= 'A' && hex <= 'F') {
        return hex - 'A' + 10;
    }
    return -1;
}

int main() {
    uint32_t component_id = 286331173;
    uint8_t component_id_hex[4];
    int_to_hex(component_id, component_id_hex);
    // Store C_KEY in a uint8_t array
    uint8_t c_key_hex[16];
    for (int i = 0; i < 16; i++) {
        c_key_hex[i] = 0;
    }
    for (int i = 0; i < 16; i += 1) {
        c_key_hex[i] = (hex_to_int(C_KEY[2*i]) << 4) | hex_to_int(C_KEY[(2*i) + 1]);
    }
    // Xor c_key_hex's last four bytes with component_id_hex
    for (int i = 0; i < 4; i++) {
        c_key_hex[12 + i] ^= component_id_hex[i];
    }
}