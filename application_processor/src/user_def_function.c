#include "user_def_function.h"
#include "stdio.h"
#include "stdlib.h"

void str_to_hex(char* str, uint8_t* hex) {
    for (int i = 0; i < strlen(str); i += 2) {
        hex[i/2] = (hex_to_int(str[i]) << 4) | hex_to_int(str[i + 1]);
    }
}

void hex_to_str(unsigned char *hex, char *str, int len) {
    for (int i = 0; i < len; i++) {
        sprintf(str + (i * 2), "%02x", hex[i]);
    }
}

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

int nearest_16_multiple(int num){
    int rem = (num & 15);
    return (num-rem+16);
}

void uint8_to_hex(uint8_t num, uint8_t* hex) {
    hex[0] = (num >> 4) & 0xF;
    hex[1] = num & 0xF;
}

uint8_t hex_to_uint8(uint8_t* hex) {
    return (hex[0] << 4) | hex[1];
}