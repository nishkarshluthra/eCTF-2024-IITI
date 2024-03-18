#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define AP_PIN "1234567890123456"

void read_ap_pin(uint8_t* pin) {
    memcpy(pin, AP_PIN, 16);
}

int compare_pins(uint8_t* user_pin) {
    uint8_t ap_pin[16];
    read_ap_pin(ap_pin);
    // Hash the user_pin using SHA256
    // Compare the hash with the ap_pin
    uint8_t hash[16];
    wolfSSL_SHA256(user_pin, 16, hash);
    for (int i = 0; i < 16; i++) {
        if (hash[i] != ap_pin[i]) {
            return 0;
        }
    }
    return 1;
}
