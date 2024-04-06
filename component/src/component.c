/**
 * @file component.c
 * @author Jacob Doll 
 * @brief eCTF Component Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "board.h"
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "simple_i2c_peripheral.h"
#include "board_link.h"

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"
#include "simple_crypto.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define COMPONENT_ID 0x11111124
#define COMPONENT_BOOT_MSG "Component boot"
#define ATTESTATION_LOC "McLean"
#define ATTESTATION_DATE "08/08/08"
#define ATTESTATION_CUSTOMER "Fritz"
*/
/******************************** FLASH DEFINATIONS *******************************/

#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF
uint8_t hashed_rand_number[16];

/******************************** TYPE DEFINITIONS ********************************/
// Commands received by Component using 32 bit integer
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for receiving messages from the AP
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

typedef struct {
    uint32_t component_id;
    uint8_t rand_no[16] // for validation rand_no
} validate_message;

typedef struct {
    uint32_t component_id;
} scan_message;

// struct for flash
typedef struct{
    uint32_t flash_magic;
    uint8_t encrypted_key[16];
    uint32_t rand_no;
} flash_entry;
/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void component_process_cmd(void);
void process_boot(command_message* command);
void process_scan(void);
void process_validate(command_message* command);
void process_attest(void);

/*******************************BREAK uint32_t in uint8_t ***********************************************/
// output is 4 parts we break our input into
void uint32_t_to_uint8_t(uint32_t input, uint8_t *output){
    output[3] = (input >> 24) & 0xFF;
    output[2] = (input >> 16) & 0xFF;
    output[1] = (input >> 8) & 0xFF;
    output[0] = input & 0xFF; // & 0xFF takes last 8 bits
}

/***************************** COMBINE 4 UINT8_T TO ONE UINT32_T *****************************************/
uint32_t uint8_t_to_uint32_t(uint8_t *arr){
    uint32_t result = 0;

    result |= (uint32_t)arr[0] << 24;
    result |= (uint32_t)arr[1] << 16;
    result |= (uint32_t)arr[2] << 8;
    result |= (uint32_t)arr[3];

    return result;
}

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
flash_entry flash_status;

/********************************* USER FUNCTIONS **********************************/
int hex_to_int(char hex) {
    // Convert a hex character to an integer
    if (hex >= '0' && hex <= '9') {
        return hex - '0';
    } else if (hex >= 'a' && hex <= 'f') {
        return hex - 'a' + 10;
    } else if (hex >= 'A' && hex <= 'F') {
        return hex - 'A' + 10;
    }
    return -1;
}

void str_to_hex(char* str, uint8_t* hex) {
    // Convert a string of hex characters to a byte array
    for (int i = 0; i < strlen(str); i += 2) {
        hex[i/2] = (hex_to_int(str[i]) << 4) | hex_to_int(str[i + 1]);
    }
}

void tell_aes_key(uint8_t addr, uint8_t *buffer){
    // Generate a key based on the address of the component
    int seed = addr, mult = 103, adder = 31;
    uint8_t key[16];
    str_to_hex(C_KEY, key);
    for(int i = 0; i < 16; i++){
        uint8_t curr = ((seed = seed * mult + adder) & 255);
        buffer[i] = *((uint8_t*)(key + i*sizeof(uint8_t))) ^ curr;
    }
}

void int_to_hex(uint32_t num, uint8_t* hex) {
    // Convert a 32-bit integer to a byte array
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

void generate_key(uint8_t *key, uint32_t component_id) {
    // Generate a key based on the component ID
    uint8_t component_id_hex[4];
    int_to_hex(component_id, component_id_hex);
    for (int i = 0; i < 16; i++) {
        key[i] = 0;
    }
    for (int i = 0; i < 16; i += 1) {
        key[i] = (hex_to_int(C_KEY[2*i]) << 4) | hex_to_int(C_KEY[(2*i) + 1]);
    }
    // Xor key's last four bytes with component_id_hex
    for (int i = 0; i < 4; i++) {
        key[12 + i] ^= component_id_hex[i];
    }
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

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/

void secure_send_single_message(uint8_t* buffer, uint8_t len, uint8_t* aes_key) {
    int result;
    uint8_t hashed_buffer[len];
    result = encrypt_sym(buffer, len, aes_key, hashed_buffer);
    send_packet_and_ack(len, hashed_buffer); 
}

// void secure_send(uint8_t* buffer, uint8_t len) {
//     i2c_addr_t address = component_id_to_i2c_addr(COMPONENT_ID);
//     uint8_t aes_key[16];
//     generate_key(aes_key, address);

//     uint8_t len_hex[16];
//     for (int i = 0; i < 16; i++) {
//         len_hex[i] = 0;
//     }
//     uint8_to_hex(len, len_hex);
//     secure_send_single_message(len_hex, 16, aes_key);

//     // Receive ACK
//     uint8_t ack_packet[1];
//     wait_and_receive_packet(ack_packet);

//     int msg_len = nearest_16_multiple(len);
//     secure_send_single_message(buffer, msg_len, aes_key);

//     // Receive ACK
//     wait_and_receive_packet(ack_packet);
// }

// void secure_send(uint8_t* buffer, uint8_t len) {
//     send_packet_and_ack(len, buffer); 
// }

void secure_send(uint8_t* buffer, uint8_t len) {
    i2c_addr_t address = component_id_to_i2c_addr(COMPONENT_ID);
    uint8_t aes_key[16];
    generate_key(aes_key, address);

    uint8_t padded_msg_len = nearest_16_multiple(len);
    if ((len & 15)==0) {
        padded_msg_len = len;
    }

    uint8_t padded_buffer[padded_msg_len];
    for (int i = 0; i < padded_msg_len; i++) {
        padded_buffer[i] = 0;
    }
    memcpy(padded_buffer, buffer, len);

    uint8_t msg_len = nearest_16_multiple(len);
    uint8_t hashed_buffer[msg_len];

    int result = encrypt_sym(padded_buffer, padded_msg_len, aes_key, hashed_buffer);
    if (result != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }

    uint8_t buffer_to_send[MAX_I2C_MESSAGE_LEN-1] = {0};
    buffer_to_send[0] = len;
    buffer_to_send[1] = padded_msg_len;
    buffer_to_send[2] = msg_len;
    memcpy(buffer_to_send+3, hashed_buffer, msg_len);

    send_packet_and_ack(MAX_I2C_MESSAGE_LEN-1, buffer_to_send);
}

/**
 * @brief Secure Receive
 * 
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/

int secure_receive_with_len(uint8_t* buffer, uint8_t len, uint8_t* aes_key) {
    int result;
    uint8_t hashed_buffer[len];
    result = wait_and_receive_packet(hashed_buffer);
    if (result == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    result = decrypt_sym(hashed_buffer, len, aes_key, buffer);
    if (result != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }
    return result;
}

// int secure_receive(uint8_t* buffer) {
//     i2c_addr_t address = component_id_to_i2c_addr(COMPONENT_ID);
//     uint8_t aes_key[16];
//     generate_key(aes_key, address);

//     uint8_t len_hex[16];
//     int result = secure_receive_with_len(len_hex, 16, aes_key);
//     if (result == ERROR_RETURN) {
//         return ERROR_RETURN;
//     }

//     uint8_t ack_packet[1] = {0};
//     send_packet_and_ack(1, ack_packet);

//     uint8_t len = hex_to_uint8(len_hex);
//     int msg_len = nearest_16_multiple(len);

//     uint8_t temp_buffer[msg_len];
//     result = secure_receive_with_len(temp_buffer, msg_len, aes_key);
//     if (result < SUCCESS_RETURN) {
//         return ERROR_RETURN;
//     }
    
//     send_packet_and_ack(1, ack_packet);
//     memcpy(buffer, temp_buffer, len);
//     return result;
// }

// int secure_receive(uint8_t* buffer) {
//     return wait_and_receive_packet(buffer);
// }

int secure_receive(uint8_t* buffer) {
    i2c_addr_t address = component_id_to_i2c_addr(COMPONENT_ID);
    uint8_t aes_key[16];
    generate_key(aes_key, address);

    uint8_t temp_buffer[MAX_I2C_MESSAGE_LEN-1];
    int rcv_len = wait_and_receive_packet(temp_buffer);
    if (rcv_len == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    uint8_t len = temp_buffer[0];
    uint8_t padded_msg_len = temp_buffer[1];
    uint8_t msg_len = temp_buffer[2];
    uint8_t hashed_buffer[msg_len];
    memcpy(hashed_buffer, temp_buffer + 3, msg_len*sizeof(uint8_t));

    uint8_t decrypted_buffer[padded_msg_len];

    int result = decrypt_sym(hashed_buffer, msg_len, aes_key, decrypted_buffer);
    if (result != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }
    memcpy(buffer, decrypted_buffer, len);
    return len;
}

/******************************* FUNCTION DEFINITIONS *********************************/

// Example boot sequence
// Your design does not need to change this
void boot() {
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
    // LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
    #endif
}

// Handle a transaction from the AP
void component_process_cmd() {
    command_message* command = (command_message*) receive_buffer;

    // Output to application processor dependent on command received
    switch (command->opcode) {
    case COMPONENT_CMD_BOOT:
        process_boot(command);
        break;
    case COMPONENT_CMD_SCAN:
        process_scan();
        break;
    case COMPONENT_CMD_VALIDATE:
        process_validate(command);
        break;
    case COMPONENT_CMD_ATTEST:
        process_attest();
        break;
    default:
        printf("Error: Unrecognized command received %d\n", command->opcode);
        break;
    }
}

void process_boot(command_message* command) {
    // The AP requested a boot. Set `component_boot` for the main loop and
    // respond with the boot message
    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);

    uint8_t received_hashed_rand_no[16];
    memcpy(received_hashed_rand_no, command->params, 16*sizeof(uint8_t));
    if(memcmp(received_hashed_rand_no, hashed_rand_number, 16*sizeof(uint8_t)) != 0){
        return;
    }
    send_packet_and_ack(len, transmit_buffer);
    // Call the boot function
    boot();
}

void process_scan() {
    // The AP requested a scan. Respond with the Component ID
    scan_message* packet = (scan_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(scan_message), transmit_buffer);
    // uint8_t test_secure_send[MAX_I2C_MESSAGE_LEN-1];
    // wait_and_receive_packet(test_secure_send);
    // send_packet_and_ack(255, test_secure_send);
}

void process_validate(command_message* command) {
    //Extract the puzzle 
    uint8_t puzzle[MAX_I2C_MESSAGE_LEN - 1];
    memcpy(puzzle, command->params, (MAX_I2C_MESSAGE_LEN - 1)*sizeof(uint8_t));

    // Generate key
    uint8_t key[16];
    generate_key(key, COMPONENT_ID);

    //Decrypting Puzzle
    uint8_t temp_array[16];
    int temp = decrypt_sym(puzzle, BLOCK_SIZE, key, temp_array);
    if(temp != 0){
        printf("ERROR DECRYPITING\n");
        return;
    }
    uint32_t temp1 = uint8_t_to_uint32_t(temp_array);

    uint32_t rand_no = temp1 - COMPONENT_ID;

    uint8_t to_encrypt_and_hash[16], hashed_rand_no_temp[16];
    
    uint8_t rand_no_split[16];
        for(int i = 0; i < 16; i++){
            rand_no_split[i] = 0;
        }
    int_to_hex(rand_no, rand_no_split);

    uint8_t to_hash[4];
    uint32_t_to_uint8_t(rand_no, to_hash);

    //encrypting random number
    temp = encrypt_sym(rand_no_split, BLOCK_SIZE, key, temp_array);
    //again using temp array to to store encrypted rand no.
    if(temp != 0){
        return;
    }

    temp = hash((void*)to_hash, 4, hashed_rand_no_temp);
    if(temp != 0){
        return;
    }

    memcpy(hashed_rand_number, hashed_rand_no_temp, 16*sizeof(uint8_t));
    // The AP requested a validation. Respond with the Component ID
    validate_message* packet = (validate_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    memcpy(packet->rand_no, temp_array, 16*sizeof(uint8_t));
    send_packet_and_ack(sizeof(validate_message), transmit_buffer);
}

void process_attest() {
    uint8_t loc_len = strlen(ATTESTATION_LOC);
    uint8_t date_len = strlen(ATTESTATION_DATE);
    uint8_t cust_len = strlen(ATTESTATION_CUSTOMER);

    uint8_t loc[80], date[80], cust[80];

    for (int i = 0; i < 80; i++) {
        loc[i] = 0;
        date[i] = 0;
        cust[i] = 0;
    }

    str_to_hex(ATTESTATION_LOC, loc);
    str_to_hex(ATTESTATION_DATE, date);
    str_to_hex(ATTESTATION_CUSTOMER, cust);
    // The AP requested attestation. Respond with the attestation data

    // Fill the first 80 bytes of the transmit buffer with the attestation location
    memcpy(transmit_buffer, loc, 80*sizeof(uint8_t));
    // Fill the next 80 bytes of the transmit buffer with the attestation date
    memcpy(transmit_buffer + 80, date, 80*sizeof(uint8_t));
    // Fill the next 80 bytes of the transmit buffer with the attestation customer
    memcpy(transmit_buffer + 160, cust, 80*sizeof(uint8_t));
    // Fill the next byte with loc_len
    transmit_buffer[240] = loc_len;
    // Fill the next byte with date_len
    transmit_buffer[241] = date_len;
    // Fill the next byte with cust_len
    transmit_buffer[242] = cust_len;
    // Send the transmit buffer
    send_packet_and_ack(243, transmit_buffer);
}
/*********************************** MAIN *************************************/

int main(void) {
    printf("Component Started\n");
    
    // Enable Global Interrupts
    __enable_irq();
    
    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);
    
    LED_On(LED2);

    while (1) {
        wait_and_receive_packet(receive_buffer);
        // send_packet_and_ack(len, receive_buffer);
        // int len= secure_receive(receive_buffer);
        // if(len == ERROR_RETURN){
        //     continue;
        // }
        // secure_send(receive_buffer, len);
        component_process_cmd();
    }
}
