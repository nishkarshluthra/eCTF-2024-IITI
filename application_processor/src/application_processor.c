/**
 * @file application_processor.c
 * @author Jacob Doll
 * @brief eCTF AP Example Design Implementation
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
#include "icc.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_device.h"
#include "nvic_table.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include<stdatomic.h> // to support atomic operations

#include "board_link.h"
#include "simple_flash.h"
#include "host_messaging.h"
// #include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
// #include <wolfssl/wolfcrypt/aes.h>
// #ifdef CRYPTO_EXAMPLE
#include "simple_crypto.h"
#include "user_def_function.h"
// #endif

#ifdef POST_BOOT
#include "mxc_delay.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define AP_PIN "123456"
#define AP_TOKEN "0123456789abcdef"
#define COMPONENT_IDS 0x11111124, 0x11111125
#define COMPONENT_CNT 2
#define AP_BOOT_MSG "Test boot message"
*/

// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

uint8_t len_issue_cmd = sizeof(uint8_t);

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for sending commands to component
// Params allows for up to MAX_I2C_MESSAGE_LEN - 1 bytes to be send
// along with the opcode through board_link. This is not utilized by the example
// design but can be utilized by your design.
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

// Data type for receiving a validate message
typedef struct {
    uint32_t component_id;
    uint8_t rand_no[16];
} validate_message;

// Data type for receiving a scan message
typedef struct {
    uint32_t component_id;
} scan_message;

// Datatype for information stored in flash
typedef struct {
    uint32_t flash_magic;
    uint32_t component_cnt;
    uint32_t component_ids[32];
} flash_entry;

//Data type for atomic counting semaphore
typedef struct{
    atomic_int count;
}atomic_semaphore_t;

// Datatype for commands sent to components
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/********************************* GLOBAL VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;

// to store Map in AP
uint8_t hashed_random_number0[16];
uint8_t hashed_random_number1[16];

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

    result |= ((uint32_t)arr[0] << 24);
    result |= ((uint32_t)arr[1] << 16);
    result |= ((uint32_t)arr[2] << 8);
    result |= arr[3];

    return result;
}

/******************************Temporary Random Number Generator**************************************/

void TRNG_IRQHandler(void)
{
    MXC_TRNG_Handler();
}

uint32_t random_number_generation(){
    MXC_TRNG_Init();
    uint32_t random_number;
    MXC_TRNG_Random((uint8_t*)&random_number, sizeof(uint32_t));
    MXC_TRNG_Shutdown();
    return random_number;
}

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param address: i2c_addr_t, I2C address of recipient
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/

void tell_aes_key(uint8_t addr, uint8_t *buffer){
    int seed = addr, mult = 103, adder = 31;
    uint8_t key[16];
    str_to_hex(C_KEY, key);
    for(int i = 0; i < 16; i++){
        uint8_t curr = ((seed = seed * mult + adder) & 255);
        buffer[i] = *((uint8_t*)(key + i*sizeof(uint8_t))) ^ curr;
    }
}

// int secure_send_single_message(uint8_t address, uint8_t* buffer, uint8_t len, uint8_t *aes_key) {
//     int result;
//     uint8_t hashed_buffer[len];
//     result = encrypt_sym(buffer, len, aes_key, hashed_buffer);
//     if (result != SUCCESS_RETURN) {
//         return ERROR_RETURN;
//     }
//     return send_packet(address, len, buffer);
// }

// int secure_send(uint8_t address, uint8_t* buffer, uint8_t len) {
//     int result;
//     uint8_t aes_key[16];
//     generate_key(aes_key, address);

//     uint8_t len_hex[16];
//     for (int i = 0; i < 16; i++) {
//         len_hex[i] = 0;
//     }
//     uint8_to_hex(len, len_hex);
//     print_debug("About to send len: %d\n", len);
//     result = secure_send_single_message(address, len_hex, 16, aes_key);
//     if (result != SUCCESS_RETURN) {
//         return ERROR_RETURN;
//     }
//     // Receive ACK
//     uint8_t ack_packet[1];
//     result = poll_and_receive_packet(address, ack_packet);
//     print_debug("Sent len\n");

//     int msg_len = nearest_16_multiple(len);

//     print_debug("About to send msg");
//     result = secure_send_single_message(address, buffer, msg_len, aes_key);

//     // Receive ACK
//     result = poll_and_receive_packet(address, ack_packet);
//     print_debug("Sent msg\n");
//     return result;
// }

// int secure_send(uint8_t address, uint8_t* buffer, uint8_t len) {
//     return send_packet(address, len, buffer);
// }

int secure_send(i2c_addr_t address, uint8_t* buffer, uint8_t len){
    int result;
    uint8_t aes_key[16];
    generate_key(aes_key, address);
    uint8_t msg_len = nearest_16_multiple(len);
    uint8_t hashed_buffer[msg_len];
    result = encrypt_sym(buffer, msg_len, aes_key, hashed_buffer);
    if (result != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }
    return send_packet(address, msg_len, hashed_buffer);
}

/**
 * @brief Secure Receive
 * 
 * @param address: i2c_addr_t, I2C address of sender
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/

// int secure_receive_with_len(i2c_addr_t address, uint8_t* buffer, uint8_t len, uint8_t* aes_key){
//     int result;
//     uint8_t hashed_buffer[len];
//     result = poll_and_receive_packet(address, hashed_buffer);
//     if (result != SUCCESS_RETURN){
//         return ERROR_RETURN;
//     }
//     print_debug("Hashed Buffer: ");
//     print_hex_debug(hashed_buffer, len);

//     result = decrypt_sym(hashed_buffer, len, &aes_key, buffer);
//     if (result != SUCCESS_RETURN) {
//         return ERROR_RETURN;
//     }
//     print_debug("Decrypted Buffer: ");
//     print_hex_debug(buffer, len);
//     return result;
// }

// int secure_receive(i2c_addr_t address, uint8_t* buffer) {
//     uint8_t aes_key[16];
//     generate_key(aes_key, address);
    
//     int result;
//     uint8_t len_hex[16];
//     result = secure_receive_with_len(address, len_hex, 16, aes_key);
//     if (result != SUCCESS_RETURN){
//         return ERROR_RETURN;
//     }
//     // Send ACK
//     uint8_t ack_packet[1] = {0};
//     send_packet(address, 1, ack_packet);

//     print_debug("Len Hex: ");
//     print_hex_debug(len_hex, 16);
//     uint8_t len = hex_to_uint8(len_hex);
//     print_debug("Len: %d\n", len);
//     uint8_t msg_len = nearest_16_multiple(len);
//     print_debug("Msg Len: %d\n", msg_len);

//     uint8_t temp_buffer[msg_len];
//     result = secure_receive_with_len(address, temp_buffer, msg_len, aes_key);
//     if (result != SUCCESS_RETURN){
//         return ERROR_RETURN;
//     }

//     // Send ACK
//     send_packet(address, 1, ack_packet);
//     print_debug("Temp Buffer: ");
//     print_hex_debug(temp_buffer, msg_len);
//     print_debug("Msg: ");
//     print_debug("%s\n", temp_buffer);
//     memcpy(buffer, temp_buffer, len);
//     return result;
// }

// int secure_receive(i2c_addr_t address, uint8_t* buffer) {
//     return poll_and_receive_packet(address, buffer);
// }

int secure_receive(i2c_addr_t address, uint8_t* buffer) {
    uint8_t aes_key[16];
    generate_key(aes_key, address);
    
    uint8_t temp_buffer[MAX_I2C_MESSAGE_LEN];
    int len = poll_and_receive_packet(address, temp_buffer);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    uint8_t hashed_buffer[len];
    int result = decrypt_sym(temp_buffer, len, aes_key, hashed_buffer);
    if (result != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }
    memcpy(buffer, hashed_buffer, len);
    return len;
}

/**
 * @brief Get Provisioned IDs
 * 
 * @param uint32_t* buffer
 * 
 * @return int: number of ids
 * 
 * Return the currently provisioned IDs and the number of provisioned IDs
 * for the current AP. This functionality is utilized in POST_BOOT functionality.
 * This function must be implemented by your team.
*/
int get_provisioned_ids(uint32_t* buffer) {
    memcpy(buffer, flash_status.component_ids, flash_status.component_cnt * sizeof(uint32_t));
    return flash_status.component_cnt;
}

void generate_key(uint8_t *key, uint32_t component_id) {
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

/********************************* UTILITIES **********************************/

// Initialize the device
// This must be called on startup to initialize the flash and i2c interfaces
void init() {

    // Enable global interrupts    
    __enable_irq();

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_simple_read(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
        print_debug("First boot, setting flash!\n");

        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.component_cnt = COMPONENT_CNT;
        uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
        memcpy(flash_status.component_ids, component_ids, 
            COMPONENT_CNT*sizeof(uint32_t));

        flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));
    }
    
    // Initialize board link interface
    board_link_init();
}

// Send a command to a component and receive the result
int issue_cmd(i2c_addr_t addr, uint8_t* transmit, uint8_t* receive) {
    // Send message
    int result = send_packet(addr, len_issue_cmd, transmit);
    if (result == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    
    // Receive message
    int len = poll_and_receive_packet(addr, receive);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    return len;
}

/******************************** COMPONENT COMMS ********************************/

int scan_components() {
    // Print out provisioned component IDs
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        print_info("P>0x%08x\n", flash_status.component_ids[i]);
    }

    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Scan scan command to each component 
    for (i2c_addr_t addr = 0x8; addr < 0x78; addr++) {
        // I2C Blacklist:
        // 0x18, 0x28, and 0x36 conflict with separate devices on MAX78000FTHR
        if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            continue;
        }

        // Create command message 
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_SCAN;
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);

        // Success, device is present
        if (len > 0) {
            scan_message* scan = (scan_message*) receive_buffer;
            print_info("F>0x%08x\n", scan->component_id);
        }
        // const char* message = "Received Command from AP";
        // secure_send(addr, (uint8_t*)message, strlen(message));
        // uint8_t test_send_buffer[MAX_I2C_MESSAGE_LEN-1];
        // secure_receive(addr, (uint8_t*)test_send_buffer);
        // print_debug("Recieved test buffer send: %s\n", test_send_buffer);
    }
    // const char* message = "Received Command from AP";
    //     for (unsigned i = 0; i < flash_status.component_cnt; i++) {
    //         i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
    //         secure_send(addr, (uint8_t*)message, strlen(message));
    //         uint8_t test_send_buffer[MAX_I2C_MESSAGE_LEN-1];
    //         secure_receive(addr, (uint8_t*)test_send_buffer);
    //         print_debug("Recieved test buffer send: %s\n", test_send_buffer);
    //     }
    print_success("List\n");
    
    return SUCCESS_RETURN;
}

int validate_components() {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t support_array[MAX_I2C_MESSAGE_LEN - 1]; //dummy array for encyption
    // Send validate command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        uint32_t puzzle = flash_status.component_ids[i]; // adding the component id
        uint32_t random_number = random_number_generation(); //generating a random number for this component
        puzzle += random_number; // adding the random number

        uint8_t puzzle_split[16];
        for(int i = 0; i < 16; i++){
            puzzle_split[i] = 0;
        }
        int_to_hex(puzzle, puzzle_split);

        // generating key for encryption
        uint8_t key[16];
        generate_key(key, flash_status.component_ids[i]);

        // encryption
        int temp = encrypt_sym(puzzle_split, BLOCK_SIZE, key, support_array); // encrypting and storing in transmit buffer
        if(temp != 0){
            print_error("Cound not encrypt\n");
            return ERROR_RETURN;
        }
        
        //hashing the random number
        uint8_t input_split[4], output_split[16]; // temporary storage of 4 parts of random number
        uint32_t_to_uint8_t(random_number, input_split);
        temp = hash((void*)input_split, 4, output_split);
        if(temp != 0){
            print_error("Could not hash\n");
            return ERROR_RETURN;
        }// if error occured
        //storing hashed random number
        if (i == 0)
            memcpy(hashed_random_number0, output_split, 16*sizeof(uint8_t));
        else
            memcpy(hashed_random_number1, output_split, 16*sizeof(uint8_t));

        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_VALIDATE;
        memcpy(command->params, support_array, (MAX_I2C_MESSAGE_LEN-1)*sizeof(uint8_t)); // storing puzzle here
        // Send out command and receive result
        len_issue_cmd = 255*sizeof(uint8_t);
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not validate component\n");
            return ERROR_RETURN;
        }
        len_issue_cmd = sizeof(uint8_t);

        validate_message* validate = (validate_message*) receive_buffer;

        //extracting the random number returned by the component
        uint8_t temp_array[16], temp_array1[16]; // temp arrays to assist decryption
        temp = decrypt_sym(validate->rand_no, BLOCK_SIZE, key, temp_array1);
        if(temp != 0){
            return ERROR_RETURN;
        }
        uint32_t rand_number = uint8_t_to_uint32_t(temp_array1);

        // uint32_t rand_number = uint8_t_to_uint32_t(temp_array1);//No use??
        // Check that the result is correct
        if (validate->component_id != flash_status.component_ids[i] || random_number != rand_number) {
            print_error("Component ID: 0x%08x invalid\n", flash_status.component_ids[i]);
            return ERROR_RETURN;
        }
    }
    return SUCCESS_RETURN;
}

int boot_components() {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send boot command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        
        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_BOOT;

        uint8_t temp_array[MAX_I2C_MESSAGE_LEN - 1];
        if (i == 0)
            memcpy(temp_array, hashed_random_number0, 16*sizeof(uint8_t));
        else
            memcpy(temp_array, hashed_random_number1, 16*sizeof(uint8_t));
        memcpy(command->params, temp_array, (MAX_I2C_MESSAGE_LEN-1)*sizeof(uint8_t)); // storing hashed random number here
        
        // Send out command and receive result
        len_issue_cmd = 255*sizeof(uint8_t);
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not boot component\n");
            return ERROR_RETURN;
        }
        len_issue_cmd = sizeof(uint8_t);

    
        // Print boot message from component
        print_info("0x%08x>%s\n", flash_status.component_ids[i], receive_buffer);
    }
    return SUCCESS_RETURN;
}

void decrypt(uint8_t *transmit_buffer, uint32_t component_id) {
    char LOC[256], DATE[256], CUST[256];
    sscanf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n", LOC, DATE, CUST);

    // Get the actual length of the strings
    int loc_len = strlen(LOC);
    int date_len = strlen(DATE);
    int cust_len = strlen(CUST);

    // Convert the strings to hex
    uint8_t hex_loc[loc_len/2], hex_date[date_len/2], hex_cust[cust_len/2];
    str_to_hex(LOC, hex_loc);
    str_to_hex(DATE, hex_date);
    str_to_hex(CUST, hex_cust);
    
    // Decrypt the strings
    uint8_t decrypt_LOC[256], decrypt_DATE[256], decrypt_CUST[256];

    // Generate key
    uint8_t key[16];
    generate_key(key, component_id);
    
    // Decrypt the strings
    decrypt_sym(hex_loc, loc_len/2, key, decrypt_LOC);
    decrypt_sym(hex_date, date_len/2, key, decrypt_DATE);
    decrypt_sym(hex_cust, cust_len/2, key, decrypt_CUST);
    
    // Print the decrypted strings
    sprintf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n", decrypt_LOC, decrypt_DATE, decrypt_CUST);
}

int attest_component(uint32_t component_id) {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    // Create command message
    command_message* command = (command_message*) transmit_buffer;
    command->opcode = COMPONENT_CMD_ATTEST;

    // Send out command and receive result
    int len = issue_cmd(addr, transmit_buffer, receive_buffer);
    if (len == ERROR_RETURN) {
        print_error("Could not attest component\n");
        return ERROR_RETURN;
    }

    //decrypt(receive_buffer, component_id);

    // Print out attestation data 
    print_info("C>0x%08x\n", component_id);
    print_info("%s", receive_buffer);
    return SUCCESS_RETURN;
}

/********************************* AP LOGIC ***********************************/

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot() {
    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Everything after this point is modifiable in your design
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

// Compare the entered PIN to the correct PIN
int validate_pin() {
    char buf[6]= {0};
    recv_input("Enter pin: ", buf);
    unsigned char hash[WC_SHA256_DIGEST_SIZE];
    wc_Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, (unsigned char*)buf, strlen(buf));
    wc_Sha256Final(&sha, hash);
    char hash_str[WC_SHA256_DIGEST_SIZE * 2 + 1];
    hex_to_str(hash, hash_str, WC_SHA256_DIGEST_SIZE);
    // Compare hash to AP_PIN
    if (strcmp(hash_str, AP_PIN) == 0) {
        print_debug("Pin Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid PIN!\n");
    return ERROR_RETURN;
}

int validate_token() {
    char buf[50];
    recv_input("Enter token: ", buf);
    unsigned char hash[WC_SHA256_DIGEST_SIZE];
    wc_Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, (unsigned char*)buf, strlen(buf));
    wc_Sha256Final(&sha, hash);
    // Compare hash to AP_TOKEN
    char hash_str[WC_SHA256_DIGEST_SIZE * 2 + 1];
    hex_to_str(hash, hash_str, WC_SHA256_DIGEST_SIZE);
    // Compare hash to AP_TOKEN
    if (strcmp(hash_str, AP_TOKEN) == 0) {
        print_debug("TOKEN Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid TOKEN!\n");
    return ERROR_RETURN;
}

// Boot the components and board if the components validate
void attempt_boot() {
    if (validate_components()) {
        print_error("Components could not be validated\n");
        return;
    }
    print_debug("All Components validated\n");
    if (boot_components()) {
        print_error("Failed to boot all components\n");
        return;
    }
    // This always needs to be printed when booting
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");
    // Boot
    boot();
}

// Replace a component if the PIN is correct
void attempt_replace() {
    char buf[50];

    if (validate_token()) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf);
    sscanf(buf, "%x", &component_id_out);

    // Find the component to swap out
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id_out) {
            flash_status.component_ids[i] = component_id_in;

            // write updated component_ids to flash
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

            print_debug("Replaced 0x%08x with 0x%08x\n", component_id_out,
                    component_id_in);
            print_success("Replace\n");
            return;
        }
    }

    // Component Out was not found
    print_error("Component 0x%08x is not provisioned for the system\r\n",
            component_id_out);
}

// Attest a component if the PIN is correct
void attempt_attest() {
    char buf[10]= {0};

    if (validate_pin()) {
        print_error("Attestation failed\n");
        return;
    }
    uint32_t component_id;
    recv_input("Component ID: ", buf);
    sscanf(buf, "%x", &component_id);
    if (attest_component(component_id) == SUCCESS_RETURN) {
        print_success("Attest\n");
    }
    print_error("Attestation failed\n");
}

/*********************************** MAIN *************************************/

int main() {
    // Initialize board
    init();

    // Print the component IDs to be helpful
    // Your design does not need to do this
    print_info("Application Processor Started\n");
    // Handle commands forever
    char buf[100];
    while (1) {
        recv_input("Enter Command: ", buf);
        // const char* message = "Received Command";
        // for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        //     i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        //     secure_send(addr, (uint8_t*)message, (strlen(message)+1));
        //     uint8_t test_send_buffer[MAX_I2C_MESSAGE_LEN-1];
        //     secure_receive(addr, (uint8_t*)test_send_buffer);
        //     print_hex_debug(test_send_buffer, MAX_I2C_MESSAGE_LEN-1);
        //     print_debug("Recieved test buffer send: %s\n", test_send_buffer);
        // }

        //secure_send(0x8, (uint8_t*)message, strlen(message));
        // Execute requested command
        if (!strcmp(buf, "list")) {
            scan_components();
        } else if (!strcmp(buf, "boot")) {
            attempt_boot();
        } else if (!strcmp(buf, "replace")) {
            attempt_replace();
        } else if (!strcmp(buf, "attest")) {
            attempt_attest();
        } else {
            print_error("Unrecognized command '%s'\n", buf);
        }
    }

    // Code never reaches here
    return 0;
}

