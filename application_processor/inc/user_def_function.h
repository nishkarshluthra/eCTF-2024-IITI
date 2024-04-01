#include "stdint.h"

void str_to_hex(char* str, uint8_t* hex);

void hex_to_str(unsigned char *hex, char *str, int len);

int hex_to_int(char hex);

void int_to_hex(uint32_t num, uint8_t* hex);

int nearest_16_multiple(int num);

void uint8_to_hex(uint8_t num, uint8_t* hex);

uint8_t hex_to_uint8(uint8_t* hex);