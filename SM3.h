#ifndef SM3_H
#define SM3_H
#include <stdint.h>
#include "SM3_basic.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

word* SM3( byte *message, size_t bit_len);
word* SM3_attack( byte *message, size_t bit_len, word *V,uint64_t force_message_bit_len);
byte* padding(byte *message, uint64_t bit_length);
void CF(word V[8],word B_list[16]);

#endif