#ifndef SM3_BASIC_H
#define SM3_BASIC_H
#include<stdint.h>

// 添加循环左移和字节序转换函数
static inline uint32_t left_rotate(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// 字节序转换 (主机序 <-> 大端序)
static inline uint32_t to_big_endian(uint32_t val) {
    return ((val << 24) | ((val << 8) & 0x00FF0000) |
           ((val >> 8) & 0x0000FF00) | (val >> 24));
}

typedef uint8_t byte;
typedef uint32_t word;

extern const word IV[8];
extern const word T0_15;
extern const word T_16_63;
#define T(j) ((j<=15 && j>=0)?T0_15:T_16_63)

word FF(word x, word y, word z, byte j);
word GG(word x, word y, word z, byte j);
word P0(word x);
word P1(word x);

#endif