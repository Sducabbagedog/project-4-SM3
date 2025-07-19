#include "SM3_basic.h"

const word IV[8] = {0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e};
const word T0_15=0x79cc4519;
const word T_16_63=0x7a879d8a;


// 使用循环左移实现P函数
word P0(word x) {
    return x ^ left_rotate(x, 9) ^ left_rotate(x, 17);
}

word P1(word x) {
    return x ^ left_rotate(x, 15) ^ left_rotate(x, 23);
}

word FF(word x, word y, word z, byte j){
    if (j<=15 && j>=0)
    {
        return x^y^z;
    }
    else if(j<=63 && j>=16)
    {
        return (x&y)|(y&z)|(z&x);
    }
    else return 0;
}


word GG(word x, word y, word z, byte j){
    if (j<=15 && j>=0)
    {
        return x^y^z;
    }
    else if(j<=63 && j>=16)
    {
        return (x&y)|((~x)&z);
    }
    else return 0;   
}
