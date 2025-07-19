#include "SM3.h"



word swap_endian_32(word val) {
    return ((val << 24) | ((val << 8) & 0x00FF0000) |
           ((val >> 8) & 0x0000FF00) | (val >> 24));
}



//length以字节为单位
size_t cal_length(size_t bit_length)
{
    if(bit_length%512<=447)
    {
        return (bit_length/512+1)*512;
    }
    else if(bit_length%512>447)
    {
        return (bit_length/512+2)*512;
    }
}

byte* padding(byte *message, uint64_t bit_length) {
    size_t alloc_bit_length = cal_length(bit_length);
    byte *message_padding = calloc(alloc_bit_length / 8, 1);
    
    // 复制原始消息
    size_t byte_len = (bit_length + 7) / 8; // 向上取整字节数
    memcpy(message_padding, message, byte_len);
    
    // 添加1比特
    if (bit_length % 8 == 0) {
        message_padding[byte_len] = 0x80; // 新字节开始
    } else {
        // 在最后一个字节添加1
        message_padding[byte_len - 1] |= (0x80 >> (bit_length % 8));
    }
    
    // 添加长度字段（64位大端序）
    uint64_t len_be = bit_length;
    for (int i = 0; i < 8; i++) {
        message_padding[alloc_bit_length / 8 - 8 + i] = (len_be >> (56 - i * 8)) & 0xFF;
    }
    
    return message_padding;
}

void message_extend(word *W1,word *W2,word B[16])
{
    for(int i=0;i<16;i++)
    {
        W1[i]=B[i];
    }
    for(int i=16;i<68;i++)
    {
        W1[i]=P1(W1[i-16]^W1[i-9]^left_rotate(W1[i-3],15))^left_rotate(W1[i-13],7)^W1[i-6];
    }
    for (int i=0;i<64;i++)
    {
        W2[i]=W1[i]^W1[i+4];
    }
}

void CF(word V[8],word B_list[16])
{
    word A=V[0];
    word B=V[1];
    word C=V[2];
    word D=V[3];
    word E=V[4];
    word F=V[5];
    word G=V[6];
    word H=V[7];

    word W1[68];
    word W2[64];

    message_extend(W1,W2,B_list);

    for(int i=0;i<64;i++)
    {
        word SS1=left_rotate(left_rotate(A,12)+E+left_rotate(T(i),i),7);
        word SS2=SS1^left_rotate(A,12);
        word TT1=FF(A,B,C,i)+D+SS2+W2[i];
        word TT2=GG(E,F,G,i)+H+SS1+W1[i];
        D=C;
        C=left_rotate(B,9);
        B=A;
        A=TT1;
        H=G;
        G=left_rotate(F,19);
        F=E;
        E=P0(TT2);
    }
    V[0]=V[0]^A;
    V[1]=V[1]^B;
    V[2]=V[2]^C;
    V[3]=V[3]^D;
    V[4]=V[4]^E;
    V[5]=V[5]^F;
    V[6]=V[6]^G;
    V[7]=V[7]^H;
}

word* SM3( byte *message, size_t bit_len) {
    size_t bit_length=cal_length(bit_len);
    size_t n=bit_length/512;
    //change big and little endian
    byte* message_padding=padding(message,bit_len);
    for(int i=0;i<bit_length/32;i++)
    {   
        ((word *)message_padding)[i]=swap_endian_32(((word *)message_padding)[i]);
    }
    
    //load IV
    word *V=malloc(8*sizeof(word));
    for(int i=0;i<8;i++)
    {
        V[i]=IV[i];
    }

    //iterlate
    for (int i=0;i<n;i++)
    {
        word *B=(word *)message_padding+i*16;
        CF(V,B);
    }
    free(message_padding);
    //change big and little endian
    for(int i=0;i<8;i++)
    {
        V[i]=swap_endian_32(V[i]);
    }

    return V;
}

word* SM3_attack( byte *message, size_t bit_len, word *V,uint64_t force_message_bit_len) {
    size_t bit_length=cal_length(bit_len);
    size_t n=bit_length/512;
    //change big and little endian
    byte* message_padding=padding(message,bit_len);

    //64 bit length correct
    for (int i = 0; i < 8; i++) {
        message_padding[bit_length / 8 - 8 + i] = (force_message_bit_len >> (56 - i * 8)) & 0xFF;
    }

    for(int i=0;i<bit_length/32;i++)
    {
        ((word *)message_padding)[i]=swap_endian_32(((word *)message_padding)[i]);
    }
    
    //change big and little endian
    for(int i=0;i<8;i++)
    {
        V[i]=swap_endian_32(V[i]);
    }

    //iterlate
    for (int i=0;i<n;i++)
    {
        word *B=(word *)message_padding+i*16;
        CF(V,B);
    }
    free(message_padding);
    //change big and little endian
    for(int i=0;i<8;i++)
    {
        V[i]=swap_endian_32(V[i]);
    }

    return V;
}

// //#define SM3_TEST
// // 测试用例
// #ifdef SM3_TEST
// int main() {
//     byte msg[] = "abc";
//     byte* result=(byte *)SM3(msg, 24);
    
//     printf("SM3(\"abc\") = ");
//     for (int i = 0; i < 32; i++) 
//         printf("%x",*(result+i) );
//     printf("\n");

//     byte msg1[]="abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
//     result=(byte*)SM3(msg1,512);
//     printf("SM3(\"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd\") = ");
//     for (int i = 0; i < 32; i++) 
//         printf("%x",*(result+i) );
//     printf("\n");
//     return 0;
// }
// #endif
