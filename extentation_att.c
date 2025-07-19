#define ATTACK 1
#include "SM3.h"
//try to vertify the extentation attack

int main()
{
    //construct secret :we dont know it's abc ,but we can know how many 512bit block it has.
    byte secret[]= "abc";
    byte* result=(byte *)SM3(secret, 24);
    printf("secret message is: abc\n");
    printf("SM3(\"abc\") = \n");
    for (int i = 0; i < 32; i++) 
        printf("%x",*(result+i) );
    printf("\n");

    //construct message,define message_length= secret_length+message_length
    //this message length is we constructed.
    byte message[]="def";
    size_t message_len=512+24;

    //attack force set the message length in padding and the IV.
    byte* result1=(byte *)SM3_attack(message, 24,(word *)result,message_len);
    printf("secret message is: def\n");
    printf("SM3(\"def\") = \n");
    //now we can confrim the constructed m' :secret+secret_padding+message 's hash is below
    for (int i = 0; i < 32; i++) 
        printf("%x",*(result1+i) );
    printf("\n");

    //vertify
    byte * message_padding=padding(secret,24);
    byte *secret_padding_message=malloc(64*sizeof(byte)+3);
    memcpy(secret_padding_message,message_padding,64);
    memcpy(secret_padding_message+64,message,3);
    byte* result2=(byte *)SM3(secret_padding_message, message_len);
    printf("SM3(\"abc+padding+def\") = \n");
    for (int i = 0; i < 32; i++) 
        printf("%x",*(result2+i) );
    printf("\n");
}
