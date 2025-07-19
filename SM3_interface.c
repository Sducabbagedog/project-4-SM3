#include "SM3.h"


//interface
int main(int argc, char *argv[]) {
    //check arguments' amount
    if (argc!=3)
    {
        printf("Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }
    
    //read input
    FILE *input_file = fopen(argv[1], "rb");
    if (input_file == NULL) {
        printf("Failed to open input file.\n");
        return 1;
    }
    //get input size
    fseek(input_file, 0, SEEK_END);
    size_t n=ftell(input_file);
    fseek(input_file, 0, SEEK_SET);
    byte *message = malloc(n);
    fread(message, 1, n, input_file);
    fclose(input_file);

    //get hash
    word *result=SM3(message,n*8);

    //write output
    FILE *output_file = fopen(argv[2], "wb");
    if (output_file == NULL) {
        printf("Failed to open output file.\n");
        return 1;
    }
    fwrite(result, 1, 32, output_file);
    fclose(output_file);

    //free
    free(message);
    free(result);
    return 0;
}

