//
//  Utils.c
//  Crypto
//
//  Created by Adhiraj Singh on 2/27/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include "Utils.h"
#include <stdio.h>

void print_str(const char *str) {
    print_bytes((unsigned char *)str, (int)(str ? strlen(str) : 0));
}
void print_bytes(const unsigned char *str, int len)
{
    if (!str) {
        printf("NULL");
    } else {
        int i = 0;
        while (len > 0) {
            for(i = 0;i < 8;i++) {
                printf("%d", ((*str) >> i ) & 1 );
            }
            str += 1;
            len -= 1;
            printf(" ");
        }
    }
    
    printf("\n");
}

void print_as_hex(const unsigned char *buff, int len) {
    char *str = buffer_to_hex_str(buff, len);
    printf("%s", str);
    free(str);
}

char *buffer_to_hex_str (const unsigned char *buff, int len) {
    /* target buffer should be large enough */
    char *pout = (char *)malloc( len*3 );
    const char hex[] = "0123456789ABCDEF";
    
    for (int i = 0; i < len;i++) {
        pout[i*3 + 0] = hex[ (buff[i]>>4) & 0xF ];
        pout[i*3 + 1] = hex[ buff[i] & 0xF ];
        pout[i*3 + 2] = ' ';
        
    }
    pout[len*3 - 1] = 0;
    return pout;
}
unsigned char to_num (char hex_char) {
    unsigned char c = hex_char - '0';
    return c > 9 ? c-7 : c;
}
unsigned char *hex_str_to_buffer (const char *hex, int len) {
    unsigned char *out = (unsigned char *)malloc( (len/2) );
    
    int count = 0;
    int nc = 0;
    while (count < len) {
        if (hex[count] == ' ' || hex[count] == ':') {
            count += 1;
        } else {
          
            out[nc] = (to_num(hex[count])<<4) | to_num(hex[count+1]);
            count += 2;
            nc += 1;
        }
    }
    out = realloc(out, nc);
    return out;
}

/// XORs 2 byte buffers, outputs on the first buffer
void xor_string(unsigned char *a, const unsigned char *b, int len)
{
    while (len) {
        len -= 1;
        a[len] ^= b[len];
    }
}
/// swaps two character arrays
void swap (uint8_t *a, uint8_t *b, int len) {
    uint8_t tmp;
    while (len) {
        len -= 1;
        
        tmp = a[len];
        a[len] = b[len];
        b[len] = tmp;
    }
}



/// Reads till the EOF; str => the pointer in which the buffer will be stored (provide NULL), rlen => the length of the buffer
char *get_text(const char *filename, int *rlen)
{
    FILE *file = fopen(filename, "r");
    if (!file) {
        return NULL;
    }
    
    fseek(file, 0, SEEK_END); // maybe do error handling?
    *rlen = (int) ftell(file);
    
    char *str = malloc( sizeof(char) * (*rlen + 1));
    str[*rlen] = 0;
    if (fread(str, *rlen, 1, file) != 1) {
        free(str);
        return NULL;
    }
    
    fclose(file);
    return str;
}
int set_text(const char *filename, char *str, int len)
{
    FILE *file = fopen(filename, "w");
    if (!file) {
        return -1;
    }
    
    if (fwrite(str, sizeof(char), len, file) != 1) {
        return -1;
    }
    return 0;
}
