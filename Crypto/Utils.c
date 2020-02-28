//
//  Utils.c
//  Crypto
//
//  Created by Adhiraj Singh on 2/27/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include "Utils.h"

void print_str(const char *str) {
    print_bytes(str, (int)(str ? strlen(str) : 0));
}
void print_bytes(const char *str, int len)
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
