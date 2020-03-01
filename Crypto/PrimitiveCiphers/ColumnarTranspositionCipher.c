//
//  ColumnarTranspositionCipher.c
//  Crypto
//
//  Created by Adhiraj Singh on 2/14/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include "ColumnarTranspositionCipher.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>

/**
 For a given string, maps position of ith character to the corresponding index of the string;
 eg. for str = 'DACBE', function will return indices = [1, 3, 2, 0, 4]
 now if one wants to know what the first character in the string is, one can simply call str [ indices[0] ]
**/
int *sortIndices (const char *str, int strlen) {
    int *map = malloc( strlen * sizeof(int) );
    
    int i, p, j;
    for (i = 0; i < strlen;i++) {
        p = 0;
        for (j = 0; j < strlen;j++) {
            if ((str[j] < str[i]) || (str[j] == str[i] && i > j)) {
                p += 1;
            }
        }
        map[p] = i; // character at pth position is available at index i of str
    }
    return map;
}
void columnarTranspositionEncrypt (const char *text, int textlen, const char *key, int keylen, char *ciphertext) {

    int *columnIndices = sortIndices(key, keylen);
    
    int i = 0, ptr = 0, p = 0, k = 0;
    for (i = 0;i < keylen;i++) {
        p = columnIndices[i]; // p is the index of character in the key at the ith position
        k = 0;

        while ( (p+k*keylen) < textlen ) {
            ciphertext[ ptr ] = text[ p + k*keylen ];;
            ptr += 1;
            k += 1;
        }
    }
    
    free(columnIndices);
}
void columnarTranspositionDecrypt (const char *ciphertext, int textlen, const char *key, int keylen, char *plaintext) {
    int columnLen = textlen/keylen;
    int eColumns = textlen % keylen;
    
    int *columnIndices = sortIndices(key, keylen);
    int i, ptr = 0, p, k, columns;
    for (i = 0; i < keylen;i++) {
        p = columnIndices[i];
        
        columns = p<eColumns ? columnLen+1 : columnLen;
        
        for (k = 0; k < columns;k++) {
            plaintext[ p + k*keylen ] = ciphertext[ ptr ];
            ptr += 1;
        }
    }
    
    free(columnIndices);
}
void columnarTranspositionTest () {
    const char key[] = "CRYPTOGRAPHY";
    const int keylen = (int)strlen(key);
    
    const char plaintext[] = "my name ";
    const int textlen = (int)strlen(plaintext);

    char ciphertext[textlen+1];
    memset(ciphertext, 0, (textlen+1) * sizeof(char));
    
    char decryptedtext[textlen+1];
    memset(decryptedtext, 0, (textlen+1) * sizeof(char));
    
    columnarTranspositionEncrypt(plaintext, textlen, key, keylen, ciphertext);
    printf("ciphertext: %s\n", ciphertext);
    
    columnarTranspositionDecrypt(ciphertext, textlen, key, keylen, decryptedtext);
    printf("plaintext: %s\n", decryptedtext);
    
    assert( memcmp(plaintext, decryptedtext, textlen) == 0 );
}
