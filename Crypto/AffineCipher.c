//
//  AffineCipher.c
//  Crypto
//
//  Created by Adhiraj Singh on 2/14/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include "AffineCipher.h"
#include "LetterFrequency.h"
#include <string.h>

int modInv (int n, int m) {
    for (int i = 1; i < m;i++) {
        if (n*i % m == 1) {
            return i;
        }
    }
    return -1;
}

int affineEncrypt (char *text, int len, int key[2]) {
    for (int i = 0; i < len;i++) {
        
        if (text[i] == 32) { continue; }
        if (text[i] < 97 || text[i] > 122) { return -1; }
        
        text[i] = ( key[0]*(text[i]-97) + key[1] ) % 26 + 97;
    }
    return 0;
}
int affineDecrypt (char *text, int len, int key[2]) {
    int keyInv = modInv(key[0], 26);
    if (keyInv < 0) {
        return keyInv;
    }
    int k[] = {keyInv, -(keyInv)*key[1] };
    return affineEncrypt(text, len, k);
}
int caesarEncrypt (char *text, int len, int key) {
    int k[] = {1, key};
    return affineEncrypt(text, len, k);
}
void breakCaesarCipher (const char *ciphertext, int len, int bruteForce) {
    char plaintext[len+1];
    
    if (bruteForce)  {
        for (int i = 0; i < 26;i++) {
            memcpy(plaintext, ciphertext, len * sizeof(char));
            caesarEncrypt(plaintext, len, i);
            printf("using key %d: %s\n", i, plaintext);
        }
    } else {
        int minVarianceKey = 0;
        float minVariance = 100.0f;
        char minVarianceText[len+1];
        
        for (int i = 0; i < 26;i++) {
            memcpy(plaintext, ciphertext, len * sizeof(char));
            caesarEncrypt(plaintext, len, i);
            
            float fit = goodnessOfFit(plaintext, len);
            if (fit < minVariance) {
                minVariance = fit;
                minVarianceKey = (i);
                memcpy(minVarianceText, plaintext, sizeof(char) * len);
            }
        }
        
        printf("using key %d: %s\n", minVarianceKey, minVarianceText);
    }
    
}
