//
//  VigenereCipher.c
//  Crypto
//
//  Created by Adhiraj Singh on 2/15/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include "VigenereCipher.h"
#include "LetterFrequency.h"

#define CHAR_LOWERBOUND 97
#define CHAR_UPPERBOUND 122

int vigenereCipher (char *text, int textlen, const char *key, int keylen, int encrypt) {
    const int charSize = CHAR_UPPERBOUND - CHAR_LOWERBOUND + 1;
    
    int numSpaces = 0;
    for (int i = 0; i < textlen;i++) {
        
        if (text[i] == 32) {
            numSpaces += 1;
            continue;
        }
        
        if (text[i] < CHAR_LOWERBOUND || text[i] > CHAR_UPPERBOUND) {
            return -1;
        }
        
        char k = key[ (i-numSpaces) % keylen ]-CHAR_LOWERBOUND;
        char ch = (text[ i ]-CHAR_LOWERBOUND);
        if (encrypt) {
            ch += k;
        } else {
            ch = ch >= k ? ch-k : charSize+ch-k;
        }
        text[i] = (ch % charSize) + CHAR_LOWERBOUND;
    }
    return 0;
}

int vigenereCipherEncrypt (char *text, int textlen, const char *key, int keylen) {
    return vigenereCipher(text, textlen, key, keylen, 1);
}
int vigenereCipherDecrypt (char *text, int textlen, const char *key, int keylen) {
    return vigenereCipher(text, textlen, key, keylen, 0);
}

void generatePermutation (const char *set, int setlen, int stringlen, int number, char *out) {
    
    int num;
    while (stringlen > 0) {
        stringlen -= 1;
        
        num = pow(setlen, stringlen);

        *out = set[ number/num ];
        
        out += 1;
        number = number%num;
    }
    
}
void printAllPermutations (const char *set, int setlen, int stringlen) {
    
    int total = pow(setlen, stringlen);
    char out[stringlen+1];
    out[stringlen] = 0;
    while (total > 0) {
        total -= 1;
        generatePermutation(set, setlen, stringlen, total, out);
        printf("p: %s\n", out);
    }
    
}
/// sort floats
int *simpleSortF (const float *arr, int len) {
    int *map = malloc( len * sizeof(int) );
    
    int i, p, j;
    for (i = 0; i < len;i++) {
        p = 0;
        for (j = 0; j < len;j++) {
            if ((arr[j] < arr[i]) || (arr[j] == arr[i] && i > j)) {
                p += 1;
            }
        }
        map[p] = i; // character at pth position is available at index i of str
    }
    return map;
}
/**
 Break the vigenere cipher using the letter frequencies of the english alphabet to construct a key that gives the lowest variance with respect to the alphabet frequencies found in the English language. See LetterFrequency.c for the letter frequency computation.
**/
void breakVigenereCipher (const char *text, int textlen, const int *keylens, int keylensLen) {

    const int numCharacters = CHAR_UPPERBOUND-CHAR_LOWERBOUND+1; // size of the set of characters used in the text. In this case, the english alphabet (a-z)
    
    // loop through all the possible keylengths of the key
    while (keylensLen > 0) {
        keylensLen -= 1;
        int keylen = keylens[keylensLen]; // the length of the key we're trying to break
        
        char key[keylen+1]; // variable to store the keys we're going to try out
        char tmp[textlen+1]; // temp variable to store the decrypted texts in
        
        memset(key, CHAR_LOWERBOUND, sizeof(char) * keylen); // initialize the key to a string of 'a's. This will be a starting point for the decryption
        
        char charactersWithLowestV[keylen][numCharacters]; // a list of characters which give the lowest variance of letters at the given position in the text
        float characterVariances[keylen][numCharacters]; // a list of the variances caused by the character in the certain position
        
        /*
         Now, loop through each position in the key and compute the variance from the letter frequencies of the english alphabet. Then, we'll store N characters with the lowest variances.
         */
        for (int i = 0; i < keylen;i++) {
            
            float variances[numCharacters];
            
            // loop through all the characters in our character set
            for (int j = 0; j < numCharacters;j++) {
                key[i] = j+CHAR_LOWERBOUND; // set the ith character in the string to j
                
                memcpy(tmp, text, sizeof(char) * textlen); // set tmp to the cipher text
                vigenereCipherDecrypt(tmp, textlen, key, keylen); // decrypt using this key
                
                float fit = goodnessOfFit(tmp, textlen); // computes the chi square fit it has with respect to the letter frequencies of the english alphabet has
                variances[j] = fit; // store how well using character j fit
            }
            
            // sort & store
            int *sorted = simpleSortF(variances, numCharacters);
            for (int j = 0; j < numCharacters;j++) {
                charactersWithLowestV[i][j] = (char)sorted[j];
                characterVariances[i][j] = variances[ sorted[j] ];
            }
            free(sorted);
            
            key[i] = CHAR_LOWERBOUND; // reset the key
        }
        
        /*
         construct our key with the characters that gave the lowest variance
         optionally, one could also go over a few permutations using the characters with the lowest variance using the characterVariance data
        */
        for (int i = 0; i < keylen;i++) {
            key[i] = charactersWithLowestV[i][0] + CHAR_LOWERBOUND;
        }
        
        memcpy(tmp, text, sizeof(char) * textlen); // set tmp to the cipher text
        vigenereCipherDecrypt(tmp, textlen, key, keylen); // finally (and hopefully) decrypt the text
        
        printf("key: %s, out: %s\n", key, tmp);
    }
    
}

/// simple unit test to check encryption & decryption
void vigenereCipherTest () {
    
    const char txt[] = "hello fren my name jeff";
    const int textlen = (int)strlen(txt);
    
    const char key[] = "thisisakey";
    const int keylen = (int)strlen(key);
    
    char *text = malloc( textlen * sizeof(char) + 1 );
    memcpy(text, txt, textlen * sizeof(char) + 1);
    
    assert( vigenereCipherEncrypt(text, textlen, key, keylen) == 0);
    
    printf("ciphertext: %s\n", text);
    
    assert( vigenereCipherDecrypt(text, textlen, key, keylen) == 0);
    
    printf("plaintext: %s\n", text);
    
    assert( memcmp(text, txt, textlen * sizeof(char)) == 0 );
}
