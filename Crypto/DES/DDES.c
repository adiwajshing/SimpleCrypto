//
//  DDES.c
//  Crypto
//
//  Created by Adhiraj Singh on 2/29/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include "DDES.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>

uint8_t *ddes_encrypt(const uint8_t *plaintext, int *len, const uint8_t K[8], const uint8_t K1[7], const uint8_t K2[7]) {
    
    // encrypt first using key K1 & CBC mode using IV, K
    uint8_t *tmptext = vdes_encrypt(plaintext, len, K1, K);
    // encrypt the ciphertext using key K2 and ECB mode
    uint8_t *ciphertext = vdes_encrypt(tmptext, len, K2, NULL);
    
    free(tmptext);
    return ciphertext;
}
uint8_t *ddes_decrypt(const uint8_t *ciphertext, int *len, const uint8_t K[8], const uint8_t K1[7], const uint8_t K2[7]) {
    
    uint8_t *tmptext = vdes_decrypt(ciphertext, len, K2, NULL);
    uint8_t *plaintext = vdes_decrypt(tmptext, len, K2, K);
    
    free(tmptext);
    return plaintext;
}

void testDDES () {
    
    const char plaintext[] = "romeoandjulietweregreatlovers";
    const char key1[] = "Z8tb;a=8";
    const char key2[] = "Z8tb;a=8";

    const char K[] = "abcdefgh";
    
    int plaintextlen = (int)strlen(plaintext);
    uint8_t *ciphertext = ddes_encrypt((uint8_t *)plaintext, &plaintextlen, (uint8_t *)key1, (uint8_t *)K, (uint8_t *)key2 );
    
    assert( plaintextlen % DES_BLOCK_SIZE == 0 ); // check if padding was done right
    
    uint8_t *decryptedtext = ddes_decrypt((uint8_t *)ciphertext, &plaintextlen, (uint8_t *)key1, (uint8_t *)K, (uint8_t *)key2 );
    
    assert( memcmp(plaintext, decryptedtext, plaintextlen) == 0 ); // check if the original plaintext and decrypted text are the same

    free(ciphertext);
    free(decryptedtext);
    
}
