//
//  AES.h
//  Crypto
//
//  Created by Adhiraj Singh on 2/29/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#ifndef AES_h
#define AES_h

#include <stdlib.h>

#define AES_BLOCK_SIZE 16

enum AES_MODE {
    AES_128 = 0,
    AES_192 = 1,
    AES_256 = 2
};

uint8_t *aes_cbc_encrypt (const uint8_t *plaintext, int *len, const uint8_t *key, const uint8_t *iv, int mode);
uint8_t *aes_cbc_decrypt (const uint8_t *plaintext, int *len, const uint8_t *key, const uint8_t *iv, int mode);

void testAES (void);

#endif /* AES_h */
