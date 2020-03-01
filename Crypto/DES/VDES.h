//
//  VDES.h
//  Crypto
//
//  Created by Adhiraj Singh on 2/28/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#ifndef VDES_h
#define VDES_h

#include "DES.h"

uint8_t *vdes_encrypt(const uint8_t *plaintext, int *len, const uint8_t key[7], const uint8_t iv[8]);
uint8_t *vdes_decrypt(const uint8_t *ciphertext, int *len, const uint8_t key[7], const uint8_t iv[8]);

void run_vdes_encrypt (void);
void run_vdes_decrypt (void);

void testVDES (void);

#endif /* VDES_h */
