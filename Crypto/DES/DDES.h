//
//  DDES.h
//  Crypto
//
//  Created by Adhiraj Singh on 2/29/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#ifndef DDES_h
#define DDES_h

#include <stdio.h>
#include "DES.h"
#include "VDES.h"

/// encrypt using double DES
uint8_t *ddes_encrypt(const uint8_t *plaintext, int *len, const uint8_t K[8], const uint8_t K1[7], const uint8_t K2[7]);
/// decrypt using double DES
uint8_t *ddes_decrypt(const uint8_t *plaintext, int *len, const uint8_t K[8], const uint8_t K1[7], const uint8_t K2[7]);

void testDDES (void);

#endif /* DDES_h */
