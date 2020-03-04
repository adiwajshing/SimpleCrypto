//
//  Padding.h
//  Crypto
//
//  Created by Adhiraj Singh on 2/29/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#ifndef Padding_h
#define Padding_h

#include <stdlib.h>

void pad_PKCS7 (uint8_t *plaintext, int *len, uint8_t block_size);
void unpad_PKCS7 (uint8_t *plaintext, int *len);
void chain_cbc (uint8_t *txt, const uint8_t *iv, int block_size, int offset);

#endif /* Padding_h */
