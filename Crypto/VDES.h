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

char *vdes_encrypt(const char *plaintext, int *len, const char key[7], const char iv[8]);
char *vdes_decrypt(const char *ciphertext, int *len, const char key[7], const char iv[8]);

void run_vdes_encrypt (void);
void run_vdes_decrypt (void);

#endif /* VDES_h */
