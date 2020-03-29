//
//  ASN1.h
//  Crypto
//
//  Created by Adhiraj Singh on 3/29/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#ifndef ASN1_h
#define ASN1_h

#include <stdio.h>
#include "RSA.h"

void ASN1_write_private_key (RSAKeyPair *key, const char *filename);
int ASN1_read_private_key (RSAKeyPair *key, const char *filename);

void ASN1_write_public_key (mpz_t n, mpz_t e, const char *filename);
int ASN1_read_public_key (mpz_t n, mpz_t e, const char *filename);
#endif /* ASN1_h */
