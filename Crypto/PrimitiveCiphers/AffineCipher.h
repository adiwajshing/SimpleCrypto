//
//  AffineCipher.h
//  Crypto
//
//  Created by Adhiraj Singh on 2/14/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#ifndef AffineCipher_h
#define AffineCipher_h

#include <stdio.h>

int affineEncrypt (char *text, int len, int key[2]);
int affineDecrypt (char *text, int len, int key[2]);
int caesarEncrypt (char *text, int len, int key);

void breakCaesarCipher (const char *ciphertext, int len, int bruteForce);

#endif /* AffineCipher_h */
