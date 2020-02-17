//
//  VigenereCipher.h
//  Crypto
//
//  Created by Adhiraj Singh on 2/15/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#ifndef VigenereCipher_h
#define VigenereCipher_h

#include <stdio.h>

int vigenereCipherEncrypt (char *text, int textlen, const char *key, int keylen);
int vigenereCipherDecrypt (char *text, int textlen, const char *key, int keylen);
void breakVigenereCipher (const char *text, int textlen, const int *keylens, int keylensLen);

void vigenereCipherTest (void);


#endif /* VigenereCipher_h */
