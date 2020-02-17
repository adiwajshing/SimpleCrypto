//
//  ColumnarTranspositionCipher.h
//  Crypto
//
//  Created by Adhiraj Singh on 2/14/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#ifndef ColumnarTranspositionCipher_h
#define ColumnarTranspositionCipher_h

#include <stdio.h>

void columnarTranspositionEncrypt (const char *text, int textlen, const char *key, int keylen, char *ciphertext);
void columnarTranspositionDecrypt (const char *ciphertext, int textlen, const char *key, int keylen, char *plaintext);
void columnarTranspositionTest (void);
#endif /* ColumnarTranspositionCipher_h */
