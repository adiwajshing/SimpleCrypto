//
//  Padding.c
//  Crypto
//
//  Created by Adhiraj Singh on 2/29/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include "Padding.h"
#include "Utils.h"

#include <math.h>
#include <string.h>
#include <stdlib.h>


///do PKCS5 padding in place, block_size is in bytes, updates plaintext and the new length of the plaintext
void pad_PKCS5 (uint8_t *plaintext, int *len, int block_size) {
    /*
     Examples of PKCS5 padding for block length B = 8:

        3 bytes: FDFDFD           --> FDFDFD0505050505
        7 bytes: FDFDFDFDFDFDFD   --> FDFDFDFDFDFDFD01
        8 bytes: FDFDFDFDFDFDFDFD --> FDFDFDFDFDFDFDFD0808080808080808
    */

    // example used from the CryptoSysk PKI Pro Manual, https://cryptosys.net/pki/manpki/pki_paddingschemes.html
    
    int pad_value = (ceilf( (float)*len / (float)block_size )*block_size) - *len;
    
    if (pad_value > 0) {
        plaintext = realloc(plaintext, (*len + pad_value + 1));
        memset(plaintext + (*len), pad_value, pad_value);
        
        *len += pad_value;
        
        plaintext[*len] = 0;
    }
    
}
void unpad_PKCS5 (uint8_t *plaintext, int *len) {
    
    int count = 0;
    while (plaintext[*len - count - 1] == plaintext[*len - 1]) {
        count += 1;
    }
    
    if (count == plaintext[*len - 1]) {
        *len -= count;
        plaintext = realloc(plaintext, *len);
    }
    
}

/// do chaning in CBC mode
void chain_cbc (uint8_t *txt, const uint8_t *iv, int block_size, int offset) {
    if (iv) {
        // if it's the first block, XOR with IV, otherwise XOR with the previous block
        const uint8_t *v = offset == 0 ? iv : txt+offset-block_size;
        xor_string(txt+offset, v, block_size);
    }
    // don't do any chaining if no IV is provided
}
