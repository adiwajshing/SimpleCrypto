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


///do PKCS7 padding in place, block_size is in bytes, updates plaintext and the new length of the plaintext
void pad_PKCS7 (uint8_t **plaintext, int *len, uint8_t block_size) {
    /*
     Examples of PKCS5 padding for block length B = 8:

        3 bytes: FDFDFD           --> FDFDFD0505050505
        7 bytes: FDFDFDFDFDFDFD   --> FDFDFDFDFDFDFD01
        8 bytes: FDFDFDFDFDFDFDFD --> FDFDFDFDFDFDFDFD0808080808080808
    */

    // example used from the CryptoSysk PKI Pro Manual, https://cryptosys.net/pki/manpki/pki_paddingschemes.html
    
    int pad_value = (ceilf( (float)*len / (float)block_size )*block_size) - *len;
    if (pad_value == 0) {
        pad_value = block_size;
    }
    
    *plaintext = realloc(*plaintext, *len + pad_value);
    memset(*plaintext + *len, pad_value, pad_value);
    
    *len += pad_value;
}
void unpad_PKCS7 (uint8_t **plaintext, int *len) {
    
    int count = 0;
    while (plaintext[0][ (*len) - count - 1] == plaintext[0][ *len - 1 ] && count < *len) {
        count += 1;
    }
    
    if (count == plaintext[0][*len - 1]) {
        *len -= count;
        *plaintext = realloc(*plaintext, *len);
    }
    
}
void pad_PKCS1 (uint8_t **plaintext, int *len, int block_size) {
	int u_block_size = block_size-1;
	pad_PKCS7(plaintext, len, u_block_size);
	
	int blocks = ceil( (*len)/(double)u_block_size );

	*len = blocks * block_size;
	*plaintext = realloc(*plaintext, *len);
	
	uint8_t tmp[u_block_size];
	while (blocks > 0) {
		blocks -= 1;
		memcpy(tmp, (*plaintext) + blocks*u_block_size, u_block_size);
		memcpy((*plaintext) + blocks*block_size, tmp, u_block_size);
		for (int i = 0; i < block_size-u_block_size;i++) {
			(*plaintext)[ (blocks+1)*block_size - 1 - i] = 0;
		}
		
	}
	
}
void unpad_PKCS1 (uint8_t **ciphertext, int *len, int block_size) {
	//*block = realloc(block, len-1);
	int u_block_size = block_size-1;
	int blocks = (*len)/block_size;
	
	uint8_t tmp[u_block_size];
	for (int i = 1; i < blocks;i++) {
		memcpy(tmp, (*ciphertext) + i*block_size, u_block_size);
		memcpy((*ciphertext) + i*u_block_size, tmp, u_block_size);
	}
	
	*len = blocks * u_block_size;
	*ciphertext = realloc(*ciphertext, *len);
	
	unpad_PKCS7(ciphertext, len);
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
