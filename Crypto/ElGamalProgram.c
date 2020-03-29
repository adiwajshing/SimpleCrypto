//
//  ElGamalProgram.c
//  Crypto
//
//  Created by Adhiraj Singh on 3/29/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//
//  Example usage of the ElGamal cryptosystem

#include <stdio.h>
#include <string.h>
#include "ElGamal.h"
#include "Utils.h"

int main (int argc, const char * argv[]) {
	ElGamalKeyPair key;
	ElGamal_key_init(&key);
	
	ElGamal_key_gen(&key, ELGAMAL_512, 0);
	
	char plaintext[] = "hello this is a plaintext!!!";
	size_t plaintextlen = strlen(plaintext)+1;
	
	printf("plaintext: %s\n", plaintext);
	printf("encrypting...\n");
	
	uint8_t *ciphertext = ElGamal_encrypt((uint8_t *)plaintext, &plaintextlen, key.g, key.h, key.q);
	printf("ciphertext (hex): "); print_as_hex(ciphertext, (int)plaintextlen); printf("\n");
	
	printf("decrypting...\n");
	uint8_t *decryptedtext = ElGamal_decrypt(ciphertext, &plaintextlen, key.a, key.q);
	
	printf("decrypted plaintext: %s\n", (char *)decryptedtext);
}
