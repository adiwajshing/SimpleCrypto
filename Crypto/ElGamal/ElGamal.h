//
//  ElGamal.h
//  Crypto
//
//  Created by Adhiraj Singh on 3/29/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#ifndef ElGamal_h
#define ElGamal_h

#include <stdio.h>
#include <gmp.h>

#define ELGAMAL_300 300
#define ELGAMAL_512 512

struct ElGamalKeyPair {
	mpz_t q;
	mpz_t g;
	mpz_t h;
	
	mpz_t a; // private key
};
typedef struct ElGamalKeyPair ElGamalKeyPair;

/// initialize memory of key
void ElGamal_key_init (ElGamalKeyPair *key);
/// generate a public & private key pair, store in key; set seed = 0 to randomly initialize
void ElGamal_key_gen (ElGamalKeyPair *key, unsigned int modulo_size, unsigned long seed);
/// free all memory in the RSAKeyPair structure
void ElGamal_key_free (ElGamalKeyPair *key);

uint8_t *ElGamal_encrypt (const uint8_t *plaintext, size_t *len, mpz_t g, mpz_t h, mpz_t q);
uint8_t *ElGamal_decrypt (const uint8_t *ciphertext, size_t *len, mpz_t a, mpz_t q);

void testElGamal (void);
#endif /* ElGamal_h */
