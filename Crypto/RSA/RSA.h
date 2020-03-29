//
//  RSA.h
//  Crypto
//
//  Created by Adhiraj Singh on 3/28/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#ifndef RSA_h
#define RSA_h

#include <gmp.h>
#include <stdlib.h>

// key size in bits
#define RSA_512 512
#define RSA_1024 1024
#define RSA_2048 2048
#define RSA_4096 4096 // does not work with padding

/// Structure to store information about the RSA private & public keys
struct RSAKeyPair {
	mpz_t n; // the modulus = prime1*prime2
	mpz_t e; // public key
	mpz_t d; // private key
	mpz_t p; // prime 1
	mpz_t q; // prime 2
	mpz_t exp1; // d mod (p-1)
	mpz_t exp2; // d mod (q-1)
	mpz_t coeff; // q^-1 mod p
};
typedef struct RSAKeyPair RSAKeyPair;

/// initialize memory of key
void RSA_key_init (RSAKeyPair *key);
/// generate a public & private key pair, store in key; set seed = 0 to randomly initialize
void RSA_key_gen (RSAKeyPair *key, const unsigned int key_size_bits, unsigned long seed);
/// free all memory in the RSAKeyPair structure
void RSA_key_free (RSAKeyPair *key);

uint8_t* RSA_encrypt (const uint8_t *plaintext, int *len, mpz_t e, mpz_t n, const unsigned int key_size_bits);
uint8_t* RSA_decrypt (const uint8_t *ciphertext, int *len, mpz_t d, mpz_t n, const unsigned int key_size_bits);

void testRSA(void);

#endif /* RSA_h */
