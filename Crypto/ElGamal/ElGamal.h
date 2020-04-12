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

/// encrypt a given plaintexttext using ElGamal
uint8_t *ElGamal_encrypt (const uint8_t *plaintext, size_t *len, mpz_t g, mpz_t h, mpz_t q);
/// decrypt a given ElGamal encrypted ciphertext
uint8_t *ElGamal_decrypt (const uint8_t *ciphertext, size_t *len, mpz_t a, mpz_t q);

/// sign a plaintext using ElGamal; set hash_sha256 = 1 to hash the plaintext before signing
uint8_t *ElGamal_signature (const uint8_t *plaintext, size_t *len, mpz_t g, mpz_t a, mpz_t q, int hash_sha256);
/// verify a given ElGamal signature is valid
int ElGamal_sign_verify_mpz (mpz_t m, mpz_t r, mpz_t s, mpz_t h, mpz_t q, mpz_t g);
/// verify a given ElGamal signature is valid; set hash_sha256 = 1 to hash the plaintext before verifying the sign
int ElGamal_sign_verify (const uint8_t *plaintext, size_t plaintextlen, const uint8_t *sign, mpz_t h, mpz_t q, mpz_t g, int hash_sha256);
/// generate an existential forgery in the given ElGamal scheme; sets r, s & m to be an existential forgery
void ElGamal_generate_existential_forge (mpz_t r, mpz_t s, mpz_t m, mpz_t h, mpz_t q, mpz_t g, unsigned long seed);

void ElGamal_get_block_size (int *block_size, int *u_block_size, mpz_t q);

void testElGamal (void);
#endif /* ElGamal_h */
