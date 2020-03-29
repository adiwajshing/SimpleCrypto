//
//  ElGamal.c
//  Crypto
//
//  Created by Adhiraj Singh on 3/29/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//
#include "ElGamal.h"
#include "Utils.h"
#include "Padding.h"

#include <assert.h>
#include <time.h>
#include <math.h>

/// check if g is a primitve root mod n
int check_primitive_root (mpz_t g, mpz_t n, mpz_t factors[2]) {
	mpz_t tmp;
	mpz_init(tmp);
	for (int i = 0; i < 2;i++) {
		mpz_sub_ui(tmp, n, 1);
		mpz_div(tmp, n, factors[i]);
		mpz_powm(tmp, g, tmp, n);
		if (mpz_cmp_ui(tmp, 1) == 0) {
			return 0;
		}
	}
	mpz_clear(tmp);
	return 1;
}
/// generate a prime q, where q = 2p + 1 & also generate g, a primitive root of q
void generate_prime_and_root (mpz_t g, mpz_t q, unsigned int modulo_size, unsigned long seed) {
	
	do {
		seed += 10;
		gen_prime(g, seed, modulo_size-2); // generate a random prime p
		mpz_mul_ui(q, g, 2); // q = 2p
		mpz_add_ui(q, q, 1); // q = 2p + 1

	} while (!mpz_probab_prime_p(q, 10)); // check if q is also prime, break if it is
	
	// q-1 will have 2 factors only, 2 & p
	mpz_t factors[2];
	mpz_init_set_ui(factors[0], 2);
	mpz_init_set(factors[1], g);
	
	mpz_set(g, q); // set g as q
	
	do {
		mpz_sub_ui(g, g, 2); // keep subtracting 2
	} while (check_primitive_root(g, q, factors)); // and checking for primitive root
}
void ElGamal_key_init (ElGamalKeyPair *key) {
	mpz_init(key->q);
	mpz_init(key->g);
	mpz_init(key->h);
	mpz_init(key->a);
}
void ElGamal_key_gen (ElGamalKeyPair *key, unsigned int modulo_size, unsigned long seed) {
	if (seed == 0) { // if no seed was provided,
		srand48( time(0) );
		seed = random(); // generate a random seed
	}
	
	generate_prime_and_root(key->g, key->q, modulo_size, seed); // generate g & q
	
	gmp_randstate_t rand_state;
	gmp_randinit_default(rand_state);
	gmp_randseed_ui(rand_state, seed);
	
	mpz_urandomm(key->a, rand_state, key->q); // choose a random 'a' between [1,...,(q-1)]
	
	gmp_randclear(rand_state);
	
	mpz_powm(key->h, key->g, key->a, key->q); // set h = g^a mod q
}
void ElGamal_key_free (ElGamalKeyPair *key) {
	mpz_clear(key->q);
	mpz_clear(key->g);
	mpz_clear(key->h);
	mpz_clear(key->a);
}

uint8_t *ElGamal_encrypt (const uint8_t *plaintext, size_t *len, mpz_t g, mpz_t h, mpz_t q) {
	const int block_size = (int)mpz_sizeinbase(q, 16); // block size for ElGamal, is twice the size of the message to accomodate (c1, c2)
	const int u_block_size = block_size/2 -1; // block size of message, should be < block_size/2 so that it is less than q
	
	uint8_t *buffer = malloc( *len );
	memcpy(buffer, plaintext, *len);
	
	pad_PKCS7Ext(&buffer, (int *)len, block_size, u_block_size); // pad
	//print_as_hex(buffer, *len); printf("\n");
	
	int blocks = (int)(*len)/block_size; // number of blocks we gave
	
	mpz_t c1, c2, tmp;
	mpz_init(c1);
	mpz_init(c2);
	mpz_init(tmp);
	
	gmp_randstate_t rand_state;
	gmp_randinit_default(rand_state);
	gmp_randseed_ui(rand_state, 13123123);
	
	
	for (int i = 0; i < blocks;i++) {
		mpz_urandomm(c1, rand_state, q); // choose a random r between [1,...,(q-1)]
		mpz_powm(c2, h, c1, q); // c2 = h^r mod q
		mpz_powm(c1, g, c1, q); // c1 = g^r mod q
		
		mpz_import(tmp, u_block_size, -1, sizeof(uint8_t), 1, 0, buffer + i*block_size);
		
		mpz_mul(c2, c2, tmp); // c2 = h^r * m
		mpz_mod(c2, c2, q); // c2 = h^r * m mod q
		
		memset(buffer + i*block_size, 0, block_size); // clear block
		mpz_export(buffer + i*block_size, NULL, -1, sizeof(uint8_t), 1, 0, c1); // set first half as c1
		mpz_export(buffer + i*block_size + block_size/2, NULL, -1, sizeof(uint8_t), 1, 0, c2); // set 2nd half as c2
	}
	
	gmp_randclear(rand_state);
	mpz_clears(c1, c2, tmp);
	
	return buffer;
}
uint8_t *ElGamal_decrypt (const uint8_t *ciphertext, size_t *len, mpz_t a, mpz_t q) {
	const int block_size = (int)mpz_sizeinbase(q, 16); //(int)mpz_sizeinbase(q, 2)/4; // block size for ElGamal, is twice the size of the message to accomodate (c1, c2)
	const int u_block_size = block_size/2 -1; // block size of message, should be < block_size/2 so that it is less than q
	
	
	uint8_t *buffer = malloc( *len );
	memcpy(buffer, ciphertext, *len);
		
	int blocks = (int)(*len)/block_size;
	
	mpz_t c1, c2;
	mpz_init(c1);
	mpz_init(c2);
	
	for (int i = 0; i < blocks;i++) {
		mpz_import(c1, block_size/2, -1, sizeof(uint8_t), 1, 0, buffer + i*block_size); // 1st half of block is c1
		mpz_import(c2, block_size/2, -1, sizeof(uint8_t), 1, 0, buffer + i*block_size + block_size/2); // 2nd half of block is c2
		
		mpz_powm(c1, c1, a, q); // t1 = c1^a mod q
		mpz_invert(c1, c1, q); // get t1^-1 mod 1
		mpz_mul(c1, c1, c2); // m = c2 * t1^-1
		mpz_mod(c1, c1, q); // m = c2 * t1^-1 mod q
		 
		memset(buffer + i*block_size, 0, block_size); // clear memory
		mpz_export(buffer + i*block_size, NULL, -1, sizeof(uint8_t), 1, 0, c1); // set block
	}
	
	//print_as_hex(buffer, *len); printf("\n");
	unpad_PKCS7Ext(&buffer, (int *)len, block_size, u_block_size); // unpad
	
	mpz_clear(c1);
	mpz_clear(c2);
	
	return buffer;
}

/// unit test to run ElGamal, generate a bunch of plaintexts & check cryptosystem validity
void testElGamal () {
	const size_t num_plaintexts = 20;
	
	ElGamalKeyPair key;
	mpz_t plaintexts[num_plaintexts];
	uint8_t *plaintext, *ciphertext, *decryptedtext;
	
	gmp_randstate_t rand_state;
	gmp_randinit_default(rand_state);
	
	ElGamal_key_init(&key);
	
	// generate a random set of plaintexts
	for (int i = 0; i < num_plaintexts;i++) {
		int bitlen = 8*((rand() % 1024) + 8);
		
		mpz_init(plaintexts[i]);
		mpz_urandomb(plaintexts[i], rand_state, bitlen);
		mpz_setbit(plaintexts[i], bitlen-1);
	}
	
	for (int i = 0; i < 5;i++) {
		ElGamal_key_gen(&key, ELGAMAL_512, 0);
		
		for (int j = 0; j < num_plaintexts;j++) {
			plaintext = (uint8_t *)(plaintexts[j]->_mp_d);
			size_t plaintextlen = (plaintexts[j] -> _mp_size)*sizeof(mp_limb_t);
			
			// encrypt using public key
			ciphertext = ElGamal_encrypt(plaintext, &plaintextlen, key.g, key.h, key.q);
			// decrypt using private key
			decryptedtext = ElGamal_decrypt(ciphertext, &plaintextlen, key.a, key.q);
			
			// check if plaintexts are equal
			assert( memcmp(plaintext, decryptedtext, plaintextlen) == 0 );
			
			free(ciphertext);
			free(decryptedtext);
		}
		
	}
	
	ElGamal_key_free(&key);
	for (int i = 0; i < num_plaintexts;i++) {
		mpz_clear(plaintexts[i]);
	}
}
