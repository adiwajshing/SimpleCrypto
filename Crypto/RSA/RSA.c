//
//  RSA.c
//  Crypto
//
//  Created by Adhiraj Singh on 3/28/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include "RSA.h"
#include "Padding.h"
#include "Utils.h"

#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>

void RSA_key_init (RSAKeyPair *key) {
	mpz_init(key->n);
	mpz_init(key->e);
	mpz_init(key->d);
	mpz_init(key->p);
	mpz_init(key->q);
	mpz_init(key->exp1);
	mpz_init(key->exp2);
	mpz_init(key->coeff);
}
void RSA_key_gen (RSAKeyPair *key, const unsigned int key_size_bits, unsigned long seed) {
	if (seed == 0) { // if no seed was provided,
		srand48( time(0) );
		seed = random(); // generate a random seed
	}
	
	mpz_t phiN, tmp;
	mpz_init(phiN);
	mpz_init(tmp);
	gen_prime(key->p, seed, key_size_bits/2); // generate a random p
	gen_prime(key->q, seed*2, key_size_bits/2); // generate a random q
	
	mpz_mul(key->n, key->p, key->q); // n = pq

	mpz_sub_ui(key->p, key->p, 1); // temp, set p = p-1
	mpz_sub_ui(key->q, key->q, 1); // temp, set q = q-1
	
	mpz_mul(phiN, key->p, key->q); // set phi(N) = (p-1)(q-1)

	mpz_set_ui(key->e, 65537); // set public key to fermat number 4 (gives quick encryption as its 0x010001, only 2 1s)
	
	mpz_gcd(tmp, phiN, key->e);
	if (mpz_cmp_ui(tmp, 1) != 0) { // if gcd(e, phi(N)) != 1
		gen_prime(key->e, mpz_mod_ui(NULL, key->e, seed), 8*sizeof(mp_limb_t)); // set e to a small random prime
	}
	
	mpz_invert(key->d, key->e, phiN); // d = e^-1 mod N
	
	mpz_mod(key->exp1, key->d, key->p); // exp1 = d mod (p-1)
	mpz_mod(key->exp2, key->d, key->q); // exp1 = d mod (q-1)
	
	mpz_add_ui(key->p, key->p, 1); // revert p
	mpz_add_ui(key->q, key->q, 1); // revert q
	
	mpz_invert(key->coeff, key->q, key->p); // coeff = q mod p
	
	mpz_clear(tmp);
	mpz_clear(phiN);
}
void RSA_key_free (RSAKeyPair *key) {
	mpz_clear(key->n);
	mpz_clear(key->d);
	mpz_clear(key->e);
	mpz_clear(key->p);
	mpz_clear(key->q);
	mpz_clear(key->exp1);
	mpz_clear(key->exp2);
	mpz_clear(key->coeff);
}

uint8_t* RSA_crypt (const uint8_t *m, int *len, mpz_t e, mpz_t n, const unsigned int key_size_bits, int encrypt) {
	const int block_size = key_size_bits/8; // block size in bytes
	
	uint8_t *buffer = malloc( *len ); // temp buffer
	memcpy(buffer, m, *len);
	if (encrypt) {
		pad_PKCS7Ext(&buffer, len, block_size, block_size-1); // pad
	}
	
	const int blocks = *len / block_size; // number of blocks
	
	mpz_t tmp;
	mpz_init(tmp);
	for (int i = 0; i < blocks; i++) {
		mpz_import(tmp, block_size, -1, sizeof(uint8_t), 1, 0, buffer + i*block_size);
		assert( mpz_cmp(tmp, n) < 0 ); // ensure the block is less than the modulus
		mpz_powm(tmp, tmp, e, n); // c = m^e mod n
		
		size_t count = 0;
		mpz_export(buffer + i*block_size, &count, -1, sizeof(uint8_t), 1, 0, tmp);
		if (count < block_size) { // pad with zeros if answer is less than the block size
			memset(buffer + i*block_size + count, 0, block_size-count);
		}
	}
	mpz_clear(tmp);
	
	if (!encrypt) {
		unpad_PKCS7Ext(&buffer, len, block_size, block_size-1); // unpad on decryption
	}
	
	return buffer;
}

uint8_t* RSA_encrypt (const uint8_t *plaintext, int *len, mpz_t e, mpz_t n, const unsigned int key_size_bits) {
	return RSA_crypt(plaintext, len, e, n, key_size_bits, 1);
}
uint8_t* RSA_decrypt (const uint8_t *ciphertext, int *len, mpz_t d, mpz_t n, const unsigned int key_size_bits) {
	return RSA_crypt(ciphertext, len, d, n, key_size_bits, 0);
}

/// unit test for RSA; generate a set of random plaintexts & random keys and check validity of cryptosystem
void testRSA () {
	const int modes[] = {RSA_512, RSA_1024, RSA_2048};
	mpz_t plaintexts[10];
	RSAKeyPair key;
	uint8_t *plaintext, *ciphertext, *decryptedtext;
	
	gmp_randstate_t rand_state;
	gmp_randinit_default(rand_state);
	
	for (int i = 0; i < 10;i++) {
		int bitlen = 8*((rand() % 512) + 8);
		mpz_init(plaintexts[i]);
		mpz_urandomb(plaintexts[i], rand_state, bitlen);
		mpz_setbit(plaintexts[i], bitlen-1);
	}
	
	for (int i = 0; i < 3; i++) {
		RSA_key_gen(&key, modes[i], 0);
		
		for (int j = 0; j < 10;j++) {
			plaintext = (uint8_t *)(plaintexts[j]->_mp_d);
			int plaintextlen = (plaintexts[j] -> _mp_size)*sizeof(mp_limb_t);
			
			ciphertext = RSA_encrypt(plaintext, &plaintextlen, key.e, key.n, modes[i]);
			decryptedtext = RSA_decrypt(ciphertext, &plaintextlen, key.d, key.n, modes[i]);

			assert(memcmp(plaintext, decryptedtext, plaintextlen) == 0);
			
			free(ciphertext);
			free(decryptedtext);
		}
		
		
	}
	RSA_key_free(&key);
	for (int i = 0; i < 10;i++) {
		mpz_clear(plaintexts[i]);
	}
}


/// Miller & Robin probabalistic  prime checking (not needed as GMP already has implements it)
/*int is_prolly_prime (mpz_t n, unsigned long k) {
	mpz_t a, x, d;
	unsigned long r = 0, i = 0;
	
	mpz_sub_ui(d, n, 1);
	while (mpz_even_p(d)) {
		mpz_div_ui(d, d, 2);
		r += 1;
	}
	
	gmp_randstate_t rand_state;
	gmp_randinit_mt(rand_state);
	
	while (k > 0) {
		k -= 1;
		
		mpz_urandomm(a, rand_state, n);
		
		mpz_powm(x, a, d, n);
		mpz_add_ui(x, x, 1);
		if (mpz_cmp_ui(x, 2) == 0 || mpz_cmp(x, n) == 0) {
			continue;
		}
		mpz_sub_ui(x, x, 1);
		
		for (i = 1; i < r;i++) {
			mpz_powm_ui(x, x, 2, n);
			mpz_add_ui(x, x, 1);
			if (mpz_cmp(x, n) == 0) {
				i = -1;
				break;
			}
		}
		if (i > 0) {
			return 0;
		}
	}
	gmp_randclear(rand_state);
	return 1;
}*/
