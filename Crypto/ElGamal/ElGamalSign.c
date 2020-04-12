//
//  ElGamal2.c
//  Crypto
//
//  Created by Adhiraj Singh on 4/11/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include "ElGamal.h"
#include "Padding.h"
#include "Utils.h"
#include "sha-256.h"

#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>

uint8_t *ElGamal_signature (const uint8_t *plaintext, size_t *len, mpz_t g, mpz_t a, mpz_t q, int hash_sha256) {
	
	if (hash_sha256) {
		uint8_t hash[32];
		calc_sha_256(hash, plaintext, *len);
		*len = 32;
		plaintext = hash;
	}
	
	int block_size, u_block_size;
	ElGamal_get_block_size(&block_size, &u_block_size, q);
	
	uint8_t *buffer = malloc(*len);
	memcpy(buffer, plaintext, *len);
	
	pad_PKCS7Ext(&buffer, (int *)len, block_size, u_block_size); // pad
	//print_as_hex(buffer, *len); printf("\n");
	
	int blocks = (int)(*len)/block_size; // number of blocks we gave
	
	mpz_t c1, c2, tmp, p;
	mpz_init(c1);
	mpz_init(c2);
	mpz_init(tmp);
	mpz_init(p);
	
	mpz_sub_ui(p, q, 1); // p = (q-1)
	mpz_div_ui(p, p, 2); // p = (q-1)/2
	
	gmp_randstate_t rand_state;
	gmp_randinit_default(rand_state);
	gmp_randseed_ui(rand_state, 13123123); // TODO; change to something else
	
	for (int i = 0; i < blocks;i++) {
		mpz_urandomm(c1, rand_state, p); // choose a random k between [1,...,(p-1)]
		mpz_invert(c2, c1, p); // c2 = k^-1 mod p
		mpz_powm(c1, g, c1, q); // c1 = r = g^k mod q

		mpz_import(tmp, u_block_size, -1, sizeof(uint8_t), 1, 0, buffer + i*block_size);
		
		mpz_mul(tmp, tmp, c2); // tmp = s = m*k^-1
		mpz_mul(c2, c2, a); // c2 = a*k^-1
		mpz_mul(c2, c2, c1); // c2 = a*r*k^-1
		
		mpz_sub(tmp, tmp, c2); // tmp = s = (m-ar)k^-1
		mpz_mod(tmp, tmp, p); // tmp = s = (m-ar)k^-1 mod p
		
		//mpz_out_str(stdout, 16, tmp); printf("\n");
		
		memset(buffer + i*block_size, 0, block_size); // clear block
		mpz_export(buffer + i*block_size, NULL, -1, sizeof(uint8_t), 1, 0, c1); // set first half as c1
		mpz_export(buffer + i*block_size + block_size/2, NULL, -1, sizeof(uint8_t), 1, 0, tmp); // set 2nd half as tmp
	}
	
	gmp_randclear(rand_state);
	mpz_clears(c1, c2, tmp);
	
	return buffer;
}
int ElGamal_sign_verify_mpz (mpz_t m, mpz_t r, mpz_t s, mpz_t h, mpz_t q, mpz_t g) {
	mpz_powm(m, g, m, q); // m = g^m mod q
	
	mpz_powm(s, r, s, q); // r = r^s mod q
	mpz_powm(r, h, r, q); // s = h^r mod q
	
	mpz_mul(r, r, s); // r = r^s * h^r
	mpz_mod(r, r, q); // r = r^s * h^r mod q
	
	return mpz_cmp(r, m) == 0; // check if (g^m mod q) = (r^s * h^r mod q)
}
int ElGamal_sign_verify (const uint8_t *plaintext, size_t plaintextlen, const uint8_t *sign, mpz_t h, mpz_t q, mpz_t g, int hash_sha256) {
	
	if (hash_sha256) {
		uint8_t hash[32];
		calc_sha_256(hash, plaintext, plaintextlen);
		plaintextlen = 32;
		plaintext = hash;
	}
	
	int block_size, u_block_size;
	ElGamal_get_block_size(&block_size, &u_block_size, q);
	
	uint8_t *buffer = malloc(plaintextlen);
	memcpy(buffer, plaintext, plaintextlen);
	
	pad_PKCS7Ext(&buffer, (int *)(&plaintextlen), block_size, u_block_size); // pad
	//print_as_hex(buffer, *len); printf("\n");
	
	int blocks = (int)(plaintextlen)/block_size; // number of blocks we gave
	
	mpz_t c1, c2, tmp;
	mpz_init(c1);
	mpz_init(c2);
	mpz_init(tmp);
	
	for (int i = 0; i < blocks;i++) {
		mpz_import(c1, block_size/2, -1, sizeof(uint8_t), 1, 0, sign + i*block_size); // 1st half of block is c1
		mpz_import(c2, block_size/2, -1, sizeof(uint8_t), 1, 0, sign + i*block_size + block_size/2); // 2nd half of block is c2
		
		mpz_import(tmp, u_block_size, -1, sizeof(uint8_t), 1, 0, buffer + i*block_size);
		
		if (!ElGamal_sign_verify_mpz(tmp, c1, c2, h, q, g)) {
			return 0;
		}
	}
	
	mpz_clear(c1);
	mpz_clear(c2);
	mpz_clear(tmp);
	free(buffer);
	
	return 1;
}

void ElGamal_generate_existential_forge (mpz_t r, mpz_t s, mpz_t m, mpz_t h, mpz_t q, mpz_t g, unsigned long seed) {
	
	if (seed == 0) { // if no seed was provided,
		srand48( time(0) );
		seed = random(); // generate a random seed
	}
	
	mpz_t p;
	
	mpz_init(r);
	mpz_init(s);
	mpz_init(m);
	mpz_init(p);
	
	mpz_sub_ui(p, q, 1); // p = (q-1)
	mpz_div_ui(p, p, 2); // p = (q-1)/2
	
	gmp_randstate_t rand_state;
	gmp_randinit_default(rand_state);
	gmp_randseed_ui(rand_state, seed);
	
	mpz_urandomm(m, rand_state, p); // choose a random 'z' between [1,...,(p-1)]
	mpz_add_ui(m, m, 1); // ensure z is between [2,...p] (z will almost never actually be 2 or p)
	
	mpz_powm(r, g, m, q); // r = g^z mod q
	mpz_mul(r, r, h); // r = h*g^z
	mpz_mod(r, r, q);
	
	mpz_mod(s, r, p); // s = r mod p
	mpz_sub(s, p, s); // s = -r
	//mpz_mul_ui(s, s, -1);
	
	mpz_mul(m, m, s); // m = zs
	mpz_mod(m, m, p); // m = zs mod p
	
	assert(ElGamal_sign_verify_mpz(m, r, s, h, q, g) == 1);
}
