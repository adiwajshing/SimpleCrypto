//
//  RSAProgram.c
//  Crypto
//
//  Created by Adhiraj Singh on 3/29/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include <assert.h>

#include "Utils.h"
#include "RSA.h"
#include "ASN1.h"

int main (int argc, const char * argv[]) {
	argc -= 1;
	argv ++;
	if (argc < 1) {
		printf("please enter one or more of the following arguments: -keygenerator, -encrypt, -decrypt\n");
		return -1;
	}
	
	const char public_key_file[] = "public_key.txt";
	const char private_key_file[] = "private_key.txt";
	const char plaintext_file[] = "plaintext.txt";
	const char ciphertext_file[] = "ciphertext.txt";
	
	int p = 0;
	if (strcmp(argv[p], "-keygenerator") == 0) {
		RSAKeyPair key;
		RSA_key_init(&key);
		RSA_key_gen(&key, RSA_1024, 0);
		
		printf("generated keys, saving...\n");
		
		ASN1_write_private_key(&key, private_key_file);
		ASN1_write_public_key(key.n, key.e, public_key_file);
		
		printf("saved to %s & %s\n", private_key_file, public_key_file);
		
		// uncomment to test validity of ASN1 parsing
		/*RSAKeyPair key2;
		assert( ASN1_read_private_key(&key2, private_key_file) == 0 );
		assert( mpz_cmp(key2.n, key.n) == 0 );
		assert( mpz_cmp(key2.d, key.d) == 0 );
		assert( mpz_cmp(key2.e, key.e) == 0 );
		
		assert( ASN1_read_public_key(key2.n, key2.e, public_key_file) == 0 );
		assert( mpz_cmp(key2.n, key.n) == 0 );
		assert( mpz_cmp(key2.e, key.e) == 0 );*/
		
		RSA_key_free(&key);
		p += 1;
		if (p >= argc) {
			return 0;
		}
	}
	
	if (strcmp(argv[p], "-encrypt") == 0) {
		mpz_t e, n;
		ASN1_read_public_key(n, e, public_key_file);
		
		size_t len;
		uint8_t *plaintext = get_text(plaintext_file, &len, FILE_MODE_UTF8);
		if (!plaintext) {
			printf("plain text not present at %s\n", plaintext_file);
			return -1;
		}
		//printf("plaintext: %s\n", (char *)plaintext);
		printf("encrypting...\n");
		uint8_t *ciphertext = RSA_encrypt(plaintext, (int *)&len, e, n, RSA_1024);
		set_text(ciphertext_file, ciphertext, len, FILE_MODE_BASE64);
		
		
		printf("encrypted\n");
		free(ciphertext);
		free(plaintext);
		mpz_clear(n);
		mpz_clear(e);
		
		p += 1;
		if (p >= argc) {
			return 0;
		}
	}
	
	if (strcmp(argv[p], "-decrypt") == 0) {
		RSAKeyPair key;
		RSA_key_init(&key);
		ASN1_read_private_key(&key, private_key_file);
		
		size_t len;
		uint8_t *ciphertext = get_text(ciphertext_file, &len, FILE_MODE_BASE64);
		if (!ciphertext) {
			printf("ciphertext not present at %s\n", plaintext_file);
			return -1;
		}

		printf("decrypting...\n");
		uint8_t *plaintext = RSA_decrypt(ciphertext, (int *)&len, key.d, key.n, RSA_1024);
		
		set_text(plaintext_file, plaintext, len, FILE_MODE_UTF8);
		
		free(ciphertext);
		free(plaintext);
		RSA_key_free(&key);
		
		printf("decrypted\n");
		p += 1;
	}
	
	return 0;
}
