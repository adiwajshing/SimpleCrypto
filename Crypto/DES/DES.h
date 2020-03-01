//
//  DES.h
//  Crypto
//
//  Created by Adhiraj Singh on 2/26/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#ifndef DES_h
#define DES_h

#include <stdlib.h>

#define DES_KEY_SIZE 8
#define DES_BLOCK_SIZE 8
#define DES_FEISTAL_ROUNDS 16

typedef void (*FiestalNetworkFunction)(uint8_t block[DES_BLOCK_SIZE], const uint8_t subkeys[16][6], int is_decryption);
typedef void (*SubKeyGenerationFunction)(const uint8_t *key, uint8_t subkeys[16][6]);

/// encrypt/decrypt using DES
uint8_t *des_cbc_crypt(const uint8_t *txt, int *len, const uint8_t key[DES_KEY_SIZE], const uint8_t iv[DES_BLOCK_SIZE], FiestalNetworkFunction feistal_network_func, SubKeyGenerationFunction sub_key_generator, int is_decryption);
/// encrypt using vanilla DES
uint8_t *des_cbc_encrypt(const uint8_t *plaintext, int *len, const uint8_t key[8], const uint8_t iv[8]);
/// decrypt using vanilla DES
uint8_t *des_cbc_decrypt(const uint8_t *ciphertext, int *len, const uint8_t key[8], const uint8_t iv[8]);

/// feistal network without the inital & final permutations
void vanilla_feistel_network(uint8_t block[DES_BLOCK_SIZE], const uint8_t subkeys[16][6], int is_decryption);

#endif /* DES_h */
