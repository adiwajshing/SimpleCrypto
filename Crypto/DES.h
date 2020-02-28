//
//  DES.h
//  Crypto
//
//  Created by Adhiraj Singh on 2/26/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#ifndef DES_h
#define DES_h

#define DES_KEY_SIZE 8
#define DES_BLOCK_SIZE 8
#define DES_FEISTAL_ROUNDS 16

typedef void (*FiestalNetworkFunction)(char block[DES_BLOCK_SIZE], const char subkeys[16][6], int is_decryption);
typedef void (*SubKeyGenerationFunction)(const char *key, char subkeys[16][6]);

char *des_cbc_crypt(const char *txt, int *len, const char key[DES_KEY_SIZE], const char iv[DES_BLOCK_SIZE], FiestalNetworkFunction feistal_network_func, SubKeyGenerationFunction sub_key_generator, int is_decryption);
char *des_cbc_encrypt(const char *ciphertext, int *len, const char key[8], const char iv[8]);
char *des_cbc_decrypt(const char *ciphertext, int *len, const char key[8], const char iv[8]);

void vanilla_feistel_network(char block[DES_BLOCK_SIZE], const char subkeys[16][6], int is_decryption);

#endif /* DES_h */
