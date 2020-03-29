//
//  VDES.c
//  Crypto
//
//  Created by Adhiraj Singh on 2/28/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include <string.h>
#include "VDES.h"
#include "Utils.h"

const uint8_t vdes_default_iv[] = "abcdefgh";

void left_rotate_2 (uint64_t *key) {
    uint64_t fb = *key & 0b11;
    
    *key >>= 2;
    *key &= ~((uint64_t)0b11 << 54);
    *key |= fb << 54;
}
/// subkey generation as mentioned in HW2 1.7 (f)
void gen_subkeys (const uint8_t *key, uint8_t subkeys[16][6]) {
    uint64_t k = 0;
    memcpy(&k, key, 7 * sizeof(uint8_t));
    
    for (int i = 0; i < 16;i++) {
        left_rotate_2(&k);
        
        memset(subkeys[i], 0, sizeof(uint8_t) * 6);
        memcpy(subkeys[i], &k, sizeof(uint8_t) * 3); // copy first 24 bits
        memcpy(subkeys[i]+3, ((uint8_t *)&k)+4, sizeof(uint8_t) * 3); // copy last 24 bits
    }
}
uint8_t *vdes_crypt(const uint8_t *plaintext, int *len, const uint8_t key[7], const uint8_t iv[8], int is_decryption) {
    // run DES with a vanilla feistal network (without the IP & FP) and use the key generation as mentioned in the question
    return des_cbc_crypt(plaintext, len, key, iv, vanilla_feistel_network, gen_subkeys, is_decryption);
}
uint8_t *vdes_encrypt(const uint8_t *plaintext, int *len, const uint8_t key[7], const uint8_t iv[8]) {
    // run DES with a vanilla feistal network (without the IP & FP) and use the key generation as mentioned in the question
    return vdes_crypt(plaintext, len, key, iv, 0);
}
uint8_t *vdes_decrypt(const uint8_t *ciphertext, int *len, const uint8_t key[7], const uint8_t iv[8]) {
    return vdes_crypt(ciphertext, len, key, iv, 1);
}

void run_vdes_crypt (int is_decryption) {
    
    size_t textlen = 0, keylen = 0;
    
    uint8_t *text = get_text( is_decryption ? "ciphertext.txt" : "plaintext.txt", &textlen, FILE_MODE_UTF8);
    uint8_t *key = get_text("key.txt", &keylen, FILE_MODE_UTF8);
    
    uint8_t *newtext = vdes_crypt(text, (int *)&textlen, key, vdes_default_iv, is_decryption);
    
    char *filename = is_decryption ? "plaintext.txt" : "ciphertext.txt";
    set_text(filename, newtext, textlen, FILE_MODE_UTF8);
    printf("saved file as: %s", filename);
    free(newtext);
}
void run_vdes_encrypt () {
    run_vdes_crypt(0);
}
void run_vdes_decrypt () {
    run_vdes_crypt(1);
}

void testVDES () {
  
    const char plaintext[] = "romeoandjulietweregreatlovers";
    const char key[] = "Z8tb;a=8";

    const char iv[8] = {0};
    
    int plaintextlen = (int)strlen(plaintext);
    uint8_t *ciphertext = vdes_encrypt((uint8_t *)plaintext, &plaintextlen, (uint8_t *)key, (uint8_t *)iv);
    print_bytes(ciphertext, 32);
    uint8_t *decryptedtext = vdes_decrypt(ciphertext, &plaintextlen, (uint8_t *)key, (uint8_t *)iv);
    printf("%s\n", decryptedtext);

    free(ciphertext);
    free(decryptedtext);
}
