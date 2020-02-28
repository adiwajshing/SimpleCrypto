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

const char vdes_default_iv[] = "abcdefgh";

void left_rotate_2 (uint64_t *key) {
    uint64_t fb = *key & 0b11;
    
    *key >>= 2;
    *key &= ~((uint64_t)0b11 << 54);
    *key |= fb << 54;
}

void gen_subkeys (const char *key, char subkeys[16][6]) {
    uint64_t k = 0;
    memcpy(&k, key, 7 * sizeof(char));
    
    for (int i = 0; i < 16;i++) {
        left_rotate_2(&k);
        
        memset(subkeys[i], 0, sizeof(char) * 6);
        memcpy(subkeys[i], &k, sizeof(char) * 3); // copy first 24 bits
        memcpy(subkeys[i]+3, ((char *)&k)+4, sizeof(char) * 3); // copy last 24 bits
    }
}

char *vdes_encrypt(const char *plaintext, int *len, const char key[7], const char iv[8]) {
    return des_cbc_crypt(plaintext, len, key, iv, vanilla_feistel_network, gen_subkeys, 0);
}
char *vdes_decrypt(const char *ciphertext, int *len, const char key[7], const char iv[8]) {
    return des_cbc_crypt(ciphertext, len, key, iv, vanilla_feistel_network, gen_subkeys, 1);
}

void run_vdes_crypt (int is_decryption) {
    
    int textlen = 0, keylen = 0;
    
    char *text = get_text( is_decryption ? "ciphertext.txt" : "plaintext.txt", &textlen);
    char *key = get_text("key.txt", &keylen);
    
    char *newtext = des_cbc_crypt(text, &textlen, key, vdes_default_iv, vanilla_feistel_network, gen_subkeys, 1);
    
    set_text(is_decryption ? "plaintext.txt" : "ciphertext.txt", newtext, textlen);
    
    free(newtext);
}
void run_vdes_encrypt () {
    run_vdes_crypt(0);
}
void run_vdes_decrypt () {
    run_vdes_crypt(1);
}
