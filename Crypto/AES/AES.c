//
//  AES.c
//  Crypto
//
//  Created by Adhiraj Singh on 2/29/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include "AES.h"
#include "Padding.h"
#include "Utils.h"

#include <assert.h>

const int aes_key_sizes[] = {
    16, // AES 128
    24, // AES 192
    32 // AES 256
};
const int aes_rounds_for_mode[] = {
    10, //AES 128
    12, //AES 192
    14 //AES 256
};

const uint8_t aes_sboxes[] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};
const uint8_t aes_sboxes_inv[] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};
void print_inv_sboxes () {
    uint8_t inv[256];
    for (int i = 0; i < 256; i++) {
        inv[ aes_sboxes[i] ] = i;
    }
    for (int i = 0; i < 256; i++) {
        printf("0x");
        print_as_hex(inv+i, 1);
        printf(", ");
    }
}

/// calculate the round constant used in key expansion
uint32_t round_constant(uint8_t round) {
    /// round constant values for given round
    const uint32_t rcs[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5 };
    return rcs[round-1];
}
/// the grouping function used in AES
void aes_grouping(uint8_t *in, int round) {
    // rotate
    uint8_t a = *in;
    *((uint32_t *)in) >>= 8; // cast as 32 bit integer and rotate by 8 bits (1 byte)
    in[3] = a;
        
    for(a = 0; a < 4; a++) {
        in[a] = aes_sboxes[ in[a] ]; // substitute using s box
    }
    
    in[0] ^= round_constant(round); // xor using the round constant
}
uint8_t *get_key_schedule (const uint8_t *key, int mode) {
    
    const int key_size = aes_key_sizes[mode];
    const int rounds = aes_rounds_for_mode[mode];
    
    const int key_len_words = key_size/4;
    
    uint32_t *subkeys = malloc( key_len_words * (rounds+1) * sizeof(uint32_t) );
    
    int i = 0, j = 0;
    for (i = 0; i < key_len_words;i++) {
        subkeys[i] = *((uint32_t *)(key + i*4)); // copy key into first sub key
    }
    uint32_t grp;
    for (i = 1; i <= rounds;i++) {
        // the first word in every 4 word block has to be defined using a function of the previous word & the word 3 words back
        grp = subkeys[ (i-1)*key_len_words + key_len_words-1]; // the previous word
        aes_grouping((uint8_t *)&grp, i); // the grouping function
        
        subkeys[i*key_len_words + 0] = subkeys[(i-1)*key_len_words + 0] ^ grp;
        for (j = 1; j < key_len_words;j++) {
            // word(w) = w_ij = w_i(j-1) + w_(i-1)(j)
            subkeys[ i*key_len_words + j ] = subkeys[i*key_len_words + j-1] ^ subkeys[(i-1)*key_len_words + j];
        }
        
    }
    
    return (uint8_t *)subkeys;
}
void add_round_key (uint8_t *block, const uint8_t *subkey) {
    xor_string(block, subkey, AES_BLOCK_SIZE);
}
void sub_bytes (uint8_t *block, const uint8_t *table) {
    int len = AES_BLOCK_SIZE;
    while (len) {
        len -= 1;
        block[len] = table[ block[len] ];
    }
}

void shift_rows (uint8_t *block) {
    
    const int rows = 4;
    const int columns = AES_BLOCK_SIZE/rows;
    
    int i = 0, j = 0, k = 0;
    uint8_t fb;
    for (i = 1; i < rows;i++) {
        
        for (j = 0; j < i;j++) {
            // rotate to the left i times
            fb = block[i];
            for (k = 0; k < columns-1;k++) {
                block[i + k*rows] = block[i + (k+1)*rows];
            }
            block[i + (columns-1)*rows] = fb;
        }
    }
    
}
void shift_rows_inv (uint8_t *block) {
    
    const int rows = 4;
    int columns = AES_BLOCK_SIZE/rows;
    
    int i = 0, j = 0, k = 0;
    uint8_t lb;
    for (i = 1; i < rows;i++) {
        
        for (j = 0; j < i;j++) {
            // rotate to the right i times
            lb = block[i + (columns-1)*rows];
            for (k = columns-1; k > 0;k--) {
                block[i + k*rows] = block[i + (k-1)*rows];
            }
            block[i] = lb;
        }
    }
    
}
/// galois field multiplication by 2
static inline uint8_t gmul_2(uint8_t a) {
    return (a << 1) ^ (0x11b & -(a >> 7));
}
/// galois field multiplication
uint8_t gmul (uint8_t a, uint8_t b) {
    uint8_t p = 0;
    while (b > 0) {
        p ^= a & -(b & 1);         /* add a to p if the lowest bit of b is set */
        a = gmul_2(a);                /* multiply a by 2 in the finite field */
        b >>= 1;                   /* shift the next bit of b to the lowest position */
    }
    return p;
}
void mix_columns (uint8_t *block, const uint8_t m[4]) {
    
    const int columns = AES_BLOCK_SIZE/4;
    
    uint8_t tmp[4];
    
    for (int i = 0; i < columns;i++) {
        tmp[0] = block[i]; tmp[1] = block[i+4];
        tmp[2] = block[i+8]; tmp[3] = block[i+12];
        
        block[i] = gmul(tmp[0], m[0]) ^ gmul(tmp[1], m[1]) ^ gmul(tmp[2], m[2]) ^ gmul(tmp[3], m[3]);
        block[i + 4] = gmul(tmp[0], m[3]) ^ gmul(tmp[1], m[0]) ^ gmul(tmp[2], m[1]) ^ gmul(tmp[3], m[2]);
        block[i + 8] = gmul(tmp[0], m[2]) ^ gmul(tmp[1], m[3]) ^ gmul(tmp[2], m[0]) ^ gmul(tmp[3], m[1]);
        block[i + 12] = gmul(tmp[0], m[1]) ^ gmul(tmp[1], m[2]) ^ gmul(tmp[2], m[3]) ^ gmul(tmp[3], m[0]);
    }

}
void aes_encrypt_block (uint8_t *block, const uint8_t *keys, int mode) {
    
    const uint8_t galois_field_m[] = {2, 3, 1, 1};
    
    int rounds = aes_rounds_for_mode[mode];
    
    add_round_key(block, keys);
    
    while (rounds) {
        rounds -= 1;
        
        sub_bytes(block, aes_sboxes);
        shift_rows(block);
        
        if (rounds > 0) {
            mix_columns(block, galois_field_m);
        }
        
        keys += AES_BLOCK_SIZE;
        add_round_key(block, keys);
    }
    
}
void aes_decrypt_block (uint8_t *block, const uint8_t *keys, int mode) {
    
    const uint8_t galois_field_m[] = {14, 11, 13, 9};
    int rounds = aes_rounds_for_mode[mode];
        
    while (rounds) {
        add_round_key(block, keys + rounds*AES_BLOCK_SIZE);

        if (rounds < aes_rounds_for_mode[mode]) {
            mix_columns(block, galois_field_m);
        }
        
        shift_rows_inv(block);
        sub_bytes(block, aes_sboxes_inv);
        
        rounds -= 1;
    }
    
    add_round_key(block, keys);
}
uint8_t *aes_cbc_encrypt (const uint8_t *plaintext, int *len, const uint8_t *key, const uint8_t *iv, int mode) {
    
    uint8_t *newtxt = malloc( *len );
    memcpy(newtxt, plaintext, *len);
    
    if (*len % AES_BLOCK_SIZE != 0) { // if length is not a multiple of block size
        pad_PKCS5(newtxt, len, AES_BLOCK_SIZE);
    }
    
    uint8_t *subkeys = get_key_schedule(key, mode);
    
    for (int i = 0; i < *len;i += AES_BLOCK_SIZE) {
        chain_cbc(newtxt, iv, AES_BLOCK_SIZE, i);
        aes_encrypt_block(newtxt+i, subkeys, mode);
    }
    
    free(subkeys);
    return newtxt;
}

uint8_t *aes_cbc_decrypt (const uint8_t *ciphertext, int *len, const uint8_t *key, const uint8_t *iv, int mode) {
    
    uint8_t *newtxt = malloc( *len );
    memcpy(newtxt, ciphertext, *len);
    
    if (*len % AES_BLOCK_SIZE != 0) { // if length is not a multiple of block size
        return NULL; // cipher text is corrupt :/
    }
    
    uint8_t *subkeys = get_key_schedule(key, mode);
    
    for (int i = *len - AES_BLOCK_SIZE; i >= 0;i -= AES_BLOCK_SIZE) {
        aes_decrypt_block(newtxt+i, subkeys, mode);
        chain_cbc(newtxt, iv, AES_BLOCK_SIZE, i);
    }
    
    unpad_PKCS5(newtxt, len);
    
    free(subkeys);
    return newtxt;
}

void testAES () {
        
    const uint8_t *key = hex_str_to_buffer("7750F228896EB4561B9CD67497AAD0B17750F228896EB4561B9CD67497AAD0B1", 64);

    const char plaintext_hex[] = "27153A16906EF425D078796F71569CBEB6F2D9B55D607B9A3E23CB4B9E133A181A9D31F65A985AE9DFB6344CC90EC75B4E90A7CD0D8BCE7285161377F0FD6FCA"; // 128 bytes
    const uint8_t *plaintext = hex_str_to_buffer(plaintext_hex, 128); // 64 bytes
    int plaintextlen = 64;
    
    uint8_t *ciphertext = aes_cbc_encrypt(plaintext, &plaintextlen, key, NULL, AES_128);
    
    print_as_hex(ciphertext, plaintextlen); printf("\n");
    
    uint8_t *decryptedtext = aes_cbc_decrypt(ciphertext, &plaintextlen, key, NULL, AES_128);
    
    print_as_hex(decryptedtext, plaintextlen); printf("\n");
    
    assert( memcmp(plaintext, decryptedtext, plaintextlen) == 0 );
    
    free(ciphertext);
    free(decryptedtext);
}
