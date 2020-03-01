//
//  DES.c
//  Crypto
//
//  Created by Adhiraj Singh on 2/26/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include "DES.h"
#include "Utils.h"
#include "Padding.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// First dimension is which sbox, second dimension is row, third dimension is column
const uint8_t sboxes[8][4][16] = {
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    {
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    {
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    {
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    {
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    {
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    {
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
};
/// the first permutation choice for the key
const uint8_t PC1[] = { 56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3 };
/// the second permutation choice for the key
const uint8_t PC2[] = { 13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31 };
/// the initial permutation for the block
const uint8_t IP[] = {
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7, 56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6
};
/// the final permutation for the block
const uint8_t FP[] = {
    39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24
};

/**
 shifts bits according to a permutation table
 example: {57,12,1,2} => bit 57 will now be at position 0, bit 12 at position 1 and so on
**/
void bit_permute (const uint8_t *bytes, uint8_t *output, const uint8_t *table, int tablelen) {
    
    int i1 = 0, b1 = 0;
    int i2 = 0, b2 = 0;
    uint8_t bit2;
    for (int i = 0; i < tablelen;i++) {
        i1 = i >> 3; b1 = (i % 8);
        i2 = table[i] >> 3; b2 = (table[i] % 8);
        //uint8_t bit1 = (bytes[i1] >> b1) & 1;
        bit2 = bytes[i2] & (1 << b2) ? 1 : 0; // get the bit
        //output[i1] &= ~(1 << b1);
        output[i1] |= bit2 << b1; // set the bit at the new position
    }
}
/// expands a 4 byte string to 6 bytes using the DES expansion permutation table
void expansion(const uint8_t halfblock[4], uint8_t expanded[6])
{
    const uint8_t order[] = { 31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0 };
    bit_permute(halfblock, expanded, order, 48);
}
/// Takes in the expanded half block and substitutes the bytes with the bytes from the Sbox; Returns a 4 byte string
void substitute(uint8_t keymixed_halfblock[6], uint8_t output[DES_BLOCK_SIZE/2])
{
    memset(output, 0, 4); // clear our output
    
    uint8_t row_order[2]; // the table we will use to extract the 0th & 5th bit in each 6 bit block
    uint8_t col_order[4]; // the table we will use to extract the 0th, 1st, 2nd & 3rd bit in each 6 bit block
    
    uint8_t row, col, block;
    
    for (int i = 0; i < 8; i++) {
        // get the bits used to point to a row in the s box
        row_order[0] = 0 + 6*i; row_order[1] = 5 + 6*i;
        // get the bits used to point to a column in the s box
        col_order[0] = 1 + 6*i; col_order[1] = 2 + 6*i;
        col_order[2] = 3 + 6*i; col_order[3] = 4 + 6*i;
        
        // extract the bits
        bit_permute(keymixed_halfblock, &row, row_order, 2);
        bit_permute(keymixed_halfblock, &col, col_order, 4);
        
        // move the extracted bits to the LSB position
        row >>= 6;
        col >>= 4;
        
        block = sboxes[i][ row ][ col ]; // get the block
        
        output[i/2] |= block >> ( (i%2) * 4); // each byte will contain 2 blocks
    }

}
/// mix the expanded halfblock with a subkey
void key_mixing(uint8_t expanded_halfblock[6], const uint8_t subkey[6])
{
    // Xor the expanded halfblock with the key here.
    xor_string(expanded_halfblock, subkey, 6);
}
/// permutes the bits of a given half block as given by the DES algorithm
void permute(uint8_t *halfblock)
{
    // the order of the bits
    const uint8_t order[] = {
        15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24
    };
    uint8_t output[DES_BLOCK_SIZE/2] = {0};
    bit_permute(halfblock, output, order, 32);
    
    memcpy(halfblock, output, DES_BLOCK_SIZE/2);
}
/// produce the set of sub keys from a given key
void des_derive_subkeys(const uint8_t *key, uint8_t subkeys[16][6])
{
    uint8_t k[7] = {0};
    bit_permute(key, k, PC1, 56);

    const int shift_table[] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
    const uint8_t left_rotate_1[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 0, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 28};
    const uint8_t left_rotate_2[] = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 0, 1, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 28, 29};
    
    uint8_t tmp[7];
    
    int i = 0;
    for (i = 0; i < 16; i++) {
        
        memset(tmp, 0, 7);
        bit_permute(k, tmp, shift_table[i] == 1 ? left_rotate_1 : left_rotate_2, 56);
        memcpy(k, tmp, 7);
        
        memset(subkeys[i], 0, 6);
        bit_permute(k, subkeys[i], PC2, 48);
        
    }
}
/// Performs the feistal function on a given half block
void feistel_function(uint8_t halfblock[DES_BLOCK_SIZE/2], const uint8_t subkey[6])
{
    //expand => key mix => substitute => permute
    uint8_t expanded[6] = {0};
    expansion(halfblock, expanded); // expand the half block
    key_mixing(expanded, subkey); // mix with the subkey
   
    substitute(expanded, halfblock); // substritute mixed block using the Sbox
    permute(halfblock); // finally, permute it for some confusion
}
/// Applies a vanilla feistel network on an eight byte block with a given subkey set
void vanilla_feistel_network(uint8_t block[DES_BLOCK_SIZE], const uint8_t subkeys[16][6], int is_decryption)
{
    uint8_t *left_half = block;
    uint8_t *right_half = block+(DES_BLOCK_SIZE/2);
    uint8_t tmp_rh[DES_BLOCK_SIZE/2];
    
    uint8_t *tmp;

    for (int i = 0; i < DES_FEISTAL_ROUNDS; i++) {
        memcpy(tmp_rh, right_half, DES_BLOCK_SIZE/2);
        feistel_function(tmp_rh, subkeys[ is_decryption ? DES_FEISTAL_ROUNDS-1-i : i ]);
        
        xor_string(left_half, tmp_rh, 4);
        if (i < DES_FEISTAL_ROUNDS-1) {
            tmp = left_half;
            left_half = right_half;
            right_half = tmp;
        }
    }
    
    swap(left_half, right_half, DES_BLOCK_SIZE/2);
}
/// Applies Feistel network on an eight byte block as specified by DES
void des_feistel_network(uint8_t block[DES_BLOCK_SIZE], const uint8_t subkeys[16][6], int is_decryption)
{
    // perform the initial permutations
    uint8_t permuted_block[DES_BLOCK_SIZE] = {0};
    bit_permute(block, permuted_block, IP, 64);
    
    vanilla_feistel_network(permuted_block, subkeys, is_decryption);
    
    memset(block, 0, 8);
    bit_permute(permuted_block, block, FP, 64);
}

void pad_plaintext(uint8_t *plaintext, int *len)
{
    pad_PKCS5(plaintext, len, 8);
}
void unpad_plaintext (uint8_t *plaintext, int *len) {
    unpad_PKCS5(plaintext, len);
}
uint8_t *des_cbc_crypt(const uint8_t *txt, int *len, const uint8_t key[DES_KEY_SIZE], const uint8_t iv[DES_BLOCK_SIZE], FiestalNetworkFunction feistal_network_func, SubKeyGenerationFunction sub_key_generator, int is_decryption)
{
    uint8_t *newtxt = (uint8_t *)malloc( *len );
    memcpy(newtxt, txt, *len);
    
    if (*len % DES_BLOCK_SIZE != 0) { // if length is not a multiple of block size
        if (is_decryption) {
            return NULL; // return NULL as the cipher text is corrupt
        } else {
            pad_plaintext(newtxt, len); // pad it as necessary
        }
    }
    
    uint8_t subkeys[16][6]; // array of subkeys
    sub_key_generator(key, subkeys);
    
    if (is_decryption) {
        for (int i = *len-8; i >= 0;i-=8) {
            feistal_network_func(newtxt+i, subkeys, 1);
            chain_cbc(newtxt, iv, 8, i);
        }
        unpad_plaintext(newtxt, len);
    } else {
        for (int i = 0; i < *len;i += 8) {
            chain_cbc(newtxt, iv, 8, i);
            feistal_network_func(newtxt+i, subkeys, 0);
        }
    }
    
    return newtxt;
    
}
uint8_t *des_cbc_encrypt(const uint8_t *plaintext, int *len, const uint8_t key[8], const uint8_t iv[8])
{
    return des_cbc_crypt(plaintext, len, key, iv, des_feistel_network, des_derive_subkeys, 0);
}

uint8_t *des_cbc_decrypt(const uint8_t *ciphertext, int *len, const uint8_t key[8], const uint8_t iv[8])
{
    return des_cbc_crypt(ciphertext, len, key, iv, des_feistel_network, des_derive_subkeys, 1);
}
