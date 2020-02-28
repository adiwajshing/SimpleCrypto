//
//  main.c
//  Crypto
//
//  Created by Adhiraj Singh on 2/14/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "ColumnarTranspositionCipher.h"
#include "AffineCipher.h"
#include "HillCipher.h"
#include "VigenereCipher.h"
#include "LetterFrequency.h"
#include "DES.h"
#include "VDES.h"
#include "Utils.h"


void testBreakVigenereCipher () {
    const char text[] = "qivjukosqegnyiytxypshzewjsnsdpeybsuiranshzewjsnsdvusdvozqhasg hexhvtdrynjyirlrrnfpekjbsuhucnjyirlrrnfveylrsdgbinjyirlrrnfwi lqbsuqlisfqhhzuxytxaewhroxwvasjirxwsltyiytxontzxhjuyljvenivsd tlectpqiypinylwwmdxirosoplrgkrvytxaoswkeywlixivordrytwlewjyyn mysyzensdxeqocozkswnpjejomnlzensdqaphcozxrdjuwtfqhnjyirlrrnfj mvjbsuzsreahvgtqraqhxytxhobq";
    const int textlen = (int)strlen(text);

    const int keylens[] = {1, 2, 3, 4, 5, 6};
    breakVigenereCipher(text, textlen, keylens, 6);
}
void testBreakCaesarCipher () {
    const char text[] = "hgnodxnthmsdqbdossghrrdbqdssqzmrlhrrhnmvhsgntszmxdqqnqsghrsqz mrlhrrhnmgzrsqzudkkdczlhkkhnmkhfgsxdzqrsnhmenqlxntsgzsvdzqdbn lhmfrnnm";
    const int textlen = (int)strlen(text);
    
    breakCaesarCipher(text, textlen, 0);
}
void testDES () {
  
    const char plaintext[] = "romeoandjulietweregreatlovers";
    const char key[] = "Z8tb;a=8";

    const char iv[8] = {0};
    
    int plaintextlen = (int)strlen(plaintext);
    char *ciphertext = vdes_encrypt(plaintext, &plaintextlen, key, iv);
    print_bytes(ciphertext, 32);
    char *decryptedtext = vdes_decrypt(ciphertext, &plaintextlen, key, iv);
    printf("%s\n", decryptedtext);
    //print_str(plaintext);
    //print_str(key);
    //print_str(decryptedtext);
    
    free(ciphertext);
    free(decryptedtext);
}


int main(int argc, const char * argv[]) {
    //testBreakVigenereCipher();
    testDES();
    
    return 0;
}
