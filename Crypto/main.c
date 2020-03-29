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
#include <gmp.h>
#include <assert.h>

#include "number_theory.h"
#include "ColumnarTranspositionCipher.h"
#include "AffineCipher.h"
#include "HillCipher.h"
#include "VigenereCipher.h"
#include "LetterFrequency.h"
#include "DES.h"
#include "VDES.h"
#include "Utils.h"
#include "DDES.h"
#include "AES.h"
#include "RSA.h"
#include "ASN1.h"
#include "ElGamal.h"

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
void rsa_key_gen () {
	RSAKeyPair key;
	RSA_key_init(&key);
	RSA_key_gen(&key, RSA_1024, 0);
	RSA_key_free(&key);
}

int main(int argc, const char * argv[]) {
	//testRSA();
	//char* args2[] = { "-keygenerator", "-encrypt" };
	//runRSAProgram(1, args2);
	//measure(&rsa_key_gen, 10);
	testElGamal();
	
	return 0;
    //return runRSAProgram(argc, argv);
}
