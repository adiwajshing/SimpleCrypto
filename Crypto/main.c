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

int main(int argc, const char * argv[]) {
    testBreakVigenereCipher();
    
    return 0;
}
