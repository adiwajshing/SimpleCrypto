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
#include "DDES.h"
#include "AES.h"

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
    //testBreakVigenereCipher();
    //testDDES();
    /*char buff[] = {200, 50, 16, 32};
    buff_rotate_left_2(buff, 4, 2);
    
    print_as_hex(buff, 4);*/
    testAES();
    
    return 0;
}
