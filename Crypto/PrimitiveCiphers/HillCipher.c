//
//  HillCipher.c
//  Crypto
//
//  Created by Adhiraj Singh on 2/14/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include "HillCipher.h"
#include <stdlib.h>

int matrixMultiplyNaive (const float *M, int Mrows, int Mcols, float *N, int Nrows, int Ncols, float *result) {
    if (Mcols != Nrows) { return -1; }
    
    if (!result) {
        result = (float *) malloc( Ncols*Mrows * sizeof(float) );
    }
    
    int col, row;
    for (col = 0; col < Ncols;col++) {
        for (row = 0; row < Mrows;row++) {
            
            int i = col*Ncols + row;
            
            result[i] = 0;
            for (int j = 0; j < Mcols;j++) {
                result[i] += ( M[ row*Mcols + j ] * N[ j*Ncols + col ]);
                //printf("%f, %f\n", M[ row*Mcols + j ], N[ j*Ncols + col ]);
            }
        }
    }
    
    return 0;
}
int matrixInverse (float *M, float Mrows, float Mcols, float *Inv) {
    if (Mrows != Mcols) { return -1; }
    
    if (Mrows != 2) { return -2; }
    
    
    
    return 0;
}
