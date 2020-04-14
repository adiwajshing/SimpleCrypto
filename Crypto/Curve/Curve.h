//
//  Curve.h
//  Crypto
//
//  Created by Adhiraj Singh on 4/12/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#ifndef Curve_h
#define Curve_h

#include <stdio.h>
#include <gmp.h>

struct CurvePoint {
	mpz_t x, y;
};
/// structure to store a curve point
typedef struct CurvePoint CurvePoint[1];
/// pointer to CurvePoint
typedef struct CurvePoint *CurvePointPtr;

/// the infinity point; represented unambigously as (0,0) as the curves used do not fall on (0,0)
extern CurvePoint curve_inf;

/**
 setup curve as a P-192 curve as mentioned here:
 https://csrc.nist.gov/csrc/media/publications/fips/186/2/archive/2000-01-27/documents/fips186-2.pdf
**/
void curve_set_params_P192(void);
/**
 setup curve as an M-221 (Curve2213) curve as mentioned here:
 https://safecurves.cr.yp.to
**/
void curve_set_params_M221 (void);


int curve_init (CurvePointPtr p);
/// set the curve point as INF; P = (0,0)
void curve_init_set_inf (CurvePointPtr p);
/// (h) given x, find y1 & y2 such that (x, y1) on Curve & (x, y2) on Curve; return 0 if no such y exits
int curve_get_y (mpz_t y1, mpz_t y2, const mpz_t x);
/// init & set a curve point with given coordinates of q
void curve_init_set (CurvePointPtr p, const CurvePointPtr q);
/// init & set a curve point with given unsigned integers x & y
void curve_init_set_ui (CurvePointPtr a, const unsigned long x, const unsigned long y);
/// init & set a curve point with given char arrays x & y written in base
void curve_init_set_str (CurvePointPtr p, const char *x, const char *y, const int base);
/// set a curve point with given coordinates of q
void curve_set (CurvePointPtr p, const CurvePointPtr q);
/// set a curve point with given unsigned integers x & y
void curve_set_ui (CurvePointPtr a, const unsigned long x, const unsigned long y);
/// set a curve point with given char arrays x & y written in base
void curve_set_str (CurvePointPtr p, const char *x, const char *y, const int base);

/// free all memory associated with a curve point
void curve_free (CurvePointPtr p);

/// (a), (b) read a curve point from an open stream; read only if input in the format 'Px Py', return 0 otherwise
int curve_inp_str (FILE *file, int base, CurvePointPtr p);
/// (c) write a curve point to the specified file; write in format: 'Px Py'
void curve_out_str (FILE *file, int base, CurvePointPtr p);

/// compare two curve points; return 0 if they're equal
int curve_cmp (const CurvePointPtr p, const CurvePointPtr q);

/// (d) set R = P + Q
void curve_add (CurvePointPtr r, const CurvePointPtr p, const CurvePointPtr q);
/// (e) set Q = -P
void curve_negate (CurvePointPtr r, const CurvePointPtr p);
/// (f) set R = P - Q
void curve_sub (CurvePointPtr r, const CurvePointPtr p, CurvePoint q);
/// (g) set R = kP
void curve_mul (CurvePointPtr r, const CurvePointPtr p, const mpz_t k);

void curve_test (void);

#endif /* Curve_h */
