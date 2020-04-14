//
//  Curve.c
//  Crypto
//
//  Created by Adhiraj Singh on 4/12/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include "Curve.h"
#include "Utils.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

/// structure to store curve parameters
struct Curve {
	mpz_t a, b, p;
} curve;

CurvePoint curve_inf;

void curve_set_params_P192 () {
	mpz_init_set_str(curve.a, "-3", 10);
	mpz_init_set_str(curve.b, "64210519 e59c80e7 0fa7e9ab 72243049 feb8deec c146b9b1", 16);
	mpz_init_set_str(curve.p, "6277101735386680763835789423207666416083908700390324961279", 10);
	//mpz_out_str(stdout, 10, curve.a); printf("\n");
	curve_init_set_inf(curve_inf);
}
void curve_set_params_M221 () {
	mpz_init_set_ui(curve.a, 117050);
	mpz_init_set_ui(curve.b, 1);
	
	mpz_init(curve.p);
	mpz_setbit(curve.p, 221); // p = 2^221
	mpz_sub_ui(curve.p, curve.p, 3); // p 2^221 - 3
	
	curve_init_set_inf(curve_inf);
}
int curve_init (CurvePointPtr p) {
	if (!curve.a->_mp_d) {
		curve_set_params_M221();
	}
	if (p->is_init != 1) {
		p->is_init = 1;
		mpz_init(p->x);
		mpz_init(p->y);
		return 1;
	}
	return 0;
}
int curve_init_get_y (mpz_t y1, mpz_t y2, const mpz_t x) {
	mpz_t tmp;
	mpz_init(tmp);
	
	mpz_mul(tmp, x, curve.a); // tmp = ax
	
	mpz_powm_ui(y1, x, 3, curve.p); // y^2 = x^3 mod p
	mpz_add(y1, y1, tmp); // y^2 = x^3 + ax
	mpz_add(y1, y1, curve.b); // y^2 = x^3 + ax + b
	mpz_mod(y1, y1, curve.p); // y^2 = x^3 + ax + b mod p
	
	if (mod_square_root(tmp, y1, curve.p)) { // check if sqrt exists & compute
		mpz_set(y1, tmp); // set y as sqrt of y^2
		mpz_sub(y2, curve.p, y1);
		mpz_clear(tmp);
		return 1;
	} else { // if no sqrt exists :(
		mpz_clear(tmp);
		return 0;
	}
}
void curve_init_set_inf (CurvePointPtr p) {
	curve_init(p);
	mpz_set_ui(p->x, 0);
	mpz_set_ui(p->y, 0);
}
void curve_init_set_ui (CurvePointPtr p, const unsigned long x, const unsigned long y) {
	curve_init(p);
	mpz_set_ui(p->x, x);
	mpz_set_ui(p->y, y);
}
void curve_init_set_str (CurvePointPtr p, const char *x, const char *y, const int base) {
	curve_init(p);
	mpz_set_str(p->x, x, base);
	mpz_set_str(p->y, y, base);
}
void curve_init_set (CurvePointPtr p, const CurvePointPtr q) {
	curve_init(p);
	mpz_init_set(p->x, q->x);
	mpz_init_set(p->y, q->y);
}
void curve_free (CurvePointPtr p) {
	if (p) {
		mpz_clear(p->x);
		mpz_clear(p->y);
	}
}

void curve_out_str (FILE *file, int base, CurvePointPtr p) {
	mpz_out_str(file, base, p->x);
	fputc(' ', file);
	mpz_out_str(file, base, p->y);
}
int curve_inp_str (FILE *file, int base, CurvePointPtr p) {
	curve_init(p);
	mpz_inp_str(p->x, file, base);
	if (fgetc(file) == ' ') { // must enter a space after number X
		mpz_inp_str(p->y, file, base);
		return 1;
	}
	return 0;
}

int curve_cmp (const CurvePointPtr p, const CurvePointPtr q) {
	int r = mpz_cmp(p->x, q->x) != 0;
	r += mpz_cmp(p->y, q->y) != 0;
	return r;
}
void curve_negate (const CurvePointPtr p, CurvePointPtr q) {
	if (p != q) {
		curve_init_set(p, q);
	}
	mpz_sub(q->y, curve.p, q->y);
	mpz_mod(q->y, q->y, curve.p);
}
/// given the slope of a line, lambda, compute R
void curve_compute (const CurvePointPtr p, const CurvePointPtr q, CurvePointPtr r, mpz_t lambda) {
	mpz_powm_ui(r->x, lambda, 2, curve.p); // Rx = L^2 mod p
	mpz_sub(r->x, r->x, p->x); // Rx = L^2 - Px
	mpz_sub(r->x, r->x, q->x); // Rx = L^2 - Px - Qx
	mpz_mod(r->x, r->x, curve.p); // Rx = L^2 - Px - Qx mod p
	
	mpz_sub(r->y, p->x, r->x); // Ry = Px-Rx
	mpz_mul(r->y, r->y, lambda); // Ry = L(Px-Rx)
	mpz_sub(r->y, r->y, p->y); // Ry = L(Px-Rx) - Py
	mpz_mod(r->y, r->y, curve.p); // Ry = L(Px-Rx) - Py mod p
}
void curve_sub (const CurvePointPtr p, CurvePoint q, CurvePointPtr r) {
	/*
	 Used a jugadoo method. But its correct
	*/
	if (p==q) { // if P == Q, then P-Q = INF
		curve_init_set(r, curve_inf);
	} else {
		curve_out_str(stdout, 16, q); printf("\n");
		curve_negate(q, q); // Q = -Q
		curve_out_str(stdout, 16, q); printf("\n");
		curve_add(p, q, r); // R = P + (-Q)
		curve_negate(q, q); // set Q back
	}
}
void curve_add (const CurvePointPtr p, const CurvePointPtr q, CurvePointPtr r) {
	mpz_t tmp, tmp2;
	
	if (curve_cmp(p, curve_inf) == 0) { // if one point is INF
		curve_init_set(r, q); // q + INF = q
	} else if (curve_cmp(q, curve_inf) == 0) {
		curve_init_set(r, p); // p + INF = p
	} else {
		mpz_init(tmp);
		mpz_add(tmp, p->y, q->y);
		if (mpz_cmp(q->x, p->x) == 0 && mpz_cmp(tmp, curve.p) == 0) { // essentially, if p = -p or q = -q
			curve_init_set(r, curve_inf); // set to INF
		} else {
			curve_init(r);
			mpz_init(tmp2);
			
			if ((p==q) || (mpz_cmp(q->x, p->x)==0 && mpz_cmp(q->y, p->y)==0)) { // if P==Q
				/*
				 compute lambda as the tangent to the curve at P
				*/
				mpz_powm_ui(tmp, p->x, 2, curve.p); // L = Px^2
				mpz_mul_ui(tmp, tmp, 3); // L = 3Px^2
				mpz_add(tmp, tmp, curve.a); // L = 3Px^2 + a
				
				mpz_mul_ui(tmp2, p->y, 2); // tmp2 = 2Py
				mpz_invert(tmp2, tmp2, curve.p); // tmp2 = 2Py^-1 mod p
				
				mpz_mul(tmp, tmp, tmp2); // L = (3Px^2 + a)*2Py^-1
				mpz_mod(tmp, tmp, curve.p); // L = (3Px^2 + a)*2Py^-1 mod p
			} else {
				/*
				 compute lambda as the slope of the line between P & Q
				*/
				mpz_sub(tmp, q->y, p->y); // L = tmp = Qy-Py

				mpz_sub(tmp2, q->x, p->x); // tmp2 = Qx-Px
				mpz_invert(tmp2, tmp2, curve.p); // tmp2 = (Qx-Px)^-1 mod p

				mpz_mul(tmp, tmp, tmp2); // L = (Qy-Py) * (Qx-Px)^-1
				mpz_mod(tmp, tmp, curve.p); // L = (Qy-Py) * (Qx-Px)^-1 mod p
			}
			
			// check if result & operator pointers are the same (i.e P = R or Q = R) & resolve
			if (p==r || q==r) {
				CurvePoint tmp_point;
				if (p == r) {
					curve_init_set(tmp_point, p);
					if (p == q) {
						curve_compute(tmp_point, tmp_point, r, tmp);
					} else {
						curve_compute(tmp_point, q, r, tmp);
					}
				} else if (q == r) {
					curve_init_set(tmp_point, q);
					curve_compute(p, tmp_point, r, tmp);
				}
				curve_free(tmp_point);
			} else {
				curve_compute(p, q, r, tmp);
			}
			mpz_clear(tmp2);
		}
		mpz_clear(tmp);
	}
}
void curve_mul (const CurvePointPtr p, const mpz_t k, CurvePointPtr r) {
	if (curve_cmp(p, curve_inf) == 0 || mpz_cmp_ui(k, 0) == 0) {
		curve_init_set(r, curve_inf);
	} else {
		CurvePoint tmp;
		curve_init_set(tmp, p); // set tmp = P

		if (mpz_tstbit(k, 0) == 1) { // if k is odd
			curve_init_set(r, tmp); // set R as P
		} else {
			curve_init_set_ui(r, 0, 0); // set curve as (0,0)
		}
		
		int bitlen = (int)mpz_sizeinbase(k,2);
		
		for (int i = 1; i < bitlen;i++) {
			curve_add(tmp, tmp, tmp); // tmp = 2tmp
			if (mpz_tstbit(k, i) == 1) {
				curve_add(r, tmp, r); // r = tmp
			}
		}
		curve_free(tmp);
		//printf("\n");
	}
}
