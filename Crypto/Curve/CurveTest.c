//
//  CurveTest.c
//  Crypto
//
//  Created by Adhiraj Singh on 4/13/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include <stdio.h>
#include <assert.h>

#include "Curve.h"

/*
 Test script for Curve functions; test vectors for P-192 curve
*/

/// test that if a given X lies on the curve, we can produce a corresponding Y for it
void curve_test_gen_y (void) {
	/*
	 Test vectors from http://point-at-infinity.org/ecc/nisttv
	*/
	const int num_test_vectors = 4;
	const char testvectors[num_test_vectors][2][100] = {
		{
			"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
			"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"
		},
		{
			"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
			"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"
		},
		{
			
			"DAFEBF5828783F2AD35534631588A3F629A70FB16982A888",
			"DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB"
		},
		{
			"10BB8E9840049B183E078D9C300E1605590118EBDD7FF590",
			"31361008476F917BADC9F836E62762BE312B72543CCEAEA1"
		}
	};
	
	curve_set_params_P192();
	
	mpz_t x, y, y1, y2;
	mpz_init(y1);
	mpz_init(y2);
	for (int i = 0; i < num_test_vectors;i++) {
		mpz_init_set_str(x, testvectors[i][0], 16);
		mpz_init_set_str(y, testvectors[i][1], 16);
		
		assert(curve_init_get_y(y1, y2, x) == 1);
		assert(mpz_cmp(y1, y) == 0 || mpz_cmp(y2, y) == 0); // y should equal either one of the roots
	}
	mpz_clear(x);
	mpz_clear(y);
	mpz_clear(y1);
	mpz_clear(y2);
}
/**
 given a list of addition & multiplication test vectors,
 check if performing the addition, subtraction & multiplication arithmetic returns the right answers
**/
void curve_test_arithmetic (void) {
	/*
	 Test vectors from http://point-at-infinity.org/ecc/nisttv
	*/
	const int num_add_test_vectors = 5;
	const char add_testvectors[num_add_test_vectors][6][100] = {
		{
			"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", // Px
			"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", // Py
			
			"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", // Qx
			"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", // Qy
			
			"DAFEBF5828783F2AD35534631588A3F629A70FB16982A888", // (P+Q)x
			"DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB"  // (P+Q)y
		},
		{
			"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", // Px
			"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", // Py
			
			"DAFEBF5828783F2AD35534631588A3F629A70FB16982A888", // Qx
			"DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB", // Qy
			
			"76E32A2557599E6EDCD283201FB2B9AADFD0D359CBB263DA", // (P+Q)x
			"782C37E372BA4520AA62E0FED121D49EF3B543660CFD05FD"  // (P+Q)y
		},
		{
			"DAFEBF5828783F2AD35534631588A3F629A70FB16982A888",
			"DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB",
			
			"76E32A2557599E6EDCD283201FB2B9AADFD0D359CBB263DA",
			"782C37E372BA4520AA62E0FED121D49EF3B543660CFD05FD",
			
			"10BB8E9840049B183E078D9C300E1605590118EBDD7FF590",
			"31361008476F917BADC9F836E62762BE312B72543CCEAEA1"
		},
		{
			"76E32A2557599E6EDCD283201FB2B9AADFD0D359CBB263DA",
			"782C37E372BA4520AA62E0FED121D49EF3B543660CFD05FD",
			
			"10BB8E9840049B183E078D9C300E1605590118EBDD7FF590",
			"31361008476F917BADC9F836E62762BE312B72543CCEAEA1",
			
			"2FA1F92D1ECCE92014771993CC14899D4B5977883397EDDE",
			"A338AFDEF78B7214273B8B5978EF733FF2DD8A8E9738F6C0"
		},
		{
			"76E32A2557599E6EDCD283201FB2B9AADFD0D359CBB263DA",
			"782C37E372BA4520AA62E0FED121D49EF3B543660CFD05FD",
			
			"0",
			"0",
			
			"76E32A2557599E6EDCD283201FB2B9AADFD0D359CBB263DA",
			"782C37E372BA4520AA62E0FED121D49EF3B543660CFD05FD"
		}
	};
	const int num_mul_test_vectors = 6;
	const char mul_testvectors[num_mul_test_vectors][5][100] = {
		{
			"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", // Px
			"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", // Py
			
			"2", // k (always in decimal)
			
			"DAFEBF5828783F2AD35534631588A3F629A70FB16982A888", // (kP)x
			"DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB"  // (kP)y
		},
		{
			"DAFEBF5828783F2AD35534631588A3F629A70FB16982A888",
			"DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB",
			
			"5",
			
			"AA7C4F9EF99E3E96D1AEDE2BD9238842859BB150D1FE9D85",
			"3212A36547EDC62901EE3658B2F4859460EB5EB2491397B0"
		},
		{
			"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
			"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
			
			"17",
			
			"44275CD2E1F46DC3F9F57636C2B4213B8BB445930510FF8A",
			"EFAD8348FDE30C87DE438612A818E98D9B76A67AD25DDFD0"
		},
		{
			"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
			"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
			
			"6277101735386680763835789423176059013767194773182842284072",
			
			"818A4D308B1CABB74E9E8F2BA8D27C9E1D9D375AB980388F",
			"FE2E55A1DF72783283D6D08344BA831FCF15ABDE893718C6"
		},
		{
			"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
			"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
			
			"6277101735386680763835789423176059013767194773182842284077",
			
			"35433907297CC378B0015703374729D7A4FE46647084E4BA",
			"5D9B667B0DECA3CFE15C534F88932B0DDAC764CEE24C41CD"
		},
		{
			"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
			"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
			
			"0",
			
			"0",
			"0"
		}
	};
	
	curve_set_params_P192();
	
	CurvePoint p, q, r, rcheck;
	mpz_t k;
	
	for (int i = 0; i < num_add_test_vectors;i++) {
		curve_init_set_str(p, add_testvectors[i][0], add_testvectors[i][1], 16); // set P
		curve_init_set_str(q, add_testvectors[i][2], add_testvectors[i][3], 16); // set Q
		curve_init_set_str(rcheck, add_testvectors[i][4], add_testvectors[i][5], 16); // set R'
		
		curve_add(p, q, r); // actually do the multiplication
		
		assert(curve_cmp(r, rcheck) == 0); // check if R is correct
		
		curve_sub(rcheck, q, r); // Also, then R-Q = P
		
		assert(curve_cmp(r, p) == 0); // check if result is correct
	}
	for (int i = 0; i < num_mul_test_vectors;i++) {
		curve_init_set_str(p, mul_testvectors[i][0], mul_testvectors[i][1], 16); // set P
		mpz_init_set_str(k, mul_testvectors[i][2], 10); // set k
		curve_init_set_str(rcheck, mul_testvectors[i][3], mul_testvectors[i][4], 16); // set R'
		
		curve_mul(p, k, r); // actually do the multiplication
		
		assert( curve_cmp(r, rcheck) == 0 ); // ensure results match
	}
}
/// check if writing & reading a curve to a file works
void curve_test_inp_out (void) {
	curve_set_params_P192();
	
	CurvePoint p, p2;
	curve_init_set_str(p,
					   "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
					   "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
	FILE *f = fopen("curve_test.txt", "w");
	curve_out_str(f, 16, p); // store curve in file
	fclose(f);
	
	f = fopen("curve_test.txt", "r");
	curve_inp_str(f, 16, p2);
	assert(curve_cmp(p, p2) == 0);
}
/// run all tests
void curve_test (void) {
	curve_test_gen_y();
	curve_test_arithmetic();
	curve_test_inp_out();
}
