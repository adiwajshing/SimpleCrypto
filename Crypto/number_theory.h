//
//  number_theory.h
//  Crypto
//
//  Created by Adhiraj Singh on 3/28/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#ifndef number_theory_h
#define number_theory_h

#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

/// compute GCD of 2 numbers in O(D) time
long euc_gcd (long num1, long num2) {
	long tmp;
	while (num1 != 0) {
		tmp = num1;
		num1 = num2%num1;
		num2 = tmp;
	}
	return num2;
}
/// compute GCD of N numbers in O(NlogN) time
long fast_gcd (const long *nums, int len) {
	long tmp[len];
	memcpy(tmp, nums, len*sizeof(long)); // copy numbers into temp storage
	
	int len2;
	while (len > 1) { // recursively calculate GCD of pairs of numbers
		len2 = len&1 ? len/2+1 : len/2; // fast ceil(len/2)
		len = len/2;
		while (len2 > 0) {
			len2-=1;
			tmp[len2] = euc_gcd(tmp[len2], tmp[len2+len]);
		}
	}
	return tmp[0];
}
/// compute euler's totient function naively
long naive_totient (long num) {
	long count = 0;
	for (int i = 1; i < num;i++) {
		if (euc_gcd(i, num) == 1) {
			count+=1;
		}
	}
	return count;
}
/// solve a linear diophantine written in the form, ax+by = c
void solve_linear_diophantine (long a, long b, long c) {
	if (c != 1) {
		
	}
}
/// find all factors of a given n in O(n) time
unsigned long* factorize_naive (unsigned long n, unsigned long *len) {
	*len = 2;
	unsigned long *factors = malloc( sizeof(long) * (*len) );
	factors[0] = 1;
	
	for (unsigned long i = 2; i < n;i++) {
		if (n % i == 0) {
			*len += 1;
			factors = realloc(factors, sizeof(long) * (*len));
			factors[(*len)-2] = i;
		}
	}
	factors[(*len) - 1] = n;
	return factors;
}
/// modular exponentiation in O(logb) time
unsigned long pow_modl (unsigned long a, unsigned long b, unsigned long p) {
	unsigned long r = 1;
	int i;
	for (i = 63; ((b>>i) & 1) == 0; i--);
	
	for (; i >= 0; i--) {
		a %= p;
		if (b & 1) {
			r *= a;
			r %= p;
		}
		b >>= 1;
		a *= a;
	}
	return r;
}

unsigned long find_primitive_root_naive (unsigned long p) {
	
	unsigned long len = 0;
	unsigned long *factors = factorize_naive(p-1, &len); // get all factors of p-1, i.e. all q|(p-1)
	unsigned long g, q;
	int found_mod_1 = 0;
	for (g = p-2; g >= 2;g--) {
		found_mod_1 = 0;
		for (q = 1; q < len;q++) { // check if all g^[(p-1)/q] != 1 mod p
			if (pow_modl(g, (p-1)/factors[q], p) == 1) {
				found_mod_1 = 1;
				break;
			}
		}
		if (!found_mod_1) {
			return g;
		}
	}
	free(factors);
	return 0;
}
unsigned long factorize_RSA_N (unsigned long n, unsigned long e, unsigned long d) {
	// find s,t such that ed−1=2^st and t is odd
	unsigned long t = e*d - 1;
	while ((t & 1) == 0) { // while t is even
		t /= 2;
	}
	
	unsigned long a, b, bsq;
	do {
		// find an a < N & co-prime to N. That is, a is in Z* of N
		do { a = random()%n; } while ( euc_gcd(a, n) != 1 );
		
		b = pow_modl(a, t, n);
		bsq = b*b % n;
		while (bsq != 1) {
			b = bsq;
			bsq = b*b % n;
		}
	} while ( b == 1 );
	
	unsigned long p = euc_gcd(b-1, n);
	unsigned long q = n/p;
	
	// verify that factors are correct.
	// check that ed = 1 mod (p-1)(q-1)
	unsigned long phiN = (p-1)*(q-1);
	if ( (e*d) % phiN == 1 ) {
		// return p, user can then just compute q by dividing p by N
		return p;
	} else { // in case factorization was incorrect
		return -1;
	}
}

#endif /* number_theory_h */
