//
//  UtilsBase64.c
//  Crypto
//
//  Created by Adhiraj Singh on 3/29/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//
// Code from https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/

#include "Utils.h"
#include <string.h>

const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const int b64invs[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
43, 44, 45, 46, 47, 48, 49, 50, 51 };

size_t b64_encoded_size(size_t inlen)
{
	size_t ret;

	ret = inlen;
	if (inlen % 3 != 0)
		ret += 3 - (inlen % 3);
	ret /= 3;
	ret *= 4;

	return ret;
}
size_t b64_decoded_size(const char *in)
{
	size_t len;
	size_t ret;
	size_t i;

	if (in == NULL)
		return 0;

	len = strlen(in);
	ret = len / 4 * 3;

	for (i=len; i-->0; ) {
		if (in[i] == '=') {
			ret--;
		} else {
			break;
		}
	}

	return ret;
}
char *b64_encode(const unsigned char *in, size_t len)
{
	char   *out;
	size_t  elen;
	size_t  i;
	size_t  j;
	size_t  v;

	if (in == NULL || len == 0)
		return NULL;

	elen = b64_encoded_size(len);
	out  = malloc(elen+1);
	out[elen] = '\0';

	for (i=0, j=0; i<len; i+=3, j+=4) {
		v = in[i];
		v = i+1 < len ? v << 8 | in[i+1] : v << 8;
		v = i+2 < len ? v << 8 | in[i+2] : v << 8;

		out[j]   = b64chars[(v >> 18) & 0x3F];
		out[j+1] = b64chars[(v >> 12) & 0x3F];
		if (i+1 < len) {
			out[j+2] = b64chars[(v >> 6) & 0x3F];
		} else {
			out[j+2] = '=';
		}
		if (i+2 < len) {
			out[j+3] = b64chars[v & 0x3F];
		} else {
			out[j+3] = '=';
		}
	}

	return out;
}

int b64_isvalidchar(char c)
{
	if (c >= '0' && c <= '9')
		return 1;
	if (c >= 'A' && c <= 'Z')
		return 1;
	if (c >= 'a' && c <= 'z')
		return 1;
	if (c == '+' || c == '/' || c == '=')
		return 1;
	return 0;
}
unsigned char* b64_decode(const char *in, size_t *outlen)
{
	size_t len;
	size_t i = 0;
	size_t j;
	int    v;
	
	*outlen = b64_decoded_size(in);
	unsigned char *out = malloc( *outlen );

	if (in == NULL)
		return NULL;

	len = strlen(in);
	char sin[len];
	while (*in) {
		if (b64_isvalidchar(*in)) {
			sin[i] = *in;
			i += 1;
		}
		in += 1;
	}
	len = i;

	for (i=0, j=0; i<len; i+=4, j+=3) {
		v = b64invs[sin[i]-43];
		v = (v << 6) | b64invs[sin[i+1]-43];
		v = sin[i+2]=='=' ? v << 6 : (v << 6) | b64invs[sin[i+2]-43];
		v = sin[i+3]=='=' ? v << 6 : (v << 6) | b64invs[sin[i+3]-43];

		out[j] = (v >> 16) & 0xFF;
		if (sin[i+2] != '=')
			out[j+1] = (v >> 8) & 0xFF;
		if (sin[i+3] != '=')
			out[j+2] = v & 0xFF;
	}

	return out;
}
