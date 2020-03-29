//
//  Utils.h
//  Crypto
//
//  Created by Adhiraj Singh on 2/27/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#ifndef Utils_h
#define Utils_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_str(const char *str);
void print_bytes(const unsigned char *str, int len);

void print_as_hex(const unsigned char *buff, int len);

unsigned char *hex_str_to_buffer (const char *hex, int len);
char *buffer_to_hex_str (const unsigned char *buff, int len);

void xor_string(unsigned char *a, const unsigned char *b, int len);
void swap (unsigned char *a, unsigned char *b, int len);

char *b64_encode(const unsigned char *in, size_t len);
unsigned char* b64_decode(const char *in, size_t *outlen);

enum {
	FILE_MODE_UTF8 = 0,
	FILE_MODE_BASE64 = 1,
	FILE_MODE_HEX = 2
};

uint8_t *get_text(const char *filename, size_t *rlen, int mode);
int set_text(const char *filename, uint8_t *str, size_t len, int mode);

double measure (void (*function)(void), int iterations);

#endif /* Utils_h */
