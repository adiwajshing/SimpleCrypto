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

char *get_text(const char *filename, int *rlen);
int set_text(const char *filename, char *str, int len);

#endif /* Utils_h */
