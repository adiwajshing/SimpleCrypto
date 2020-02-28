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
void print_bytes(const char *str, int len);

char *get_text(const char *filename, int *rlen);
int set_text(const char *filename, char *str, int len);

#endif /* Utils_h */
