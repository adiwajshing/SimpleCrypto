//
//  ASN1.c
//  Crypto
//
//  Created by Adhiraj Singh on 3/29/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//
// implemented 

#include "ASN1.h"
#include "Utils.h"

#include <string.h>

const uint8_t private_header[] = {0x30, 0x82, 0x02, 0x5D}; // header for ASN.1
const char private_header_str[] = "-----BEGIN RSA PRIVATE KEY-----\n";
const char private_footer_str[] = "\n-----END RSA PRIVATE KEY-----";

const uint8_t public_header[] = {0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89}; // header for ASN.1
const char public_header_str[] = "-----BEGIN RSA PUBLIC KEY-----\n";
const char public_footer_str[] = "\n-----END RSA PUBLIC KEY-----";

int append_integer (mpz_t num, uint8_t *buffer, uint8_t prefix) {
	int count = 0;
	buffer[count] = 0x02;
	count += 1;
	
	size_t size = mpz_sizeinbase(num, 16);
	size = (size%2 == 0) && (size != 0) ? size/2 : size/2 + 1;
	
	if (prefix == 0) {
		size += 1;
	}
	
	buffer[count] = size;
	count += 1;
	if (size > 0x80) {
		buffer[count] = size;
		count += 1;
	}
	if (prefix == 0) {
		buffer[count] = prefix;
		count += 1;
		size -= 1;
	}
	
	mpz_export(buffer + count, NULL, 1, sizeof(uint8_t), 1, 0, num);
	count += size;
	return count;
}
int read_integer (mpz_t num, uint8_t *buffer) {
	int count = 0;
	if (buffer[count] != 0x02) {
		return -1;
	}
	count += 1;
	
	size_t size = buffer[count];
	count += 1;
	if (size > 0x80) {
		count += 1;
	}
	
	if (num)
		mpz_import(num, size, 1, sizeof(uint8_t), 1, 0, buffer + count);

	count += size;
	return count;
}

void ASN1_write_private_key (RSAKeyPair *key, const char *filename) {
	size_t size = (key->n->_mp_size)*sizeof(mp_limb_t)*5;
	
	uint8_t buffer[size];
	uint8_t *tmp = buffer;
	
	memcpy(tmp, private_header, 4);
	tmp += 4;
	
	tmp[0] = 0x02; tmp[1] = 0x01; tmp[2] = 0x00;
	tmp += 3;
	
	tmp += append_integer(key->n, tmp, 0x00);
	tmp += append_integer(key->e, tmp, 0x01);
	tmp += append_integer(key->d, tmp, 0x00);
	tmp += append_integer(key->p, tmp, 0x00);
	tmp += append_integer(key->q, tmp, 0x00);
	tmp += append_integer(key->exp1, tmp, 0x01);
	tmp += append_integer(key->exp2, tmp, 0x00);
	tmp += append_integer(key->coeff, tmp, 0x00);
	
	size = tmp-buffer;
	
	FILE *file = fopen(filename, "w");
	
	fwrite(private_header_str, sizeof(char), strlen(private_header_str), file);
	
	char *base64encoded = b64_encode(buffer, size);
	fwrite(base64encoded, sizeof(char), strlen(base64encoded), file);
	
	free(base64encoded);
	
	fwrite(private_footer_str, sizeof(char), strlen(private_footer_str), file);
	
	fclose(file);
	//print_as_hex(buffer, size); printf("\n");
}

int ASN1_read_private_key (RSAKeyPair *key, const char *filename) {
	size_t len;
	char *data = (char *) get_text(filename, &len, FILE_MODE_UTF8);
	
	char *f_index = strstr(data, private_header_str);
	if (!f_index) {
		return -1;
	}
	f_index += strlen(private_header_str);
	
	char *l_index = strstr(data, private_footer_str);
	if (!l_index) {
		return -1;
	}
	len = (l_index-f_index);
	f_index[len] = 0;
	
	uint8_t *decoded = b64_decode(f_index, &len);
	free(data);
	
	//print_as_hex(decoded, len); printf("\n");
	
	if (memcmp(decoded, private_header, 4) != 0) {
		return -2;
	}
	decoded += 4;
	
	int tmpcount = read_integer(NULL, decoded);
	if (tmpcount > 0) { decoded += tmpcount; }
	
	mpz_t *pointers = (mpz_t *) key;
	
	for (int i = 0; i < 8; i++) {
		tmpcount = read_integer(pointers[i], decoded);
		if (tmpcount > 0) {
			decoded += tmpcount;
		} else {
			return -1;
		}
	}
	return 0;
}
void ASN1_write_public_key (mpz_t n, mpz_t e, const char *filename) {
	size_t len = (n->_mp_size)*sizeof(mp_limb_t)*2;
	uint8_t buffer[len];
	uint8_t *tmp = buffer;
	
	memcpy(tmp, public_header, 25);
	tmp += 25;
	
	tmp += append_integer(n, tmp, 0x00);
	tmp += append_integer(e, tmp, 0x01);
	
	len = tmp-buffer;
	
	FILE *file = fopen(filename, "w");
	
	fwrite(public_header_str, sizeof(char), strlen(public_header_str), file);
	
	char *base64encoded = b64_encode(buffer, len);
	fwrite(base64encoded, sizeof(char), strlen(base64encoded), file);
	
	free(base64encoded);
	
	fwrite(public_footer_str, sizeof(char), strlen(public_footer_str), file);
	
	fclose(file);
}
int ASN1_read_public_key (mpz_t n, mpz_t e, const char *filename) {
	size_t len;
	char *data = (char *) get_text(filename, &len, FILE_MODE_UTF8);
	
	char *f_index = strstr(data, public_header_str);
	if (!f_index) {
		return -1;
	}
	f_index += strlen(public_header_str);
	
	char *l_index = strstr(data, public_footer_str);
	if (!l_index) {
		return -1;
	}
	len = (l_index-f_index);
	f_index[len] = 0;
	
	uint8_t *decoded = b64_decode(f_index, &len);
	free(data);
	
	if (memcmp(decoded, public_header, 25) != 0) {
		return -2;
	}
	decoded += 25;
	
	int tmpcount = read_integer(n, decoded);
	if (tmpcount > 0) {
		decoded += tmpcount;
	} else {
		return -1;
	}
	tmpcount = read_integer(e, decoded);
	if (tmpcount > 0) {
		decoded += tmpcount;
	} else {
		return -1;
	}
	
	return 0;
}
