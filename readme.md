# ElGamal (HW4 1.5)

Please refer to [ElGamalSign.c](Crypto/ElGamal/ElGamalSign.c) for the signing, sign verification & existential forgery functions. I'm using this [library](https://github.com/amosnier/sha-2) for the SHA256 hashing.

1. To sign something, use  ``` uint8_t *ElGamal_signature (const uint8_t *plaintext, size_t *len, mpz_t g, mpz_t a, mpz_t q, int hash_sha256) ```.
2. To verify a signature, use ``` int ElGamal_sign_verify (const uint8_t *plaintext, size_t plaintextlen, const uint8_t *sign, mpz_t h, mpz_t q, mpz_t g, int hash_sha256) ```.
3. To generate an existential forgery, use ``` void ElGamal_generate_existential_forge (mpz_t r, mpz_t s, mpz_t m, mpz_t h, mpz_t q, mpz_t g, unsigned long seed) ```.
4. For a test of the signing, sign verification & existential forgery, please refer to ```testElGamal()``` in [ElGamal.c](Crypto/ElGamal/ElGamal.c).
5. For a small demo of signing & verification, please refer to [ElGamalProgram.c](Crypto/ElGamalProgram.c).

# ElGamal (HW3 1.10)

To view the implementation of ElGamal, please refer to ElGamal.h & ElGamal.c. There is also a unit test present in the files. It can work with 300 or 512 bit modes.
However, for a simple example, please refer to ElGamalProgram.c.

# RSA (HW3 1.9)

To run any RSA related function, please ensure that you have the GMP library installed on your computer. I have also provided a complied binary in the project (RSAProgram) to run what is required of in the question. However, if you so wish to see the code please refer to RSAProgram.c for the running, ASN1.h & ASN1.c for the implentation of the ASN.1 protocol, RSA.h &  RSA.c for the implementation of RSA. The program, by default uses RSA 1024, however, it can be recomplied for RSA 512 or RSA 2048 as well. A unit test for RSA are also present in RSA.c

1. To generate keys, call ./RSAProgram -keygenerator
2. To encrypt plaintext.txt, call ./RSAProgram -encrypt
2. To decrypt ciphertext.txt, call ./RSAProgram -decrypt.

The benchmarks for different versions of RSA are the following:
### RSA 1024
1. time taken: 0.004163
2. time taken: 0.004677
3. time taken: 0.010959
4. time taken: 0.009929
5. time taken: 0.021239
6. time taken: 0.011216
7. time taken: 0.015868
8. time taken: 0.008040
9. time taken: 0.005892
10. time taken: 0.020896

average time: 0.011288

### RSA 2048
1. time taken: 0.122571
2. time taken: 0.094352
3. time taken: 0.120993
4. time taken: 0.085912
5. time taken: 0.052626
6. time taken: 0.063667
7. time taken: 0.059860
8. time taken: 0.088416
9. time taken: 0.137585
10. time taken: 0.085261

average time: 0.091124

### RSA 4096
1. time taken: 0.620837
2. time taken: 0.806106
3. time taken: 1.491062
4. time taken: 0.837068
5. time taken: 1.649042
6. time taken: 1.519799
7. time taken: 5.413277
8. time taken: 0.892993
9. time taken: 1.117289
10. time taken: 1.403269

average time: 1.575074

# DES

## For HW2 1.7
I initially wrote the vanilla DES algorithm with CBC chaining & PKCS5 padding with all the permutations (see DES.h & DES.c). 

To encrypt using vanilla DES, call ``` des_cbc_encrypt(plaintext, &len, key,  iv) ```, where: 

**plaintext** is the pointer to the byte array you want to encrypt.

**len** is the parameter for the length (pass a reference to it, as the function will update the length of the text if padding was added)

**key** is the 8 byte key

**iv** is the 8 byte long IV (provide NULL to use without CBC chaining, i.e. ECB mode)

For decryption, call ``` des_cbc_decrypt(ciphertext, &len, key, iv) ``` , same arguments apply.

To use the variation of DES mentioned in the question, I simply swapped out the sub key generation function & the feistel network function (see VDES.h & VDES.c).

To encrypt a piece of text using this variation of DES (VDES), call ``` vdes_encrypt(plaintext, &len, key, iv) ``` . The only difference in the arguments being passed is that the key is 7 bytes long.  

For decryption, call ``` vdes_decrypt(ciphertext, &len, key, iv) ``` .


To run the program:

1. include VDES.h in your main file (VDES => Variation DES)
2. to run the program in encryption mode: call ``` run_vdes_encrypt() ```
3. to run the program in decryption mode: call ``` run_vdes_decrypt() ```

## For HW 1.8

I encrypt the plaintext using the variation of DES mentioned the previous question in CBC mode and then using DES in ECB mode. (See DDES.h & DDES.c)

To encrypt using D-DES, call ``` ddes_encrypt(plaintext, &len, K1, K, K2) ``` the function takes in a pointer to the byte array you want to encrypt, a parameter for the length (pass a reference to it, as the function will update the length of the text if padding was added), a 7 byte long key (K1), an 8 byte long K, and another 7 byte long key (K2). 

For decryption, call ``` ddes_decrypt(ciphertext, &len, K1, K, K2) ``` , same arguments apply.

# AES

## For HW2 1.4
See AES.h & AES.c and run  ``` testAES(); ``` to run the encrypt the plaintext using the key mentioned in the template in AES 128 mode. 
To generally use AES encryption, you can call ``` aes_cbc_encrypt (plaintext, &len, key, iv, mode)``` where:

**plaintext** is the pointer to the byte array you want to encrypt.

**len** is the parameter for the length (pass a reference to it, as the function will update the length of the text if padding was added)

**key** is the  key (16 bytes for AES 128, 24 bytes for AES 192, 32 bytes for AES 256)

**iv** is the IV (provide NULL to use without CBC chaining, i.e. ECB mode)

**mode** is the AES mode ==> AES_128, AES_192, AES_256

For decryption, you can call ``` aes_cbc_decrypt (ciphertext, &len, key, iv, mode)``` where the same arguments apply except the first parameter is the ciphertext you want to decrypt.

Note: the ``` mix_columns() ``` step was not present in the template, however, I have implemented it.
