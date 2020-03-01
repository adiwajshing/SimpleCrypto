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

