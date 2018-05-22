
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <cstring>

#include "bip38.hpp"
#include "base58.hpp"
#include "../libscrypt/libscrypt.h"
#include "util.hpp"
#include "hash.hpp"

BIP38::BIP38() {
}

std::vector<unsigned char> BIP38::decrypt(unsigned char *ciphertext, std::string passphrase) {
	EVP_CIPHER_CTX *ctx;

	// TODO: check flag byte

	unsigned char *salt = (unsigned char*)malloc(4);
	memcpy(salt, &ciphertext[3], 4);

	uint8_t *buf = (uint8_t*)malloc(64);

	uint8_t *pass_p = (uint8_t*)passphrase.c_str();
	uint8_t *salt_p = (uint8_t*)salt;

	int len;
	int plaintext_len;
	int ciphertext_len = 32;
	unsigned char *plaintext = (unsigned char*)malloc(1024);

	memset(plaintext, 0, 1024);

	libscrypt_scrypt(pass_p, passphrase.length(), salt_p, 4, 16384, 8, 8, buf, 64);

	uint8_t *dh1 = (uint8_t*)malloc(32);
	uint8_t *dh2 = (uint8_t*)malloc(32);

	memcpy(dh1, buf, 32);
	memcpy(dh2, &buf[32], 32);

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		std::cout << "EVP_CIPHER_CTX_new() error" << std::endl;
		return {};
	}

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, dh2, NULL) != 1) {
		std::cout << "EVP_DecryptInit_ex() error" << std::endl;
		return {};
	}

	if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
		std::cout << "EVP_CIPHER_CTX_set_padding() error" << std::endl;
		return {};
	}

	if (EVP_DecryptUpdate(ctx, plaintext, &len, &ciphertext[7], ciphertext_len) != 1) {
		std::cout << "EVP_DecryptUpdate() error" << std::endl;
		return {};
	}
	plaintext_len = len;

	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
		std::cout << "EVP_DecryptFinal_ex() error" << std::endl;
		return {};
	}
	printf("dec: %d\n", len);
	plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	printf("plaintext: ");
	print_hex(plaintext, plaintext_len);
	printf("pt len: %d\n", plaintext_len);

	for (int i = 0; i < 32; i++) {
		dh1[i] ^= plaintext[i];
	}
	
	printf("decrypted bytes: ");
	print_hex(dh1, plaintext_len);
	//std::string wif =  EncodeBase58(&wif[0], &wif[pklen+5]);

	return {};
}

std::string BIP38::encrypt(unsigned char *pkey, std::string address, std::string passphrase) {
	unsigned char salt[32];

	unsigned char *s_p = (unsigned char*)address.c_str();
	
	std::cout << "addr: " << address << std::endl;
	sha256(s_p, address.length(), salt);

	unsigned char sha256_1[32];
	unsigned char sha256_2[32];
	sha256(s_p, address.length(), sha256_1);
	sha256(sha256_1, 32, salt);

	printf("salt: ");
	print_hex(salt, 4);

	printf("pkey: ");
	print_hex(pkey, 32);

	uint8_t *buf = (uint8_t*)malloc(64);
	uint8_t *pass_p = (uint8_t*)passphrase.c_str();
	uint8_t *pkey_p = (uint8_t*)pkey;
	uint8_t *salt_p = (uint8_t*)salt;

	unsigned char ciphertext[1024];
	int ciphertext_len;
	int len;

	libscrypt_scrypt(pass_p, passphrase.length(), salt_p, 4, 16384, 8, 8, buf, 64);

	uint8_t *dh1 = (uint8_t*)malloc(32);
	uint8_t *dh2 = (uint8_t*)malloc(32);

	memcpy(dh1, buf, 32);
	memcpy(dh2, &buf[32], 32);

	//printf("KEY: ", dh2);
	//print_hex(dh2, 32);

	for (int i = 0; i < 32; i++) {
		dh1[i] ^= pkey_p[i];
	}
	
	printf("PLAIN: ", dh1);
	print_hex(dh1, 32);

	EVP_CIPHER_CTX *ctx;
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		std::cout << "EVP_CIPHER_CTX_new() error" << std::endl;
		return {};
	}

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, dh2, NULL) != 1) {
		std::cout << "EVP_EncryptInit_ex() error" << std::endl;
		return {};
	}

	if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
		std::cout << "EVP_CIPHER_CTX_set_padding() error" << std::endl;
		return {};
	}

	if (EVP_EncryptUpdate(ctx, ciphertext, &len, dh1, 32) != 1) {
		std::cout << "EVP_EncryptUpdate() error" << std::endl;
		return {};
	}
	ciphertext_len = len;

	if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
		std::cout << "EVP_EncryptFinal_ex() error" << std::endl;
		return {};
	}

	ciphertext_len += len;

	print_hex(ciphertext, ciphertext_len);
	printf("ciphertext len: %d\n", ciphertext_len);

	// TODO: ECB should not be used if encrypting more than one block of data with the same key

	free(buf);
	free(dh1);
	free(dh2);

	EVP_CIPHER_CTX_free(ctx);

	unsigned char d[43];
	memset(d, 0, 43);

	// 0x01 | 0x42 | flagByte | salt (4) | cipherText (32)
	d[0] = 0x01;
	d[1] = 0x42;
	d[2] = 0xc0; // compressed? 0xe0 for compressed, 0xc0 for uncompressed
	memcpy(&d[3], salt_p, 4);
	memcpy(&d[7], ciphertext, 32);

	printf("DONE: ");
	print_hex(d, 39);

	sha256(d, 39, sha256_1);
	sha256(sha256_1, 32, sha256_2);
	printf("Check: ");
	print_hex(sha256_2, 32);

	memcpy(d+39, sha256_2, 4);

	std::string wif = EncodeBase58(d, d+43);
	std::cout << "WIF: " << wif << std::endl;

	return wif;
}
