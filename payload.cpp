
#include <cstring>
#include <string>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>

namespace payload {
	// Mostly cribbed from: https://eclipsesource.com/blogs/2016/09/07/tutorial-code-signing-and-verification-with-openssl/
	RSA* createPrivateRSA(std::string key) {
		::RSA *rsa = NULL;
		const char* c_string = key.c_str();
		BIO * keybio = BIO_new_mem_buf((void*)c_string, -1);
		if (keybio==NULL) {
			return 0;
		}
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
		return rsa;
	}

	bool RSASign( RSA* rsa, 
			const unsigned char* Msg, 
			size_t MsgLen,
			unsigned char** EncMsg, 
			size_t* MsgLenEnc) {
		EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
		EVP_PKEY* priKey  = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(priKey, rsa);
		if (EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha256(), NULL,priKey)<=0) {
			return false;
		}
		if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
			return false;
		}
		if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <=0) {
			return false;
		}
		*EncMsg = (unsigned char*)malloc(*MsgLenEnc);
		if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
			return false;
		}

		//EVP_MD_CTX_cleanup(m_RSASignCtx);
		return true;
	}

	void Base64Encode( const unsigned char* buffer, 
			size_t length, 
			char** base64Text) { 
		BIO *bio, *b64;
		BUF_MEM *bufferPtr;
		b64 = BIO_new(BIO_f_base64());
		bio = BIO_new(BIO_s_mem());
		bio = BIO_push(b64, bio);
		BIO_write(bio, buffer, length);
		BIO_flush(bio);
		BIO_get_mem_ptr(bio, &bufferPtr);
		BIO_set_close(bio, BIO_NOCLOSE);
		BIO_free_all(bio);
		*base64Text=(*bufferPtr).data;
	}

	char* signMessage(std::string privateKey, std::string plainText) {
		RSA* privateRSA = createPrivateRSA(privateKey);
		unsigned char* encMessage;
		char* base64Text;
		size_t encMessageLength;
		RSASign(privateRSA, (unsigned char*) plainText.c_str(), plainText.length(), &encMessage, &encMessageLength);
		Base64Encode(encMessage, encMessageLength, &base64Text);
		free(encMessage);
		return base64Text;
	}

	size_t calcDecodeLength(const char* b64input) {
		size_t len = strlen(b64input), padding = 0;
		if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
			padding = 2;
		else if (b64input[len-1] == '=') //last char is =
			padding = 1;
		return (len*3)/4 - padding;
	}

	void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
		BIO *bio, *b64;
		int decodeLen = calcDecodeLength(b64message);
		*buffer = (unsigned char*)malloc(decodeLen + 1);
		(*buffer)[decodeLen] = '\0';
		bio = BIO_new_mem_buf(b64message, -1);
		b64 = BIO_new(BIO_f_base64());
		bio = BIO_push(b64, bio);
		*length = BIO_read(bio, *buffer, strlen(b64message));
		BIO_free_all(bio);
	}

	RSA* createPublicRSA(std::string key) {
		RSA *rsa = NULL;
		BIO *keybio;
		const char* c_string = key.c_str();
		keybio = BIO_new_mem_buf((void*)c_string, -1);
		if (keybio==NULL) {
			return 0;
		}
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
		return rsa;
	}

	bool RSAVerifySignature( RSA* rsa, 
			unsigned char* MsgHash, 
			size_t MsgHashLen, 
			const char* Msg, 
			size_t MsgLen, 
			bool* Authentic) {
		*Authentic = false;
		EVP_PKEY* pubKey  = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(pubKey, rsa);
		EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();
		if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0) {
			return false;
		}
		if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
			return false;
		}
		int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
		if (AuthStatus==1) {
			*Authentic = true;
			//EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
			return true;
		} else if(AuthStatus==0){
			*Authentic = false;
			//EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
			return true;
		} else{
			*Authentic = false;
			//EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
			return false;
		}
	}

	bool verify_signature(std::string data, std::string signature, std::string pubkey) {
		RSA* publicRSA = createPublicRSA(pubkey);
		unsigned char* encMessage;
		size_t encMessageLength;
		bool authentic;

		Base64Decode(signature.c_str(), &encMessage, &encMessageLength);
		bool result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, data.c_str(), data.length(), &authentic);

		return result & authentic;
	}
}
