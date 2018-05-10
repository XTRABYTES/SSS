
#include <cstring>
#include <string>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>

namespace payload {
	// TODO: Generate these per connection
	std::string sss_pubkey = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzKzjJSMnbnZPjsUNmO1X
wOf3RgigWekuTn8o7WPTPw2bkNTWx6I+KQT3aXVcyO5GfisG4+LpJ5wMdO+5EZDp
wngrlgQKmgz44+I69F7WNt1E8NYJNal7HRcH+CSjp5yCCSdrqZuN2lfdJS8Lbalc
uFSEDccw0LEDDCJENGJrD9cOYnonLjLHPj+Fh5OXblFibifIG4r2BAtoLFHRpg1w
vxvmDIUzusiBVTinw9CTQdDe/9WIu2GSrju+5VyE9x+ncsB1gJZw1Dob2QacE5JU
KZRVaqh0f+YmetvM3rAXVwnjrxY8SJeXjwFNHSuUtQzk7rN74wVfOg0lXB956c+M
wwIDAQAB
-----END PUBLIC KEY-----)";

	std::string sss_privkey = R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMrOMlIydudk+O
xQ2Y7VfA5/dGCKBZ6S5OfyjtY9M/DZuQ1NbHoj4pBPdpdVzI7kZ+Kwbj4uknnAx0
77kRkOnCeCuWBAqaDPjj4jr0XtY23UTw1gk1qXsdFwf4JKOnnIIJJ2upm43aV90l
LwttqVy4VIQNxzDQsQMMIkQ0YmsP1w5ieicuMsc+P4WHk5duUWJuJ8gbivYEC2gs
UdGmDXC/G+YMhTO6yIFVOKfD0JNB0N7/1Yi7YZKuO77lXIT3H6dywHWAlnDUOhvZ
BpwTklQplFVqqHR/5iZ628zesBdXCeOvFjxIl5ePAU0dK5S1DOTus3vjBV86DSVc
H3npz4zDAgMBAAECggEAYfUkyXNnveB19zisZ1LAuxzKJgSe6ilF9l+5sNQkGHtk
xw52tRkbcvpjh1+aRrhzmJLzO0IwoLp448aP5q5akq58/dF1WYF35WkzGh4BnESO
aE2oHry8pZGOSN8QTHoFamgpiQVgAO4oc1FuwM9cBwS8JvP8kwUFFluYFRI9d1hz
rpEzodAXMMZQngOA9hXg1/4C1chh1BFmRbWmkdjXUpurLsPSairGlUPDyvk6E4Z9
P4YjtNaSDsYlIPAnOmG2JV6dhgWtVPXBNgNBgzwRNB9oinUDnCtIRTz7v1FudVWV
UK3RdDI2d3wOtEbnHvCJahPskZsCL3G8LwfLdrkDEQKBgQD/FoFJr8f2Ubv+McDO
uVeafX019IoR4A1QsUKHKD/7xKOqr49XEnzBVa6ocXdfUjOuZtiMRTkCWVWCtheh
4puCj+9UJZ/fCt9RpL4+xOUYExKksPSGOtzKiOLYX+ii4Yy9XFQfdt4/kVpqWNJO
DEFa8a0EuNHN6bcdDzn96heAJQKBgQDNaDyv9aVLcLiZ3BDrVQ1xcYQr53qqvmsU
kOra1+mfIUMmXiCizq3IQexrOs1A9Lf4YTMnTXITvYwMj3gCteXmkhuXI8vr86wg
xOd9KqeEmE4rEghOTpQWlTJCLQWZlqQwozUDD49ONzAIlelu1SHas96AIVdd16hj
Fb1j2jQwxwKBgQDL64rJhFt/X1HA4Lc4y1Pr7du10Vq69XjPhBUiBRw5QbZxEc2u
FtpimAN7JtH+ArHL/u2oHQJ5DT9dsgHsaUJWOohhpX5LiN6D3wYzGaXm/ABQZiHk
WJP+2TU3MlzAMT0YeAHL8XO0L5evInhk6kko0cC14KXgTbET6wM6J/RHfQKBgBBh
7u0tz2gr7l0/Iw5R80eIAT2rMapqk4nJYSHhNJ3ffkaSHVI+37doIp4Oy44RtpaV
0gmhcKbIaGIcEztMHLD+GDs+vKXuAl1+tuPRwhieOSXQQ19TfxYqAh8rDhZI4IGM
ks7Sr+BSIH+ezUZss02JKQbZIem3KJP2iOts3NrDAoGAFb/FMsFIwoDyixcVEeaf
+cLCK5m83EFLBitjjRWrKjiawHzAspTfdf1GgyUbG0YJ9g8cj+cVCrn4TNVMD7/l
0gYR3yI1ngCm3JDgXyK3TV/8MYk9vQ1UfsbirRHZ69+om7lvKy1G2bO3hOucWhHm
2yyfWNo1WyN+w6DjJinXCG8=
-----END PRIVATE KEY-----)";

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

	char* generate_signature(std::string plainText, std::string privateKey) {
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
