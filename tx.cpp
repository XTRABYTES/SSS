
#include <cstring>

#include "tx.hpp"
#include "hash.hpp"
#include "base58.hpp"

tx::tx(std::vector<unsigned char> tx, std::vector<unsigned char> spk, uint32_t out, std::string toAddr, uint64_t amnt) {
	txid = tx;
	vout = out;
	amount = amnt;
	scriptPubKey = spk;

	std::vector<unsigned char> tmp;
	DecodeBase58((const char*)toAddr.c_str(), tmp);
	addr = std::vector<unsigned char>(tmp.begin() + 1, tmp.end() - 4);
}

std::vector<unsigned char> tx::sign(key &keypair) {
	std::vector<unsigned char> tx;

	tx.push_back(0x01); tx.push_back(0x00); tx.push_back(0x00); tx.push_back(0x00); // version
	tx.push_back(0x01); // num inputs

	// reverse txid
	for (std::vector<unsigned char>::reverse_iterator i = txid.rbegin(); i != txid.rend(); ++i) {
		tx.push_back(*i);
	}

	// output index
	unsigned char o[4];
	o[0] = (int)((vout >> 24) & 0x0FF);
	o[1] = (int)((vout >> 16) & 0x0FF);
	o[2] = (int)((vout >> 8) & 0x0FF);
	o[3] = (int)((vout) & 0x0FF);
	tx.push_back(o[3]); tx.push_back(o[2]); tx.push_back(o[1]); tx.push_back(o[0]);

	// temporary scriptSig
	tx.push_back(scriptPubKey.size()); // len
	for (std::vector<unsigned char>::iterator i = scriptPubKey.begin(); i != scriptPubKey.end(); ++i) {
		tx.push_back(*i);
	}

	// sequence
	tx.push_back(0xff); tx.push_back(0xff); tx.push_back(0xff); tx.push_back(0xff);

	// OUTPUTS
	// TODO: balance output
	tx.push_back(0x01); // num outputs

	// amount
	unsigned char b[8];
	b[0] = (int)((amount >> 56) & 0x0FF);
	b[1] = (int)((amount >> 48) & 0x0FF);
	b[2] = (int)((amount >> 40) & 0x0FF);
	b[3] = (int)((amount >> 32) & 0x0FF);
	b[4] = (int)((amount >> 24) & 0x0FF);
	b[5] = (int)((amount >> 16) & 0x0FF);
	b[6] = (int)((amount >> 8) & 0x0FF);
	b[7] = (int)(amount & 0x0FF);

	tx.push_back(b[7]);
	tx.push_back(b[6]);
	tx.push_back(b[5]);
	tx.push_back(b[4]);
	tx.push_back(b[3]);
	tx.push_back(b[2]);
	tx.push_back(b[1]);
	tx.push_back(b[0]);

	// scriptPubKey
	tx.push_back(0x19); // len
	tx.push_back(0x76); // OP_DUP
	tx.push_back(0xa9); // OP_HASH160
	tx.push_back(0x14); // PUSHDATA (20)
	// address
	for (unsigned int i = 0; i < 20; i++) {
		tx.push_back(addr[i]);
	}
	tx.push_back(0x88); // OP_EQUALVERIFY
	tx.push_back(0xac); // OP_CHECKSIG

	// lock time
	tx.push_back(0x00); tx.push_back(0x00); tx.push_back(0x00); tx.push_back(0x00);

	// hash-code-type
	tx.push_back(0x01); tx.push_back(0x00); tx.push_back(0x00); tx.push_back(0x00);

	unsigned char sha256_1[32];
	unsigned char sha256_2[32];

	sha256(&tx[0], tx.size(), sha256_1);
	sha256(sha256_1, 32, sha256_2);

	std::vector<unsigned char> sig = keypair.sign(sha256_2);

	unsigned int scriptSigSize = 1+sig.size()+1;

	unsigned char *scriptSig = (unsigned char*)malloc(scriptSigSize);
	memset(scriptSig, 0, scriptSigSize);

	scriptSig[0] = sig.size() + 1;
	memcpy(&scriptSig[1], &sig[0], sig.size());
	scriptSig[sig.size()+1] = 0x01;

	tx[41] = scriptSigSize;

	int finaltxSize = 4+1+32+4+1+scriptSigSize+4+1+8+1+25+4;
	unsigned char *finaltx = (unsigned char*)malloc(finaltxSize);
	memset(finaltx, 0, finaltxSize); 

	memcpy(finaltx, &tx[0], 4+1+32+4+1);
	memcpy(&finaltx[4+1+32+4+1], &scriptSig[0], scriptSigSize);
	memcpy(&finaltx[4+1+32+4+1+scriptSigSize], &tx[4+1+txid.size()+4+1+scriptPubKey.size()], 4+1+8+1+25+4);

	std::vector<unsigned char> ret(finaltxSize);
	memcpy(&ret[0], finaltx, finaltxSize);

	free(scriptSig);
	free(finaltx);

	return ret;
}
