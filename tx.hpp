/**
 * Filename: tx.hpp
 *
 * Transactions
 *
 * Copyright (c) 2017-2018 Zoltan Szabo & XtraBYtes developers
 *
 * This file is part of xtrabytes project.
 *
 */

#ifndef TX_HPP
#define TX_HPP

#include <vector>
#include <iostream>
#include <stdint.h>

#include "key.hpp"

class tx {
public:
	tx(std::vector<unsigned char> tx, std::vector<unsigned char> spk, unsigned int out, std::string toAddr, uint64_t amnt);
	std::vector<unsigned char> sign(key &keypair);

private:
	std::vector<unsigned char> txid;
	std::vector<unsigned char> addr;
	uint64_t amount;
	std::vector<unsigned char> scriptPubKey;
	unsigned int vout;
};

#endif 
