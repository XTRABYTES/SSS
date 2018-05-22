/**
 * Filename: bip38.hpp
 *
 * BIP38 routines
 *
 * Copyright (c) 2017-2018 Zoltan Szabo & XtraBYtes developers
 *
 * This file is part of xtrabytes project.
 *
 */

#ifndef BIP38_HPP
#define BIP38_HPP

#include <vector>
#include <iostream>

class BIP38 {

public:
	BIP38();
	std::string encrypt(unsigned char *pkey, std::string address, std::string passphrase);
	std::vector<unsigned char> decrypt(unsigned char *ciphertext, std::string passphrase);
};

#endif 
