/**
 * Filename: dicom.hpp
 *
 * Distributed Command Message (DICOM) 
 * is the API through which Decentralized Applications interact with each others. 
 *
 * Copyright (c) 2017-2018 Zoltan Szabo & XtraBYtes developers
 *
 * This file is part of xtrabytes project.
 *
 */

#ifndef PAYLOAD_HPP
#define PAYLOAD_HPP

namespace payload {
	class keypair {
		public:
			std::string priv;
			std::string pub;
	};

	bool verify_signature(std::string data, std::string signature, std::string pubkey);
	std::string generate_signature(std::string data, std::string privkey);
	bool generate_keypair(keypair &keypair);
}

#endif 
