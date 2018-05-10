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

	bool verify_signature(std::string data, std::string signature, std::string pubkey);
}

#endif 
