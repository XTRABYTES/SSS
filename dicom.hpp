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

#ifndef DICOM_HPP
#define DICOM_HPP

#include "ssserver.hpp"
#include <rapidjson/document.h>

namespace dicom {

	std::string exec(http::dicomserver::client *client, const rapidjson::Document &d);

}

#endif // DICOM_HPP
