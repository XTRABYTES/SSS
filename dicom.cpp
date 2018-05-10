/**
 * Filename: dicom.cpp
 *
 * Distributed Command Message (DICOM) 
 * is the API through which Decentralized Applications interact with each others. 
 *
 * Copyright (c) 2017-2018 Zoltan Szabo & XtraBYtes developers
 *
 * This file is part of xtrabytes project.
 *
 */

#include <iostream>
#include <string>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <rapidjson/document.h>

namespace dicom {

	struct dicomhandler {
		std::string method;
		bool (*actor)(const rapidjson::Document &request, boost::property_tree::ptree &reply);
	};

	static bool ping(const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		reply.put("ping", "pong");
		return true;
	}

	static bool echo(const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		// TODO: param checks
		reply.put("echo", request["params"].GetString());
		return true;
	}

	static const struct dicomhandler dicom_handlers[] = {
		{ "ping", ping },
		{ "echo", echo },
	};

	std::string exec(boost::property_tree::ptree reqpt) {
		boost::property_tree::ptree reppt;		   
		reppt.put("dicom", "1.0");

		// TODO: param checks
		std::string payload = reqpt.get("payload", "");
		std::string signature = reqpt.get("signature", "");
		std::string pubkey = reqpt.get("pubkey", "");

		rapidjson::Document d;
		d.Parse(payload.c_str());

		std::cout << payload << std::endl;

		std::string method = d["method"].GetString();

		unsigned int i = 0;
		bool methodfound = false;
		for (; i < (sizeof(dicom_handlers)/sizeof((dicom_handlers)[0])); i++) {
			if (!method.compare(dicom_handlers[i].method)) {
				methodfound = true;
				bool rc = dicom_handlers[i].actor(d, reppt);
				if (!rc) {
					reppt.put("error", "DICOM call failed.");
				}
			}
		}

		if (!methodfound) {
			reppt.put("error", "unknown DICOM method.");
		}

		std::stringstream repss;
		boost::property_tree::write_json(repss, reppt);
		return repss.str();  
	}
}
