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
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <rapidjson/document.h>

#include "payload.hpp"

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

	static bool connect(const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		// TODO: generate unique session id per connection
		// TODO: generate new keypair for the client 
		// TODO: link their session to the pubkey
		// TODO: use the previously given pubkey to verify other requests
		
		reply.put("session_id", "1234567890");

		return true;
	}

	static const struct dicomhandler dicom_handlers[] = {
		{ "ping", ping },
		{ "echo", echo },
		{ "connect", connect },
	};

	std::string exec(std::string payload) {
		boost::property_tree::ptree reppt;		   

		rapidjson::Document d;
		d.Parse(payload.c_str());

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
		boost::property_tree::write_json(repss, reppt, false);
		std::string data = repss.str();  

		// fix property_tree compact write_json bug: https://svn.boost.org/trac10/ticket/121490
		boost::trim_right(data);

		char *signature = payload::generate_signature(data, payload::sss_privkey);

		boost::property_tree::ptree res;
		res.put("dicom", "1.0");
		res.put("method", method);
		res.put("payload", data);
		res.put("pubkey", payload::sss_pubkey);
		res.put("signature", signature);

		std::stringstream resss;
		boost::property_tree::write_json(resss, res);

		return resss.str();
	}
}
