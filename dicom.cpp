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
#include <exception>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <rapidjson/document.h>

#include "rpcutil.hpp"
#include "keyvaluedb.hpp"
#include "ssserver.hpp"
#include "payload.hpp"

namespace dicom {
	class user {
		public:
			user(std::string u, std::string p) {
				username = u;
				password = p;
			}

			std::string username;
			std::string password;
	};

	std::map<std::string, user*> userlist;

	struct dicomhandler {
		std::string method;
		bool (*actor)(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply);
	};

	static bool rpcq(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {

		boost::asio::io_service ios;
		boost::property_tree::ptree rpcreply;

		rpcutil::client c( ios );
		c.connect( "localhost:4434", "xfuelrpc", "pw123" );

		rpcreply = c.rpcquery(request["params"].GetString());

		std::stringstream rpcrepss;
		try {
			boost::property_tree::write_json(rpcrepss, rpcreply);
		}	catch (std::exception& e)  {
			rpcrepss << "bad rpc reply error";
		}	
		reply.put("rpcreply", rpcrepss.str() );
		return true;
	}

	static bool ping(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		reply.put("ping", "pong");
		return true;
	}

	static bool echo(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		if (!request.HasMember("params")) {
			return false;
		}

		reply.put("echo", request["params"].GetString());
		return true;
	}

	static bool write(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		std::string value = request["value"].GetString();			
		std::string key = keyvaluedb.getkey(value);
		keyvaluedb.write(key,value);
		reply.put("write", value);
		reply.put("key", key);
		return true;
	}

	static bool read(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		std::string key = request["key"].GetString();	   
		std::string value = keyvaluedb.read(key);	   
		reply.put("read", key);
		reply.put("value", value);
		return true;
	}

	static bool connect(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		reply.put("session_id", client->session_id);
		reply.put("pubkey", client->server_keys.pub);
		return true;
	}

	static bool CreateUser(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		if (!request.HasMember("username")) {
			return false;
		}

		if (!request.HasMember("password")) {
			return false;
		}

		std::string username = request["username"].GetString();
		std::string password = request["password"].GetString();

		bool user_exists = (userlist.count(username) == 1);
		if (!user_exists) {
			user *u = new user(username, password);
			userlist[username] = u;
		}

		reply.put("username", username);
		reply.put("usercreated", !user_exists);
		reply.put("existingusername", user_exists);

		return true;
	}

	static bool CheckUser(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		if (!request.HasMember("username")) {
			return false;
		}

		if (!request.HasMember("password")) {
			return false;
		}

		user *u = new user("nrocy", "foobarbaz");
		userlist["nrocy"] = u;

		std::string username = request["username"].GetString();
		std::string password = request["password"].GetString();

		bool user_valid = false;

		bool user_exists = (userlist.count(username) == 1);
		if (user_exists) {
			user *u = userlist[username];
			user_valid = (u->username == username) && (u->password == password);
		}

		reply.put("username", username);
		reply.put("credentialcheck", user_valid);

		return true;
	}

	static bool CheckUsername(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		if (!request.HasMember("username")) {
			return false;
		}

		std::string username = request["username"].GetString();
		bool user_exists = (userlist.count(username) == 1);

		reply.put("username", username);
		reply.put("existingusername", user_exists);

		return true;
	}

	static bool user_create(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		if (!request.HasMember("username")) {
			reply.put("message", "username required");
			return false;
		}

		if (!request.HasMember("password")) {
			reply.put("message", "password required");
			return false;
		}

		std::string username = request["username"].GetString();
		std::string password = request["password"].GetString();

		if (password.length() < 8) {
			reply.put("message", "password must be more than 8 characters");
			return false;
		}

		std::string key = "user:" + username + password + ":xby";
		std::string value = "";

		std::string hash = keyvaluedb.getkey(key);

		if (keyvaluedb.exists(hash)) {
			reply.put("message", "username exists");
			return false;
		}

		keyvaluedb.write(hash, value);

		return true;
	}

	static bool user_login(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		if (!request.HasMember("username")) {
			reply.put("message", "username required");
			return false;
		}

		if (!request.HasMember("password")) {
			reply.put("message", "password required");
			return false;
		}

		std::string username = request["username"].GetString();
		std::string password = request["password"].GetString();

		std::string key = "user:" + username + password + ":xby";
		std::string hash = keyvaluedb.getkey(key);

		std::string private_key; 
		if (!keyvaluedb.read(hash, private_key)) {
			reply.put("message", "user not found");
			return false;
		}

		client->set_userhash(hash);
		reply.put("username", username);
		reply.put("key", private_key);

		return true;
	}

	static bool privatekey_import(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		if (!client->is_logged_in()) {
			reply.put("message", "login required");
			return false;
		}

		if (!request.HasMember("key")) {
			reply.put("message", "key required");
			return false;
		}

		std::string private_key = request["key"].GetString();
		boost::algorithm::trim(private_key);

		std::string key = client->get_userhash();
		keyvaluedb.write(key, private_key);

		reply.put("key", private_key);

		return true;
	}

	static const struct dicomhandler dicom_handlers[] = {
		{ "rpcq", rpcq },
		{ "ping", ping },
		{ "echo", echo },
		{ "write", write },
		{ "read", read },
		{ "connect", connect },
		{ "CheckUsername", CheckUsername },
		{ "CreateUser", CreateUser },
		{ "CheckUser", CheckUser },

		// refactored 
		{ "privatekey.import", privatekey_import },
		{ "user.create", user_create },
		{ "user.login", user_login },
	};

	std::string exec(http::dicomserver::client *client, const rapidjson::Document &request) {
		boost::property_tree::ptree reppt;		   

		std::string method = request["method"].GetString();
		reppt.put("method", method);

		unsigned int i = 0;
		bool methodfound = false;
		for (; i < (sizeof(dicom_handlers)/sizeof((dicom_handlers)[0])); i++) {
			if (!method.compare(dicom_handlers[i].method)) {
				methodfound = true;
				bool rc = dicom_handlers[i].actor(client, request, reppt);
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

		char *signature = payload::generate_signature(data, client->server_keys.priv);

		boost::property_tree::ptree res;
		res.put("dicom", "1.0");
		res.put("payload", data);
		res.put("signature", signature);

		std::stringstream resss;
		boost::property_tree::write_json(resss, res);

		return resss.str();
	}
}
