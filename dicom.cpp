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
#include "base64.hpp"

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

		rpcutil::client c(ios);
		// TODO: fixup host and extract login parameters to config
		c.connect("localhost:2222", "xcuser", "yxcpwd");

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

	static bool rpc_command(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		boost::asio::io_service ios;
		boost::property_tree::ptree rpcreply;

		if (!request.HasMember("rpc_method")) {
			reply.put("message", "rpc_method required");
			return false;
		}

		std::string rpc_method = request["rpc_method"].GetString();

		std::string rpc_params;
		if (request.HasMember("rpc_params")) {
			rpc_params = decode64(request["rpc_params"].GetString());
		}


		/*
		boost::property_tree::ptree jsonrpc;		   
		boost::property_tree::ptree params;		   
		std::vector<std::string> rpc_params;

		if (request.HasMember("rpc_params")) {
			std::string paramstr = decode64(request["rpc_params"].GetString());
			boost::split(rpc_params, paramstr, boost::is_any_of(" "));
			for (unsigned int i = 0; i < rpc_params.size(); i++) {
				boost::property_tree::ptree item;		   

				item.put("", rpc_params[i]);
				params.push_back(std::make_pair("", item));
			}
		}

		jsonrpc.put("jsonrpc", "1.0");
		jsonrpc.put("id", "sssd");
		jsonrpc.put("method", rpc_method);

		if (rpc_params.size() > 0) {
			jsonrpc.add_child("params", params);
		}

		std::stringstream repss;
		boost::property_tree::write_json(repss, jsonrpc, false);
		std::string command = repss.str();  
		*/

		std::string command = R"({"jsonrpc":"1.0","id":"sss-daemon","method":")" + rpc_method + R"(","params":[)" + rpc_params + R"(]})";

		std::cout << command << std::endl;
	
		rpcutil::client c(ios);
		c.connect("localhost:2222", "xcuser", "yxcpwd");
		std::stringstream rpcrepss;
		try {
			boost::property_tree::write_json(rpcrepss, c.rpcquery(command), false);
		}	catch (std::exception& e)  {
			rpcrepss << "bad rpc reply error:" << e.what();
		}	
		reply.put("reply", rpcrepss.str() );

		return true;
	}

	static bool user_verify(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		// TODO: add proof-of-work to this to avoid brute force attempts
		if (!request.HasMember("username")) {
			reply.put("message", "Username required");
			return false;
		}

		if (!request.HasMember("password")) {
			reply.put("message", "Password required");
			return false;
		}

		std::string username = request["username"].GetString();
		std::string password = request["password"].GetString();

		std::string key = "user:" + username + password + ":xby";
		std::string hash = keyvaluedb.getkey(key);

		std::string private_key; 
		if (!keyvaluedb.read(hash, private_key)) {
			reply.put("message", "User not found");
			return false;
		}

		reply.put("username", username);

		return true;
	}

	static bool user_create(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		if (!request.HasMember("username")) {
			reply.put("message", "Username required");
			return false;
		}

		if (!request.HasMember("password")) {
			reply.put("message", "Password required");
			return false;
		}

		std::string username = request["username"].GetString();
		std::string password = request["password"].GetString();

		if (password.length() < 8) {
			reply.put("message", "Password must be more than 8 characters");
			return false;
		}

		std::string key = "user:" + username + password + ":xby";
		std::string value = "";

		std::string hash = keyvaluedb.getkey(key);

		// TODO: Better sanity check required: usernames should be unique

		if (keyvaluedb.exists(hash)) {
			reply.put("message", "Username already exists");
			return false;
		}

		keyvaluedb.write(hash, value);

		return true;
	}

	static bool user_login(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		// TODO: add proof-of-work to this to avoid brute force attempts
		if (!request.HasMember("username")) {
			reply.put("message", "Username required");
			return false;
		}

		if (!request.HasMember("password")) {
			reply.put("message", "Password required");
			return false;
		}

		std::string username = request["username"].GetString();
		std::string password = request["password"].GetString();

		std::string key = "user:" + username + password + ":xby";
		std::string hash = keyvaluedb.getkey(key);

		std::string private_key; 
		if (!keyvaluedb.read(hash, private_key)) {
			reply.put("message", "Login failed: Invalid username/password");
			return false;
		}

		client->set_userhash(hash);
		reply.put("username", username);
		reply.put("key", private_key);

		return true;
	}

	static bool privatekey_import(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		if (!client->is_logged_in()) {
			reply.put("message", "Logged in session required");
			return false;
		}

		if (!request.HasMember("key")) {
			reply.put("message", "Key required");
			return false;
		}

		std::string private_key = request["key"].GetString();
		boost::algorithm::trim(private_key);

		std::string key = client->get_userhash();
		keyvaluedb.write(key, private_key);

		reply.put("key", private_key);

		return true;
	}

	static bool transaction_send(http::dicomserver::client *client, const rapidjson::Document &request, boost::property_tree::ptree &reply) {
		if (!client->is_logged_in()) {
			reply.put("message", "Logged in session required");
			return false;
		}

		if (!request.HasMember("transaction")) {
			reply.put("message", "Transaction required");
			return false;
		}

		std::string tx = request["transaction"].GetString();

		reply.put("rawbytes", tx);

		reply.put("transaction_id", tx);

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
		{ "transaction.send", transaction_send },
		{ "rpc.command", rpc_command },
		{ "user.create", user_create },
		{ "user.verify", user_verify },
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

		std::string signature = payload::generate_signature(data, client->server_keys.priv);

		boost::property_tree::ptree res;
		res.put("dicom", "1.0");
		res.put("payload", data);
		res.put("signature", signature);

		std::stringstream resss;
		boost::property_tree::write_json(resss, res);

		return resss.str();
	}
}
