/**
 * Filename: rpcutil.cpp
 *
 * Copyright (c) 2017-2018 Zoltan Szabo & XtraBYtes developers
 *
 * This file is part of xtrabytes project.
 *
 */

#include <ostream>
#include <istream>
#include <iostream>
#include <sstream>

#include <exception>
#include <sstream>
#include <boost/format.hpp>
#include <boost/exception/all.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/property_tree/json_parser.hpp>

#include "rpcutil.hpp"


namespace rpcutil {

	typedef boost::error_info<struct rpcutil_msg_,std::string> rpcutil_msg;

	using namespace boost::asio::ip;

	namespace detail {
		using namespace boost::asio::ip;

		class client 
		{
			public:
				client( boost::asio::io_service& i, rpcutil::client* c )
					:ios(i),sock(i),self(c)
				{

				}

				boost::property_tree::ptree request( const std::string& json )
				{
					boost::system::error_code error = boost::asio::error::host_not_found;
					sock.close();
					sock.connect( ep, error );
					if( error )
						throw boost::system::system_error(error);
					boost::asio::streambuf request_buf;
					std::ostream request_info(&request_buf);
					request_info << "POST / HTTP/1.1\r\n";
					request_info << "Host: 127.0.0.1\r\n";
					request_info << "Content-Type: application/json-rpc\r\n";
					request_info << "Authorization: Basic " << b64_password << "\r\n";
					request_info << "Content-Length: "<<json.size() << "\r\n";
					request_info << "Connection: close\r\n\r\n";

					request_info << json;
					std::cout << std::endl;

					boost::asio::write( sock, request_buf );

					// Read the response status line. The response streambuf will automatically
					// grow to accommodate the entire line. The growth may be limited by passing
					// a maximum size to the streambuf constructor.
					boost::asio::streambuf response;
					boost::asio::read_until(sock, response, "\r\n");

					std::istream response_stream(&response);
					std::string http_version;
					response_stream >> http_version;
					unsigned int status_code;
					response_stream >> status_code;
					std::string status_message;
					std::getline(response_stream, status_message);
					if (!response_stream || http_version.substr(0, 5) != "HTTP/")
					{
						boost::property_tree::ptree	pt;
						pt.put("error", "Invalid response." );
						return pt;					 
					}
					/*
					   if (status_code != 200)					   
					   {
					   boost::property_tree::ptree	pt;
					   pt.put("error", "Response returned with bad status code." );
					   pt.put("code", status_code );
					   return pt;					 
					   }
					   */
					boost::asio::read_until(sock, response, "\r\n\r\n");
					// Process the response headers.
					std::string header;
					while (std::getline(response_stream, header) && header != "\r") {

						std::cout << header << std::endl;
					}

					std::stringstream req;
					if (response.size() > 0) {
						//std::cout << &response;
						req << &response;
					}

					// Read until EOF, writing data to output as we go.
					while (boost::asio::read(sock, response, boost::asio::transfer_at_least(1), error)) {
						//std::cout << &response;
						req << &response;
					}

					if (error != boost::asio::error::eof) {
						throw boost::system::system_error(error);
					}

					/*
					std::cout << "READ LOOP" << std::endl;
					while (boost::asio::read(sock, response, boost::asio::transfer_at_least(0), error)) {
						//req << &response;
						std::cout << &response;

					}
					std::cout << "END READ LOOP" << std::endl;
					*/


						if (error != boost::asio::error::eof) {
							throw boost::system::system_error(error);
						}
					using boost::property_tree::ptree;
					ptree  pt;
					std::stringstream rtnss(req.str());

					std::cout << req.str() << std::endl;

					boost::property_tree::json_parser::read_json( rtnss, pt );

					return pt;
				}

				boost::asio::io_service& ios;
				tcp::socket				 sock;
				tcp::endpoint			 ep;
				rpcutil::client*		 self;

				std::string				 user;
				std::string				 pass;
				std::string				 b64_password;

		}; // detail::client


	} // namespace detail

	client::client( boost::asio::io_service& s )
	{
		my = new detail::client(s,this);
	}

	client::~client()
	{
		delete my;
	}

	bool client::connect( const std::string& host_port, const std::string& user, const std::string& pass )
	{
		std::string pre_encode = user + ":" + pass;
		my->user = user;
		my->pass = pass;
		my->b64_password = base64_encode( (const unsigned char*)pre_encode.c_str(), pre_encode.size() );

		std::string host = host_port.substr( 0, host_port.find(':') );
		std::string port = host_port.substr( host.size() + 1 );

		tcp::resolver resolver(my->ios);
		tcp::resolver::query q(host,port);
		tcp::resolver::iterator epi = resolver.resolve(q);
		tcp::resolver::iterator end;

		boost::system::error_code error = boost::asio::error::host_not_found;
		while( error && epi != end )
		{
			my->sock.close();
			my->sock.connect( *epi, error );
		}
		if( error )
		{
			std::cerr<< boost::system::system_error(error).what() << std::endl;
			return false;
		}
		my->ep = *epi;
		my->request("{\"jsonrpc\": \"1.0\", \"id\":\"1\", \"method\": \"getinfo\", \"params\": [] }");
		return true;
	}

	boost::property_tree::ptree client::rpcquery(std::string request) {


		boost::property_tree::ptree reply = my->request(request);

		return reply;
	}

}
