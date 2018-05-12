/**
 * Filename: ssserver.cpp
 *
 * STaTiC simulation server (SSS) 
 *
 * This file is part of xtrabytes project.
 *
 */

#include <locale.h>
#include <stdio.h>

#include <fstream>
#include <sstream>
#include <iostream>
#include <string>
#include <cassert>
#include <exception>
#include <vector>

#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <rapidjson/document.h>

#include "dicom.hpp"
#include "ssserver.hpp"
#include "payload.hpp"

namespace http {
	namespace dicomserver {
		std::map<std::string, client*> clients;

		std::string FormatTime(std::string fmt, boost::posix_time::ptime now) {
			static std::locale loc(std::cout.getloc(),
					new boost::posix_time::time_facet(fmt.c_str()));

			std::stringstream ss;
			ss.imbue(loc);
			ss << now;
			return ss.str();
		}

		void base_connection::log_request() {
			using namespace boost::posix_time;
			using namespace boost::gregorian;

			std::string addrstr = peer.address().to_string();
			std::string timestr = FormatTime("%d/%b/%Y:%H:%M:%S", request_.tstamp);
			printf("%s - - [%s -0000] \"%s %s HTTP/%d.%d\" %d %lu\n",
					addrstr.c_str(),
					timestr.c_str(),
					request_.method.c_str(),
					request_.uri.c_str(),
					request_.http_version_major,
					request_.http_version_minor,
					reply_.status,
					reply_.content.size());
		}

		boost::asio::ip::tcp::socket& connection::socket() { return socket_; }

		void connection::start() {	read_more(); }

		void connection::read_more() {
			socket_.async_read_some(boost::asio::buffer(buffer_),
					strand_.wrap(
						boost::bind(&connection::handle_read, shared_from_this(),
							boost::asio::placeholders::error,
							boost::asio::placeholders::bytes_transferred)));
		}

		void connection::handle_read(const boost::system::error_code& e, std::size_t bytes_transferred) {

			if (e) {	return; }

			boost::tribool result;
			boost::tie(result, boost::tuples::ignore) = request_parser_.parse(
					request_, buffer_.data(), buffer_.data() + bytes_transferred);

			if (result) {
				keepalive_ = request_.want_keepalive();
				request_.tstamp =
					boost::posix_time::second_clock::universal_time();

				request_handler_.handle_request(request_, reply_, keepalive_);
				boost::asio::async_write(socket_, reply_.to_buffers(),
						strand_.wrap(
							boost::bind(&connection::handle_write, shared_from_this(),
								boost::asio::placeholders::error)));

				log_request();

			} else if (!result) {
				reply_ = reply::stock_reply(reply::bad_request);
				boost::asio::async_write(socket_, reply_.to_buffers(),
						strand_.wrap(
							boost::bind(&connection::handle_write, shared_from_this(),
								boost::asio::placeholders::error)));
			} else {	read_more(); }
		}

		void connection::handle_write(const boost::system::error_code& e) {
			if (e) {	return;	}

			if (keepalive_) {
				reset();
				read_more();
			} else {
				boost::system::error_code ignored_ec;
				socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored_ec);
			}
		}

		void ssl_connection::start() {
			socket_.async_handshake(boost::asio::ssl::stream_base::server,
					boost::bind(&ssl_connection::handle_handshake, shared_from_this(),
						boost::asio::placeholders::error));
		}

		void ssl_connection::read_more() {
			socket_.async_read_some(boost::asio::buffer(buffer_),
					strand_.wrap(
						boost::bind(&ssl_connection::handle_read, shared_from_this(),
							boost::asio::placeholders::error,
							boost::asio::placeholders::bytes_transferred)));
		}

		void ssl_connection::handle_handshake(const boost::system::error_code& e) {
			if (!e) { read_more(); }
		}

		void ssl_connection::handle_read(const boost::system::error_code& e, std::size_t bytes_transferred) {
			if (e) {	return;	}

			boost::tribool result;
			boost::tie(result, boost::tuples::ignore) = request_parser_.parse(
					request_, buffer_.data(), buffer_.data() + bytes_transferred);

			if (result)	{
				keepalive_ = request_.want_keepalive();
				request_.tstamp =
					boost::posix_time::second_clock::universal_time();

				request_handler_.handle_request(request_, reply_, keepalive_);
				boost::asio::async_write(socket_, reply_.to_buffers(),
						strand_.wrap(
							boost::bind(&ssl_connection::handle_write, shared_from_this(),
								boost::asio::placeholders::error)));

				log_request();

			} else if (!result) {
				reply_ = reply::stock_reply(reply::bad_request);
				boost::asio::async_write(socket_, reply_.to_buffers(),
						strand_.wrap(
							boost::bind(&ssl_connection::handle_write, shared_from_this(),
								boost::asio::placeholders::error)));
			} else {	read_more(); }
		}

		void ssl_connection::handle_write(const boost::system::error_code& e) {
			if (e) { return;	}

			if (keepalive_) {
				reset();
				read_more();
			} else {
				boost::system::error_code ignored_ec;
				socket_.shutdown(ignored_ec);
			}
		}


		namespace status_strings {

			const std::string ok = "HTTP/1.1 200 OK\r\n";
			const std::string created = "HTTP/1.1 201 Created\r\n";
			const std::string accepted = "HTTP/1.1 202 Accepted\r\n";
			const std::string no_content = "HTTP/1.1 204 No Content\r\n";
			const std::string multiple_choices = "HTTP/1.1 300 Multiple Choices\r\n";
			const std::string moved_permanently = "HTTP/1.1 301 Moved Permanently\r\n";
			const std::string moved_temporarily = "HTTP/1.1 302 Moved Temporarily\r\n";
			const std::string not_modified = "HTTP/1.1 304 Not Modified\r\n";
			const std::string bad_request = "HTTP/1.1 400 Bad Request\r\n";
			const std::string unauthorized = "HTTP/1.1 401 Unauthorized\r\n";
			const std::string forbidden = "HTTP/1.1 403 Forbidden\r\n";
			const std::string not_found = "HTTP/1.1 404 Not Found\r\n";
			const std::string internal_server_error = "HTTP/1.1 500 Internal Server Error\r\n";
			const std::string not_implemented = "HTTP/1.1 501 Not Implemented\r\n";
			const std::string bad_gateway = "HTTP/1.1 502 Bad Gateway\r\n";
			const std::string service_unavailable = "HTTP/1.1 503 Service Unavailable\r\n";

			boost::asio::const_buffer to_buffer(reply::status_type status) {
				switch (status)
				{
					case reply::ok: return boost::asio::buffer(ok);
					case reply::created: return boost::asio::buffer(created);
					case reply::accepted: return boost::asio::buffer(accepted);
					case reply::no_content: return boost::asio::buffer(no_content);
					case reply::multiple_choices: return boost::asio::buffer(multiple_choices);
					case reply::moved_permanently: return boost::asio::buffer(moved_permanently);
					case reply::moved_temporarily: return boost::asio::buffer(moved_temporarily);
					case reply::not_modified: return boost::asio::buffer(not_modified);
					case reply::bad_request: return boost::asio::buffer(bad_request);
					case reply::unauthorized: return boost::asio::buffer(unauthorized);
					case reply::forbidden: return boost::asio::buffer(forbidden);
					case reply::not_found: return boost::asio::buffer(not_found);
					case reply::internal_server_error: return boost::asio::buffer(internal_server_error);
					case reply::not_implemented: return boost::asio::buffer(not_implemented);
					case reply::bad_gateway:  return boost::asio::buffer(bad_gateway);
					case reply::service_unavailable: return boost::asio::buffer(service_unavailable);
					default: return boost::asio::buffer(internal_server_error);
				}
			}

		} // namespace status_strings

		namespace misc_strings {

			const char name_value_separator[] = { ':', ' ' };
			const char crlf[] = { '\r', '\n' };

		} // namespace misc_strings

		std::vector<boost::asio::const_buffer> reply::to_buffers()
		{
			std::vector<boost::asio::const_buffer> buffers;
			buffers.push_back(status_strings::to_buffer(status));
			for (std::size_t i = 0; i < headers.size(); ++i)
			{
				header& h = headers[i];
				buffers.push_back(boost::asio::buffer(h.name));
				buffers.push_back(boost::asio::buffer(misc_strings::name_value_separator));
				buffers.push_back(boost::asio::buffer(h.value));
				buffers.push_back(boost::asio::buffer(misc_strings::crlf));
			}
			buffers.push_back(boost::asio::buffer(misc_strings::crlf));
			buffers.push_back(boost::asio::buffer(content));
			return buffers;
		}

		namespace stock_replies {

			const char ok[] = "";
			const char created[] =
				"<html>"
				"<head><title>Created</title></head>"
				"<body><h1>201 Created</h1></body>"
				"</html>\r\n";
			const char accepted[] =
				"<html>"
				"<head><title>Accepted</title></head>"
				"<body><h1>202 Accepted</h1></body>"
				"</html>\r\n";
			const char no_content[] =
				"<html>"
				"<head><title>No Content</title></head>"
				"<body><h1>204 Content</h1></body>"
				"</html>\r\n";
			const char multiple_choices[] =
				"<html>"
				"<head><title>Multiple Choices</title></head>"
				"<body><h1>300 Multiple Choices</h1></body>"
				"</html>\r\n";
			const char moved_permanently[] =
				"<html>"
				"<head><title>Moved Permanently</title></head>"
				"<body><h1>301 Moved Permanently</h1></body>"
				"</html>\r\n";
			const char moved_temporarily[] =
				"<html>"
				"<head><title>Moved Temporarily</title></head>"
				"<body><h1>302 Moved Temporarily</h1></body>"
				"</html>\r\n";
			const char not_modified[] =
				"<html>"
				"<head><title>Not Modified</title></head>"
				"<body><h1>304 Not Modified</h1></body>"
				"</html>\r\n";
			const char bad_request[] =
				"<html>"
				"<head><title>Bad Request</title></head>"
				"<body><h1>400 Bad Request</h1></body>"
				"</html>\r\n";
			const char unauthorized[] =
				"<html>"
				"<head><title>Unauthorized</title></head>"
				"<body><h1>401 Unauthorized</h1></body>"
				"</html>\r\n";
			const char forbidden[] =
				"<html>"
				"<head><title>Forbidden</title></head>"
				"<body><h1>403 Forbidden</h1></body>"
				"</html>\r\n";
			const char not_found[] =
				"<html>"
				"<head><title>Not Found</title></head>"
				"<body><h1>404 Not Found</h1></body>"
				"</html>\r\n";
			const char internal_server_error[] =
				"<html>"
				"<head><title>Internal Server Error</title></head>"
				"<body><h1>500 Internal Server Error</h1></body>"
				"</html>\r\n";
			const char not_implemented[] =
				"<html>"
				"<head><title>Not Implemented</title></head>"
				"<body><h1>501 Not Implemented</h1></body>"
				"</html>\r\n";
			const char bad_gateway[] =
				"<html>"
				"<head><title>Bad Gateway</title></head>"
				"<body><h1>502 Bad Gateway</h1></body>"
				"</html>\r\n";
			const char service_unavailable[] =
				"<html>"
				"<head><title>Service Unavailable</title></head>"
				"<body><h1>503 Service Unavailable</h1></body>"
				"</html>\r\n";

			std::string to_string(reply::status_type status)
			{
				switch (status) {
					case reply::ok:  return ok;
					case reply::created:  return created;
					case reply::accepted:  return accepted;
					case reply::no_content:  return no_content;
					case reply::multiple_choices:  return multiple_choices;
					case reply::moved_permanently:  return moved_permanently;
					case reply::moved_temporarily:  return moved_temporarily;
					case reply::not_modified:  return not_modified;
					case reply::bad_request:  return bad_request;
					case reply::unauthorized:  return unauthorized;
					case reply::forbidden:  return forbidden;
					case reply::not_found:  return not_found;
					case reply::internal_server_error:  return internal_server_error;
					case reply::not_implemented:  return not_implemented;
					case reply::bad_gateway:  return bad_gateway;
					case reply::service_unavailable:  return service_unavailable;
					default:  return internal_server_error;
				}
			}

		} // namespace stock_replies

		reply reply::stock_reply(reply::status_type status)
		{
			reply rep;
			rep.status = status;
			rep.content = stock_replies::to_string(status);
			rep.headers.clear();
			rep.headers.push_back(header("Content-Length",
						boost::lexical_cast<std::string>(rep.content.size())));
			rep.headers.push_back(header("Content-Type", "text/html"));
			return rep;
		}


		server::server(const std::string& address, unsigned int port,
				const std::string& doc_root, std::size_t thread_pool_size)
			: thread_pool_size_(thread_pool_size),
			signals_(io_service_),
			acceptor_(io_service_),
			context_(boost::asio::ssl::context::tlsv1),
			new_connection_(),
			request_handler_(doc_root)
		{
			signals_.add(SIGINT);
			signals_.add(SIGTERM);
#if defined(SIGQUIT)
			signals_.add(SIGQUIT);
#endif // defined(SIGQUIT)
			signals_.async_wait(boost::bind(&server::handle_stop, this));

			std::string pemfile="ssserver.pem";
			context_.use_certificate_chain_file(pemfile);
			context_.use_private_key_file(pemfile, boost::asio::ssl::context::pem);
			char portstr[32];
			snprintf(portstr, sizeof(portstr), "%u", port);
			boost::asio::ip::tcp::resolver resolver(io_service_);
			boost::asio::ip::tcp::resolver::query query(address, portstr);
			boost::asio::ip::tcp::endpoint endpoint = *resolver.resolve(query);
			acceptor_.open(endpoint.protocol());
			acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
			acceptor_.bind(endpoint);
			acceptor_.listen();

			start_accept();
		}

		void server::run() {
			std::vector<boost::shared_ptr<boost::thread> > threads;
			for (std::size_t i = 0; i < thread_pool_size_; ++i) {
				boost::shared_ptr<boost::thread> thread(new boost::thread(
							boost::bind(&boost::asio::io_service::run, &io_service_)));
				threads.push_back(thread);
			}
			for (std::size_t i = 0; i < threads.size(); ++i)
				threads[i]->join();
		}

		void server::start_accept() {
			new_ssl_conn_.reset(new ssl_connection(io_service_, context_, request_handler_));
			acceptor_.async_accept(new_ssl_conn_->socket(), new_ssl_conn_->peer,
					boost::bind(&server::handle_accept, this,
						boost::asio::placeholders::error));
		}

		void server::handle_accept(const boost::system::error_code& e) {
			if (!e)	{	new_ssl_conn_->start(); 	}
			start_accept();
		}

		void server::handle_stop() {
			io_service_.stop();
		}

		request_parser::request_parser() : state_(method_start) {}

		void request_parser::reset() {
			state_ = method_start;
		}

		boost::tribool request_parser::consume(request& req, char input) {
			switch (state_)
			{
				case method_start:
					if (!is_char(input) || is_ctl(input) || is_tspecial(input))
					{
						return false;
					}
					else
					{
						state_ = method;
						req.method.push_back(input);
						return boost::indeterminate;
					}
				case method:
					if (input == ' ')
					{
						state_ = uri;
						return boost::indeterminate;
					}
					else if (!is_char(input) || is_ctl(input) || is_tspecial(input))
					{
						return false;
					}
					else
					{
						req.method.push_back(input);
						return boost::indeterminate;
					}
				case uri:
					if (input == ' ')
					{
						state_ = http_version_h;
						return boost::indeterminate;
					}
					else if (is_ctl(input))
					{
						return false;
					}
					else
					{
						req.uri.push_back(input);
						return boost::indeterminate;
					}
				case http_version_h:
					if (input == 'H')
					{
						state_ = http_version_t_1;
						return boost::indeterminate;
					}
					else
					{
						return false;
					}
				case http_version_t_1:
					if (input == 'T')
					{
						state_ = http_version_t_2;
						return boost::indeterminate;
					}
					else
					{
						return false;
					}
				case http_version_t_2:
					if (input == 'T')
					{
						state_ = http_version_p;
						return boost::indeterminate;
					}
					else
					{
						return false;
					}
				case http_version_p:
					if (input == 'P')
					{
						state_ = http_version_slash;
						return boost::indeterminate;
					}
					else
					{
						return false;
					}
				case http_version_slash:
					if (input == '/')
					{
						req.http_version_major = 0;
						req.http_version_minor = 0;
						state_ = http_version_major_start;
						return boost::indeterminate;
					}
					else
					{
						return false;
					}
				case http_version_major_start:
					if (is_digit(input))
					{
						req.http_version_major = req.http_version_major * 10 + input - '0';
						state_ = http_version_major;
						return boost::indeterminate;
					}
					else
					{
						return false;
					}
				case http_version_major:
					if (input == '.')
					{
						state_ = http_version_minor_start;
						return boost::indeterminate;
					}
					else if (is_digit(input))
					{
						req.http_version_major = req.http_version_major * 10 + input - '0';
						return boost::indeterminate;
					}
					else
					{
						return false;
					}
				case http_version_minor_start:
					if (is_digit(input))
					{
						req.http_version_minor = req.http_version_minor * 10 + input - '0';
						state_ = http_version_minor;
						return boost::indeterminate;
					}
					else
					{
						return false;
					}
				case http_version_minor:
					if (input == '\r')
					{
						state_ = expecting_newline_1;
						return boost::indeterminate;
					}
					else if (is_digit(input))
					{
						req.http_version_minor = req.http_version_minor * 10 + input - '0';
						return boost::indeterminate;
					}
					else
					{
						return false;
					}
				case expecting_newline_1:
					if (input == '\n')
					{
						state_ = header_line_start;
						return boost::indeterminate;
					}
					else
					{
						return false;
					}
				case header_line_start:
					if (input == '\r')
					{
						state_ = expecting_newline_3;
						return boost::indeterminate;
					}
					else if (!req.headers.empty() && (input == ' ' || input == '\t'))
					{
						state_ = header_lws;
						return boost::indeterminate;
					}
					else if (!is_char(input) || is_ctl(input) || is_tspecial(input))
					{
						return false;
					}
					else
					{
						req.headers.push_back(header());
						req.headers.back().name.push_back(tolower(input));
						state_ = header_name;
						return boost::indeterminate;
					}
				case header_lws:
					if (input == '\r')
					{
						state_ = expecting_newline_2;
						return boost::indeterminate;
					}
					else if (input == ' ' || input == '\t')
					{
						return boost::indeterminate;
					}
					else if (is_ctl(input))
					{
						return false;
					}
					else
					{
						state_ = header_value;
						req.headers.back().value.push_back(input);
						return boost::indeterminate;
					}
				case header_name:
					if (input == ':')
					{
						state_ = space_before_header_value;
						return boost::indeterminate;
					}
					else if (!is_char(input) || is_ctl(input) || is_tspecial(input))
					{
						return false;
					}
					else
					{
						req.headers.back().name.push_back(tolower(input));
						return boost::indeterminate;
					}
				case space_before_header_value:
					if (input == ' ')
					{
						state_ = header_value;
						return boost::indeterminate;
					}
					else
					{
						return false;
					}
				case header_value:
					if (input == '\r')
					{
						state_ = expecting_newline_2;
						return boost::indeterminate;
					}
					else if (is_ctl(input))
					{
						return false;
					}
					else
					{
						req.headers.back().value.push_back(input);
						return boost::indeterminate;
					}
				case expecting_newline_2:
					if (input == '\n')
					{
						state_ = header_line_start;
						return boost::indeterminate;
					}
					else
					{
						return false;
					}
				case expecting_newline_3:
					{
						bool have_newline = (input == '\n');

						if (have_newline) {
							std::string clen_hdr = req.get_header("content-length");
							int clen = atoi(clen_hdr.c_str());
							if (clen > 0) {
								if (clen > (16 * 1024 * 1024))
									return false;
								req.content.reserve(clen);
								body_bytes_ = clen;
								state_ = body;
								return boost::indeterminate;
							}
						}

						return have_newline;
					}

				case body:
					req.content.push_back(input);
					body_bytes_--;
					if (body_bytes_ == 0)
						return true;
					return boost::indeterminate;

				default:
					return false;
			}
		}

		bool request_parser::is_char(int c)
		{
			return c >= 0 && c <= 127;
		}

		bool request_parser::is_ctl(int c)
		{
			return (c >= 0 && c <= 31) || (c == 127);
		}

		bool request_parser::is_tspecial(int c)
		{
			switch (c)
			{
				case '(': case ')': case '<': case '>': case '@':
				case ',': case ';': case ':': case '\\': case '"':
				case '/': case '[': case ']': case '?': case '=':
				case '{': case '}': case ' ': case '\t':
					return true;
				default:
					return false;
			}
		}

		bool request_parser::is_digit(int c)
		{
			return c >= '0' && c <= '9';
		}

		extern std::string FormatTime(std::string fmt, boost::posix_time::ptime now);

		request_handler::request_handler(const std::string& doc_root)
			: doc_root_(doc_root)
		{
		}

		void request_handler::handle_request(const request& req, reply& rep,
				bool keepalive)
		{
			// Decode url to path.
			std::string request_path;
			if (!url_decode(req.uri, request_path)) {
				rep = reply::stock_reply(reply::bad_request);
				return;
			}

			if (req.method != "GET" && req.method != "POST") {
				rep = reply::stock_reply(reply::bad_request);
				return;
			}

			// Request path must be absolute and not contain "..".
			if (request_path.empty() || request_path[0] != '/'
					|| request_path.find("..") != std::string::npos) {
				rep = reply::stock_reply(reply::bad_request);
				return;
			}

			if (request_path != "/v1.0/dicom") {
				rep = reply::stock_reply(reply::not_found);
				return;
			}


			boost::property_tree::ptree reqpt;
			std::stringstream reqss;



			try  {
				reqss << req.content;

				boost::property_tree::read_json(reqss, reqpt);  

				std::stringstream ss;
				ss << reqpt.get<std::string>("dicom");          
				if (ss.str().compare("1.0")) {
					rep = reply::stock_reply(reply::bad_request);
					return;    
				}

			}  catch (std::exception& e)  {
				std::cout << e.what() << std::endl;
				rep = reply::stock_reply(reply::bad_request);
				return;        
			}   

			std::string payload = reqpt.get("payload", "");
			std::string signature = reqpt.get("signature", "");
			std::string pubkey = reqpt.get("pubkey", "");

			// parse out the payload
			rapidjson::Document request;
			request.Parse(payload.c_str());

			client *client = NULL;

			// Temporary basic sanity checking 
			try {
				if (signature == "") {
					throw std::invalid_argument("missing payload");
				}

				if (signature == "") {
					throw std::invalid_argument("missing signature");
				}

				if (!request.HasMember("method")) {
					throw std::invalid_argument("missing method");
				}

				std::string method = request["method"].GetString();
				if (method == "connect") {
					if (!request.HasMember("pubkey")) {
						throw std::invalid_argument("missing pubkey");
					}

					pubkey = request["pubkey"].GetString();

					// TODO: generate new keypair
					// TODO: check for existing sessions before overwriting (pubkey differs)

					boost::uuids::random_generator session_generator;
					boost::uuids::uuid sid = session_generator();

					std::string session_id = to_string(sid);

					client = new ::http::dicomserver::client(session_id, pubkey);
					clients[session_id] = client;

					std::cout << "new client session: " << client->session_id << std::endl;
				} else {
					if (!request.HasMember("session_id")) {
						throw std::invalid_argument("missing session_id");
					}

					std::string session_id = request["session_id"].GetString();

					if (clients.count(session_id) == 0) {
						// TODO: Handle by telling the client to establish a new connection
						throw std::invalid_argument("invalid session");
					}

					client = clients[session_id];
					pubkey = client->pubkey;
					std::cout << "using pubkey for session: " << session_id << std::endl << pubkey << std::endl;
				}


				// verify signature
				if (!payload::verify_signature(payload, signature, pubkey)) {
					throw std::invalid_argument("invalid signature");
				}
			}  catch (std::exception& e)  {
				// TODO: temporary error state for debugging
				boost::property_tree::ptree res;		   
				res.put("dicom", "1.0");
				res.put("error", e.what());

				std::stringstream repss;
				boost::property_tree::write_json(repss, res);
				
				rep.status = reply::bad_request;
				rep.content = repss.str();
				rep.headers.clear();
				rep.headers.push_back(header("Content-Length",
							boost::lexical_cast<std::string>(rep.content.size())));
				rep.headers.push_back(header("Content-Type", "application/json"));
				return;
			}   

			std::cout << "client count: " << clients.size() << std::endl;

			// Fill out the reply to be sent to the client.
			rep.status = reply::ok;

			rep.content = dicom::exec(client, request);
			rep.content += "\r\n";

			rep.headers.push_back(header("Date",
						FormatTime("%a, %d %b %Y %H:%M:%S GMT", req.tstamp)));
			rep.headers.push_back(header(		"Server", "DICOM/V1.0" ));
			rep.headers.push_back(header("Content-Length",
						boost::lexical_cast<std::string>(rep.content.size())));
			rep.headers.push_back(header("Content-Type", "application/json"));
			if (keepalive)
				rep.headers.push_back(header("Connection", "Keep-Alive"));
			else
				rep.headers.push_back(header("Connection", "close"));
		}

		bool request_handler::url_decode(const std::string& in, std::string& out)
		{
			out.clear();
			out.reserve(in.size());
			for (std::size_t i = 0; i < in.size(); ++i)
			{
				if (in[i] == '%')
				{
					if (i + 3 <= in.size())
					{
						int value = 0;
						std::istringstream is(in.substr(i + 1, 2));
						if (is >> std::hex >> value)
						{
							out += static_cast<char>(value);
							i += 2;
						}
						else
						{
							return false;
						}
					}
					else
					{
						return false;
					}
				}
				else if (in[i] == '+')
				{
					out += ' ';
				}
				else
				{
					out += in[i];
				}
			}
			return true;
		}


	} // namespace dicomserver
} // namespace http
