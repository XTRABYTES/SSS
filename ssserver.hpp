/**
 * Filename: ssserver.hpp
 *
 * STaTiC simulation server (SSS) 
 *
 * This file is part of xtrabytes project.
 *
 */

#ifndef SSSERVER_HPP
#define SSSERVER_HPP

#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/array.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/logic/tribool.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/property_tree/ptree.hpp>


namespace http {
	namespace dicomserver {

		struct header {

			std::string name;
			std::string value;

			header() { }

			header(std::string name_, std::string value_) {
				name = name_;
				value = value_;
			}
		};


		struct reply {
			enum status_type	{
				ok = 200,
				created = 201,
				accepted = 202,
				no_content = 204,
				multiple_choices = 300,
				moved_permanently = 301,
				moved_temporarily = 302,
				not_modified = 304,
				bad_request = 400,
				unauthorized = 401,
				forbidden = 403,
				not_found = 404,
				internal_server_error = 500,
				not_implemented = 501,
				bad_gateway = 502,
				service_unavailable = 503
			} status;

			std::vector<header> headers;
			std::string content;
			std::vector<boost::asio::const_buffer> to_buffers();
			static reply stock_reply(status_type status);

			void clear() {
				headers.clear();
				content.clear();
			}
		};


		struct request {
			std::string		method;
			std::string		uri;
			int			http_version_major;
			int			http_version_minor;
			std::vector<header>	headers;
			std::string		content;
			boost::posix_time::ptime tstamp;

			void clear() {
				method.clear();
				uri.clear();
				http_version_major = 0;
				http_version_minor = 0;
				headers.clear();
				content.clear();
			}

			std::string get_header(std::string name) {
				std::vector<header>::iterator hi;
				for (hi = headers.begin(); hi != headers.end();hi++) {
					if ((*hi).name == name)
						return (*hi).value;
				}

				return "";
			}

			bool is_http11() const {
				if ((http_version_major > 1) ||
						((http_version_major == 1) && (http_version_minor > 0)))
					return true;

				return false;
			}

			bool want_keepalive() {
				bool rc = is_http11();

				std::string cxn_hdr = boost::to_lower_copy(get_header("connection"));

				if (cxn_hdr == "close")
					rc = false;
				else if (cxn_hdr == "keep-alive")
					rc = true;

				return rc;
			}
		};


		class request_handler : private boost::noncopyable {
			public:
				explicit request_handler(const std::string& doc_root);
				void handle_request(const request& req, reply& rep, bool keepalive);

			private:
				std::string doc_root_;
				static bool url_decode(const std::string& in, std::string& out);
		};

		class request_parser {
			public:	
				request_parser();
				void reset();
				template <typename InputIterator>
					boost::tuple<boost::tribool, InputIterator> parse(request& req,
							InputIterator begin, InputIterator end)
					{
						while (begin != end)
						{
							boost::tribool result = consume(req, *begin++);
							if (result || !result)
								return boost::make_tuple(result, begin);
						}
						boost::tribool result = boost::indeterminate;
						return boost::make_tuple(result, begin);
					}

			private:
				boost::tribool consume(request& req, char input);
				static bool is_char(int c);
				static bool is_ctl(int c);
				static bool is_tspecial(int c);
				static bool is_digit(int c);
				unsigned int body_bytes_;

				enum state	{
					method_start,
					method,
					uri,
					http_version_h,
					http_version_t_1,
					http_version_t_2,
					http_version_p,
					http_version_slash,
					http_version_major_start,
					http_version_major,
					http_version_minor_start,
					http_version_minor,
					expecting_newline_1,
					header_line_start,
					header_lws,
					header_name,
					space_before_header_value,
					header_value,
					expecting_newline_2,
					expecting_newline_3,
					body
				} state_;
		};


		class base_connection {
			public:
				explicit base_connection(boost::asio::io_service& io_service,
						request_handler& handler) :
					strand_(io_service),
					request_handler_(handler)	{}

				boost::asio::ip::tcp::endpoint peer;

			protected:
				void log_request();
				boost::asio::io_service::strand strand_;
				request_handler& request_handler_;
				boost::array<char, 8192> buffer_;
				request request_;
				reply reply_;
				request_parser request_parser_;
				bool keepalive_;

				void reset() {
					request_.clear();
					reply_.clear();
					request_parser_.reset();
				}
		};


		class connection
			: public boost::enable_shared_from_this<connection>, public base_connection,	private boost::noncopyable {

				public:
					explicit connection(boost::asio::io_service& io_service,
							request_handler& handler) :
						base_connection(io_service, handler),
						socket_(io_service)	{}
					boost::asio::ip::tcp::socket& socket();
					void start();

				private:
					void read_more();
					void handle_read(const boost::system::error_code& e,
							std::size_t bytes_transferred);
					void handle_write(const boost::system::error_code& e);
					boost::asio::ip::tcp::socket socket_;
			};

		class client {
			public:
				client(std::string sid, std::string pk) {
					session_id = sid;
					pubkey = pk;
				}

				std::string session_id;
				std::string pubkey;
		};

		typedef boost::shared_ptr<connection> connection_ptr;
		typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;

		class ssl_connection
			: public boost::enable_shared_from_this<ssl_connection>,	public base_connection,	private boost::noncopyable {

				public:
					explicit ssl_connection(boost::asio::io_service& io_service,
							boost::asio::ssl::context& context,	request_handler& handler) :
						base_connection(io_service, handler),	socket_(io_service, context)	{}
					void start();
					ssl_socket::lowest_layer_type& socket() {
						return socket_.lowest_layer();
					}

				private:
					void read_more();
					void handle_read(const boost::system::error_code& e,
							std::size_t bytes_transferred);
					void handle_write(const boost::system::error_code& e);
					void handle_handshake(const boost::system::error_code& e);
					ssl_socket socket_;

			};

		typedef boost::shared_ptr<ssl_connection> ssl_conn_ptr;

		class server : private boost::noncopyable {

			public:
				explicit server(const std::string& address, unsigned int port,
						const std::string& doc_root, std::size_t thread_pool_size);
				void run();

			private:
				void start_accept();
				void handle_accept(const boost::system::error_code& e);
				void handle_stop();
				std::size_t thread_pool_size_;
				boost::asio::io_service io_service_;
				boost::asio::signal_set signals_;
				boost::asio::ip::tcp::acceptor acceptor_;
				boost::asio::ssl::context context_;
				connection_ptr new_connection_;
				ssl_conn_ptr new_ssl_conn_;
				request_handler request_handler_;
		};


	} // namespace dicomserver
} // namespace http


#endif // SSSERVER_HPP
