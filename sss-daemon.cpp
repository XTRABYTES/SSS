/**
 * Filename: sss-daemon.cpp
 *
 * STaTiC simulation server daemon 
 *
 * Copyright (c) 2017-2018 Zoltan Szabo & XtraBYtes developers
 *
 * This file is part of xtrabytes project.
 *
 */


#include <locale.h>
#include <string>
#include <exception>

#include "ssserver.hpp"

static std::string bind_addr = "0.0.0.0";
static unsigned int bind_port = 8080;
static unsigned int n_threads = 10;
static std::string doc_root = ".";


int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "");

	try {
		std::size_t num_threads = boost::lexical_cast<std::size_t>(n_threads);
		http::dicomserver::server s(bind_addr, bind_port, doc_root, num_threads);
		s.run();
	}
	catch (std::exception& e) {
		std::cerr << "exception: " << e.what() << "\n";
	}

	return 0;
}
