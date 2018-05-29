/**
 * Filename: base64.hpp
 *
 * Copyright (c) 2017-2018 Zoltan Szabo & XtraBYtes developers
 *
 * This file is part of xtrabytes project.
 *
 */

#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>

#ifndef BASE64_HPP
#define BASE64_HPP

std::string decode64(const std::string &val);
std::string encode64(const std::string &val);

#endif 
