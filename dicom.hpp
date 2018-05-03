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


namespace dicom {

  std::string exec(boost::property_tree::ptree reqpt);
  
}

#endif // DICOM_HPP