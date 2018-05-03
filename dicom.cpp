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

#include <string>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>


namespace dicom {
	
	struct dicomhandler {
	   std::string	method;
	   bool (*actor)(boost::property_tree::ptree &request, boost::property_tree::ptree &reply);
   };

   static bool ping(boost::property_tree::ptree &request, boost::property_tree::ptree &reply) {
	  reply.put("ping", "pong");
     return true;
   }

   static bool echo(boost::property_tree::ptree &request, boost::property_tree::ptree &reply) {
	  reply.put("echo", request.get("params","Missing params!"));
	  return true;
   }


   static const struct dicomhandler dicom_handlers[] = {
		{ "ping", ping },
		{ "echo", echo },
   };

   std::string exec(boost::property_tree::ptree reqpt) {
   	
      boost::property_tree::ptree reppt;           
      reppt.put("dicom", "1.0");
      reppt.put("type", "reply");
    
      std::string method = reqpt.get<std::string>("method","");

	   unsigned int i = 0;
	   bool methodfound = false;
	   for (; i < (sizeof(dicom_handlers)/sizeof((dicom_handlers)[0])); i++) {
		   if (!method.compare(dicom_handlers[i].method)) {
			   methodfound = true;
			   bool rc = dicom_handlers[i].actor(reqpt, reppt);
			   if (!rc)	reppt.put("error", "DICOM call failed.");
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
