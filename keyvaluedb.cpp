#include <stdexcept>
#include <string>
#include <stdio.h>
#include <boost/filesystem.hpp>
#include "keyvaluedb.hpp"

KeyValueDB keyvaluedb;

KeyValueDB::KeyValueDB() {
        
	 boost::filesystem::path kvdatadir("kvdata");
	 boost::filesystem::create_directory(kvdatadir);        
    options.create_if_missing = true;
    leveldb::Status status = leveldb::DB::Open(options, kvdatadir.string(), &kvdb);
    if (!status.ok())
        throw std::runtime_error("KeyValueDB(): error opening key value database environment.");
}

KeyValueDB::~KeyValueDB() {
    delete kvdb;
    kvdb = NULL;
}

bool KeyValueDB::write(std::string &key, std::string &value) {
   kvdb->Put(writeOptions, key, value);
   return true;
}

std::string KeyValueDB::read(std::string &key ) {

 std::string value; 
 leveldb::Status status = kvdb->Get(leveldb::ReadOptions(), key, &value);
 if (!status.ok()) value=""; 
 return value;
}

std::string KeyValueDB::getkey(std::string &value ) {

    const char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    unsigned char digest[SHA256_DIGEST_LENGTH];    
    const char *cstr = value.c_str(); 
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, cstr, strlen(cstr));
    SHA256_Final(digest, &ctx);
 
    std::string s(SHA256_DIGEST_LENGTH*2, ' ');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
      s[2 * i]     = hexmap[(digest[i] & 0xF0) >> 4];
      s[2 * i + 1] = hexmap[digest[i] & 0x0F];
    }
    return s;

}


