#ifndef KEYVALUEDB_HPP
#define KEYVALUEDB_HPP

#include <string>
#include <leveldb/db.h>
#include <leveldb/options.h>
#include <openssl/sha.h>

class KeyValueDB {
private:
    
    leveldb::Options options;
    leveldb::WriteOptions writeOptions;    
    leveldb::DB *kvdb;

public:
    KeyValueDB();
    ~KeyValueDB();
    bool write(std::string &key, std::string &value);
    std::string read(std::string &key );
    std::string getkey(std::string &value );


};

extern KeyValueDB keyvaluedb;

#endif // KEYVALUEDB_HPP
