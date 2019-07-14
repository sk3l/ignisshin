#ifndef APP_DB_H
#define APP_DB_H

#include <string>
#include <unordered_map>

namespace ignisshin {
namespace db {

struct Login
{
    std::string secret_;
    std::string cipher_key_path_;   // optional path to crypt key
};

enum SessionAuthTypes
{
    UNDEFINED = 0,
    PASSWORD  = 1,
    KEY       = 2
};

// JSON object for SSH session
struct Session
{
    std::string       sess_name_;
    SessionAuthTypes  auth_type_;
    std::string       auth_str_;  
};

using SessionDict = std::unordered_map<std::string,struct Session>;
// Root JSON object for the app DB 
struct Config
{
    struct Login   login_;
    SessionDict    sessions_;
};

/*/////////////////////////////////////////////////////////////////////////////
   config_parser - utility class for deserializing JSON app config

   Callers use this class to read in the application config file from a given
   logcation on the filesystem.

   The file format is expected to be valid JSON, with a structural pattern
   relating to POD (plain ol' data) structs declared above.
*//////////////////////////////////////////////////////////////////////////////
//class config_parser
//{
//   public:
//      static AppDb_config read_from_file(const std::string & path);
//};

}
}

#endif
