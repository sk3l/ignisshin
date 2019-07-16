#ifndef APP_DB_H
#define APP_DB_H

#include <string>
#include <unordered_map>

#include "crypto_utils.h"

namespace ignisshin {
namespace db {

struct Auth 
{
    crypt::CryptoString secret_;
};

enum SshAuthTypes
{
    UNDEFINED = 0,
    PASSWORD  = 1,
    KEY       = 2
};

// JSON object for SSH session
struct SshSession
{
    crypt::CryptoString sess_name_;
    SshAuthTypes        auth_type_;
    crypt::CryptoString auth_str_;  
    // TO DO - SSH connection metadata
};

using SessionDict = std::unordered_map<crypt::CryptoString, struct SshSession,
      crypt::CryptoHash >;

// Root JSON object for the app DB 
struct IgnisshinDb 
{
    struct Auth auth_;
    SessionDict sessions_;
};

/*/////////////////////////////////////////////////////////////////////////////
   Serializer - utility class for deserializing JSON app config

   Callers use this class to read in the application config file from a given
   logcation on the filesystem.

   The file format is expected to be valid JSON, with a structural pattern
   relating to POD (plain ol' data) structs declared above.
////////////////////////////////////////////////////////////////////////////*/
class Serializer 
{
   public:
      static struct IgnisshinDb deserialize(const std::string & str);
      static void               serialize(const struct IgnisshinDb & db);
};

}
}

#endif
