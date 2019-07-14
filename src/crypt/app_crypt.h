#ifndef APP_CRYPT_H
#define APP_CRYPT_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <stdexcept>

#include "crypto_utils.h"

namespace ignisshin {
namespace crypt {

class CryptManager 
{
   public:
       static const std::uint32_t KEY_SIZE = 32;
       static const std::uint32_t BLOCK_SIZE = 16;

       using Key = std::array<ignisshin::crypt::byte, KEY_SIZE>;
       using IV = std::array<ignisshin::crypt::byte, BLOCK_SIZE>;
   private:
       static std::once_flag crypto_init_;

       Key key_;

   public:

       CryptManager(const Key & key);

       CryptManager(const CryptManager &) = delete;
       CryptManager & operator= (const CryptManager &) = delete;

       CryptoString encipherStr(const CryptoString & plaintxt);
       CryptoString decipherStr(const CryptoString & ciphtertxt);
};

}
}

const unsigned char* operator"" _bytes (const char* c, std::size_t s);

#endif
