//#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
//#define CATCH_CONFIG_RUNNER
//#undef CATCH_CONFIG_POSIX_SIGNALS
//#include <catch/catch.hpp>

//#include <signal.h>
//#include <sys/types.h>
//#include <unistd.h>

#include "crypto_utils.h"
#include "app_crypt.h"

int main(int argc, char ** argv)
{
    auto bp = "Test byte ptr"_bytes;

    ignisshin::crypt::CryptManager::Key k = {"abcdefghijklmnoprstuvwxyz012345"};
    ignisshin::crypt::CryptManager cm(k);

    ignisshin::crypt::CryptoString ptxt("The digital projection of your mental self.");

    auto etxt = cm.encipherStr(ptxt);
    auto dtxt = cm.decipherStr(etxt);

    return 0;
}
