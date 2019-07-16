//#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
//#define CATCH_CONFIG_RUNNER
//#undef CATCH_CONFIG_POSIX_SIGNALS
//#include <catch/catch.hpp>

#include <iostream>
#include <limits>
#include <random>
//#include <signal.h>
//#include <sys/types.h>
//#include <unistd.h>
#include <gtest/gtest.h>

#include "crypto_utils.h"
#include "app_crypt.h"

std::random_device rnd;

TEST(CryptTests, testDecrypt)
{
    ignisshin::crypt::CryptManager::Key k = {"abcdefghijklmnoprstuvwxyz012345"};
    ignisshin::crypt::CryptManager cm(k);

    ignisshin::crypt::CryptoString ptxt("The digital projection of your mental self.");

    auto etxt = cm.encipherStr(ptxt);
    auto dtxt = cm.decipherStr(etxt);

    ASSERT_STREQ(ptxt.c_str(), dtxt.c_str());
}

TEST(CryptTests, testLargeDecrypt)
{
    ignisshin::crypt::CryptManager::Key k = {"abcdefghijklmnoprstuvwxyz012345"};
    ignisshin::crypt::CryptManager cm(k);

    ignisshin::crypt::CryptoString ptxt;
    auto max = (2<<20); // 2Mb string
    ptxt.resize(max);

    std::uniform_int_distribution<> dis(1, std::numeric_limits<char>::max());

    for (auto it = ptxt.begin(); it != ptxt.end(); ++it)
        *it = dis(rnd);

    auto etxt = cm.encipherStr(ptxt);
    auto dtxt = cm.decipherStr(etxt);

    ASSERT_STREQ(ptxt.c_str(), dtxt.c_str());
}

TEST(CryptTests, testRandDecrypt)
{
    ignisshin::crypt::CryptManager::Key k = {"abcdefghijklmnoprstuvwxyz012345"};
    ignisshin::crypt::CryptManager cm(k);

    ignisshin::crypt::CryptoString ptxt;
    auto max = (2<<20); // 2Mb string
    ptxt.resize(max);

    std::uniform_int_distribution<> lendis(1, 1 << 10); // rand len <= 1Kb
    std::uniform_int_distribution<> chardis(1, std::numeric_limits<char>::max()); //rand char

    for (int i = 0; i < 10; ++i)
    {
        auto len = lendis(rnd);
        ptxt.resize(len);
        for (auto it = ptxt.begin(); it != ptxt.end(); ++it)
            *it = chardis(rnd);

        auto etxt = cm.encipherStr(ptxt);
        auto dtxt = cm.decipherStr(etxt);

        ASSERT_STREQ(ptxt.c_str(), dtxt.c_str());
    }

}

int main(int argc, char ** argv)
{
    std::cout << std::endl << ">>> Initializaing Google Test framework <<<" << std::endl;

    ::testing::InitGoogleTest(&argc, argv);

    std::cout << std::endl << "*** Beginning ignisshin tests ***" << std::endl;
    auto testResults = RUN_ALL_TESTS();

    std::cout << std::endl << ">>> ignisshin test completed  <<<" << std::endl;
    return testResults;
}
