#include <catch/catch.hpp>
#include <fstream>
#include <stdexcept>

#include <libgen.h>
#include <linux/limits.h>
#include <unistd.h>

#include "private_key.h"

#include "keymaster_test_utils.h"

using privkey_t = BloombergLP::keymaster::private_key;

TEST_CASE("Test private_key ctor()"){

    REQUIRE_NOTHROW(privkey_t(getTestDirFQN() + "/testkey", "test"));
}

TEST_CASE("Test private_key get_public_key()"){

    privkey_t pk(getTestDirFQN() + "/testkey", "test");

    std::string pubkey = getFile(getTestDirFQN() + "/testkey.pub");

    REQUIRE(!pubkey.empty());

    // Need to discard public key file's type prefix and comment
    auto start = pubkey.find(" ") + 1;
    auto end   = pubkey.rfind(" ");
    pubkey = pubkey.substr(start, end-start);

    REQUIRE(pk.get_public_key() == pubkey);
}

TEST_CASE("Test private_key get_fingerprint()"){

    std::string keypath = getTestDirFQN();
    privkey_t pk(keypath + "/testkey", "test");

    // Generate MD5 fingerprint of test pubkey file
    std::string cmd("ssh-keygen -l -E md5 -f");
    cmd += keypath + "/testkey.pub";
    char * pipestream = nullptr;
    FILE * outpipe = popen(cmd.c_str(), "r");

    std::string fingerprint;
    size_t pipesize;
    while (getline(&pipestream, &pipesize, outpipe) != -1)
        fingerprint += pipestream;
    free(pipestream);
    pclose(outpipe);

    // Need to discard fingerprint metadata
    auto start = fingerprint.find(":") + 1;
    auto end   = fingerprint.rfind(":") + 3;
    fingerprint = fingerprint.substr(start, end-start);

    REQUIRE(pk.get_fingerprint() == fingerprint);

}

TEST_CASE("Test private_key get_private_key()"){

    privkey_t pk(getTestDirFQN() + "/testkey", "test");

    std::string privkey = getFile(getTestDirFQN() + "/testkey");

    REQUIRE(!privkey.empty());

    REQUIRE(pk.get_private_key() == privkey);
}

TEST_CASE("Test private_key get_name()"){

    privkey_t pk(getTestDirFQN() + "/testkey", "test");

    REQUIRE(pk.get_name() == "test");
}

TEST_CASE("Test private_key get_filename()"){

    std::string fname = getTestDirFQN() + "/testkey";
    privkey_t pk(fname, "test");

    REQUIRE(pk.get_filename() == fname);
}
