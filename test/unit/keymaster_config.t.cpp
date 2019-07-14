#include <catch/catch.hpp>
#include <unistd.h>
#include <libgen.h>
#include <linux/limits.h>

#include <fstream>
#include <future>
#include <memory>
#include <string>

#include "keymaster_config.h"
#include "keymaster_test_utils.h"

using cfgparser_t = BloombergLP::keymaster::config_parser;
using kmconfig_t  = BloombergLP::keymaster::keymaster_config;
using agentclst_t = BloombergLP::keymaster::agent_config_list;

TEST_CASE("Test keymaster_config read_from_file"){

    std::unique_ptr<kmconfig_t> kmcfg;
    REQUIRE_NOTHROW(kmcfg.reset(new kmconfig_t(cfgparser_t::read_from_file(getTestDirFQN() + "/kmconfig.json"))));

    REQUIRE(kmcfg->agents_.size() > 0);
}

TEST_CASE("Test keymaster_config read_from_file2"){

    std::unique_ptr<kmconfig_t> kmcfg;
    REQUIRE_NOTHROW(kmcfg.reset(new kmconfig_t(cfgparser_t::read_from_file(getTestDirFQN() + "/kmconfig.json"))));

    REQUIRE(kmcfg->agents_.size() > 0);
    REQUIRE(kmcfg->agents_.at(0).agent_name_ == "phoenix");
}

TEST_CASE("Test keymaster_config read_from_file3"){

    std::unique_ptr<kmconfig_t> kmcfg;
    REQUIRE_NOTHROW(kmcfg.reset(new kmconfig_t(cfgparser_t::read_from_file(getTestDirFQN() + "/kmconfig.json"))));

    REQUIRE(kmcfg->agents_.size() > 0);
    REQUIRE(kmcfg->agents_.at(0).key_path_ == "/home/mskelton8/Code/bb/sftp-proxy-core/keymaster/test/keys");
}

TEST_CASE("Test keymaster_config read_from_file4"){

    std::unique_ptr<kmconfig_t> kmcfg;
    REQUIRE_NOTHROW(kmcfg.reset(new kmconfig_t(cfgparser_t::read_from_file(getTestDirFQN() + "/kmconfig.json"))));

    REQUIRE(kmcfg->agents_.size() > 0);
    REQUIRE(kmcfg->agents_.at(0).account_name_ == "ftpsystem");
}

TEST_CASE("Test keymaster_config read_from_file5"){

    std::unique_ptr<kmconfig_t> kmcfg;
    REQUIRE_NOTHROW(kmcfg.reset(new kmconfig_t(cfgparser_t::read_from_file(getTestDirFQN() + "/kmconfig.json"))));

    REQUIRE(kmcfg->agents_.size() > 0);
    REQUIRE(kmcfg->agents_.at(0).socket_addr_ == "/tmp/keymaster_phoenix.sock");
}
