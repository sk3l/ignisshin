#include <catch/catch.hpp>
#include <unistd.h>
#include <libgen.h>
#include <linux/limits.h>

#include <fstream>
#include <iostream>
#include <string>

#include "private_key.h"
#include "ssh_agent.h"

#include "keymaster_test_utils.h"

using agent_t = BloombergLP::keymaster::ssh_agent;

TEST_CASE("Test ssh_agent ctor()"){

    REQUIRE_NOTHROW(agent_t("testagent", "ftpsystem", "/tmp/testagent.sock"));
}

TEST_CASE("Test ssh_agent get_agent_name()"){

   agent_t a("testagent", "", "/tmp/testagent.sock");
   REQUIRE(a.get_agent_name() == "testagent");
}

TEST_CASE("Test ssh_agent get_account_name()"){

   agent_t a("testagent", "ftpsystem", "/tmp/testagent.sock");
   REQUIRE(a.get_account_name() == "ftpsystem");
}

TEST_CASE("Test ssh_agent get_sock_addr()"){

   agent_t a("testagent", "", "/tmp/testagent.sock");
   REQUIRE(a.get_sock_addr() == "/tmp/testagent.sock");
}

TEST_CASE("Test ssh_agent start_stop"){

    agent_t a("testagent", "", "/tmp/testagent1.sock");

    REQUIRE(a.start(10, 100));

    REQUIRE_NOTHROW(a.stop());
}

TEST_CASE("Test ssh_agent add_key"){

   agent_t a("testagent", "", "/tmp/testagent2.sock");

   // TO DO : would like to mock private_key
   BloombergLP::keymaster::private_key pk(getTestDirFQN() + "/testkey", "test");

   REQUIRE(a.start(10, 100));
   REQUIRE(a.get_pid() != 0);

   REQUIRE_NOTHROW(a.add_key(pk));

   REQUIRE_NOTHROW(a.stop());
}

TEST_CASE("Test ssh_agent write_env()"){

   agent_t a("testagent", "", "/tmp/testagent3.sock");

   // TO DO : would like to mock private_key
   //BloombergLP::keymaster::private_key pk(getTestDirFQN() + "/testkey", "test");

   REQUIRE(a.start(10, 100));
   REQUIRE(a.get_pid() != 0);

   REQUIRE_NOTHROW(a.write_env());

   REQUIRE_NOTHROW(a.stop());
}

TEST_CASE("Test ssh_agent is_running()"){

   agent_t a("testagent", "", "/tmp/testagent3.sock");

   REQUIRE(a.start(10, 100));
   REQUIRE(a.is_listening());

   REQUIRE_NOTHROW(a.stop());
   REQUIRE(!a.is_listening());
}
