#include <catch/catch.hpp>
#include <unistd.h>
#include <libgen.h>
#include <linux/limits.h>

#include <fstream>
#include <future>
#include <memory>
#include <string>

#include "private_key.h"
#include "ssh_agent.h"
#include "agent_mgr.h"

#include "keymaster_test_utils.h"

using privkey_t = BloombergLP::keymaster::private_key;
using agent_t = BloombergLP::keymaster::ssh_agent;
using amgr_t = BloombergLP::keymaster::agent_mgr;

TEST_CASE("Test agent_mgr add_agent()"){

    std::shared_ptr<agent_t> a = std::make_shared<agent_t>("testagent", "", "/tmp/testagent1.sock");

    amgr_t mgr;
    REQUIRE_NOTHROW(mgr.add_agent(a));
}

TEST_CASE("Test agent_mgr monitor_stop"){

    std::shared_ptr<agent_t> a = std::make_shared<agent_t>("testagent", "", "/tmp/testagent1.sock");

    amgr_t mgr;
    REQUIRE_NOTHROW(mgr.add_agent(a));

    a->start(10, 100);
    // Launch agent_mgr::monitor asynchronously, then kill the managed agent
    // wait for monitor to end.
    auto mgrfuture =  std::async(std::launch::async, &amgr_t::monitor, &mgr);

    // Seem to need to wait some amount of time to kill process, so wait like 200ms
    struct timespec slp;
    slp.tv_sec = 0;
    slp.tv_nsec = 200000000;
    nanosleep(&slp, NULL);

    REQUIRE_NOTHROW(a->stop());
    mgrfuture.wait();
}

