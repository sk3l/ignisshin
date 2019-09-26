#ifndef AGENT_MGR_H
#define AGENT_MGR_H

#include <atomic>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include <sys/types.h>

//#include "ssh_agent.h"

namespace sk3l {
namespace ignisshin {

//using agent_t = std::shared_ptr<ssh_agent>;

/*/////////////////////////////////////////////////////////////////////////////
   session_mgr - interface for managing multiple instances of OpenSSH ssh-agent

   This class permits callers to:
      * aggregate multiple ssh-agents, add, remove, lookup by name/PID (TODO)
      * control run state of managed ssh-agent instances
      * apply concurrent actions (timed updates, OS monitoring) to agents
*//////////////////////////////////////////////////////////////////////////////
class session_mgr
{
   private:

      using session_list_t= std::vector<agent_t>;
      using name_map_t  = std::unordered_map<std::string, agent_t>;
      using pid_map_t   = std::unordered_map<pid_t, agent_t>;

      agent_list_t agents_;
        name_map_t agents_by_name_;
         pid_map_t agents_by_pid_;

      std::atomic<bool> stop_flag_;
            std::mutex  lock_;      // Protect access to containers

      void monitor_loop();

   public:

      session_mgr();

      // Non-copyable class
      session_mgr(const session_mgr &) = delete;
      session_mgr & operator=(const session_mgr &) = delete;

      void add_agent(const agent_t & agent);
      void monitor();
      void stop();

      // TO-DO
      // Implement accessor methods for agents, by name/PID
};

}
}

#endif

