#include <iostream>
#include <mutex>
#include <stdexcept>
#include <sstream>
#include <thread>

#include <spdlog/spdlog.h>
#include <sys/wait.h>

#include "agent_mgr.h"

namespace sk3l {
namespace keymaster {

agent_mgr::agent_mgr()
{}

void agent_mgr::monitor_loop()
{
   std::stringstream logbuf;
   try
   {

      spdlog::debug("Entering agent_mgr::monitor_loop()");

      int state = 0;
      while (!this->stop_flag_.load())
      {
         // Terminate if there are no ssh_agents available to manage
         if (agents_.size() < 1)
            break;

         pid_t pid = waitpid(-1, &state, 0);

         // Received a signal to this (keymaster) process; ignore it.
         if (pid == -1)
         {
            if (errno == EINTR)
            {
               spdlog::debug("waitpid returned EINTR in agent_mgr::monitor_loop");
               continue;
            }
            else if (errno == 10)
            {
               spdlog::info("No agents managed; quiting");
               break;
            }
            else
            {
               std::stringstream().swap(logbuf);
               logbuf << "waitpid returned errno "
                      << errno
                      << " in agent_mgr::monitor_loop";
               spdlog::warn(logbuf.str());
            }
         }

         std::stringstream().swap(logbuf);
         logbuf << "Detected agent termination (pid=" << pid << "), state=" << state;
         spdlog::info(logbuf.str());
         // TO DO : Will need to acquire lock, lookup and re-start the agent
      }
      spdlog::debug("Exiting agent_mgr::monitor_loop()");
   }
   catch (const std::exception & e)
   {
      std::stringstream().swap(logbuf);
      logbuf << "Encountered exception in agent_mgr::monitor_loop(): "
             << e.what();
      spdlog::error(logbuf.str());
   }
}

void agent_mgr::monitor()
{
   spdlog::debug("Entering agent_mgr::monitor");
   // TO DO : add additional threads for :
   //    * timed check in with back-end keystore
   //    * control socket for manual manipulation of the service
   std::thread monitorthread(&agent_mgr::monitor_loop, this);
   monitorthread.join();
}

void agent_mgr::add_agent(const agent_t & agent)
{
   std::lock_guard<std::mutex> guard(this->lock_);

   std::stringstream logbuf;
   logbuf << "Adding agent '"
          << agent->get_agent_name() << "'"
          << "to agent_mgr";
   spdlog::debug(logbuf.str());

   if (this->stop_flag_.load())
      return;

   this->agents_.push_back(agent);
   this->agents_by_name_[agent->get_agent_name()] = agent;
   this->agents_by_pid_[agent->get_pid()] = agent;
}

void agent_mgr::stop()
{
   std::lock_guard<std::mutex> guard(this->lock_);

   spdlog::info("Stopping agent_mgr");

   std::stringstream logbuf;
   this->stop_flag_.store(true);

   for (auto it = this->agents_.begin(); it != agents_.end(); ++it)
   {
      try
      {
         std::stringstream().swap(logbuf);
         logbuf << "Stopping agent '"
                << it->get()->get_agent_name() << "'"
                << "in agent_mgr::stop()";
         spdlog::debug(logbuf.str());

         it->get()->stop();
      }
      catch (const std::exception & e)
      {
         std::stringstream().swap(logbuf);

         logbuf << "Encountered error in agent_mgr::stop : '"
                << e.what()
                << "'";
         spdlog::warn(logbuf.str());
      }
   }
}

}
}
