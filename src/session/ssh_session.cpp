#include <fcntl.h>
#include <pwd.h>
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <stdexcept>

#include <spdlog/spdlog.h>

#include "ssh_agent.h"
#include "private_key.h"

namespace sk3l {
namespace keymaster {

std::string ssh_agent::generate_socket_addr()
{
   // Seed rand generator
   auto now = std::chrono::system_clock::now().time_since_epoch();
   auto secs = std::chrono::duration_cast<std::chrono::seconds>(now);

   std::srand(secs.count());

   // Generate 12 random printable bytes, like the nameing convention used by
   // ssh-agent for socket addr, e.g. /tmp/ssh-a3gEc29OfvqP
   std::string rnd;
   size_t cnt = 0;
   while (cnt < 12)
   {
      uint8_t c = std::rand() % UINT8_MAX;
      if (!std::isalnum(c))
        continue;

      rnd.push_back(c);
      ++cnt;
   }


   return std::string("/tmp/keymaster_") + rnd + ".sock";
}

ssh_agent::ssh_agent
(
   const std::string & name,
   const std::string & acct_name,// = "",
   const std::string & sockaddr// = ""
)
: agent_name_(name),
  account_name_(acct_name),
  ud_sock_addr_(sockaddr.empty() ? generate_socket_addr() : sockaddr),
  agent_pid_(0)
{}

bool ssh_agent::start(uint32_t tries, uint32_t ms_wait)
{
   std::stringstream logbuf;

   logbuf << "Invoking ssh_agent::start() for agent '" << this->get_agent_name()
          << "', tries=" << tries
          << ", ms_wait=" << ms_wait;
   spdlog::debug(logbuf.str());

   // Agent has already been started
   if (this->agent_pid_ != 0)
   {
      std::stringstream().swap(logbuf);
      logbuf << "Agent '" << this->get_agent_name() << "' "
             << "already running; skipping ssh_agent::start";
      spdlog::debug(logbuf.str());
      return true;
   }

   bool active = false;

   std::string agentacct = this->get_account_name();

   pid_t p = fork();

   if (p == 0)
   {
      int rc = -1;
      if (!agentacct.empty())
      {
         // Change process effective UID to "run as" account.
         // Need to ascertain "run as" account's UID
         struct passwd * acctpwd = getpwnam(agentacct.c_str());
         if (acctpwd != NULL)
            rc = setuid(acctpwd->pw_uid);
         else
         {
            std::stringstream().swap(logbuf);
            logbuf << "Unable to locate system account '"
                   << agentacct << "';"
                   << " aborting agent start.";
            spdlog::error(logbuf.str());

            exit(EXIT_FAILURE);
         }

         if (rc != 0)
         {
            std::stringstream().swap(logbuf);
            logbuf << "Unable to setuid to system account '"
                   << agentacct << "' (was keymaster run as superuser?); "
                   << "Aborting agent start.";
             spdlog::error(logbuf.str());

             exit(EXIT_FAILURE);
         }
      }

      // Redirect ssh-agent STDOUT to bit bucket
      int nullfd = open("/dev/null", O_WRONLY|O_CREAT, 0666);

      if (nullfd == -1)
      {
         std::stringstream().swap(logbuf);
         logbuf << "Unable to open '/dev/null' file descriptor for "
                << "ssh-agent output redirection.";
         spdlog::error(logbuf.str());

      }
      else
      {
         dup2(nullfd, 1);
      }

      spdlog::debug("Preparing to invoke ssh-agent");

      // TO DO: paramterize location of ssh-agent
      rc = execlp(
              "/usr/bin/ssh-agent",
              "ssh-agent",
              "-a",
              this->ud_sock_addr_.c_str(),
              "-D",
              NULL);

      close(nullfd);
      if (rc != 0)
      {
         std::stringstream().swap(logbuf);
         logbuf << "Unable to execute ssh-agent '"
                << agentacct << "' (is it installed & in PATH?)"
                << "Aborting agent start.";
         spdlog::error(logbuf.str());

         exit(EXIT_FAILURE);
      }

   }

   std::stringstream().swap(logbuf);
   logbuf << "Confirming ssh-agent for '"
          << agentacct << "' is listening.";
   spdlog::debug(logbuf.str());

   // Wait for the agent to become active
   for (uint32_t i = 0; i < tries; ++i)
   {
       if (this->is_listening())
       {
          this->agent_pid_ = p;
          active = true;
          break;
       }

      if (ms_wait > 0)
      {
         struct timespec slp;
         slp.tv_sec = 0;
         slp.tv_nsec = ms_wait * 1000000;
         nanosleep(&slp, NULL);
      }
   }

   std::stringstream().swap(logbuf);
   logbuf << "ssh-agent for '"
          << agentacct << "' is ";

   if (active)
      logbuf << "active";
   else
      logbuf << "inactive";
   spdlog::debug(logbuf.str());

   return active;
}

void ssh_agent::restart()
{
   // TO DO
}

void ssh_agent::stop()
{
   std::stringstream logbuf;

   logbuf << "Calling ssh_agent::stop() for agent '"
          << this->get_agent_name() << "'";
   spdlog::debug(logbuf.str());

   if (this->agent_pid_ == 0)
      return;

   auto rc = ::kill(this->agent_pid_, SIGTERM);
   if (rc != 0)
   {
      std::stringstream msg("Could not stop agent process");
      msg << ", PID=" << this->agent_pid_;
      throw std::runtime_error(msg.str());
   }

   std::stringstream().swap(logbuf);
   logbuf << "Successfully called ssh_agent::stop() for agent '"
          << this->get_agent_name() << "'";
   spdlog::debug(logbuf.str());

   this->agent_pid_ = 0;
}

bool ssh_agent::is_listening()
{
   std::stringstream logbuf;
   logbuf << "Calling ssh_agent::is_listening() for agent '"
          << this->get_agent_name() << "'";
   spdlog::debug(logbuf.str());

   std::stringstream cmd;
   if (!this->get_account_name().empty())
      cmd << "sudo -u " << this->get_account_name() << " ";

   // TO DO: paramterize location of ssh-add
   cmd << "SSH_AUTH_SOCK=" << this->ud_sock_addr_
       << " /usr/bin/ssh-add -L > /dev/null 2>&1";

   auto rc = system(cmd.str().c_str());
   if (rc == -1)
      throw std::runtime_error("Could not start ssh-add.");

   // Note : ssh-add return 0 if agent has identities, 1 if agent has none
   return (rc == 0 || rc == 256);
}

bool ssh_agent::add_key(const private_key & pk)
{
   std::stringstream logbuf;
   logbuf << "Calling ssh_agent::add_key() for agent '"
          << this->get_agent_name() << "'";
   spdlog::debug(logbuf.str());

   pid_t p = fork();
   if (p == 0)
   {
       int nullfd;
       // Redirect ssh-agent STDERR to bit bucket
       // It seems ssh-add writes status output to STDERR for some reason
      nullfd = open("/dev/null", O_WRONLY|O_CREAT, 0666);

      if (nullfd == -1)
      {
         std::stringstream().swap(logbuf);
         logbuf << "Unable to open '/dev/null' file descriptor for "
                << "ssh-agent output redirection.";
         spdlog::error(logbuf.str());
      }
      else
         dup2(nullfd, 2);

      std::stringstream cmd;
      cmd << "SSH_AUTH_SOCK=" << this->get_sock_addr()
          << " /usr/bin/ssh-add - <<< "
          << "\"" << pk.get_private_key() << "\"";

      // TO DO: paramterize location of ssh-agent
      int rc = execlp(
                  "/bin/sh",
                  "sh",
                  "-c",
                  cmd.str().c_str(),
                  NULL);

      close(nullfd);
      if (rc != 0)
      {
         std::stringstream().swap(logbuf);
         logbuf << "Unable to execute ssh-add "
                << "(is it installed & in PATH?)"
                << "Aborting add key.";
         spdlog::error(logbuf.str());

         exit(EXIT_FAILURE);
      }
   }

   int state = 0;
   pid_t pid = waitpid(p, &state, 0);

   return (pid > 0) && WIFEXITED(state);

}

bool ssh_agent::del_key(const private_key & pk)
{
   return true;
   // TO DO
}

bool ssh_agent::clear_keys()
{
   std::stringstream logbuf;
   logbuf << "Calling ssh_agent::clear_keys() for agent '"
          << this->get_agent_name() << "'";
   spdlog::debug(logbuf.str());

   // TO DO: paramterize location of ssh-add
   std::stringstream cmd;
   cmd << "SSH_AUTH_SOCK=" << this->ud_sock_addr_
       << " /usr/bin/ssh-add -D";

   char * pipestream = nullptr;
   FILE * outpipe = popen(cmd.str().c_str(), "r");
   if (outpipe == nullptr)
      throw std::runtime_error("Could not start ssh-add.");

   std::string strpipe;
   size_t pipelen;
   while (getline(&pipestream, &pipelen, outpipe) != -1)
      strpipe += pipestream;
   free(pipestream);
   pclose(outpipe);

   return true;
}


void ssh_agent::write_env() const
{
   std::stringstream logbuf;
   logbuf << "Calling ssh_agent::write_env() for agent '"
          << this->get_agent_name() << "'";
   spdlog::debug(logbuf.str());

   std::stringstream envpath;
   if (!this->get_account_name().empty())
      envpath << "/home/" << this->get_account_name();
   else
      envpath << ".";

   envpath << "/.keywallet_" << this->agent_name_;

   std::ofstream envfile(envpath.str(), std::ios_base::out | std::ios_base::trunc);
   if (!envfile.good())
      throw std::runtime_error("Could not write agent environment file.");

   envfile << "export SSH_AUTH_SOCK=" << this->ud_sock_addr_ << std::endl;
}

ssh_agent::~ssh_agent()
{
   //this->stop();
}

}
}
