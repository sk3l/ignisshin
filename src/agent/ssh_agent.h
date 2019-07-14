#ifndef SSH_AGENT_H
#define SSH_AGENT_H

#include <string>
#include <unistd.h>

namespace sk3l {
namespace keymaster {

class private_key;

/*/////////////////////////////////////////////////////////////////////////////
   ssh_agent - encapsulate interaction with an instance of OpenSSH ssh-agent

   This class permits callers to:
      * tag metadata associated with an instance of ssh-agent
      * manage the run state of an instance of ssh-agent
      * add/remove SSH keys to ssh-agent
      * expose ssh-agent state enabling POSIX accounts auth using the ssh-agent
*//////////////////////////////////////////////////////////////////////////////
class ssh_agent
{
   private:

      // Name by which subsystem proc looks up the agent config.
      // This will match the SFTP service host.
      std::string agent_name_;
      // POSIX account name to run agent process under
      std::string account_name_;
      // Path to the agent's Unix domain socket
      std::string ud_sock_addr_;
      // PID assigned to the ssh-agent process
      pid_t agent_pid_;

      std::string generate_socket_addr();

   public:
      ssh_agent
      (
         const std::string & name,
         const std::string & acct_name = "",
         const std::string & sockaddr= ""
      );

      std::string get_agent_name() const     {return this->agent_name_;}
      std::string get_account_name() const   {return this->account_name_;}
      std::string get_sock_addr() const      {return this->ud_sock_addr_;}
      pid_t get_pid() const                  {return this->agent_pid_;}

      // Set up the agent, optionally waiting
      bool start(uint32_t tries = 1, uint32_t ms_wait = 0);
      // Recover from issue w/ ssh-agent
      void restart();
      // Tear down the agent
      void stop();
      // Check agent health (its domain socket)
      bool is_listening();

      bool add_key(const private_key & pk);
      bool del_key(const private_key & pk);
      bool clear_keys();

      // Write agent config environment file for use by subsystem proc
      void write_env() const;

      ~ssh_agent();
};

}
}

#endif
