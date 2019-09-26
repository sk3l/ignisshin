#ifndef SSH_AGENT_H
#define SSH_AGENT_H

#include <string>
#include <unistd.h>
#include <libssh/libssh.h>

namespace sk3l {
namespace ignisshin {

class private_key;

/*/////////////////////////////////////////////////////////////////////////////
   ssh_session - encapsulate client interaction with an OpenSSH daemon 

   This class permits callers to:
      * tag metadata associated with an instance of ssh-agent
      * manage the run state of an instance of ssh-agent
      * add/remove SSH keys to ssh-agent
      * expose ssh-agent state enabling POSIX accounts auth using the ssh-agent
*//////////////////////////////////////////////////////////////////////////////
class ssh_session
{
   private:

       // The session pointer from LibSSH
       ::ssh_session session_;

       std::string session_name_; 

   public:
      ssh_session(const std::string name);
      
      std::string get_name() const  {return this->session_name_;}

      // Connect the session, optionally retrying & waiting
      bool connect(uint32_t tries = 1, uint32_t ms_wait = 0);
      
      // Tear down the agent
      void disconnect();

      // Check session health (its domain socket)
      bool is_connected();

      ~ssh_session();
};

}
}

#endif
