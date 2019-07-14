#ifndef APP_CONFIG_H
#define APP_CONFIG_H

#include <string>
#include <vector>

namespace sk3l {
namespace ignisshin {

enum log_verbosity
{
    ERROR = 0,
    WARN  = 1,
    INFO  = 2,
    DEBUG = 3,
    TRACE = 4
};

enum log_sinks
{
    NONE        = 0,
    TO_CONSOLE  = 1,
    TO_FILE     = 2
};

// Represent logging behavior of the application
struct log_config
{
   log_sinks sinks_;
   std::string log_file_name_; 
   log_verbosity verbosity_;
};

// Represent global config governing application behavior, e.g. logging
struct service_config
{
    log_config log_;
};

// Represent a collection of ssh-agent configuration parameters
struct agent_config
{
   std::string agent_name_;   // Agent name, "handle" for lookup
   std::string key_path_;     // Filesystem path where agent's keys live
   std::string account_name_; // POSIX account name agent runs as (optional)
   std::string socket_addr_;  // Unix domain sockete taken by agent (optional)
};

using agent_config_list = std::vector<agent_config>;

// Root JSON object for the app config file
struct app_config
{
   service_config    service_;
   agent_config_list agents_;
};

/*/////////////////////////////////////////////////////////////////////////////
   config_parser - utility class for deserializing JSON app config

   Callers use this class to read in the application config file from a given
   logcation on the filesystem.

   The file format is expected to be valid JSON, with a structural pattern
   relating to POD (plain ol' data) structs declared above.
*//////////////////////////////////////////////////////////////////////////////
class config_parser
{
   public:
      static app_config read_from_file(const std::string & path);
};

}
}

#endif
