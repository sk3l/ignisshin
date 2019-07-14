
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <stdexcept>
#include <spdlog/spdlog.h>
#include <jsoncpp/json/json.h>

#include "app_config.h"

namespace sk3l {
namespace ignisshin {

app_config config_parser::read_from_file(const std::string & path)
{
   app_config kmconfig;

   std::ifstream cfgfile(path);
   if (!cfgfile.good())
   {
      std::stringstream ss;
      ss << "Could not read config file at '"
         << path
         << "'"
         << std::endl;
      throw std::invalid_argument(ss.str());
   }

   Json::Value root;
   cfgfile >> root;

   Json::Value service = root["service"];
   if (service.isNull())
      throw std::runtime_error("Missing or invalid service entry in config file.");

   Json::Value log = service["log"];
   if (!log.isNull())
   {
      Json::Value location = log["location"];
      if (!location.isNull())
         kmconfig.service_.log_.log_file_name_ = location.asString();

      Json::Value verbosity = log["verbosity"];
      if (verbosity.isNull() || !verbosity.isString())
      {
         kmconfig.service_.log_.verbosity_ = log_verbosity::ERROR;
      }
      else
      {
         // Take lower case of config log verbosity and map it to enum
         std::string verbstr = verbosity.asString();
         std::transform(
            verbstr.begin(),
            verbstr.end(),
            verbstr.begin(),
            [](unsigned char c) -> unsigned char {return std::tolower(c);});

         //if (slog::get_log_verbosity(kmconfig.service_.log_.verbosity_, verbstr)) {
         //   throw std::runtime_error("Not a valid verbosity level.");
         //}
      }
   }

   Json::Value agents = root["agents"];
   if (agents.isNull() || !agents.isArray())
      throw std::runtime_error("Missing or invalid agent list in config file.");

   for (auto it = agents.begin(); it != agents.end(); ++it)
   {
      agent_config ac;

      // Agent name - mandatory field
      Json::Value agent_name = (*it)["agent_name"];
      if (agent_name.isNull())
      {
         std::cerr << "Invalid agent config (missing 'name' key)" << std::endl;
         continue;
      }
      ac.agent_name_ = agent_name.asString();

      // Agent key path - mandatory field
      Json::Value key_path = (*it)["key_path"];
      if (key_path.isNull() || !key_path.isString())
      {
         std::cerr << "Invalid agent config (missing 'key_path' key)" << std::endl;
         continue;
      }
      ac.key_path_ = key_path.asString();

      // Agent account name - optional field
      Json::Value acct_name = (*it)["account_name"];
      if (!acct_name.isNull())
      {
         ac.account_name_ = acct_name.asString();
      }

      // Agent socket address - optional field
      Json::Value sock_addr = (*it)["socket_address"];
      if (!sock_addr.isNull())
      {
         ac.socket_addr_ = sock_addr.asString();
      }

      kmconfig.agents_.push_back(ac);
   }

   return kmconfig;
}

}
}
