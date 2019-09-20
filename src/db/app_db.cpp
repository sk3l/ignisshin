
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <stdexcept>
#include <spdlog/spdlog.h>
#include <jsoncpp/json/json.h>

#include "app_db.h"
#include "app_config.h"
namespace ignisshin {
namespace db {

static const char * SSH_AUTH_TYPE_STR [] =
{
    "password",
    "key"
};

static enum SshAuthTypes str_to_ssh_auth_type(const std::string & s)
{
    for (int atype  = SshAuthTypes::PASSWORD;
         atype <= SshAuthTypes::KEY;
         atype = atype + 1)
    {
        if (s == SSH_AUTH_TYPE_STR[atype])
            return (enum SshAuthTypes) atype;
    }

    return SshAuthTypes::UNDEFINED;
}

static std::string ssh_auth_type_to_str(enum SshAuthTypes atype)
{
    if (atype < SshAuthTypes::PASSWORD || atype > SshAuthTypes::KEY)
        throw std::range_error("Ivalid SshAuthType passed to ssh_auth_type_to_str");
    return SSH_AUTH_TYPE_STR[atype];
}

struct IgnisshinDb Serializer::deserialize(const std::string & str)
{
    struct IgnisshinDb db;

    Json::Reader reader;
    Json::Value root;

    // Convert our string to a JSON document
    if (!reader.parse(str, root))
        throw std::runtime_error("Could not deserialize IgnisshinDb as JSON");

    // Look up the login secret
    Json::Value config = root["config"];
    if (config.isNull() || !config.isObject())
      throw std::runtime_error("Missing or invalid 'config' section in IgnisshinDb.");

    Json::Value login = config["login"];
    if (login.isNull() || !login.isObject())
      throw std::runtime_error("Missing or invalid 'config.login' section in IgnisshinDb.");
    if (!login.isMember("secret"))
      throw std::runtime_error("Missing or invalid 'config.login.secret' section in IgnisshinDb.");

    db.auth_.secret_.assign(login["secret"].asCString());

    // Look up the SSH sessions
    Json::Value sessions = root["sessions"];
    if (sessions.isNull() || !sessions.isArray())
      throw std::runtime_error("Missing or invalid sessions list in IgnisshinDb.");

    for (auto it = sessions.begin(); it != sessions.end(); ++it)
    {
       struct SshSession session;

       // Session name - mandatory field
       Json::Value session_name = (*it)["name"];
       if (session_name.isNull())
       {
          throw std::runtime_error("Invalid IgnisshinDb document (missing 'name' key)");
       }
       session.sess_name_.assign(session_name.asCString());

       // Session auth type - mandatory field
       Json::Value auth_type = (*it)["auth_type"];
       if (auth_type .isNull() || !auth_type.isString())
       {
          throw std::runtime_error("Invalid IgnisshinDb document (missing 'auth_type' key)");
       }
       session.auth_type_ = str_to_ssh_auth_type(auth_type.asString());

       // Session auth credential - mandatory field
       Json::Value auth_cred = (*it)["credential"];
       if (auth_cred.isNull() || !auth_cred.isString())
       {
          throw std::runtime_error("Invalid IgnisshinDb document (missing 'auth_cred' key)");
       }
       session.auth_str_.assign(auth_cred.asCString());

       db.sessions_[session.sess_name_] = session;
    }

    return db;
}

std::string Serializer::serialize(const struct IgnisshinDb & db)
{
    Json::Value root;

    // Serialze the login secret
    Json::Value config;
    Json::Value login;

    login["secret"] = db.auth_.secret_.c_str();
    config["login"] = login;
    root["config"] = config;

    // Serialze the SSH sessions
    Json::Value sessions;
    for (auto it = db.sessions_.begin(); it != db.sessions_.end(); ++it)
    {
        Json::Value session;

        session["name"] = it->second.sess_name_.c_str();
        session["auth_type"] = ssh_auth_type_to_str(it->second.auth_type_);
        session["credential"] = it->second.auth_str_.c_str();

        sessions.append(session);
    }
    root["sessions"] = sessions;

    Json::FastWriter writer;
    return writer.write(root);
}

}
}
