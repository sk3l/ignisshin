
#include <fstream>
#include <stdexcept>
#include <sstream>

#include <spdlog/spdlog.h>

#include "private_key.h"

namespace sk3l {
namespace keymaster {

private_key::private_key()
: key_(nullptr)
{}

private_key::private_key(const std::string & filename, const std::string & name)
: filename_(filename),
  name_(name)
{
   std::stringstream logbuf;
   logbuf << "Invoking private_key::ctor for file '"
          << filename << "'";
   spdlog::debug(logbuf.str());

   std::ifstream keyfile(filename);
   if (!keyfile.good())
      throw std::invalid_argument("Could not load SSH private key file.");

   std::string line;
   while (keyfile.good())
   {
      std::getline(keyfile, line);
      this->key_text_ += line;
      this->key_text_ += "\n";
   }

   auto rc = ssh_pki_import_privkey_base64(
               this->key_text_.c_str(),
               nullptr,
               nullptr,
               nullptr,
               &this->key_);

   if (rc != SSH_OK)
      throw std::invalid_argument("File contents are not a valid private key.");
}

std::string private_key::get_public_key() const
{
   char * buffer = nullptr;

   std::stringstream logbuf;
   logbuf << "Invoking private_key::get_public_key for file '"
          << this->key_ << "'";
   spdlog::debug(logbuf.str());

   auto rc = ssh_pki_export_pubkey_base64(this->key_, &buffer);
   if (rc != SSH_OK)
   {
      if (buffer != nullptr)
         free(buffer);
      throw std::invalid_argument("Couldn't produce public key of private key file.");
   }

   std::string strpubkey(buffer);
   if (buffer != nullptr)
      free(buffer);
   return strpubkey;
}

std::string private_key::get_fingerprint() const
{
   unsigned char * hash = nullptr;
   size_t size;

   std::stringstream logbuf;
   logbuf << "Invoking private_key::get_fingerprint for file '"
          << this->key_ << "'";
   spdlog::debug(logbuf.str());

   auto rc = ssh_get_publickey_hash(
               this->key_,
               ssh_publickey_hash_type::SSH_PUBLICKEY_HASH_MD5,
               &hash,
               &size);

   if (rc != 0)
   {
      ssh_clean_pubkey_hash(&hash);
      throw std::invalid_argument("Could produce hash of private key file.");
   }

   std::string strhash(ssh_get_hexa(hash, size));
   ssh_clean_pubkey_hash(&hash);
   return strhash;
}

private_key::~private_key()
{
   if (this->key_ != nullptr)
      ssh_key_free(this->key_);
}

}
}
