#ifndef KEY_PAIR_H
#define KEY_PAIR_H

#include <string>
#include <libssh/libssh.h>

namespace sk3l {
namespace keymaster {

/*/////////////////////////////////////////////////////////////////////////////
   private_key - wrapper class for handling SSH RSA keys

   This class permits callers to:
      * load & validate an SSH key from a file path
      * manipulate metadata attached to  an SSH key (custom name, fingerprint)
*//////////////////////////////////////////////////////////////////////////////
class private_key
{
   private:

      std::string filename_;
      std::string name_;
      std::string key_text_;
          ssh_key key_;

   public:
      private_key();

      private_key
      (
         const std::string & filename,
         const std::string & name = ""
      );

      // Make object "non-copyable", as libssh ssh_key pointer is not copyable
      private_key(const private_key & pk) = delete;
      private_key & operator=(const private_key & pk) = delete;

      std::string get_public_key()  const;
      std::string get_fingerprint() const;
      std::string get_private_key() const {return this->key_text_;}
      std::string get_name()        const {return this->name_;}
      std::string get_filename()    const {return this->filename_;}

      ~private_key();
};

}
}

#endif
