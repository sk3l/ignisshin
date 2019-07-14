#ifndef KEYCACHE_H
#define KEYCACHE_H

class key_cache
{
   private:

   public:
      virtual std::string fetch_keys_from_store(const std::string & location) = 0;
      virtual std::size_t size() const = 0;
};

}
}
#endif
