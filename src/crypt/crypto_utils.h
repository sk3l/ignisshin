#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <array>
#include <string>
#include <vector>

#include <openssl/evp.h>

/* ~~~ CITATION: ~~~
 *
 * The CryptoAllocator C++ allocator and CrytoString constructs were patterned
 * after examples from below site:
 *
 * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 *
 * The basic principle is to securely dispose (using OPENSSL_cleanse) of
 * allocated string memory after its lifetime ends.
 */

namespace ignisshin {
namespace crypt {

template <typename T>
struct CryptoAllocator
{
public:
    using value_type = T;
    using pointer = value_type* ;
    using const_pointer = const value_type*;
    using reference = value_type&;
    using const_reference = const value_type&;
    using size_type = std::size_t ;
    using difference_type = std::ptrdiff_t;

    pointer address (reference v) const {return &v;}
    const_pointer address (const_reference v) const {return &v;}

    pointer allocate (size_type n, const void* hint = 0) {
        if (n > std::numeric_limits<size_type>::max() / sizeof(T))
            throw std::bad_alloc();
        return static_cast<pointer> (::operator new (n * sizeof (value_type)));
    }

    // HERE
    // Securely wipe the memory during allocation
    void deallocate(pointer p, size_type n) {
        OPENSSL_cleanse(p, n*sizeof(T));
        ::operator delete(p);
    }

    size_type max_size() const {
        return std::numeric_limits<size_type>::max() / sizeof (T);
    }

    template<typename U>
    struct rebind
    {
        typedef CryptoAllocator<U> other;
    };

    void construct (pointer ptr, const T& val) {
        new (static_cast<T*>(ptr) ) T (val);
    }

    void destroy(pointer ptr) {
        static_cast<T*>(ptr)->~T();
    }

    template<typename U, typename... Args>
    void construct (U* ptr, Args&&  ... args) {
        ::new (static_cast<void*> (ptr) ) U (std::forward<Args> (args)...);
    }

    template<typename U>
    void destroy(U* ptr) {
        ptr->~U();
    }
};

using byte = std::uint8_t;
using CryptoString = std::basic_string<char, std::char_traits<char>, CryptoAllocator<char> >;
using CryptoBuffer = std::vector<byte, CryptoAllocator<byte> >;
using CipherContextPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

struct CryptoHash
{
std::size_t operator()(CryptoString const& s) const
{
    std::string hstr(s.c_str());
    return std::hash<std::string>{}(hstr);
}
};

}
}

#endif
