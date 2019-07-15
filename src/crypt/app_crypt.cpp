#include <algorithm>
#include <mutex>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "app_crypt.h"
#include "crypto_utils.h"

namespace ignisshin {
namespace crypt {

std::once_flag CryptManager::crypto_init_;

static const int OPENSSL_SUCCESS = 1;

CryptManager::CryptManager(const Key & key)
: key_(key)
{
    // Ensure that OpenSSL library init is only done once
    std::call_once(CryptManager::crypto_init_, EVP_add_cipher, EVP_aes_256_ctr());
}

CryptoBuffer CryptManager::encipherStr(const CryptoString & plaintxt)
{
    CipherContextPtr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    CryptoBuffer ciphertxt;

    // Cipher text size = plain text len + 1 potential extra block
    ciphertxt.resize(plaintxt.size() + BLOCK_SIZE);

    // Generate our initialization vector (IV)
    IV iv;
    auto rc = RAND_bytes(iv.data(), BLOCK_SIZE);
    if (rc != OPENSSL_SUCCESS)
       throw std::runtime_error("Encountered error in OpenSSL::RAND_bytes.");

    // Prepend IV to cipher text
    ciphertxt.insert(ciphertxt.begin(), iv.begin(), iv.end());

    auto ciphertxtptr = &*(ciphertxt.begin() + iv.size());
    auto plaintxtptr = reinterpret_cast<const byte*>(&plaintxt[0]);

    // Prepare the context with our cipher type
    rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_ctr(), nullptr, this->key_.data(), iv.data());
    if (rc != OPENSSL_SUCCESS)
       throw std::runtime_error("Encountered error in OpenSSL::EVP_EncryptInit_ex.");

    // Encipher the first text block
    int firstlen = ciphertxt.size();
    rc = EVP_EncryptUpdate
         (
            ctx.get(),
            ciphertxtptr,
            &firstlen,
            plaintxtptr,
            (int)plaintxt.size()
         );
    if (rc != OPENSSL_SUCCESS)
       throw std::runtime_error("Encountered error in OpenSSL::EVP_EncryptUpdate.");

    // Encipher the remaining text block
    int remainlen = (ciphertxt.size()-iv.size()) - firstlen;
    rc = EVP_EncryptFinal_ex
         (
            ctx.get(),
            ciphertxtptr+firstlen,
            &remainlen
         );
    if (rc != OPENSSL_SUCCESS)
       throw std::runtime_error("Encountered error in OpenSSL::EVP_EncryptFinal_ex.");


    ciphertxt.resize(iv.size()+firstlen+remainlen);
    return ciphertxt;
}

CryptoString CryptManager::decipherStr(const CryptoBuffer & ciphertxt)
{
    CryptoString plaintxt;

    CipherContextPtr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    // First extract our initialization vector (IV)
    IV iv;
    std::copy(ciphertxt.begin(), ciphertxt.begin()+BLOCK_SIZE, iv.begin());

    // Prepare the context with our cipher type
    auto rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_ctr(), nullptr, this->key_.data(), iv.data());
    if (rc != OPENSSL_SUCCESS)
       throw std::runtime_error("Encountered error in OpenSSL::EVP_DecryptInit_ex.");

    plaintxt.resize(ciphertxt.size());

    auto ciphertxtptr = &*(ciphertxt.begin() + iv.size());
    auto plaintxtptr = reinterpret_cast<byte*>(&plaintxt[0]);

    // Decipher the text block
    int mainlen = ciphertxt.size();
    rc = EVP_DecryptUpdate
         (
            ctx.get(),
            plaintxtptr,
            &mainlen,
            ciphertxtptr,
            (int)ciphertxt.size() - BLOCK_SIZE
         );
    if (rc != OPENSSL_SUCCESS)
       throw std::runtime_error("Encountered error in OpenSSL::EVP_DecryptUpdate.");

    // Deicpher the remaining text block
    int remainlen = ciphertxt.size() - (mainlen+iv.size());
    rc = EVP_DecryptFinal_ex
         (
            ctx.get(),
            plaintxtptr+mainlen,
            &remainlen
         );
    if (rc != OPENSSL_SUCCESS)
       throw std::runtime_error("Encountered error in OpenSSL::EVP_DecryptFinal_ex.");

    plaintxt.resize(mainlen+remainlen);
    return plaintxt;

}

}
}

const unsigned char* operator"" _bytes (const char* c, std::size_t s)
{
   return reinterpret_cast<const unsigned char *>(c);
}

