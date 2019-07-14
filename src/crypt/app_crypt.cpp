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

CryptoString CryptManager::encipherStr(const CryptoString & plaintxt)
{
    CryptoString ciphertxt;

    CipherContextPtr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    // First generate our initialization vector (IV)
    IV iv;
    auto rc = RAND_bytes(iv.data(), BLOCK_SIZE); 
    if (rc != OPENSSL_SUCCESS)
       throw std::runtime_error("Encountered error in OpenSSL::RAND_bytes."); 

    // Prepare the context with our cipher type
    rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_ctr(), nullptr, this->key_.data(), iv.data());
    if (rc != OPENSSL_SUCCESS)
       throw std::runtime_error("Encountered error in OpenSSL::EVP_EncryptInit_ex."); 

    // The IV is inserted ahead of the ciphertxt 
    ciphertxt.append(iv.data(), iv.size());

    // Enciphered txt expands up to BLOCK_SIZE
    ciphertxt.resize(iv.size() + plaintxt.size() + BLOCK_SIZE);
    auto cipherbeg = &ciphertxt[0] + iv.size(); 

    // Encipher the text block
    int mainlen = ciphertxt.size();
    rc = EVP_EncryptUpdate
         (
            ctx.get(),
            cipherbeg,
            &mainlen,
            (const byte*)&plaintxt[0],
            (int)plaintxt.size()
         );  
    if (rc != OPENSSL_SUCCESS)
       throw std::runtime_error("Encountered error in OpenSSL::EVP_EncryptUpdate."); 
    
    // Encipher the remaining text block
    int remainlen = ciphertxt.size() - (mainlen+iv.size());
    rc = EVP_EncryptFinal_ex
         (
            ctx.get(),
            cipherbeg+mainlen,
            &remainlen
         );
    if (rc != OPENSSL_SUCCESS)
       throw std::runtime_error("Encountered error in OpenSSL::EVP_EncryptFinal_ex."); 


    ciphertxt.resize(iv.size()+mainlen+remainlen);
    return ciphertxt;
}

CryptoString CryptManager::decipherStr(const CryptoString & ciphertxt)
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

    // Deciphered txt expands up to BLOCK_SIZE
    plaintxt.resize(ciphertxt.size() + BLOCK_SIZE);

    // Decipher the text block
    int mainlen = ciphertxt.size();
    rc = EVP_DecryptUpdate
         (
            ctx.get(),
            &plaintxt[0],
            &mainlen,
            (const byte*)&ciphertxt[0] + BLOCK_SIZE,
            (int)ciphertxt.size() - BLOCK_SIZE
         );  
    if (rc != OPENSSL_SUCCESS)
       throw std::runtime_error("Encountered error in OpenSSL::EVP_DecryptUpdate."); 
    
    // Deicpher the remaining text block
    int remainlen = ciphertxt.size() - (mainlen+iv.size());
    rc = EVP_DecryptFinal_ex
         (
            ctx.get(),
            &plaintxt[0]+mainlen,
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

