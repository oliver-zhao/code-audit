/* Safe counterparts of fixtures/vulnerable/cpp/crypto.c. */
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdlib.h>

static const char password_prompt[] = "Enter password:";

void modern_crypto(const unsigned char *key, const unsigned char *iv, unsigned char *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    const char *api_key = getenv("SERVICE_API_KEY");

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, NULL);
    (void)out;
    (void)api_key;
    (void)password_prompt;
}

SSL_CTX *client_context(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_default_verify_paths(ctx);
    return ctx;
}

void fetch(CURL *curl)
{
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_perform(curl);
}
