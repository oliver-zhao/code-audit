/* Seeds for the C OpenSSL, libcurl and credential rules. */
#include <curl/curl.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

static const char admin_password[] = "Pr0dAdm1nPass";    /* cpp-hardcoded-credential */
#define SERVICE_API_KEY "kq83hfQ2mvA0pZ"                 /* cpp-hardcoded-credential */

void legacy_crypto(const unsigned char *in, size_t len, unsigned char *out, RSA *rsa)
{
    DES_key_schedule ks;
    DES_cblock key;
    unsigned int siglen = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_MD_CTX *md = EVP_MD_CTX_new();

    DES_set_key_unchecked(&key, &ks);                    /* cpp-weak-cipher */
    EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, out, NULL); /* cpp-weak-cipher */
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, out, NULL); /* cpp-ecb-mode */
    MD5(in, len, out);                                   /* cpp-weak-hash */
    EVP_DigestSignInit(md, NULL, EVP_sha1(), NULL, NULL); /* cpp-sha1-signature */
    RSA_sign(NID_sha1, in, 20, out, &siglen, rsa);       /* cpp-sha1-signature */
}

SSL_CTX *client_context(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_client_method());   /* cpp-ssl-legacy-protocol */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);      /* cpp-ssl-verify-none */
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);    /* cpp-ssl-legacy-protocol */
    return ctx;
}

void fetch(CURL *curl)
{
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);  /* cpp-curl-tls-verify-disabled */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);   /* cpp-curl-tls-verify-disabled */
    curl_easy_perform(curl);
}
