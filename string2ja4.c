// JA4 raw string to JA4 hash
// Converts the raw string into a JA4 hash.
// Reference Guide: https://tls.peet.ws/

// Created by Alex Matecas
// ADSS, February 2026.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

void sha256_truncated(const char *input, char *out12) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, strlen(input));
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);
    
    for (int i = 0; i < 6; i++)
        sprintf(out12 + i * 2, "%02x", digest[i]);
    out12[12] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ja4_raw_string>\n", argv[0]);
        fprintf(stderr, "Format: prefix_ciphers_extensions_sigalgs\n");
        return 1;
    }

    char input[65536];
    strncpy(input, argv[1], sizeof(input) - 1);
    input[sizeof(input) - 1] = '\0';

    char *parts[4] = {0};
    int nparts = 0;
    char *p = input;
    
    while (nparts < 4) {
        parts[nparts++] = p;
        p = strchr(p, '_');
        if (!p) break;
        *p++ = '\0';
    }

    if (nparts != 4) {
        fprintf(stderr, "Error: expected 4 underscore-delimited parts, got %d\n", nparts);
        fprintf(stderr, "Format: prefix_ciphers_extensions_sigalgs\n");
        return 1;
    }

    char *prefix  = parts[0];
    char *ciphers = parts[1];
    char *exts    = parts[2];
    char *sigalgs = parts[3];

    char cipher_hash[13];
    sha256_truncated(ciphers, cipher_hash);

    char ext_input[65536];
    snprintf(ext_input, sizeof(ext_input), "%s_%s", exts, sigalgs);
    char ext_hash[13];
    sha256_truncated(ext_input, ext_hash);

    printf("%s_%s_%s\n", prefix, cipher_hash, ext_hash);
    return 0;
}