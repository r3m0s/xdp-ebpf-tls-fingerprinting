// JA3 raw string to JA3 hash
// Converts the raw string into a JA3 hash.
// Reference Guide: https://tls.peet.ws/

// Created by Alex Matecas
// ADSS, February 2026.

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ja3_raw_string>\n", argv[0]);
        return 1;
    }

    const char *input = argv[1];

    // Buffer for the resulting hash
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    // Create a message digest context for the hashing operation
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    // Initialize the context to use the MD5 algorithm
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);

    // Pass the input string into the hashing function
    EVP_DigestUpdate(ctx, input, strlen(input));

    // Finalize the hash and store the result in "digest"
    EVP_DigestFinal_ex(ctx, digest, &digest_len);

    // Clean up the context memory
    EVP_MD_CTX_free(ctx);

    // Convert the binary digest into a hex-encoded string and print it
    for (unsigned int i = 0; i < digest_len; i++) {
        printf("%02x", digest[i]);
    }
    
    printf("\n");
}