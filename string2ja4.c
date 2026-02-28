// JA4 raw string to JA4 hash
// Converts the raw string into a JA4 hash.
// Reference Guide: https://tls.peet.ws/

// Created by Alex Matecas
// ADSS, February 2026.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

/**
 * Computes a SHA-256 hash of the input and truncates it to the first 12 hex characters (6 bytes).
 * 
 */
void sha256_truncated(const char *input, char *out12) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    
    // Initialize OpenSSL's EVP context for SHA-256
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    
    // Feed the input string into the hashing engine
    EVP_DigestUpdate(ctx, input, strlen(input));
    
    // Finalize the hash computation
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);
    
    // Convert only the first 6 bytes of the hash into 12 hex characters
    for (int i = 0; i < 6; i++)
        sprintf(out12 + i * 2, "%02x", digest[i]);
    
    // Null-terminate the resulting string
    out12[12] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ja4_raw_string>\n", argv[0]);
        fprintf(stderr, "Format: prefix_ciphers_extensions_sigalgs\n");
        return 1;
    }

    // Copy input to a local buffer to allow mutation
    char input[65536];
    strncpy(input, argv[1], sizeof(input) - 1);
    input[sizeof(input) - 1] = '\0';

    // Split the input string into 4 parts based on the "_" delimiter
    char *parts[4] = {0};
    int nparts = 0;
    char *p = input;
    
    while (nparts < 4) {
        parts[nparts++] = p;

        // Find the next underscore
        p = strchr(p, '_');
        if (!p) break;

        // Replace underscore with null terminator and move pointer forward
        *p++ = '\0'; 
    }

    // The JA4 raw string has exactly 4 parts
    if (nparts != 4) {
        fprintf(stderr, "Error: expected 4 underscore-delimited parts, got %d\n", nparts);
        fprintf(stderr, "Format: prefix_ciphers_extensions_sigalgs\n");
        return 1;
    }

    // Part "a" (e.g.: t13d151608)
    // This is also Section "1", as this will not be hashed in the final result.
    char *prefix  = parts[0];

    // Part "b" (Cipher list)
    char *ciphers = parts[1];

    // Part "c" (Extension list)
    char *exts    = parts[2];

    // Part "d" (Signature Algorithms)
    char *sigalgs = parts[3];

    // Section "2": Hash the cipher list
    char cipher_hash[13];

    sha256_truncated(ciphers, cipher_hash);

    // Section "3": Hash the extensions and signature algorithms together
    char ext_input[65536];
    snprintf(ext_input, sizeof(ext_input), "%s_%s", exts, sigalgs);
    char ext_hash[13];
    sha256_truncated(ext_input, ext_hash);

    // Print the final JA4 output
    printf("%s_%s_%s\n", prefix, cipher_hash, ext_hash);
}