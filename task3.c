#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define NBITS 256

// print a big number
void printBN(char *msg, BIGNUM *a)
{
    char *number_str = BN_bn2hex(a);

    printf("%s %s\n", msg, number_str);

    OPENSSL_free(number_str);
}

// Convert hex string to ASCII string
char *hexToAscii(const char *hexStr)
{
    int len = strlen(hexStr);
    if (len % 2 != 0)
    {
        fprintf(stderr, "Error: Hex string length should be even.\n");
        return NULL;
    }

    int asciiLen = len / 2;
    char *asciiStr = malloc(asciiLen + 1);

    for (int i = 0; i < len; i += 2)
    {
        sscanf(hexStr + i, "%2hhx", &asciiStr[i / 2]);
    }

    asciiStr[asciiLen] = '\0';
    return asciiStr;
}

int main()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *c = BN_new();
    BIGNUM *dec = BN_new();
    // Initialize
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&c, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    BN_mod_exp(dec, c, d, n, ctx);
    printBN("decrypt message(hex) = ", dec);

    // Convert dec to ASCII
    char *asciiStr = hexToAscii(BN_bn2hex(dec));
    if (asciiStr != NULL)
    {
        printf("decrypt message(ASCII string): %s\n", asciiStr);
        free(asciiStr);
    }

    return 0;
}
