#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "mytest/cpucycles.h"
#include "mytest/speed.h"

#define NTESTS 50

#define TEST_JSON_PLAINTEXT "{\n" \
"        body: {\n" \
"                \"from\": \"pub_key_generated_by_library_in_testing_1\",\n" \
"                \"to\": \"pub_key_generated_by_library_in_testing_2\",\n" \
"                \"amount\": 3,1415,\n" \
"                \"itemHash\": \"bdad5ccb7a52387f5693eaef54aeee6de73a6ada7acda6d93a665abbdf954094\"\n" \
"                \"seed\": \"2953135335240383704\"\n" \
"        },\n" \
"        \"fee\": 0,7182,\n" \
"        \"network_id\": 7,\n" \
"        \"protocol_version\": 0,\n" \
"        \"service_id\": 5,\n" \
"}"

unsigned long long timing_overhead;

int Ed25519PkSkGenerate(EVP_PKEY** ppKey)
{
    EVP_PKEY_CTX *pCtx = NULL;
    int ret = -1;
    if (NULL == ppKey || *ppKey) {
        printf("Input variable fail");
        return ret;
    }
    do {
        if (NULL == (pCtx = (EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL)))) {
            printf("New Key fail...");
            break;
        }
        if (0 != EVP_PKEY_keygen_init(pCtx)) {
            printf("EVP_PKEY_keygen_init fail");
            break;
        }
        if (0 != EVP_PKEY_keygen(pCtx, ppKey)) {
            printf("EVP_PKEY_kengen fail");
            break;
        }

        ret = 0;
    } while (0);

    if (pCtx) {
        EVP_PKEY_CTX_free(pCtx);
    }

    return ret;
}

int Ed25519Sign(char** ppCt, size_t* pCtLen,
                const char* pM, const size_t MLen,
                EVP_PKEY* pKey)
{
    int ret = -1;
    if (NULL == ppCt || *ppCt ||
        NULL == pCtLen ||
        NULL == pM ||
        0 == MLen ||
        NULL == pKey) {
        printf("Input variable fail");
        return ret;
    }

    EVP_MD_CTX *pMDCtx = NULL;
    do {
        if (NULL == (pMDCtx = EVP_MD_CTX_new())) {
            printf("EVP_MD_CTX_new fail");
            break;
        }

        if (0 != EVP_DigestSignInit(pMDCtx, NULL, NULL, NULL, pKey)) {
            printf("EVP_DigestSignInit fail");
            break;
        }

        ret = 0;
    } while (0);

    if (pMDCtx) {
        EVP_MD_CTX_free(pMDCtx);
    }
    return ret;
}

int main(void)
{
    unsigned int i;
    const unsigned long long mlen = strlen(TEST_JSON_PLAINTEXT) + 1;
    unsigned char* m;
//    unsigned char* m_;
    unsigned long long tkeygen[NTESTS], tsign[NTESTS], tverify[NTESTS];
    unsigned long long totalLength = 0;

    if (NULL == (m = (unsigned char*)calloc(mlen, sizeof(char)))) {
        printf("Cannot calloc data");
        return -1;
    }
    snprintf((char*)m, mlen, TEST_JSON_PLAINTEXT);

    printf("Original String:\n%s\nlength: %llu\n", (char*)m, mlen);
    printf("\n");
    timing_overhead = cpucycles_overhead();

    for (i = 0; i < NTESTS; ++i) {
        EVP_PKEY* pKey = NULL;
        int ret = -1;
        do {
            // start to prepare to generate keypair
            tkeygen[i] = cpucycles_start();
            if (0 != Ed25519PkSkGenerate(&pKey)) {
                printf("Ed25519PkSkGenerate fail");
                break;
            }
            tkeygen[i] = cpucycles_stop() - tkeygen[i] - timing_overhead;

            // start to encrypt
            tsign[i] = cpucycles_start();
            tsign[i] = cpucycles_stop() - tsign[i] - timing_overhead;

            // start to decrpt
            tverify[i] = cpucycles_start();
            tverify[i] = cpucycles_stop() - tverify[i] - timing_overhead;

            if(ret) {
                printf("Verification failed\n");
                return -1;
            }

            if(mlen != (strlen((char*)m) + 1)) {
                printf("Message lengths don't match\n");
                return -1;
            }
/*             for(j = 0; j < mlen; ++j) { */
                /* if(m[j] != m2[j]) { */
                    /* printf("Messages don't match\n"); */
                    /* return -1; */
                /* } */
            /* } */
        } while (0);

    }

    print_results("keygen:", tkeygen, NTESTS);
    print_results("sign: ", tsign, NTESTS);
    print_results("verify: ", tverify, NTESTS);
    printf("average length: %llu\n", (totalLength / NTESTS));


    return 0;
}
