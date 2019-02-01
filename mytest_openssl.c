#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
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

void printMyStr(unsigned char* bin, size_t len, const char* prefix)
{
    char *out;
    out = (char*)malloc(len*2+1);
    for (size_t i=0; i<len; i++) {
        out[i*2]   = "0123456789ABCDEF"[bin[i] >> 4];
        out[i*2+1] = "0123456789ABCDEF"[bin[i] & 0x0F];
    }
    out[len*2] = '\0';
    printf("%s(%lu): %s\n", prefix, len, out);
    free(out);
}

int Ed25519PkSkGenerate(EVP_PKEY** ppKey)
{
    EVP_PKEY_CTX *pCtx = NULL;
    int ret = -1;
    if (NULL == ppKey || *ppKey) {
        printf("Input variable fail\n");
        return ret;
    }
    do {
        if (NULL == (pCtx = (EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL)))) {
            printf("New Key fail...\n");
            break;
        }
        if (1 != EVP_PKEY_keygen_init(pCtx)) {
            printf("EVP_PKEY_keygen_init fail\n");
            break;
        }
        if (1 != EVP_PKEY_keygen(pCtx, ppKey)) {
            printf("EVP_PKEY_kengen fail\n");
            break;
        }

        ret = 0;
    } while (0);

    if (pCtx) {
        EVP_PKEY_CTX_free(pCtx);
    }

    return ret;
}

int PrintPKSK(EVP_PKEY* pKey)
{
    unsigned char sk[1024], pk[1024];
    size_t skLen, pkLen;

    if (1 != EVP_PKEY_get_raw_private_key(pKey, sk, &skLen)) {
        printf("EVP_PKEY_get_raw_private_key fail");
        char* errStr;
        int line;
        unsigned long err = ERR_get_error_line((const char**)&errStr, &line);
        printf("show me the error: %lu, %s:%i\n", err, errStr, line);
    }

    if (1 != EVP_PKEY_get_raw_public_key(pKey, pk, &pkLen)) {
        printf("EVP_PKEY_get_raw_public_key fail");
        char* errStr;
        int line;
        unsigned long err = ERR_get_error_line((const char**)&errStr, &line);
        printf("show me the error: %lu, %s:%i\n", err, errStr, line);
    }

    printMyStr(sk, skLen, "sk");
    printMyStr(pk, pkLen, "pk");
 return 0;
}

int Ed25519Sign(unsigned char** ppCt, size_t* pCtLen,
                const unsigned char* pM, size_t mLen,
                EVP_PKEY* pKey)
{
    int ret = -1;
    if (NULL == ppCt || *ppCt || NULL == pCtLen ||
        NULL == pM || 0 == mLen ||
        NULL == pKey) {
        printf("Input variable fail\n");
        return ret;
    }

    EVP_MD_CTX *pMDCtx = NULL;
    unsigned char* pTmpM = NULL;
    do {
        if (NULL == (pMDCtx = EVP_MD_CTX_new())) {
            printf("EVP_MD_CTX_new fail\n");
            break;
        }

        if (1 != EVP_DigestSignInit(pMDCtx, NULL, NULL, NULL, pKey)) {
            printf("EVP_DigestSignInit fail\n");
            break;
        }

        size_t tmpMLen = 0;
        if (1 != EVP_DigestSign(pMDCtx, NULL, &tmpMLen, pM, mLen)) {
            printf("EVP_DigestSign fail\n");
            break;
        }

        if (NULL == (pTmpM = (unsigned char*)calloc(tmpMLen, sizeof(char)))) {
            printf("calloc fail\n");
            break;
        }
        if (1 != EVP_DigestSign(pMDCtx, pTmpM, &tmpMLen, pM, mLen)) {
            printf("EVP_DigestSign fail\n");
            break;
        }
        *ppCt = pTmpM;
        *pCtLen = tmpMLen;

        ret = 0;
    } while (0);

    if (pMDCtx) {
        EVP_MD_CTX_free(pMDCtx);
    }

    if (0 == ret) {
        return ret;
    }

    //Error handling
    if (pTmpM) {
        free(pTmpM);
    }
    return ret;
}

int Ed25519Verify(const unsigned char* pCt, size_t ctLen,
                  const unsigned char* pM, size_t mLen,
                  EVP_PKEY* pKey)
{
    int ret = -1;
    if (NULL == pCt || 0 == ctLen ||
        NULL == pM || 0 == mLen ||
        NULL == pKey) {
        printf("Input variable fail\n");
        return ret;
    }

    EVP_MD_CTX *pMDCtx = NULL;
    do {
        if (NULL == (pMDCtx = EVP_MD_CTX_new())) {
            printf("EVP_MD_CTX_new fail\n");
            break;
        }

        if (1 != EVP_DigestVerifyInit(pMDCtx, NULL, NULL, NULL, pKey)) {
            printf("EVP_DigestVerrifyInit fail\n");
            break;
        }

        if (1 != EVP_DigestVerify(pMDCtx, pCt, ctLen, pM, mLen)) {
            printf("EVP_DigestSign fail\n");
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
    unsigned int i = 0;
    const size_t mLen = strlen(TEST_JSON_PLAINTEXT) + 1;
    unsigned char* m = NULL;

    bool status = true;
    unsigned long long tkeygen[NTESTS], tsign[NTESTS], tverify[NTESTS];
    unsigned long long totalLength = 0;

    if (NULL == (m = (unsigned char*)calloc(mLen, sizeof(char)))) {
        printf("Cannot calloc data\n");
        return -1;
    }
    snprintf((char*)m, mLen, TEST_JSON_PLAINTEXT);

    printf("Original String:\n%s\nlength: %lu\n", (char*)m, mLen);
    printf("\n");
    timing_overhead = cpucycles_overhead();

    for (i = 0; i < NTESTS; ++i) {
        EVP_PKEY* pKey = NULL;
        int ret = -1;
        unsigned char* pCt = NULL;
        size_t ctLen = 0;
        do {
            // start to prepare to generate keypair
            tkeygen[i] = cpucycles_start();
            if (0 != Ed25519PkSkGenerate(&pKey)) {
                printf("Ed25519PkSkGenerate fail\n");
                break;
            }
            tkeygen[i] = cpucycles_stop() - tkeygen[i] - timing_overhead;
            PrintPKSK(pKey);
            // start to encrypt
            tsign[i] = cpucycles_start();
            if (0 != Ed25519Sign(&pCt, &ctLen,
                                 m, mLen,
                                 pKey)) {
                printf("Ed25519Sign fail\n");
                break;
            }
            tsign[i] = cpucycles_stop() - tsign[i] - timing_overhead;
            // start to decrpt
            tverify[i] = cpucycles_start();
            if (0 != Ed25519Verify(pCt, ctLen, m, mLen, pKey)) {
                printf("Ed25519Verify fail\n");
                break;
            }
            tverify[i] = cpucycles_stop() - tverify[i] - timing_overhead;

            totalLength += ctLen;
//            printMyStr(m, mLen, "msg");
//           printMyStr(pCt, ctLen, "sig");

            ret = 0;
        } while (0);

        if (pKey) {
            EVP_PKEY_free(pKey);
            pKey = NULL;
        }
        if (pCt) {
            free(pCt);
            pCt = NULL;
        }
        if (0 != ret) {
            printf("Failllllllll\n");
            status = false;
            break;
        }
    }

    if (status == false) {
        printf("This test is fail, please check it\n");
    } else {
        print_results("keygen:", tkeygen, NTESTS);
        print_results("sign: ", tsign, NTESTS);
        print_results("verify: ", tverify, NTESTS);
        printf("average length: %llu\n", (totalLength / NTESTS));
    }


    return 0;
}
