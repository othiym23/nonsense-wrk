#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#define SHA_CTX    CC_SHA256_CTX
#define SHA_INIT   CC_SHA256_Init
#define SHA_UPDATE CC_SHA256_Update
#define SHA_FINAL(CTX, BUF)  CC_SHA256_Final((BUF), (CTX))
#define SHA_LENGTH CC_SHA256_DIGEST_LENGTH
#else /* !__APPLE__ */
#include <bsd/stdlib.h>
#include "sha2.h"
#define SHA_CTX    sha256_ctx
#define SHA_INIT   sha256_init
#define SHA_UPDATE sha256_update
#define SHA_FINAL(CTX, BUF)  sha256_final((CTX), (BUF))
#define SHA_LENGTH SHA256_DIGEST_SIZE
#endif

#include "tinymt64.h"

void sha256(void *, size_t, unsigned char *);
void hexillate(const unsigned char *, char *, ssize_t);
void random_hash(tinymt64_t *, char *);
