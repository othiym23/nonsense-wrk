#include <stdlib.h>
#include <string.h>

#include "hash.h"

/* Don't care about endianness -- get a uint64_t, return an array of bytes.
 */
union ll_to_ba
{
  uint8_t byte[8];
  uint64_t longlong;
} ll_to_ba;

void sha256(void *msg, size_t msg_len, unsigned char *buf) {
    SHA_CTX ctx;
    SHA_INIT(&ctx);
    SHA_UPDATE(&ctx, msg, msg_len);
    SHA_FINAL(&ctx, buf);
}

void hexillate(const unsigned char *inbuf, char *outbuf, ssize_t size) {
    const static char *hex = "0123456789abcdef";

    const unsigned char *in = inbuf;
    char *out = outbuf;
    for (int i = 0; i < size; i++) {
        *out++ = hex[(*in >> 4) & 0xf];
        *out++ = hex[*in++ & 0xf];
    }
}

void random_hash(tinymt64_t *state, char *outbuf) {
    unsigned char buf[SHA_LENGTH];
    union ll_to_ba thunk;
    unsigned char w = sizeof(ll_to_ba.byte);

    for (int j = 0; j < SHA_LENGTH / w; j++) {
        thunk.longlong = tinymt64_generate_uint64(state);
        for (int i = 0; i < w; i++) {
            buf[(j * w) + i] = thunk.byte[i];
	}
    }

    hexillate(buf, outbuf, SHA_LENGTH);
}
