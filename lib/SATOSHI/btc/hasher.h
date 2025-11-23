#ifndef __HASHER_H__
#define __HASHER_H__

#include <stddef.h>
#include <stdint.h>

#include "btc/sha2.h"
#include "btc/sha3.h"

#define HASHER_DIGEST_LENGTH 32

typedef enum {
    HASHER_SHA2,
    HASHER_SHA2D,
    HASHER_SHA2_RIPEMD,

    HASHER_SHA3,
#if USE_KECCAK
    HASHER_SHA3K,
#endif
} HasherType;

typedef struct {
    HasherType type;

    union {
        SHA256_CTX sha2;        // for HASHER_SHA2{,D}
        SHA3_CTX sha3;          // for HASHER_SHA3{,K}
    } ctx;
} Hasher;

void hasher_Init(Hasher *hasher, HasherType type);
void hasher_Reset(Hasher *hasher);
void hasher_Update(Hasher *hasher, const uint8_t *data, size_t length);
void hasher_Final(Hasher *hasher, uint8_t hash[HASHER_DIGEST_LENGTH]);

void hasher_Raw(HasherType type, const uint8_t *data, size_t length, uint8_t hash[HASHER_DIGEST_LENGTH]);

#endif
