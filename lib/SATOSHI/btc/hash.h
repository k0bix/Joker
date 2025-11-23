#ifndef __LIBBTC_HASH_H__
#define __LIBBTC_HASH_H__

#include "btc/btc.h"
#include "btc/cstr.h"
#include "btc/memory.h"
#include "btc/sha2.h"
#include "btc/vector.h"

LIBBTC_BEGIN_DECL

LIBBTC_API static inline btc_bool btc_hash_is_empty(uint256 hash)
{
    return hash[0] == 0 && !memcmp(hash, hash + 1, 19);
}

LIBBTC_API static inline void btc_hash_clear(uint256 hash)
{
    memset(hash, 0, BTC_HASH_LENGTH);
}

LIBBTC_API static inline btc_bool btc_hash_equal(uint256 hash_a, uint256 hash_b)
{
    return (memcmp(hash_a, hash_b, BTC_HASH_LENGTH) == 0);
}

LIBBTC_API static inline void btc_hash_set(uint256 hash_dest, const uint256 hash_src)
{
    memcpy(hash_dest, hash_src, BTC_HASH_LENGTH);
}

//bitcoin double sha256 hash
LIBBTC_API static inline void btc_hash(const unsigned char* datain, size_t length, uint256 hashout)
{
    sha256_Raw(datain, length, hashout);
    sha256_Raw(hashout, SHA256_DIGEST_LENGTH, hashout);
}

//single sha256 hash
LIBBTC_API static inline void btc_hash_sngl_sha256(const unsigned char* datain, size_t length, uint256 hashout)
{
    sha256_Raw(datain, length, hashout);
}

LIBBTC_END_DECL

#endif // __LIBBTC_HASH_H__
