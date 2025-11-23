#ifndef __LIBBTC_BLOCK_H__
#define __LIBBTC_BLOCK_H__

#include "btc/btc.h"
#include "btc/buffer.h"
#include "btc/cstr.h"

LIBBTC_BEGIN_DECL

typedef struct btc_block_header_ {
    int32_t version;
    uint256 prev_block;
    uint256 merkle_root;
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
} btc_block_header;

typedef struct btc_block_headerex_ {
    int32_t  version;
    uint256  prev_block;
    uint256  merkle_root;
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
    uint32_t height;
    uint256  blkhash;
    uint32_t txcount;
} btc_block_headerex;

LIBBTC_API btc_block_header* btc_block_header_new();
LIBBTC_API void btc_block_header_free(btc_block_header* header);
LIBBTC_API int btc_block_header_deserialize(btc_block_header* header, struct const_buffer* buf);
LIBBTC_API void btc_block_header_serialize(cstring* s, const btc_block_header* header);
LIBBTC_API void btc_block_header_copy(btc_block_header* dest, const btc_block_header* src);
LIBBTC_API btc_bool btc_block_header_hash(btc_block_header* header, uint256 hash);

LIBBTC_END_DECL

#endif // __LIBBTC_BLOCK_H__
