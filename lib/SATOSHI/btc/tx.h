#ifndef __LIBBTC_TX_H__
#define __LIBBTC_TX_H__

#include "btc/btc.h"
#include "btc/chainparm.h"
#include "btc/cstr.h"
#include "btc/hash.h"
#include "btc/vector.h"
#include "btc/utils.h"
#include "btc/segwit_addr.h"
#include "btc/base58.h"

LIBBTC_BEGIN_DECL

typedef struct btc_script_ {
    int* data;
    size_t limit;   // Total size of the vector
    size_t current; //Number of vectors in it at present
} btc_script;

typedef struct btc_tx_outpoint_ {
    uint256 hash;
    uint32_t n;
} btc_tx_outpoint;

typedef struct btc_tx_in_ {
    btc_tx_outpoint prevout;
    cstring* script_sig;
    uint32_t sequence;
    vector* witness_stack;
} btc_tx_in;

typedef struct btc_tx_out_ {
    int64_t value;
    cstring* script_pubkey;
} btc_tx_out;

typedef struct btc_tx_ {
    int32_t version;
    vector* vin;
    vector* vout;
    uint32_t locktime;
} btc_tx;


//!create a new tx input
LIBBTC_API btc_tx_in* btc_tx_in_new();
LIBBTC_API void btc_tx_in_free(btc_tx_in* tx_in);

//!create a new tx output
LIBBTC_API btc_tx_out* btc_tx_out_new();
LIBBTC_API void btc_tx_out_free(btc_tx_out* tx_out);

//!create a new tx input
LIBBTC_API btc_tx* btc_tx_new();
LIBBTC_API void btc_tx_free(btc_tx* tx);

//!deserialize/parse a p2p serialized bitcoin transaction
LIBBTC_API int btc_tx_deserialize(const unsigned char* tx_serialized, size_t inlen, btc_tx* tx, size_t* consumed_length, btc_bool allow_witness);

//!serialize a lbc bitcoin data structure into a p2p serialized buffer
LIBBTC_API void btc_tx_serialize(cstring* s, const btc_tx* tx, btc_bool allow_witness);

LIBBTC_API btc_bool btc_tx_has_witness(const btc_tx *tx);
LIBBTC_API void btc_tx_hash(const btc_tx *tx, uint256 hashout);

LIBBTC_API int btc_tx_deserialize(const unsigned char *tx_serialized, size_t inlen, btc_tx *tx, size_t *consumed_length, btc_bool allow_witness);
LIBBTC_API int btc_base58_decode_check(const char* str, uint8_t* data, uint32_t datalen);
LIBBTC_API void push_png_to_screen(const uint8_t *arrayData, uint32_t arraySize);
LIBBTC_API int push_jpg_to_screen(uint8_t *arrayData);

enum btc_tx_sign_result {
    BTC_SIGN_UNKNOWN = 0,
    BTC_SIGN_INVALID_KEY = -2,
    BTC_SIGN_NO_KEY_MATCH = -3, //if the key found in the script doesn't match the given key, will sign anyways
    BTC_SIGN_SIGHASH_FAILED = -4,
    BTC_SIGN_UNKNOWN_SCRIPT_TYPE = -5,
    BTC_SIGN_INVALID_TX_OR_SCRIPT = -6,
    BTC_SIGN_INPUTINDEX_OUT_OF_RANGE = -7,
    BTC_SIGN_OK = 1,
};
const char* btc_tx_sign_result_to_str(const enum btc_tx_sign_result result);

LIBBTC_END_DECL

#endif // __LIBBTC_TX_H__
