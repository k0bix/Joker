#ifndef __LIBBTC_CHAINPARAMS_H__
#define __LIBBTC_CHAINPARAMS_H__

#include "btc/btc.h"

LIBBTC_BEGIN_DECL

typedef struct btc_dns_seed_ {
    char domain[256];
} btc_dns_seed;

typedef struct btc_chainparams_ {
    char chainname[32];
    uint8_t b58prefix_pubkey_address;
    uint8_t b58prefix_script_address;
    const char bech32_hrp[5];
    uint8_t b58prefix_secret_address; //!private key
    uint32_t b58prefix_bip32_privkey;
    uint32_t b58prefix_bip32_pubkey;
    const unsigned char netmagic[4];
    uint256 genesisblockhash;
    int default_port;
    btc_dns_seed dnsseeds[8];
} btc_chainparams;

typedef struct btc_checkpoint_ {
    uint32_t height;
    const char* hash;
    uint32_t timestamp;
    uint32_t target;
} btc_checkpoint;

extern  btc_chainparams btc_chainparams_signet;
extern  btc_chainparams btc_chainparams_main;
extern  btc_chainparams btc_chainparams_test;
extern const btc_chainparams btc_chainparams_regtest;

// the mainnet checkpoins, needs a fix size
extern const btc_checkpoint btc_mainnet_checkpoint_array[21];

LIBBTC_END_DECL

#endif // __LIBBTC_CHAINPARAMS_H__
