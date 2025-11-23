#ifndef __LIBBTC_UTILS_H__
#define __LIBBTC_UTILS_H__

#include "btc/btc.h"
#include "btc/cstr.h"
#include "btc/memory.h"
#include "btc/net.h"

#define TO_UINT8_HEX_BUF_LEN 4096
#define VARINT_LEN 20

#define strlens(s) (s == NULL ? 0 : strlen(s))

int __secs_to_tm(long long t, struct tm *tm);

int evutil_inet_pton_scope(int af, const char *src, void *dst, unsigned *indexp);
int parse_sockaddr_port(const char *ip_as_string, struct sockaddr *out, int *outlen);

int __secs_to_tm(long long t, struct tm *tm);

LIBBTC_BEGIN_DECL
LIBBTC_API void utils_clear_buffers(void);
LIBBTC_API void utils_hex_to_bin(const char* str, unsigned char* out, int inLen, int* outLen);
LIBBTC_API void utils_bin_to_hex(unsigned char* bin_in, size_t inlen, char* hex_out);
LIBBTC_API uint8_t* utils_hex_to_uint8(const char* str);
LIBBTC_API char* utils_uint8_to_hex(const uint8_t* bin, size_t l);
LIBBTC_API void utils_reverse_hex(char* h, int len);
LIBBTC_API void utils_uint256_sethex(char* psz, uint8_t* out);
LIBBTC_API void* safe_malloc(size_t size);
LIBBTC_API void btc_cheap_random_bytes(uint8_t* buf, uint32_t len);
LIBBTC_API void btc_get_default_datadir(cstring *path_out);
LIBBTC_API void btc_file_commit(FILE *file);

/* support substitude for GNU only tdestroy */
/* Let's hope the node struct is always compatible */

struct btc_btree_node {
    void *key;
    struct btc_btree_node *left;
    struct btc_btree_node *right;
};

static inline void btc_btree_tdestroy(void *root, void (*freekey)(void *))
{
    struct btc_btree_node *r = (struct btc_btree_node*)root;

    if (r == 0)
        return;
    btc_btree_tdestroy(r->left, freekey);
    btc_btree_tdestroy(r->right, freekey);

    if (freekey) freekey(r->key);
    btc_free(r);
}

LIBBTC_END_DECL

#endif // __LIBBTC_UTILS_H__
