#ifndef __LIBBTC_CSTR_H__
#define __LIBBTC_CSTR_H__

#include "btc/btc.h"

LIBBTC_BEGIN_DECL

typedef struct cstring {
    char* str;    /* string data, incl. NUL */
    size_t len;   /* length of string, not including NUL */
    size_t alloc; /* total allocated buffer length */
} cstring;

LIBBTC_API cstring* cstr_new(const char* init_str);
LIBBTC_API cstring* cstr_new_sz(size_t sz);
LIBBTC_API cstring* cstr_new_buf(const void* buf, size_t sz);
LIBBTC_API cstring* cstr_new_cstr(const cstring* copy_str);
LIBBTC_API void cstr_free(cstring* s, int free_buf);

LIBBTC_API int cstr_equal(const cstring* a, const cstring* b);
LIBBTC_API int cstr_compare(const cstring* a, const cstring* b);
LIBBTC_API int cstr_resize(cstring* s, size_t sz);
LIBBTC_API int cstr_erase(cstring* s, size_t pos, ssize_t len);

LIBBTC_API int cstr_append_buf(cstring* s, const void* buf, size_t sz);
LIBBTC_API int cstr_append_cstr(cstring* s, cstring* append);

LIBBTC_API int cstr_append_c(cstring* s, char ch);

LIBBTC_API int cstr_alloc_minsize(cstring* s, size_t sz);

LIBBTC_END_DECL

#endif // __LIBBTC_CSTR_H__
