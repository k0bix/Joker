#ifndef __LIBBTC_MEMORY_H__
#define __LIBBTC_MEMORY_H__

#include "btc/btc.h"

LIBBTC_BEGIN_DECL

typedef struct btc_mem_mapper_ {
    void* (*btc_malloc)(size_t size);
    void* (*btc_calloc)(size_t count, size_t size);
    void* (*btc_realloc)(void* ptr, size_t size);
    void (*btc_free)(void* ptr);
} btc_mem_mapper;

// set's a custom memory mapper
// this function is _not_ thread safe and must be called before anything else
LIBBTC_API void btc_mem_set_mapper(const btc_mem_mapper mapper);
LIBBTC_API void btc_mem_set_mapper_default();

LIBBTC_API void* btc_malloc(size_t size);
LIBBTC_API void* btc_calloc(size_t count, size_t size);
LIBBTC_API void* btc_realloc(void* ptr, size_t size);
LIBBTC_API void  btc_free(void* ptr);

LIBBTC_API volatile void *btc_mem_zero(volatile void *dst, size_t len);

LIBBTC_API void memzero(void *s, size_t n);
LIBBTC_END_DECL

#endif // __LIBBTC_MEMORY_H__
