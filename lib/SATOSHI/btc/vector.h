#ifndef __LIBBTC_VECTOR_H__
#define __LIBBTC_VECTOR_H__

#include "btc/btc.h"

LIBBTC_BEGIN_DECL

typedef struct vector {
    void** data;  /* array of pointers */
    size_t len;   /* array element count */
    size_t alloc; /* allocated array elements */

    void (*elem_free_f)(void*);
} vector;

LIBBTC_API vector* vector_new(size_t res, void (*free_f)(void*));
LIBBTC_API void vector_free(vector* vec, btc_bool free_array);

LIBBTC_API btc_bool vector_add(vector* vec, void* data);
LIBBTC_API btc_bool vector_remove(vector* vec, void* data);
LIBBTC_API void vector_remove_idx(vector* vec, size_t idx);
LIBBTC_API void vector_remove_range(vector* vec, size_t idx, size_t len);
LIBBTC_API btc_bool vector_resize(vector* vec, size_t newsz);

LIBBTC_API ssize_t vector_find(vector* vec, void* data);

#define vector_idx(vec, idx) ((vec)->data[(idx)])

LIBBTC_END_DECL

#endif // __LIBBTC_VECTOR_H__
