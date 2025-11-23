#ifndef __LIBBTC_BUFFER_H__
#define __LIBBTC_BUFFER_H__

#include "btc/btc.h"

LIBBTC_BEGIN_DECL

struct buffer {
    void* p;
    size_t len;
};

struct const_buffer {
    const void* p;
    size_t len;
};

LIBBTC_API int buffer_equal(const void* a, const void* b);
LIBBTC_API void buffer_free(void* struct_buffer);
LIBBTC_API struct buffer* buffer_copy(const void* data, size_t data_len);

LIBBTC_END_DECL

#endif // __LIBBTC_BUFFER_H__
