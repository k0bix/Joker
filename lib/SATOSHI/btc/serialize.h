#ifndef __LIBBTC_SERIALIZE_H__
#define __LIBBTC_SERIALIZE_H__

#include "btc/btc.h"
#include "btc/buffer.h"
#include "btc/cstr.h"

LIBBTC_BEGIN_DECL

LIBBTC_API void ser_bytes(cstring* s, const void* p, unsigned int len);
LIBBTC_API void ser_u16(cstring* s, uint16_t v_);
LIBBTC_API void ser_u32(cstring* s, uint32_t v_);
LIBBTC_API void ser_u64(cstring* s, uint64_t v_);
LIBBTC_API void ser_u256(cstring* s, const unsigned char* v_);
LIBBTC_API void ser_varlen(cstring* s, uint32_t vlen);
LIBBTC_API void ser_str(cstring* s, const char* s_in, unsigned int maxlen);
LIBBTC_API void ser_varstr(cstring* s, cstring* s_in);

LIBBTC_API void ser_s32(cstring* s, int32_t v_);

LIBBTC_API void ser_s64(cstring* s, int64_t v_);

LIBBTC_API int deser_skip(struct const_buffer* buf, unsigned int len);
LIBBTC_API int deser_bytes(void* po, struct const_buffer* buf, unsigned int len);
LIBBTC_API int deser_u16(uint16_t* vo, struct const_buffer* buf);
LIBBTC_API int deser_u32(uint32_t* vo, struct const_buffer* buf);
LIBBTC_API int deser_s32(int32_t* vo, struct const_buffer* buf);
LIBBTC_API int deser_u64(uint64_t* vo, struct const_buffer* buf);
LIBBTC_API int deser_u256(uint256 vo, struct const_buffer* buf);

LIBBTC_API int deser_varlen(uint32_t* lo, struct const_buffer* buf);
LIBBTC_API int deser_varlen_from_file(uint32_t* lo, FILE* file);
LIBBTC_API int deser_varlen_file(uint32_t* lo, FILE* file, uint8_t* rawdata, unsigned int* buflen_inout);
LIBBTC_API int deser_str(char* so, struct const_buffer* buf, unsigned int maxlen);
LIBBTC_API int deser_varstr(cstring** so, struct const_buffer* buf);

LIBBTC_API int deser_s64(int64_t* vo, struct const_buffer* buf);

LIBBTC_END_DECL

#endif // __LIBBTC_SERIALIZE_H__
