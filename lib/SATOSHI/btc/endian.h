#ifndef CRYPTO_ENDIANUTIL_H
#define CRYPTO_ENDIANUTIL_H

#include <inttypes.h>

#if !defined(HOST_BUILD)

// CPU is assumed to be little endian.   Edit this file if you
// need to port this library to a big endian CPU.

#define CRYPTO_LITTLE_ENDIAN 1

#define htole16(x)  (x)
#define le16toh(x)  (x)
#define htobe16(x)  \
    (__extension__ ({ \
        uint16_t _temp = (x); \
        ((_temp >> 8) & 0x00FF) | \
        ((_temp << 8) & 0xFF00); \
    }))
#define be16toh(x)  (htobe16((x)))

#define htole32(x)  (x)
#define le32toh(x)  (x)
#define htobe32(x)  \
    (__extension__ ({ \
        uint32_t _temp = (x); \
        ((_temp >> 24) & 0x000000FF) | \
        ((_temp >>  8) & 0x0000FF00) | \
        ((_temp <<  8) & 0x00FF0000) | \
        ((_temp << 24) & 0xFF000000); \
    }))
#define be32toh(x)  (htobe32((x)))

#define htole64(x)  (x)
#define le64toh(x)  (x)
#define htobe64(x)  \
    (__extension__ ({ \
        uint64_t __temp = (x); \
        uint32_t __low = htobe32((uint32_t)__temp); \
        uint32_t __high = htobe32((uint32_t)(__temp >> 32)); \
        (((uint64_t)__low) << 32) | __high; \
    }))
#define be64toh(x)  (htobe64((x)))

#else // HOST_BUILD

#include <endian.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define CRYPTO_LITTLE_ENDIAN 1
#endif

#endif // HOST_BUILD

#endif