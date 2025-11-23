#ifndef __LIBBTC_BTC_H__
#define __LIBBTC_BTC_H__

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t btc_bool; //!serialize, c/c++ save bool

#ifndef __cplusplus
# ifndef true
#  define true 1
# endif

# ifndef false
#  define false 0
# endif
#endif //__cplusplus

#ifdef __cplusplus
# define LIBBTC_BEGIN_DECL extern "C" {
# define LIBBTC_END_DECL	}
#else
# define LIBBTC_BEGIN_DECL /* empty */
# define LIBBTC_END_DECL	/* empty */
#endif

#ifndef LIBBTC_API
#if defined(_WIN32)
#ifdef LIBBTC_BUILD
#define LIBBTC_API __declspec(dllexport)
#else
#define LIBBTC_API
#endif
#elif defined(__GNUC__) && defined(LIBBTC_BUILD)
#define LIBBTC_API __attribute__((visibility("default")))
#else
#define LIBBTC_API
#endif
#endif

#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

#define BTC_ECKEY_UNCOMPRESSED_LENGTH 65
#define BTC_ECKEY_COMPRESSED_LENGTH 33
#define BTC_ECKEY_PKEY_LENGTH 32
#define BTC_ECKEY_PKEY_LENGTH 32
#define BTC_HASH_LENGTH 32

#define BTC_MIN(a,b) (((a)<(b))?(a):(b))
#define BTC_MAX(a,b) (((a)>(b))?(a):(b))

LIBBTC_BEGIN_DECL

typedef uint8_t uint256[32];
typedef uint8_t uint160[20];

LIBBTC_END_DECL

#endif // __LIBBTC_BTC_H__
