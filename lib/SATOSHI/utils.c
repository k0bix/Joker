/*

 The MIT License (MIT)

 Copyright (c) 2015 Douglas J. Bakkum
 Copyright (c) 2015 Jonas Schnelli

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <fcntl.h>
#include "btc/memory.h"
#include "btc/net.h"
#include "btc/buffer.h"
#include "btc/chainparm.h"
#include "btc/cstr.h"
#include "btc/hash.h"
#include "btc/serialize.h"
#include "btc/block.h"
#include "btc/tx.h"
#include "btc/base58.h"

#include <lwip/dns.h>
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "btc/segwit_addr.h"
#include "btc/utils.h"


static uint8_t buffer_hex_to_uint8[TO_UINT8_HEX_BUF_LEN];
static char buffer_uint8_to_hex[TO_UINT8_HEX_BUF_LEN];


/* 2000-03-01 (mod 400 year, immediately after feb29 */
#define LEAPOCH (946684800LL + 86400 * (31 + 29))

#define DAYS_PER_400Y (365 * 400 + 97)
#define DAYS_PER_100Y (365 * 100 + 24)
#define DAYS_PER_4Y (365 * 4 + 1)

#define MST (-7)
#define UTC (0)
#define CCT (+8)

int __secs_to_tm(long long t, struct tm *tm)
{
    long long days, secs;
    int remdays, remsecs, remyears;
    int qc_cycles, c_cycles, q_cycles;
    int years, months;
    int wday, yday, leap;
    static const char days_in_month[] = {31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 29};

    /* Reject time_t values whose year would overflow int */
    if (t < INT_MIN * 31622400LL || t > INT_MAX * 31622400LL)
        return -1;

    secs = t - LEAPOCH;
    days = secs / 86400;
    remsecs = secs % 86400;
    if (remsecs < 0)
    {
        remsecs += 86400;
        days--;
    }

    wday = (3 + days) % 7;
    if (wday < 0)
        wday += 7;

    qc_cycles = days / DAYS_PER_400Y;
    remdays = days % DAYS_PER_400Y;
    if (remdays < 0)
    {
        remdays += DAYS_PER_400Y;
        qc_cycles--;
    }

    c_cycles = remdays / DAYS_PER_100Y;
    if (c_cycles == 4)
        c_cycles--;
    remdays -= c_cycles * DAYS_PER_100Y;

    q_cycles = remdays / DAYS_PER_4Y;
    if (q_cycles == 25)
        q_cycles--;
    remdays -= q_cycles * DAYS_PER_4Y;

    remyears = remdays / 365;
    if (remyears == 4)
        remyears--;
    remdays -= remyears * 365;

    leap = !remyears && (q_cycles || !c_cycles);
    yday = remdays + 31 + 28 + leap;
    if (yday >= 365 + leap)
        yday -= 365 + leap;

    years = remyears + 4 * q_cycles + 100 * c_cycles + 400 * qc_cycles;

    for (months = 0; days_in_month[months] <= remdays; months++)
        remdays -= days_in_month[months];

    if (years + 100 > INT_MAX || years + 100 < INT_MIN)
        return -1;

    tm->tm_year = years + 100;
    tm->tm_mon = months + 2;
    if (tm->tm_mon >= 12)
    {
        tm->tm_mon -= 12;
        tm->tm_year++;
    }
    tm->tm_mday = remdays + 1;
    tm->tm_wday = wday;
    tm->tm_yday = yday;

    tm->tm_hour = remsecs / 3600;
    tm->tm_min = remsecs / 60 % 60;
    tm->tm_sec = remsecs % 60;

    return 0;
}


int _isdigit(char c)
{
    return c >= '0' && c <= '9';
}
/*
int isxdigit(int c)
{
    return (_isdigit(c) || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'));
}*/
int evutil_inet_pton(int af, const char *src, void *dst)
{
#if defined(EVENT__HAVE_INET_PTON) && !defined(USE_INTERNAL_PTON)
    return inet_pton(af, src, dst);
#else
    if (af == AF_INET)
    {
        unsigned a, b, c, d;
        char more;
        struct in_addr *addr = dst;
        if (sscanf(src, "%u.%u.%u.%u%c", &a, &b, &c, &d, &more) != 4)
            return 0;
        if (a > 255)
            return 0;
        if (b > 255)
            return 0;
        if (c > 255)
            return 0;
        if (d > 255)
            return 0;
        addr->s_addr = htonl((a << 24) | (b << 16) | (c << 8) | d);
        return 1;
#ifdef AF_INET6
    }
    else if (af == AF_INET6)
    {
        struct in6_addr *out = dst;
        uint16_t words[8];
        int gapPos = -1, i, setWords = 0;
        const char *dot = strchr(src, '.');
        const char *eow; /* end of words. */
        if (dot == src)
            return 0;
        else if (!dot)
            eow = src + strlen(src);
        else
        {
            unsigned byte1, byte2, byte3, byte4;
            char more;
            for (eow = dot - 1; eow >= src && isxdigit(*eow); --eow)
                ;
            ++eow;

            /* We use "scanf" because some platform inet_aton()s are too lax
			 * about IPv4 addresses of the form "1.2.3" */
            if (sscanf(eow, "%u.%u.%u.%u%c",
                       &byte1, &byte2, &byte3, &byte4, &more) != 4)
                return 0;

            if (byte1 > 255 ||
                byte2 > 255 ||
                byte3 > 255 ||
                byte4 > 255)
                return 0;

            words[6] = (byte1 << 8) | byte2;
            words[7] = (byte3 << 8) | byte4;
            setWords += 2;
        }

        i = 0;
        while (src < eow)
        {
            if (i > 7)
                return 0;
            if (isxdigit(*src))
            {
                char *next;
                long r = strtol(src, &next, 16);
                if (next > 4 + src)
                    return 0;
                if (next == src)
                    return 0;
                if (r < 0 || r > 65536)
                    return 0;

                words[i++] = (uint16_t)r;
                setWords++;
                src = next;
                if (*src != ':' && src != eow)
                    return 0;
                ++src;
            }
            else if (*src == ':' && i > 0 && gapPos == -1)
            {
                gapPos = i;
                ++src;
            }
            else if (*src == ':' && i == 0 && src[1] == ':' && gapPos == -1)
            {
                gapPos = i;
                src += 2;
            }
            else
            {
                return 0;
            }
        }

        if (setWords > 8 ||
            (setWords == 8 && gapPos != -1) ||
            (setWords < 8 && gapPos == -1))
            return 0;

        if (gapPos >= 0)
        {
            int nToMove = setWords - (dot ? 2 : 0) - gapPos;
            int gapLen = 8 - setWords;
            /* assert(nToMove >= 0); */
            if (nToMove < 0)
                return -1; /* should be impossible */
            memmove(&words[gapPos + gapLen], &words[gapPos],
                    sizeof(uint16_t) * nToMove);
            memset(&words[gapPos], 0, sizeof(uint16_t) * gapLen);
        }
        for (i = 0; i < 8; ++i)
        {
            out->s6_addr[2 * i] = words[i] >> 8;
            out->s6_addr[2 * i + 1] = words[i] & 0xff;
        }

        return 1;
#endif
    }
    else
    {
        return -1;
    }
#endif
}

int evutil_inet_pton_scope(int af, const char *src, void *dst, unsigned *indexp)
{
    int r;
    unsigned if_index;
    char *cp, *tmp_src;

    *indexp = 0; /* Reasonable default */

    /* Bail out if not IPv6 */
    if (af != AF_INET6)
        return evutil_inet_pton(af, src, dst);

    cp = strchr(src, '%');

    /* Bail out if no zone ID */
    if (cp == NULL)
        return evutil_inet_pton(af, src, dst);

    if_index = 1;
    //if_nametoindex(cp + 1);
    /*if (if_index == 0) {
		
		if_index = strtoul(cp + 1, &check, 10);
		if (check[0] != '\0')
			return 0;
	}*/
    *indexp = if_index;
    tmp_src = strdup(src);
    cp = strchr(tmp_src, '%');
    *cp = '\0';
    r = evutil_inet_pton(af, tmp_src, dst);
    free(tmp_src);
    return r;
}

int parse_sockaddr_port(const char *ip_as_string, struct sockaddr *out, int *outlen)
{
    int port;
    unsigned int if_index;
    char buf[128];
    const char *cp, *addr_part, *port_part;
    int is_ipv6;
    /* recognized formats are:
	 * [ipv6]:port
	 * ipv6
	 * [ipv6]
	 * ipv4:port
	 * ipv4
	 */

    cp = strchr(ip_as_string, ':');
    if (*ip_as_string == '[')
    {
        size_t len;
        if (!(cp = strchr(ip_as_string, ']')))
        {
            return -1;
        }
        len = (cp - (ip_as_string + 1));
        if (len > sizeof(buf) - 1)
        {
            return -1;
        }
        memcpy(buf, ip_as_string + 1, len);
        buf[len] = '\0';
        addr_part = buf;
        if (cp[1] == ':')
            port_part = cp + 2;
        else
            port_part = NULL;
        is_ipv6 = 1;
    }
    else if (cp && strchr(cp + 1, ':'))
    {
        is_ipv6 = 1;
        addr_part = ip_as_string;
        port_part = NULL;
    }
    else if (cp)
    {
        is_ipv6 = 0;
        if (cp - ip_as_string > (int)sizeof(buf) - 1)
        {
            return -1;
        }
        memcpy(buf, ip_as_string, cp - ip_as_string);
        buf[cp - ip_as_string] = '\0';
        addr_part = buf;
        port_part = cp + 1;
    }
    else
    {
        addr_part = ip_as_string;
        port_part = NULL;
        is_ipv6 = 0;
    }

    if (port_part == NULL)
    {
        port = 0;
    }
    else
    {
        port = atoi(port_part);
        if (port <= 0 || port > 65535)
        {
            return -1;
        }
    }

    if (!addr_part)
        return -1; /* Should be impossible. */
#ifdef AF_INET6
    if (is_ipv6)
    {
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof(sin6));
#ifdef EVENT__HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN
        sin6.sin6_len = sizeof(sin6);
#endif
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons(port);
        if (1 != evutil_inet_pton_scope(
                     AF_INET6, addr_part, &sin6.sin6_addr, &if_index))
        {
            return -1;
        }
        if ((int)sizeof(sin6) > *outlen)
            return -1;
        sin6.sin6_scope_id = if_index;
        memset(out, 0, *outlen);
        memcpy(out, &sin6, sizeof(sin6));
        *outlen = sizeof(sin6);
        return 0;
    }
    else
#endif
    {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
#ifdef EVENT__HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
        sin.sin_len = sizeof(sin);
#endif
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        if (1 != evutil_inet_pton(AF_INET, addr_part, &sin.sin_addr))
            return -1;
        if ((int)sizeof(sin) > *outlen)
            return -1;
        memset(out, 0, *outlen);
        memcpy(out, &sin, sizeof(sin));
        *outlen = sizeof(sin);
        return 0;
    }
}

btc_bool btc_node_set_ipport(btc_node *node, const char *ipport)
{
    int outlen = (int)sizeof(node->addr);

    //return true in case of success (0 == no error)
    return (parse_sockaddr_port(ipport, &node->addr, &outlen) == 0);
}


















void utils_clear_buffers(void)
{
    memset(buffer_hex_to_uint8, 0, TO_UINT8_HEX_BUF_LEN);
    memset(buffer_uint8_to_hex, 0, TO_UINT8_HEX_BUF_LEN);
}

void utils_hex_to_bin(const char* str, unsigned char* out, int inLen, int* outLen)
{
    int bLen = inLen / 2;
    int i;
    memset(out, 0, bLen);
    for (i = 0; i < bLen; i++) {
       
        if (str[i * 2] >= '0' && str[i * 2] <= '9') {
            *out = (str[i * 2] - '0') << 4;
        }
        if (str[i * 2] >= 'a' && str[i * 2] <= 'f') {
            *out = (10 + str[i * 2] - 'a') << 4;
        }
        if (str[i * 2] >= 'A' && str[i * 2] <= 'F') {
            *out = (10 + str[i * 2] - 'A') << 4;
        }
        if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') {
            *out |= (str[i * 2 + 1] - '0');
        }
        if (str[i * 2 + 1] >= 'a' && str[i * 2 + 1] <= 'f') {
            *out |= (10 + str[i * 2 + 1] - 'a');
        }
        if (str[i * 2 + 1] >= 'A' && str[i * 2 + 1] <= 'F') {
            *out |= (10 + str[i * 2 + 1] - 'A');
        }
        out++;
    }
    *outLen = i;
}

uint8_t* utils_hex_to_uint8(const char* str)
{
    uint8_t c;
    size_t i;
    
    if (strlens(str) > TO_UINT8_HEX_BUF_LEN) {
        return NULL;
    }

    memset(buffer_hex_to_uint8, 0, TO_UINT8_HEX_BUF_LEN);
    for (i = 0; i < strlens(str) / 2; i++) {
        c = 0;
        if (str[i * 2] >= '0' && str[i * 2] <= '9') {
            c += (str[i * 2] - '0') << 4;
        }
        if (str[i * 2] >= 'a' && str[i * 2] <= 'f') {
            c += (10 + str[i * 2] - 'a') << 4;
        }
        if (str[i * 2] >= 'A' && str[i * 2] <= 'F') {
            c += (10 + str[i * 2] - 'A') << 4;
        }
        if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') {
            c += (str[i * 2 + 1] - '0');
        }
        if (str[i * 2 + 1] >= 'a' && str[i * 2 + 1] <= 'f') {
            c += (10 + str[i * 2 + 1] - 'a');
        }
        if (str[i * 2 + 1] >= 'A' && str[i * 2 + 1] <= 'F') {
            c += (10 + str[i * 2 + 1] - 'A');
        }
        buffer_hex_to_uint8[i] = c;
    }
    return buffer_hex_to_uint8;
}


void utils_bin_to_hex(unsigned char* bin_in, size_t inlen, char* hex_out)
{
    static char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < inlen; i++) {
        hex_out[i * 2] = digits[(bin_in[i] >> 4) & 0xF];
        hex_out[i * 2 + 1] = digits[bin_in[i] & 0xF];
    }
    hex_out[inlen * 2] = '\0';
}


char* utils_uint8_to_hex(const uint8_t* bin, size_t l)
{
    static char digits[] = "0123456789abcdef";
    size_t i;
    if (l > (TO_UINT8_HEX_BUF_LEN / 2 - 1)) {
        return NULL;
    }
    memset(buffer_uint8_to_hex, 0, TO_UINT8_HEX_BUF_LEN);
    for (i = 0; i < l; i++) {
        buffer_uint8_to_hex[i * 2] = digits[(bin[i] >> 4) & 0xF];
        buffer_uint8_to_hex[i * 2 + 1] = digits[bin[i] & 0xF];
    }
    buffer_uint8_to_hex[l * 2] = '\0';
    return buffer_uint8_to_hex;
}

void utils_reverse_hex(char* h, int len)
{
    char* copy = btc_malloc(len);
    int i;
    strncpy(copy, h, len);
    for (i = 0; i < len; i += 2) {
        h[i] = copy[len - i - 2];
        h[i + 1] = copy[len - i - 1];
    }
    btc_free(copy);
}

const signed char p_util_hexdigit[256] =
    {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1,
        -1, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

signed char utils_hex_digit(char c)
{
    return p_util_hexdigit[(unsigned char)c];
}

void utils_uint256_sethex(char* psz, uint8_t* out)
{
    memset(out, 0, sizeof(uint256));

    // skip leading spaces
    while (isspace(*psz))
        psz++;

    // skip 0x
    if (psz[0] == '0' && tolower(psz[1]) == 'x')
        psz += 2;

    // hex string to uint
    const char* pbegin = psz;
    while (utils_hex_digit(*psz) != -1)
        psz++;
    psz--;
    unsigned char* p1 = (unsigned char*)out;
    unsigned char* pend = p1 + sizeof(uint256);
    while (psz >= pbegin && p1 < pend) {
        *p1 = utils_hex_digit(*psz--);
        if (psz >= pbegin) {
            *p1 |= ((unsigned char)utils_hex_digit(*psz--) << 4);
            p1++;
        }
    }
}

void* safe_malloc(size_t size)
{
    void* result;

    if ((result = ps_malloc(size))) { /* assignment intentional */
        return (result);
    } else {
        printf("memory overflow: malloc failed in safe_malloc.");
        printf("  Exiting Program.\n");
        exit(-1);
        return (0);
    }
}

void btc_cheap_random_bytes(uint8_t* buf, uint32_t len)
{
    srand(time(NULL));
    for (uint32_t i = 0; i < len; i++) {
        buf[i] = rand();
    }
}


int btc_get_active_peers_from_dns(const char *seed, vector *ips_out, int port, int family)
{
    if (!seed || !ips_out || (family != AF_INET && family != AF_INET6) || port > 99999)
    {
        return 0;
    }
    char def_port[6] = {0};
    sprintf(def_port, "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    //hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *aiTrav = NULL, *aiRes = NULL;

    int err = getaddrinfo(seed, "8333", &hints, &aiRes);

    if (err != 0)
        return 0;

    aiTrav = aiRes;
    while (aiTrav != NULL)
    {
        int maxlen = 256;
        char *ipaddr = btc_calloc(1, maxlen);
        if (aiTrav->ai_family == AF_INET)
        {
            // assert(aiTrav->ai_addrlen >= sizeof(struct sockaddr_in));
            inet_ntop(aiTrav->ai_family, &((struct sockaddr_in *)(aiTrav->ai_addr))->sin_addr, ipaddr, maxlen);
        }

        if (aiTrav->ai_family == AF_INET6)
        {
            //assert(aiTrav->ai_addrlen >= sizeof(struct sockaddr_in6));
            inet_ntop(aiTrav->ai_family, &((struct sockaddr_in6 *)(aiTrav->ai_addr))->sin6_addr, ipaddr, maxlen);
        }

        memcpy(ipaddr + strlen(ipaddr), ":", 1);
        memcpy(ipaddr + strlen(ipaddr), def_port, strlen(def_port));
        //DBGMSG("[+]DNS %s", ipaddr);
        vector_add(ips_out, ipaddr);

        aiTrav = aiTrav->ai_next;
    }
    freeaddrinfo(aiRes);
    return ips_out->len;
}

void btc_node_group_add_peers_by_ip_port(uint32_t node_ipaddr, uint16_t node_port, btc_node_group *group)
{

    btc_node *node = btc_node_new();

    node->rip = htonl(node_ipaddr);
    node->rport = node_port;
    
    
}

btc_bool btc_node_group_add_peers_by_seed(const char *btc_seed, btc_node_group *group)
{

    /* === DNS QUERY === */
    /* get a couple of peers from a seed */
    vector *ips_dns = vector_new(10, free);
    btc_bool bret = false;
    // "seed.bitcoin.sipa.be"
    /* todo: make sure we have enought peers, eventually */
    if (btc_get_active_peers_from_dns(btc_seed, ips_dns, 8333, AF_INET) != 0)
    {
        for (unsigned int i = 0; i < ips_dns->len; i++)
        {
            char *ip = (char *)vector_idx(ips_dns, i);
            DBGMSG("[+]found btc node ip %s total %d]\n", ip, ips_dns->len);

            /* create a node */
            btc_node *node = btc_node_new();
            if (btc_node_set_ipport(node, ip) > 0)
            {
                /* add the node to the group */

                //struct sockaddr_in antelope;
                unsigned int node_ipaddr;
                memcpy(&node_ipaddr, node->addr.sa_data + 2, 4); //get node ip address
                unsigned short node_port;
                memcpy(&node_port, node->addr.sa_data, 2); //get node port
                node_port = ntohs(node_port);
                node->rip = ntohl(node_ipaddr);
                node->rport = node_port;

                DBGMSG("[+]btc_node_group_add_peers_by_seed::added ip %08X:%d", node_ipaddr, node_port);

                vector_add(group->nodes, node);
                node->nodegroup = group;
                node->nodeid = group->nodes->len;
                bret = true;
            }
            break;
        }
    }
    vector_free(ips_dns, true);

    return bret;
}



void btc_get_default_datadir(cstring *path_out)
{
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\Bitcoin
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\Bitcoin
    // Mac: ~/Library/Application Support/Bitcoin
    // Unix: ~/.bitcoin
#ifdef WIN32
    // Windows
    char* homedrive = getenv("HOMEDRIVE");
    char* homepath = getenv("HOMEDRIVE");
    cstr_append_buf(path_out, homedrive, strlen(homedrive));
    cstr_append_buf(path_out, homepath, strlen(homepath));
#else
    char* home = getenv("HOME");
    if (home == NULL || strlen(home) == 0)
        cstr_append_c(path_out, '/');
    else
        cstr_append_buf(path_out, home, strlen(home));
#ifdef __APPLE__
    // Mac
    char *osx_home = "/Library/Application Support/Bitcoin";
    cstr_append_buf(path_out, osx_home, strlen(osx_home));
#else
    // Unix
    //char *posix_home = "/.bitcoin";
    //cstr_append_buf(path_out, posix_home, strlen(posix_home));
#endif
#endif
}

void btc_file_commit(FILE *file)
{
    fflush(file); // harmless if redundantly called
#ifdef WIN32
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(file));
    FlushFileBuffers(hFile);
#else
    #if defined(__linux__) || defined(__NetBSD__)
    fdatasync(fileno(file));
    #elif defined(__APPLE__) && defined(F_FULLFSYNC)
    fcntl(fileno(file), F_FULLFSYNC, 0);
    #else
    fsync(fileno(file));
    #endif
#endif
}
