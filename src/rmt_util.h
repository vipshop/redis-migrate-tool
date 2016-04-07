#ifndef _RMT_UTIL_H_
#define _RMT_UTIL_H_

#include <stdarg.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <limits.h>

#define LF                  (uint8_t) 10
#define CR                  (uint8_t) 13
#define CRLF                "\x0d\x0a"
#define CRLF_LEN            (sizeof("\x0d\x0a") - 1)

#define NELEMS(a)           ((sizeof(a)) / sizeof((a)[0]))

#define MIN(a, b)           ((a) < (b) ? (a) : (b))
#define MAX(a, b)           ((a) > (b) ? (a) : (b))

#define SQUARE(d)           ((d) * (d))
#define VAR(s, s2, n)       (((n) < 2) ? 0.0 : ((s2) - SQUARE(s)/(n)) / ((n) - 1))
#define STDDEV(s, s2, n)    (((n) < 2) ? 0.0 : sqrt(VAR((s), (s2), (n))))

#define RMT_TIME_NONE             0
#define RMT_TIME_SECOND           1
#define RMT_TIME_MILLISECOND      2
#define RMT_TIME_MICROSECOND      3

/*
 * Length of 1 byte, 2 bytes, 4 bytes, 8 bytes and largest integral
 * type (uintmax_t) in ascii, including the null terminator '\0'
 *
 * From stdint.h, we have:
 * # define UINT8_MAX	(255)
 * # define UINT16_MAX	(65535)
 * # define UINT32_MAX	(4294967295U)
 * # define UINT64_MAX	(__UINT64_C(18446744073709551615))
 */
#define RMT_UINT8_MAXLEN     (3 + 1)
#define RMT_UINT16_MAXLEN    (5 + 1)
#define RMT_UINT32_MAXLEN    (10 + 1)
#define RMT_UINT64_MAXLEN    (20 + 1)
#define RMT_UINTMAX_MAXLEN   RMT_UINT64_MAXLEN

#define RMT_MAX_MSEC (((LONG_MAX) - 999) / 1000)

/*
 * Make data 'd' or pointer 'p', n-byte aligned, where n is a power of 2
 * of 2.
 */
#define RMT_ALIGNMENT        sizeof(unsigned long) /* platform word */
#define RMT_ALIGN(d, n)      (((d) + (n - 1)) & ~(n - 1))
#define RMT_ALIGN_PTR(p, n)  \
    (void *) (((uintptr_t) (p) + ((uintptr_t) n - 1)) & ~((uintptr_t) n - 1))

#define RMT_MAX_WRITTEN_BEFORE_FSYNC (1024*1024*8) /* 8 MB */

/*
 * Wrapper to workaround well known, safe, implicit type conversion when
 * invoking system calls.
 */

#define rmt_atoi(_line, _len)          \
    _rmt_atoi((char *)_line, (int)_len)

#define rmt_atoll(_line, len)          \
    _rmt_atoll((char *)_line, (int)len)

#define rmt_itoa(n, _line)          \
    _rmt_itoa((int)n, (char *)_line)

#define rmt_lltoa(_dst, _dstlen, _svalue)      \
    _rmt_lltoa((char*)_dst, (size_t)_dstlen, (long long)_svalue)

int _rmt_atoi(const char* str, int len);
long long _rmt_atoll(const char* str, int len);
void _rmt_itoa(int n, char s[]);
int _rmt_lltoa(char* dst, size_t dstlen, long long svalue);
char _rmt_tohex(int n);
void _rmt_dec2hex(int n,char s[]);

/*
 * Memory allocation and free wrappers.
 *
 * These wrappers enables us to loosely detect double free, dangling
 * pointer access and zero-byte alloc.
 */
#define rmt_alloc(_s)                    \
    _rmt_alloc((size_t)(_s), __FILE__, __LINE__)

#define rmt_zalloc(_s)                   \
    _rmt_zalloc((size_t)(_s), __FILE__, __LINE__)

#define rmt_calloc(_n, _s)               \
    _rmt_calloc((size_t)(_n), (size_t)(_s), __FILE__, __LINE__)

#define rmt_realloc(_p, _s)              \
    _rmt_realloc(_p, (size_t)(_s), __FILE__, __LINE__)

#define rmt_free(_p) do {                \
    _rmt_free(_p, __FILE__, __LINE__);   \
    (_p) = NULL;                        \
} while (0)

void *_rmt_alloc(size_t size, const char *name, int line);
void *_rmt_zalloc(size_t size, const char *name, int line);
void *_rmt_calloc(size_t nmemb, size_t size, const char *name, int line);
void *_rmt_realloc(void *ptr, size_t size, const char *name, int line);
void _rmt_free(void *ptr, const char *name, int line);

char *rmt_malloc_lib(void);

/*
 * Wrappers to read or write data to/from (multiple) buffers
 * to a file or socket descriptor.
 */
#define rmt_read(_d, _b, _n)     \
    read(_d, _b, (size_t)(_n))

#define rmt_readv(_d, _b, _n)    \
    readv(_d, _b, (int)(_n))

#define rmt_write(_d, _b, _n)    \
    write(_d, _b, (size_t)(_n))

#define rmt_writev(_d, _b, _n)   \
    writev(_d, _b, (int)(_n))

#define rmt_fread(_d, _b, _n)   \
    fread((void *)_b, 1, _n, _d)

#ifdef HAVE_SYNC_FILE_RANGE
#define rmt_fsync_range(fd,off,size)    \
    sync_file_range(fd,off,size,SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE)
#else
#define rmt_fsync_range(fd,off,size) fsync(fd)
#endif

/*
 * Wrappers for defining custom assert based on whether macro
 * RMT_ASSERT_PANIC or RMT_ASSERT_LOG was defined at the moment
 * ASSERT was called.
 */
#ifdef RMT_ASSERT_PANIC

#define ASSERT(_x) do {                         \
    if (!(_x)) {                                \
        rmt_assert(#_x, __FILE__, __LINE__, 1);  \
    }                                           \
} while (0)

#define NOT_REACHED() ASSERT(0)

#elif RMT_ASSERT_LOG

#define ASSERT(_x) do {                         \
    if (!(_x)) {                                \
        rmt_assert(#_x, __FILE__, __LINE__, 0);  \
    }                                           \
} while (0)

#define NOT_REACHED() ASSERT(0)

#else

#define ASSERT(_x)

#define NOT_REACHED()

#endif

void rmt_assert(const char *cond, const char *file, int line, int panic);
void rmt_stacktrace(int skip_count);
void rmt_stacktrace_fd(int fd);

int _scnprintf(char *buf, size_t size, const char *fmt, ...);
int _vscnprintf(char *buf, size_t size, const char *fmt, va_list args);
long long rmt_usec_now(void);
long long rmt_msec_now(void);

/*
 * Wrapper around common routines for manipulating C character
 * strings
 */
#define rmt_memset(_d, _c, _n)           \
        memset(_d, _c, (size_t)(_n))

#define rmt_memcpy(_d, _c, _n)           \
    memcpy(_d, _c, (size_t)(_n))

#define rmt_memmove(_d, _c, _n)          \
    memmove(_d, _c, (size_t)(_n))

#define rmt_memchr(_d, _c, _n)           \
    memchr(_d, _c, (size_t)(_n))

#define rmt_strlen(_s)                   \
    strlen((char *)(_s))

#define rmt_strncmp(_s1, _s2, _n)        \
    strncmp((char *)(_s1), (char *)(_s2), (size_t)(_n))

#define rmt_strchr(_p, _l, _c)           \
    _rmt_strchr((uint8_t *)(_p), (uint8_t *)(_l), (uint8_t)(_c))

#define rmt_strrchr(_p, _s, _c)          \
    _rmt_strrchr((uint8_t *)(_p),(uint8_t *)(_s), (uint8_t)(_c))

#define rmt_strdup(_s)              \
    (char *)strdup((char *)(_s));

#define rmt_strndup(_s, _n)              \
    (char *)strndup((char *)(_s), (size_t)(_n));

#define rmt_snprintf(_s, _n, ...)        \
    snprintf((char *)(_s), (size_t)(_n), __VA_ARGS__)

#define rmt_scnprintf(_s, _n, ...)       \
    _scnprintf((char *)(_s), (size_t)(_n), __VA_ARGS__)

#define rmt_vscnprintf(_s, _n, _f, _a)   \
    _vscnprintf((char *)(_s), (size_t)(_n), _f, _a)

#define rmt_strftime(_s, _n, fmt, tm)        \
    (int)strftime((char *)(_s), (size_t)(_n), fmt, tm)


/*
 * A (very) limited version of snprintf
 * @param   to   Destination buffer
 * @param   n    Size of destination buffer
 * @param   fmt  printf() style format string
 * @returns Number of bytes written, including terminating '\0'
 * Supports 'd' 'i' 'u' 'x' 'p' 's' conversion
 * Supports 'l' and 'll' modifiers for integral types
 * Does not support any width/precision
 * Implemented with simplicity, and async-signal-safety in mind
 */
int _safe_vsnprintf(char *to, size_t size, const char *format, va_list ap);
int _safe_snprintf(char *to, size_t n, const char *fmt, ...);

#define rmt_safe_snprintf(_s, _n, ...)       \
    _safe_snprintf((char *)(_s), (size_t)(_n), __VA_ARGS__)

#define rmt_safe_vsnprintf(_s, _n, _f, _a)   \
    _safe_vsnprintf((char *)(_s), (size_t)(_n), _f, _a)

static inline uint8_t *
_rmt_strchr(uint8_t *p, uint8_t *last, uint8_t c)
{
    while (p < last) {
        if (*p == c) {
            return p;
        }
        p++;
    }

    return NULL;
}

static inline uint8_t *
_rmt_strrchr(uint8_t *p, uint8_t *start, uint8_t c)
{
    while (p >= start) {
        if (*p == c) {
            return p;
        }
        p--;
    }

    return NULL;
}

uint64_t size_string_to_integer_byte(char *size, int size_len);
void integer_byte_to_size_string(char *s, uint64_t n);

ssize_t rmt_sync_write(int fd, const char *ptr, ssize_t size, long long timeout);
ssize_t rmt_sync_read(int fd, char *ptr, ssize_t size, long long timeout);
ssize_t rmt_sync_readline(int fd, char *ptr, ssize_t size, long long timeout);


#if (BYTE_ORDER == LITTLE_ENDIAN)

#define str4cmp(m, c0, c1, c2, c3)                                                          \
    (*(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0))

#define str5cmp(m, c0, c1, c2, c3, c4)                                                      \
    (str4cmp(m, c0, c1, c2, c3) && (m[4] == c4))

#define str6cmp(m, c0, c1, c2, c3, c4, c5)                                                  \
    (str4cmp(m, c0, c1, c2, c3) &&                                                          \
        (((uint32_t *) m)[1] & 0xffff) == ((c5 << 8) | c4))

#define str7cmp(m, c0, c1, c2, c3, c4, c5, c6)                                              \
    (str6cmp(m, c0, c1, c2, c3, c4, c5) && (m[6] == c6))

#define str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                                          \
    (str4cmp(m, c0, c1, c2, c3) &&                                                          \
        (((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)))

#define str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                                      \
    (str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7) && m[8] == c8)

#define str10cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9)                                 \
    (str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7) &&                                          \
        (((uint32_t *) m)[2] & 0xffff) == ((c9 << 8) | c8))

#define str11cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10)                            \
    (str10cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9) && (m[10] == c10))

#define str12cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11)                       \
    (str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7) &&                                          \
        (((uint32_t *) m)[2] == ((c11 << 24) | (c10 << 16) | (c9 << 8) | c8)))

#else

#define str4cmp(m, c0, c1, c2, c3)                                                          \
    (m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3)

#define str5cmp(m, c0, c1, c2, c3, c4)                                                      \
    (str4cmp(m, c0, c1, c2, c3) && (m[4] == c4))

#define str6cmp(m, c0, c1, c2, c3, c4, c5)                                                  \
    (str5cmp(m, c0, c1, c2, c3, c4) && m[5] == c5)

#define str7cmp(m, c0, c1, c2, c3, c4, c5, c6)                                              \
    (str6cmp(m, c0, c1, c2, c3, c4, c5) && m[6] == c6)

#define str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                                          \
    (str7cmp(m, c0, c1, c2, c3, c4, c5, c6) && m[7] == c7)

#define str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                                      \
    (str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7) && m[8] == c8)

#define str10cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9)                                 \
    (str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8) && m[9] == c9)

#define str11cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10)                            \
    (str10cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9) && m[10] == c10)

#define str12cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11)                       \
    (str11cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) && m[11] == c11)

#endif

#define str3icmp(m, c0, c1, c2)                                                             \
    ((m[0] == c0 || m[0] == (c0 ^ 0x20)) &&                                                 \
     (m[1] == c1 || m[1] == (c1 ^ 0x20)) &&                                                 \
     (m[2] == c2 || m[2] == (c2 ^ 0x20)))

#define str4icmp(m, c0, c1, c2, c3)                                                         \
    (str3icmp(m, c0, c1, c2) && (m[3] == c3 || m[3] == (c3 ^ 0x20)))

#define str5icmp(m, c0, c1, c2, c3, c4)                                                     \
    (str4icmp(m, c0, c1, c2, c3) && (m[4] == c4 || m[4] == (c4 ^ 0x20)))

#define str6icmp(m, c0, c1, c2, c3, c4, c5)                                                 \
    (str5icmp(m, c0, c1, c2, c3, c4) && (m[5] == c5 || m[5] == (c5 ^ 0x20)))

#define str7icmp(m, c0, c1, c2, c3, c4, c5, c6)                                             \
    (str6icmp(m, c0, c1, c2, c3, c4, c5) &&                                                 \
     (m[6] == c6 || m[6] == (c6 ^ 0x20)))

#define str8icmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                                         \
    (str7icmp(m, c0, c1, c2, c3, c4, c5, c6) &&                                             \
     (m[7] == c7 || m[7] == (c7 ^ 0x20)))

#define str9icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                                     \
    (str8icmp(m, c0, c1, c2, c3, c4, c5, c6, c7) &&                                         \
     (m[8] == c8 || m[8] == (c8 ^ 0x20)))

#define str10icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9)                                \
    (str9icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8) &&                                     \
     (m[9] == c9 || m[9] == (c9 ^ 0x20)))

#define str11icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10)                           \
    (str10icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9) &&                                \
     (m[10] == c10 || m[10] == (c10 ^ 0x20)))

#define str12icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11)                      \
    (str11icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) &&                           \
     (m[11] == c11 || m[11] == (c11 ^ 0x20)))

#define str13icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12)                 \
    (str12icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11) &&                      \
     (m[12] == c12 || m[12] == (c12 ^ 0x20)))

#define str14icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13)            \
    (str13icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12) &&                 \
     (m[13] == c13 || m[13] == (c13 ^ 0x20)))

#define str15icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14)       \
    (str14icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13) &&            \
     (m[14] == c14 || m[14] == (c14 ^ 0x20)))

#define str16icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15)  \
    (str15icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14) &&       \
     (m[15] == c15 || m[15] == (c15 ^ 0x20)))


void memrev16(void *p);
void memrev32(void *p);
void memrev64(void *p);
uint16_t intrev16(uint16_t v);
uint32_t intrev32(uint32_t v);
uint64_t intrev64(uint64_t v);

/* variants of the function doing the actual convertion only if the target
 * host is big endian */
#if (BYTE_ORDER == LITTLE_ENDIAN)
#define memrev16ifbe(p)
#define memrev32ifbe(p)
#define memrev64ifbe(p)
#define intrev16ifbe(v) (v)
#define intrev32ifbe(v) (v)
#define intrev64ifbe(v) (v)
#else
#define memrev16ifbe(p) memrev16(p)
#define memrev32ifbe(p) memrev32(p)
#define memrev64ifbe(p) memrev64(p)
#define intrev16ifbe(v) intrev16(v)
#define intrev32ifbe(v) intrev32(v)
#define intrev64ifbe(v) intrev64(v)
#endif

#endif

