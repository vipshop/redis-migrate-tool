
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <rmt_core.h>

#ifdef RMT_HAVE_BACKTRACE
# include <execinfo.h>
#endif

#ifdef RMT_JEMALLOC
# include <jemalloc/jemalloc.h>
#endif

#define RMT_SYNCIO_RESOLUTION 10 /* Resolution in milliseconds */

int
_rmt_atoi(const char* str, int len){

	int res=0;
	char sign='+';
	const char *pStr=str;

    if(str == NULL || len <= 0)
	{
		return 0;
	}

	while (*pStr==' ' && len > 0)
    {   
        pStr++;
        len --;
    }

    if(len <= 0)
    {
        return 0;
    }

	if(*pStr=='+' || *pStr=='-')
    {   
	    sign=*pStr++;
        len --;
    }

    if(len <= 0)
    {
        return 0;
    }
    
	while (*pStr>='0' && *pStr<='9' && len > 0)
	{
        res=res*10+*pStr-'0';
        pStr++;
        len --;
	}

	return sign=='-'?-res:res;
}

long long
_rmt_atoll(const char* str, int len){
	
	long long res=0;
	char sign='+';
	const char *pStr=str;

    
    if(str == NULL || len <= 0)
    {
        return 0;
    }

	while (*pStr==' ' && len > 0)
	{
	    pStr++;
	    len --;
	}

    if(len <= 0)
    {
        return 0;
    }

	if(*pStr=='+' || *pStr=='-')
	{
	    sign=*pStr++;    
        len --;
	}

    if(len <= 0)
    {
        return 0;
    }

	while (*pStr>='0' && *pStr<='9' && len > 0)
	{
	    res=res*10+*pStr-'0';
	    pStr++;
	    len --;
	}

	return sign=='-'?-res:res;
}

static void
_rever(char s[]){
	if(s == NULL)
	{
	  return;
	}

	int len=(int)strlen(s);
	int i=0;
	int j=len-1;
	char c;
	while (i<j)
	{
	  c=s[i];
	  s[i]=s[j];
	  s[j]=c;
	  i++;
	  j--;
	}
}

void
_rmt_itoa(int n, char s[]){
	if(s == NULL)
	{
	  return;
	}

	int i=0;
	int sign=0;

	if((sign=n)<0)
	  n=-n;

	do {
	  s[i++]=(char)(n%10+'0');
	} while ((n/=10)>0);
	if(sign<0)
	  s[i++]='-';

	s[i]='\0';
	_rever(s);
}

/* Return the number of digits of 'v' when converted to string in radix 10.
 * See _rmt_lltoa() for more information. */
static uint32_t 
_digits10(uint64_t v) {
    if (v < 10) return 1;
    if (v < 100) return 2;
    if (v < 1000) return 3;
    if (v < 1000000000000UL) {
        if (v < 100000000UL) {
            if (v < 1000000) {
                if (v < 10000) return 4;
                return 5 + (v >= 100000);
            }
            return 7 + (v >= 10000000UL);
        }
        if (v < 10000000000UL) {
            return 9 + (v >= 1000000000UL);
        }
        return 11 + (v >= 100000000000UL);
    }
    return 12 + _digits10(v / 1000000000000UL);
}

/* Convert a long long into a string. Returns the number of
 * characters needed to represent the number.
 * If the buffer is not big enough to store the string, 0 is returned.
 *
 * Based on the following article (that apparently does not provide a
 * novel approach but only publicizes an already used technique):
 *
 * https://www.facebook.com/notes/facebook-engineering/three-optimization-tips-for-c/10151361643253920
 *
 * Modified in order to handle signed integers since the original code was
 * designed for unsigned integers. */
int 
_rmt_lltoa(char* dst, size_t dstlen, long long svalue) {
    static const char digits[201] =
        "0001020304050607080910111213141516171819"
        "2021222324252627282930313233343536373839"
        "4041424344454647484950515253545556575859"
        "6061626364656667686970717273747576777879"
        "8081828384858687888990919293949596979899";
    int negative;
    unsigned long long value;

    /* The main loop works with 64bit unsigned integers for simplicity, so
     * we convert the number here and remember if it is negative. */
    if (svalue < 0) {
        if (svalue != LLONG_MIN) {
            value = (unsigned long long)(-svalue);
        } else {
            value = ((unsigned long long) LLONG_MAX)+1;
        }
        negative = 1;
    } else {
        value = (unsigned long long)svalue;
        negative = 0;
    }

    /* Check length. */
    uint32_t const length = _digits10(value)+(uint32_t)negative;
    if (length >= dstlen) return 0;

    /* Null term. */
    uint32_t next = length;
    dst[next] = '\0';
    next--;
    while (value >= 100) {
        int const i = (int)((value % 100) * 2);
        value /= 100;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
        next -= 2;
    }

    /* Handle last 1-2 digits. */
    if (value < 10) {
        dst[next] = (char)('0' + (uint32_t) value);
    } else {
        int i = (int) (value * 2);
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
    }

    /* Add sign. */
    if (negative) dst[0] = '-';
    return (int)length;
}

char
_rmt_tohex(int n)
{
	if(n>=10 && n<=15)
	{
		return (char)('A'+n-10);
	}

	return (char)('0'+n);
}

void
_rmt_dec2hex(int n,char s[])
{
	int i=0;
	int mod;

	if(n <= 0)
	{
		s[0] = '\0';
		return;
	}

	while(n)
	{
		mod = n%16;
		s[i++]=_rmt_tohex(mod);
		n=n/16;
	}

	s[i]='\0';

	_rever(s);
}

void *
_rmt_alloc(size_t size, const char *name, int line)
{
    void *p;

    ASSERT(size != 0);
#ifdef RMT_JEMALLOC
    p = je_malloc(size);
#else
    p = malloc(size);
#endif
    if (p == NULL) {
        log_error("malloc(%zu) failed @ %s:%d", size, name, line);
    } else {
        log_debug(LOG_VVVERB, "malloc(%zu) at %p @ %s:%d", size, p, name, line);
    }

    return p;
}

void *
_rmt_zalloc(size_t size, const char *name, int line)
{
    void *p;

    p = _rmt_alloc(size, name, line);
    if (p != NULL) {
        memset(p, 0, size);
    }

    return p;
}

void *
_rmt_calloc(size_t nmemb, size_t size, const char *name, int line)
{
    return _rmt_zalloc(nmemb * size, name, line);
}

void *
_rmt_realloc(void *ptr, size_t size, const char *name, int line)
{
    void *p;

    ASSERT(size != 0);
#ifdef RMT_JEMALLOC
    p = je_realloc(ptr, size);
#else
    p = realloc(ptr, size);
#endif
    if (p == NULL) {
        log_error("realloc(%zu) failed @ %s:%d", size, name, line);
    } else {
        log_debug(LOG_VVVERB, "realloc(%zu) at %p @ %s:%d", size, p, name, line);
    }

    return p;
}

void
_rmt_free(void *ptr, const char *name, int line)
{
    ASSERT(ptr != NULL);
    log_debug(LOG_VVVERB, "free(%p) @ %s:%d", ptr, name, line);
#ifdef RMT_JEMALLOC
    je_free(ptr);
#else
    free(ptr);
#endif
}

void
rmt_stacktrace(int skip_count)
{
#ifdef RMT_HAVE_BACKTRACE
    void *stack[64];
    char **symbols;
    int size, i, j;

    size = backtrace(stack, 64);
    symbols = backtrace_symbols(stack, size);
    if (symbols == NULL) {
        return;
    }

    skip_count++; /* skip the current frame also */

    for (i = skip_count, j = 0; i < size; i++, j++) {
        loga("[%d] %s", j, symbols[i]);
    }

    free(symbols);
#endif
}

void
rmt_stacktrace_fd(int fd)
{
#ifdef RMT_HAVE_BACKTRACE
    void *stack[64];
    int size;

    size = backtrace(stack, 64);
    backtrace_symbols_fd(stack, size, fd);
#endif
}

void
rmt_assert(const char *cond, const char *file, int line, int panic)
{
    log_error("assert '%s' failed @ (%s, %d)", cond, file, line);
    if (panic) {
        rmt_stacktrace(1);
        abort();
    }
}

int
_vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
    int n;

    n = vsnprintf(buf, size, fmt, args);

    /*
     * The return value is the number of characters which would be written
     * into buf not including the trailing '\0'. If size is == 0 the
     * function returns 0.
     *
     * On error, the function also returns 0. This is to allow idiom such
     * as len += _vscnprintf(...)
     *
     * See: http://lwn.net/Articles/69419/
     */
    if (n <= 0) {
        return 0;
    }

    if (n < (int) size) {
        return n;
    }

    return (int)(size - 1);
}

int
_scnprintf(char *buf, size_t size, const char *fmt, ...)
{
    va_list args;
    int n;

    va_start(args, fmt);
    n = _vscnprintf(buf, size, fmt, args);
    va_end(args);

    return n;
}

/*
 * Return the current time in microseconds since Epoch
 */
long long
rmt_usec_now(void)
{
    struct timeval now;
    long long usec;
    int status;

    status = gettimeofday(&now, NULL);
    if (status < 0) {
        log_error("gettimeofday failed: %s", strerror(errno));
        return -1;
    }

    usec = now.tv_sec * 1000000LL + now.tv_usec;

    return usec;
}

/*
 * Return the current time in milliseconds since Epoch
 */
long long
rmt_msec_now(void)
{
    return rmt_usec_now() / 1000LL;
}

static char *
_safe_utoa(int _base, uint64_t val, char *buf)
{
    char hex[] = "0123456789abcdef";
    uint32_t base = (uint32_t) _base;
    *buf-- = 0;
    do {
        *buf-- = hex[val % base];
    } while ((val /= base) != 0);
    return buf + 1;
}

static char *
_safe_itoa(int base, int64_t val, char *buf)
{
    char hex[] = "0123456789abcdef";
    char *orig_buf = buf;
    const int32_t is_neg = (val < 0);
    *buf-- = 0;

    if (is_neg) {
        val = -val;
    }
    if (is_neg && base == 16) {
        int ix;
        val -= 1;
        for (ix = 0; ix < 16; ++ix)
            buf[-ix] = '0';
    }

    do {
        *buf-- = hex[val % base];
    } while ((val /= base) != 0);

    if (is_neg && base == 10) {
        *buf-- = '-';
    }

    if (is_neg && base == 16) {
        int ix;
        buf = orig_buf - 1;
        for (ix = 0; ix < 16; ++ix, --buf) {
            /* *INDENT-OFF* */
            switch (*buf) {
            case '0': *buf = 'f'; break;
            case '1': *buf = 'e'; break;
            case '2': *buf = 'd'; break;
            case '3': *buf = 'c'; break;
            case '4': *buf = 'b'; break;
            case '5': *buf = 'a'; break;
            case '6': *buf = '9'; break;
            case '7': *buf = '8'; break;
            case '8': *buf = '7'; break;
            case '9': *buf = '6'; break;
            case 'a': *buf = '5'; break;
            case 'b': *buf = '4'; break;
            case 'c': *buf = '3'; break;
            case 'd': *buf = '2'; break;
            case 'e': *buf = '1'; break;
            case 'f': *buf = '0'; break;
            }
            /* *INDENT-ON* */
        }
    }
    return buf + 1;
}

static const char *
_safe_check_longlong(const char *fmt, int32_t * have_longlong)
{
    *have_longlong = 0;
    if (*fmt == 'l') {
        fmt++;
        if (*fmt != 'l') {
            *have_longlong = (sizeof(long) == sizeof(int64_t));
        } else {
            fmt++;
            *have_longlong = 1;
        }
    }
    return fmt;
}

int
_safe_vsnprintf(char *to, size_t size, const char *format, va_list ap)
{
    char *start = to;
    char *end = start + size - 1;
    for (; *format; ++format) {
        int32_t have_longlong = false;
        if (*format != '%') {
            if (to == end) {    /* end of buffer */
                break;
            }
            *to++ = *format;    /* copy ordinary char */
            continue;
        }
        ++format;               /* skip '%' */

        format = _safe_check_longlong(format, &have_longlong);

        switch (*format) {
        case 'd':
        case 'i':
        case 'u':
        case 'x':
        case 'p':
            {
                int64_t ival = 0;
                uint64_t uval = 0;
                if (*format == 'p')
                    have_longlong = (sizeof(void *) == sizeof(uint64_t));
                if (have_longlong) {
                    if (*format == 'u') {
                        uval = va_arg(ap, uint64_t);
                    } else {
                        ival = va_arg(ap, int64_t);
                    }
                } else {
                    if (*format == 'u') {
                        uval = va_arg(ap, uint32_t);
                    } else {
                        ival = va_arg(ap, int32_t);
                    }
                }

                {
                    char buff[22];
                    const int base = (*format == 'x' || *format == 'p') ? 16 : 10;

		            /* *INDENT-OFF* */
                    char *val_as_str = (*format == 'u') ?
                        _safe_utoa(base, uval, &buff[sizeof(buff) - 1]) :
                        _safe_itoa(base, ival, &buff[sizeof(buff) - 1]);
		            /* *INDENT-ON* */

                    /* Strip off "ffffffff" if we have 'x' format without 'll' */
                    if (*format == 'x' && !have_longlong && ival < 0) {
                        val_as_str += 8;
                    }

                    while (*val_as_str && to < end) {
                        *to++ = *val_as_str++;
                    }
                    continue;
                }
            }
        case 's':
            {
                const char *val = va_arg(ap, char *);
                if (!val) {
                    val = "(null)";
                }
                while (*val && to < end) {
                    *to++ = *val++;
                }
                continue;
            }
        }
    }
    *to = 0;
    return (int)(to - start);
}

int
_safe_snprintf(char *to, size_t n, const char *fmt, ...)
{
    int result;
    va_list args;
    va_start(args, fmt);
    result = _safe_vsnprintf(to, n, fmt, args);
    va_end(args);
    return result;
}


uint64_t
size_string_to_integer_byte(char *size, int size_len)
{
    int i;
    char ch;
    char *pos;
    uint64_t num = 0;
    uint64_t multiple_for_unit = 1;
    int first_nonzero_flag = 0;

    if(size == NULL || size_len <= 0)
    {
        return 0;
    }
    
	if(size_len > 2)
	{
		pos = size + size_len - 2;
		if((*pos == 'G' || *pos == 'g') && (*(pos+1) == 'B' || *(pos+1) == 'b'))
		{
			multiple_for_unit = 1073741824;
			size_len -= 2;
		}
		else if((*pos == 'M' || *pos == 'm') && (*(pos+1) == 'B' || *(pos+1) == 'b'))
		{
			multiple_for_unit = 1048576;
			size_len -= 2;
		}
        else if((*pos == 'K' || *pos == 'k') && (*(pos+1) == 'B' || *(pos+1) == 'b'))
		{
			multiple_for_unit = 1024;
			size_len -= 2;
		}
		else if(*(pos+1) == 'G' || *(pos+1) == 'g')
		{
    		multiple_for_unit = 1000000000;
			size_len -= 1;
		}
		else if(*(pos+1) == 'M' || *(pos+1) == 'm')
		{
			multiple_for_unit = 1000000;
			size_len -= 1;
		}
        else if(*(pos+1) == 'K' || *(pos+1) == 'k')
		{
			multiple_for_unit = 1000;
			size_len -= 1;
		}
		else if(*(pos+1) == 'B' || *(pos+1) == 'b')
		{
			size_len -= 1;
		}
	}
	else if(size_len > 1)
	{
		pos = size + size_len - 1;
		if(*pos == 'G' || *pos == 'g')
		{   
			multiple_for_unit = 1000000000;
			size_len -= 1;
		}
		else if(*pos == 'M' || *pos == 'm')
		{   
			multiple_for_unit = 1000000;
			size_len -= 1;
		}
        else if(*pos == 'K' || *pos == 'k')
		{   
			multiple_for_unit = 1000000;
			size_len -= 1;
		}
		else if(*pos == 'B' || *pos == 'b')
		{
		    size_len -= 1;
		}
	}

	for(i = 0; i < size_len; i ++)
	{
		ch = *(size + i);
		if(ch < '0' || ch > '9')
		{
			return 0;
		}
		else if(!first_nonzero_flag && ch != '0')
		{
			first_nonzero_flag = 1;
		}
		
		if(first_nonzero_flag)
		{
			num = (uint64_t)(10*num + (ch - 48));
		}
	}
    
	num *= multiple_for_unit;

	if(first_nonzero_flag == 0)
	{
		return 0;
	}

    return num;
}


/* Write the specified payload to 'fd'. If writing the whole payload will be
 * done within 'timeout' milliseconds the operation succeeds and 'size' is
 * returned. Otherwise the operation fails, -1 is returned, and an unspecified
 * partial write could be performed against the file descriptor. */
ssize_t rmt_sync_write(int fd, const char *ptr, ssize_t size, long long timeout) {
    ssize_t nwritten, ret = size;
    long long start = rmt_msec_now();
    long long remaining = timeout;

    while(1) {
        long long wait = (remaining > RMT_SYNCIO_RESOLUTION) ?
                          remaining : RMT_SYNCIO_RESOLUTION;
        long long elapsed;

        /* Optimistically try to write before checking if the file descriptor
         * is actually writable. At worst we get EAGAIN. */
        nwritten = rmt_write(fd,ptr,size);
        if (nwritten == -1) {
            if (errno != EAGAIN) return RMT_ERROR;
        } else {
            ptr += nwritten;
            size -= nwritten;
        }
        if (size == 0) return ret;

        /* Wait */
        aeWait(fd,AE_WRITABLE,wait);
        elapsed = rmt_msec_now() - start;
        if (elapsed >= timeout) {
            errno = ETIMEDOUT;
            return -1;
        }
        remaining = timeout - elapsed;
    }
}

/* Read the specified amount of bytes from 'fd'. If all the bytes are read
 * within 'timeout' milliseconds the operation succeed and 'size' is returned.
 * Otherwise the operation fails, -1 is returned, and an unspecified amount of
 * data could be read from the file descriptor. */
ssize_t rmt_sync_read(int fd, char *ptr, ssize_t size, long long timeout) {
    ssize_t nread, totread = 0;
    long long start = rmt_msec_now();
    long long remaining = timeout;

    if (size == 0) return 0;
    while(1) {
        long long wait = (remaining > RMT_SYNCIO_RESOLUTION) ?
                          remaining : RMT_SYNCIO_RESOLUTION;
        long long elapsed;

        /* Optimistically try to read before checking if the file descriptor
         * is actually readable. At worst we get EAGAIN. */
        nread = rmt_read(fd,ptr,size);
        if (nread == 0) return -1; /* short read. */
        if (nread == -1) {
            if (errno != EAGAIN) return -1;
        } else {
            ptr += nread;
            size -= nread;
            totread += nread;
        }
        if (size == 0) return totread;

        /* Wait */
        aeWait(fd,AE_READABLE,wait);
        elapsed = rmt_msec_now() - start;
        if (elapsed >= timeout) {
            errno = ETIMEDOUT;
            return -1;
        }
        remaining = timeout - elapsed;
    }
}

/* Read a line making sure that every char will not require more than 'timeout'
 * milliseconds to be read.
 *
 * On success the number of bytes read is returned, otherwise -1.
 * On success the string is always correctly terminated with a 0 byte. */
ssize_t rmt_sync_readline(int fd, char *ptr, ssize_t size, long long timeout) {
    ssize_t nread = 0;

    size--;
    while(size) {
        char c;

        if (rmt_sync_read(fd,&c,1,timeout) == -1) return -1;
        if (c == '\n') {
            *ptr = '\0';
            if (nread && *(ptr-1) == '\r') *(ptr-1) = '\0';
            return nread;
        } else {
            *ptr++ = c;
            *ptr = '\0';
            nread++;
        }
        size--;
    }
    return nread;
}

/* Toggle the 16 bit unsigned integer pointed by *p from little endian to
 * big endian */
void memrev16(void *p) {
    unsigned char *x = p, t;

    t = x[0];
    x[0] = x[1];
    x[1] = t;
}

/* Toggle the 32 bit unsigned integer pointed by *p from little endian to
 * big endian */
void memrev32(void *p) {
    unsigned char *x = p, t;

    t = x[0];
    x[0] = x[3];
    x[3] = t;
    t = x[1];
    x[1] = x[2];
    x[2] = t;
}

/* Toggle the 64 bit unsigned integer pointed by *p from little endian to
 * big endian */
void memrev64(void *p) {
    unsigned char *x = p, t;

    t = x[0];
    x[0] = x[7];
    x[7] = t;
    t = x[1];
    x[1] = x[6];
    x[6] = t;
    t = x[2];
    x[2] = x[5];
    x[5] = t;
    t = x[3];
    x[3] = x[4];
    x[4] = t;
}

uint16_t intrev16(uint16_t v) {
    memrev16(&v);
    return v;
}

uint32_t intrev32(uint32_t v) {
    memrev32(&v);
    return v;
}

uint64_t intrev64(uint64_t v) {
    memrev64(&v);
    return v;
}

