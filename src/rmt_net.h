#ifndef _RMT_NET_H_
#define _RMT_NET_H_

#include <stdarg.h>
#include <sys/un.h>
#include <netinet/in.h>
#include<netdb.h>

#define RMT_INET4_ADDRSTRLEN (sizeof("255.255.255.255") - 1)
#define RMT_INET6_ADDRSTRLEN \
    (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1)
#define RMT_INET_ADDRSTRLEN  MAX(RMT_INET4_ADDRSTRLEN, RMT_INET6_ADDRSTRLEN)
#define RMT_UNIX_ADDRSTRLEN  \
    (sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))

#define RMT_MAXHOSTNAMELEN   256

/* Connection type can be blocking or non-blocking and is set in the
 * least significant bit of the flags field in redisContext. */
#define RMT_BLOCK 0x1

/* Connection may be disconnected before being free'd. The second bit
 * in the flags field is set when the context is connected. */
#define RMT_CONNECTED 0x2

/* The async API might try to disconnect cleanly and flush the output
 * buffer and read all subsequent replies before disconnecting.
 * This flag means no new commands can come in and the connection
 * should be terminated once all replies have been read. */
#define RMT_DISCONNECTING 0x4

/* Flag that is set when we should set SO_REUSEADDR before calling bind() */
#define RMT_REUSEADDR 0x8

/*
 * Wrapper to workaround well known, safe, implicit type conversion when
 * invoking system calls.
 */
#define rmt_gethostname(_name, _len) \
    gethostname((char *)_name, (size_t)_len)

#define rmt_getaddrinfo(_name, _service, _hints, _result) \
    getaddrinfo((char *)_name, (char *)_service, (struct addrinfo *)_hints, (struct addrinfo **)_result)

#define rmt_setsockopt(_sockfd, _level, _optname, _optval, _optlen)    \
    setsockopt(_sockfd, _level, _optname, (void *)_optval, (socklen_t)_optlen)

#define rmt_getsockopt(_sockfd, _level, _optname, _optval, _optlen)    \
    getsockopt(_sockfd, _level, _optname, (void *)_optval, (socklen_t *)_optlen)


/*
 * Address resolution for internet (ipv4 and ipv6) and unix domain
 * socket address.
 */
struct sockinfo {
    int       family;              /* socket address family */
    socklen_t addrlen;             /* socket address length */
    union {
        struct sockaddr_in  in;    /* ipv4 socket address */
        struct sockaddr_in6 in6;   /* ipv6 socket address */
        struct sockaddr_un  un;    /* unix domain address */
    } addr;
};

typedef struct tcp_context
{
    int flags;
    int sd;

    char *host;
    int port;
    
    char *source_addr;

    struct sockinfo si;

    struct timeval *timeout;
}tcp_context;


int rmt_set_blocking(int sd);
int rmt_set_nonblocking(int sd);
int rmt_set_reuseaddr(int sd);
int rmt_set_tcpnodelay(int sd);
int rmt_set_linger(int sd, int timeout);
int rmt_set_sndbuf(int sd, int size);
int rmt_set_rcvbuf(int sd, int size);
int rmt_get_soerror(int sd);
int rmt_get_sndbuf(int sd);
int rmt_get_rcvbuf(int sd);

int rmt_set_tcpkeepalive(int sd, int keepidle, int keepinterval, int keepcount);

int rmt_valid_port(int n);

/*
 * Wrappers to send or receive n byte message on a blocking
 * socket descriptor.
 */
#define rmt_sendn(_s, _b, _n)    \
    _rmt_sendn(_s, _b, (size_t)(_n))

#define rmt_recvn(_s, _b, _n)    \
    _rmt_recvn(_s, _b, (size_t)(_n))

ssize_t _rmt_sendn(int sd, const void *vptr, size_t n);
ssize_t _rmt_recvn(int sd, void *vptr, size_t n);

int rmt_resolve(char *name, int port, struct sockinfo *si);
char *rmt_unresolve_addr(struct sockaddr *addr, socklen_t addrlen);
char *rmt_unresolve_peer_desc(int sd);
char *rmt_unresolve_desc(int sd);
int rmt_get_socket_local_ip_port(int sd, char **ip, int *port);

tcp_context *rmt_tcp_context_create(void);
void rmt_tcp_context_destroy(tcp_context *tc);

int rmt_tcp_context_check_socket_error(tcp_context *tc);

void rmt_tcp_context_close_sd(tcp_context *tc);

int rmt_tcp_context_connect(tcp_context *tc, const char *host, int port,
    const struct timeval *timeout, const char *source_addr);

int rmt_tcp_context_connect_addr(tcp_context *tc, const char *addr, int len,
    const struct timeval *timeout, const char *source_addr);

int rmt_tcp_context_reconnect(tcp_context *tc);

ssize_t rmt_sendv(int sd, struct array *sendv, size_t nsend);

#endif

