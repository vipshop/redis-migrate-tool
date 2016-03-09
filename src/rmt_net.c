#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <rmt_core.h>

/* number of times we retry to connect in the case of EADDRNOTAVAIL and
 * SO_REUSEADDR is being used. */
#define RMT_CONNECT_RETRIES  10

int
rmt_set_blocking(int sd)
{
    int flags;

    flags = fcntl(sd, F_GETFL, 0);
    if (flags < 0) {
        return flags;
    }

    return fcntl(sd, F_SETFL, flags & ~O_NONBLOCK);
}

int
rmt_set_nonblocking(int sd)
{
    int flags;

    flags = fcntl(sd, F_GETFL, 0);
    if (flags < 0) {
        return flags;
    }

    return fcntl(sd, F_SETFL, flags | O_NONBLOCK);
}

int
rmt_set_reuseaddr(int sd)
{
    int reuse;
    socklen_t len;

    reuse = 1;
    len = sizeof(reuse);

    return setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &reuse, len);
}

/*
 * Disable Nagle algorithm on TCP socket.
 *
 * This option helps to minimize transmit latency by disabling coalescing
 * of data to fill up a TCP segment inside the kernel. Sockets with this
 * option must use readv() or writev() to do data transfer in bulk and
 * hence avoid the overhead of small packets.
 */
int
rmt_set_tcpnodelay(int sd)
{
    int nodelay;
    socklen_t len;

    nodelay = 1;
    len = sizeof(nodelay);

    return setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, &nodelay, len);
}

int
rmt_set_linger(int sd, int timeout)
{
    struct linger linger;
    socklen_t len;

    linger.l_onoff = 1;
    linger.l_linger = timeout;

    len = sizeof(linger);

    return setsockopt(sd, SOL_SOCKET, SO_LINGER, &linger, len);
}

int
rmt_set_sndbuf(int sd, int size)
{
    socklen_t len;

    len = sizeof(size);

    return setsockopt(sd, SOL_SOCKET, SO_SNDBUF, &size, len);
}

int
rmt_set_rcvbuf(int sd, int size)
{
    socklen_t len;

    len = sizeof(size);

    return setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &size, len);
}

int
rmt_get_soerror(int sd)
{
    int status, err;
    socklen_t len;

    err = 0;
    len = sizeof(err);

    status = getsockopt(sd, SOL_SOCKET, SO_ERROR, &err, &len);
    if (status == 0) {
        errno = err;
    }

    return status;
}

int
rmt_get_sndbuf(int sd)
{
    int status, size;
    socklen_t len;

    size = 0;
    len = sizeof(size);

    status = getsockopt(sd, SOL_SOCKET, SO_SNDBUF, &size, &len);
    if (status < 0) {
        return status;
    }

    return size;
}

int
rmt_get_rcvbuf(int sd)
{
    int status, size;
    socklen_t len;

    size = 0;
    len = sizeof(size);

    status = getsockopt(sd, SOL_SOCKET, SO_RCVBUF, &size, &len);
    if (status < 0) {
        return status;
    }

    return size;
}

int
rmt_set_tcpkeepalive(int sd, int keepidle, int keepinterval, int keepcount)
{
	r_status status;
    int tcpkeepalive;
    socklen_t len;

    tcpkeepalive = 1;
    len = sizeof(tcpkeepalive);

    status = setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, &tcpkeepalive, len);
	if(status < 0)
	{
		log_error("ERROR: setsockopt SO_KEEPALIVE call error(%s)", strerror(errno));
		return RMT_ERROR;
	}
	
	if(keepidle > 0)
	{
		len = sizeof(keepidle);
		status = setsockopt(sd, SOL_TCP, TCP_KEEPIDLE, &keepidle, len);
		if(status < 0)
		{
			log_error("ERROR: setsockopt TCP_KEEPIDLE call error(%s)", strerror(errno));
			return RMT_ERROR;
		}
	}

	if(keepinterval > 0)
	{
		len = sizeof(keepinterval);
		status = setsockopt(sd, SOL_TCP, TCP_KEEPINTVL, &keepinterval, len);
		if(status < 0)
		{
			log_error("ERROR: setsockopt TCP_KEEPINTVL call error(%s)", strerror(errno));
			return RMT_ERROR;
		}
	}

	if(keepcount > 0)
	{
		len = sizeof(keepcount);
		status = setsockopt(sd, SOL_TCP, TCP_KEEPCNT, &keepcount, len);
		if(status < 0)
		{
			log_error("ERROR: setsockopt TCP_KEEPCNT call error(%s)", strerror(errno));
			return RMT_ERROR;
		}
	}

	return RMT_OK;
}

int
rmt_valid_port(int n)
{
    if (n < 1 || n > UINT16_MAX) {
        return 0;
    }

    return 1;
}

/*
 * Send n bytes on a blocking descriptor
 */
ssize_t
_rmt_sendn(int sd, const void *vptr, size_t n)
{
    size_t nleft;
    ssize_t	nsend;
    const char *ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0) {
        nsend = send(sd, ptr, nleft, 0);
        if (nsend < 0) {
            if (errno == EINTR) {
                continue;
            }
            return nsend;
        }
        if (nsend == 0) {
            return -1;
        }

        nleft -= (size_t)nsend;
        ptr += nsend;
    }

    return (ssize_t)n;
}

/*
 * Recv n bytes from a blocking descriptor
 */
ssize_t
_rmt_recvn(int sd, void *vptr, size_t n)
{
	size_t nleft;
	ssize_t	nrecv;
	char *ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
        nrecv = recv(sd, ptr, nleft, 0);
        if (nrecv < 0) {
            if (errno == EINTR) {
                continue;
            }
            return nrecv;
        }
        if (nrecv == 0) {
            break;
        }

        nleft -= (size_t)nrecv;
        ptr += nrecv;
    }

    return (ssize_t)(n - nleft);
}

static int
rmt_resolve_inet(char *name, int port, struct sockinfo *si)
{
    int status;
    struct addrinfo *ai, *cai; /* head and current addrinfo */
    struct addrinfo hints;
    char *node, service[RMT_UINTMAX_MAXLEN];
    bool found;

    ASSERT(rmt_valid_port(port));

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICSERV;
    hints.ai_family = AF_UNSPEC;     /* AF_INET or AF_INET6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    hints.ai_addrlen = 0;
    hints.ai_addr = NULL;
    hints.ai_canonname = NULL;

    if (name != NULL) {
        node = name;
    } else {
        /*
         * If AI_PASSIVE flag is specified in hints.ai_flags, and node is
         * NULL, then the returned socket addresses will be suitable for
         * bind(2)ing a socket that will accept(2) connections. The returned
         * socket address will contain the wildcard IP address.
         */
        node = NULL;
        hints.ai_flags |= AI_PASSIVE;
    }

    rmt_snprintf(service, RMT_UINTMAX_MAXLEN, "%d", port);

    status = getaddrinfo(node, service, &hints, &ai);
    if (status < 0) {
        log_error("ERROR: address resolution of node '%s' service '%s' failed: %s",
                  node, service, gai_strerror(status));
        return -1;
    }

    /*
     * getaddrinfo() can return a linked list of more than one addrinfo,
     * since we requested for both AF_INET and AF_INET6 addresses and the
     * host itself can be multi-homed. Since we don't care whether we are
     * using ipv4 or ipv6, we just use the first address from this collection
     * in the order in which it was returned.
     *
     * The sorting function used within getaddrinfo() is defined in RFC 3484;
     * the order can be tweaked for a particular system by editing
     * /etc/gai.conf
     */
    for (cai = ai, found = 0; cai != NULL; cai = cai->ai_next) {
        si->family = cai->ai_family;
        si->addrlen = cai->ai_addrlen;
        rmt_memcpy(&si->addr, cai->ai_addr, si->addrlen);
        found = 1;
        break;
    }

    freeaddrinfo(ai);

    return !found ? -1 : 0;
}

static int
rmt_resolve_unix(char *name, struct sockinfo *si)
{
    struct sockaddr_un *un;

    if (strlen(name) >= RMT_UNIX_ADDRSTRLEN) {
        return -1;
    }

    un = &si->addr.un;

    un->sun_family = AF_UNIX;
    rmt_memcpy(un->sun_path, name, strlen(name));
    un->sun_path[strlen(name)] = '\0';

    si->family = AF_UNIX;
    si->addrlen = sizeof(*un);
    /* si->addr is an alias of un */

    return 0;
}

/*
 * Resolve a hostname and service by translating it to socket address and
 * return it in si
 *
 * This routine is reentrant
 */
int
rmt_resolve(char *name, int port, struct sockinfo *si)
{
    if (name != NULL && name[0] == '/') {
        return rmt_resolve_unix(name, si);
    }

    return rmt_resolve_inet(name, port, si);
}

/*
 * Unresolve the socket address by translating it to a character string
 * describing the host and service
 *
 * This routine is not reentrant
 */
char *
rmt_unresolve_addr(struct sockaddr *addr, socklen_t addrlen)
{
    static char unresolve[NI_MAXHOST + NI_MAXSERV];
    static char host[NI_MAXHOST], service[NI_MAXSERV];
    int status;

    status = getnameinfo(addr, addrlen, host, sizeof(host),
                         service, sizeof(service),
                         NI_NUMERICHOST | NI_NUMERICSERV);
    if (status < 0) {
        return (char *)"unknown";
    }

    rmt_snprintf(unresolve, sizeof(unresolve), "%s:%s", host, service);

    return unresolve;
}

/*
 * Unresolve the socket descriptor peer address by translating it to a
 * character string describing the host and service
 *
 * This routine is not reentrant
 */
char *
rmt_unresolve_peer_desc(int sd)
{
    static struct sockinfo si;
    struct sockaddr *addr;
    socklen_t addrlen;
    int status;

    memset(&si, 0, sizeof(si));
    addr = (struct sockaddr *)&si.addr;
    addrlen = sizeof(si.addr);

    status = getpeername(sd, addr, &addrlen);
    if (status < 0) {
        return (char *)"unknown";
    }

    return rmt_unresolve_addr(addr, addrlen);
}

/*
 * Unresolve the socket descriptor address by translating it to a
 * character string describing the host and service
 *
 * This routine is not reentrant
 */
char *
rmt_unresolve_desc(int sd)
{
    static struct sockinfo si;
    struct sockaddr *addr;
    socklen_t addrlen;
    int status;

    memset(&si, 0, sizeof(si));
    addr = (struct sockaddr *)&si.addr;
    addrlen = sizeof(si.addr);

    status = getsockname(sd, addr, &addrlen);
    if (status < 0) {
        return (char *)"unknown";
    }

    return rmt_unresolve_addr(addr, addrlen);
}

int
rmt_get_socket_local_ip_port(int sd, char **ip, int *port)
{
    struct sockaddr_in addr;
    socklen_t addrlen;
    int status;

    if(sd < 0){
        return RMT_ERROR;
    }

    addrlen = sizeof(addr);
    memset(&addr, 0, addrlen);

    status = getsockname(sd, (struct sockaddr*)(&addr), &addrlen);
    if (status < 0) {
        return RMT_ERROR;
    }

    if(ip != NULL){
        strcpy(*ip, inet_ntoa(addr.sin_addr));
    }

    if(port != NULL){
        *port = ntohs(addr.sin_port);
    }
    
    return RMT_OK;
}

void rmt_tcp_context_close_sd(tcp_context *tc) {
    if (tc && tc->sd >= 0) {
        close(tc->sd);
        tc->sd = -1;
        tc->flags &= ~RMT_CONNECTED;
    }
}

static int rmt_tcp_context_wait_ready(
    tcp_context *tc, const struct timeval *timeout) 
{
    struct pollfd   wfd[1];
    long msec;

    msec          = -1;
    wfd[0].fd     = tc->sd;
    wfd[0].events = POLLOUT;

    /* Only use timeout when not NULL. */
    if (timeout != NULL) {
        if (timeout->tv_usec > 1000000 || timeout->tv_sec > RMT_MAX_MSEC) {
            log_error("ERROR: %s", strerror(errno));
            rmt_tcp_context_close_sd(tc);
            return RMT_ERROR;
        }

        msec = (timeout->tv_sec * 1000) + ((timeout->tv_usec + 999) / 1000);

        if (msec < 0 || msec > INT_MAX) {
            msec = INT_MAX;
        }
    }

    if (errno == EINPROGRESS) {
        int res;

        if ((res = poll(wfd, 1, msec)) == -1) {
            log_error("poll(2) error: %s", strerror(errno));
            rmt_tcp_context_close_sd(tc);
            return RMT_ERROR;
        } else if (res == 0) {
            errno = ETIMEDOUT;
            log_error("poll(2) error: %s", strerror(errno));
            rmt_tcp_context_close_sd(tc);
            return RMT_ERROR;
        }

        if (rmt_tcp_context_check_socket_error(tc) != RMT_OK)
            return RMT_ERROR;

        return RMT_OK;
    }

    log_error("ERROR: %s", strerror(errno));
    rmt_tcp_context_close_sd(tc);

    return RMT_ERROR;
}

tcp_context *rmt_tcp_context_create(void)
{
    tcp_context *tc;

    tc = rmt_alloc(sizeof(*tc));
    if(tc == NULL)
    {
        log_error("ERROR: create tcp_context failed: out of memory");
        return NULL;
    }

    tc->sd = -1;
    tc->flags = 0;
    tc->host = NULL;
    tc->port = 0;
    tc->source_addr = NULL;
    tc->timeout = NULL;

    return tc;
}

void rmt_tcp_context_destroy(tcp_context *tc)
{
    if(tc == NULL)
    {
        return;
    }

    if(tc->sd > 0)
    {
        rmt_tcp_context_close_sd(tc);
    }

    if(tc->host)
    {
        free(tc->host);
    }

    if(tc->source_addr)
    {
        free(tc->source_addr);
    }

    rmt_free(tc);
}

int rmt_tcp_context_check_socket_error(tcp_context *tc) {
    int err = 0;
    socklen_t errlen = sizeof(err);

    if (rmt_getsockopt(tc->sd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
        log_error("ERROR: rmt_getsockopt(SO_ERROR) error: %s", strerror(errno));
        return RMT_ERROR;
    }

    if (err) {
        errno = err;
        log_error("ERROR: socket error: %s", strerror(errno));
        return RMT_ERROR;
    }

    return RMT_OK;
}
static int _rmt_tcp_context_connect(tcp_context *tc) {
    int ret;
    int s, n;
    char _port[6];  /* strlen("65535"); */
    struct addrinfo hints, *servinfo, *bservinfo, *p, *b;
    int blocking = (tc->flags & RMT_BLOCK);
    int reuseaddr = (tc->flags & RMT_REUSEADDR);
    int reuses = 0;
    int yes = 1;

    rmt_snprintf(_port, 6, "%d", tc->port);
    rmt_memset(&hints,0,sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    /* Try with IPv6 if no IPv4 address was found. We do it in this order since
     * in a Redis client you can't afford to test if you have IPv6 connectivity
     * as this would add latency to every connect. Otherwise a more sensible
     * route could be: Use IPv6 if both addresses are available and there is IPv6
     * connectivity. */
    if ((ret = rmt_getaddrinfo(tc->host,_port,&hints,&servinfo)) != 0) {
         hints.ai_family = AF_INET6;
         if ((ret = rmt_getaddrinfo(tc->host,_port,&hints,&servinfo)) != 0) {
            log_error("ERROR: rmt_getaddrinfo error: %s", gai_strerror(ret));
            return RMT_ERROR;
        }
    }
    
    for (p = servinfo; p != NULL; p = p->ai_next) {
addrretry:
        if ((s = socket(p->ai_family,p->ai_socktype,p->ai_protocol)) == -1)
            continue;

        tc->sd = s;
        if (rmt_set_nonblocking(tc->sd) < 0) {
            log_error("ERROR: set nonblock on socket %d on addr '%s:%d' failed: %s", 
                s, tc->host, tc->port, strerror(errno));
            rmt_tcp_context_close_sd(tc);
            goto error;
        }
        
        if (tc->source_addr) {
            int bound = 0;
            /* Using getaddrinfo saves us from self-determining IPv4 vs IPv6 */
            if ((ret = rmt_getaddrinfo(tc->source_addr, NULL, &hints, &bservinfo)) != 0) {
                log_error("ERROR: can't get %s addr: %s", tc->source_addr, gai_strerror(ret));
                rmt_tcp_context_close_sd(tc);
                goto error;
            }

            if (reuseaddr) {
                n = 1;
                if (rmt_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*) &n,
                               sizeof(n)) < 0) {
                    log_error("ERROR: set SO_REUSEADDR on socket %d on addr '%s:%d' failed: %s", 
                        tc->sd, tc->host, tc->port, strerror(errno));
                    rmt_tcp_context_close_sd(tc);
                    goto error;
                }
            }

            for (b = bservinfo; b != NULL; b = b->ai_next) {
                if (bind(s,b->ai_addr,b->ai_addrlen) != -1) {
                    bound = 1;
                    break;
                }
            }
            
            freeaddrinfo(bservinfo);
            
            if (!bound) {
                log_error("ERROR: can't bind socket: %s", strerror(errno));
                rmt_tcp_context_close_sd(tc);
                goto error;
            }
        }
        
        if (connect(s,p->ai_addr,p->ai_addrlen) == -1) {
            if (errno == EHOSTUNREACH) {
                rmt_tcp_context_close_sd(tc);
                continue;
            } else if (errno == EINPROGRESS && !blocking) {
                /* This is ok. */
            } else if (errno == EADDRNOTAVAIL && reuseaddr) {
                if (++reuses >= RMT_CONNECT_RETRIES) {
                    log_error("ERROR: retry too many times: %s", strerror(errno));
                    rmt_tcp_context_close_sd(tc);
                    goto error;
                } else {
                    goto addrretry;
                }
            } else {
                if (rmt_tcp_context_wait_ready(tc,tc->timeout) != RMT_OK)
                    goto error;
            }
        }
        
        if (blocking && rmt_set_blocking(tc->sd) < 0) {
            log_error("ERROR: set block on socket %d on addr '%s:%d' failed: %s", 
                tc->sd, tc->host, tc->port, strerror(errno));
            rmt_tcp_context_close_sd(tc);
            goto error;
        }

        if (rmt_setsockopt(tc->sd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) == -1) {
            log_error("ERROR: set TCP_NODELAY on socket %d on addr '%s:%d' failed: %s", 
                tc->sd, tc->host, tc->port, strerror(errno));
            rmt_tcp_context_close_sd(tc);
            goto error;
        }
        
        tc->flags |= RMT_CONNECTED;
        ret = RMT_OK;
        goto end;
    }
    
    if (p == NULL) {
        log_error("ERROR: can't create socket: %s", strerror(errno));
        goto error;
    }

error:
    ret = RMT_ERROR;
    tc->flags &= ~RMT_CONNECTED;
end:
    freeaddrinfo(servinfo);
    return ret;  // Need to return RMT_OK if alright
}

int rmt_tcp_context_connect_old(tcp_context *tc, const char *host, int port,
                                   const struct timeval *timeout,
                                   const char *source_addr) {
    int ret;
    int s, n;
    char _port[6];  /* strlen("65535"); */
    struct addrinfo hints, *servinfo, *bservinfo, *p, *b;
    int blocking = (tc->flags & RMT_BLOCK);
    int reuseaddr = (tc->flags & RMT_REUSEADDR);
    int reuses = 0;
    int yes = 1;

    tc->port = port;

    if(tc->host != NULL)
    {
        free(tc->host);
        tc->host = NULL;
    }

    tc->host = rmt_strdup(host);

    if (timeout) {
        if (tc->timeout == NULL) {
            tc->timeout = rmt_alloc(sizeof(struct timeval));
        }

        rmt_memcpy(tc->timeout, timeout, sizeof(struct timeval));
    } else {
        if (tc->timeout)
            rmt_free(tc->timeout);
        tc->timeout = NULL;
    }

    if (tc->source_addr != NULL) {
        free(tc->source_addr);
        tc->source_addr = NULL;
    }

    if (source_addr) {
        tc->source_addr = rmt_strdup(source_addr);
    }

    rmt_snprintf(_port, 6, "%d", port);
    rmt_memset(&hints,0,sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    /* Try with IPv6 if no IPv4 address was found. We do it in this order since
     * in a Redis client you can't afford to test if you have IPv6 connectivity
     * as this would add latency to every connect. Otherwise a more sensible
     * route could be: Use IPv6 if both addresses are available and there is IPv6
     * connectivity. */
    if ((ret = rmt_getaddrinfo(tc->host,_port,&hints,&servinfo)) != 0) {
         hints.ai_family = AF_INET6;
         if ((ret = rmt_getaddrinfo(tc->host,_port,&hints,&servinfo)) != 0) {
            log_error("ERROR: rmt_getaddrinfo error: %s", gai_strerror(ret));
            return RMT_ERROR;
        }
    }
    
    for (p = servinfo; p != NULL; p = p->ai_next) {
addrretry:
        if ((s = socket(p->ai_family,p->ai_socktype,p->ai_protocol)) == -1)
            continue;

        tc->sd = s;
        if (rmt_set_nonblocking(tc->sd) < 0)
        {
            log_error("ERROR: set nonblock on socket %d on addr '%s:%d' failed: %s", 
                s, tc->host, tc->port, strerror(errno));
            rmt_tcp_context_close_sd(tc);
            goto error;
        }
        
        if (tc->source_addr) {
            int bound = 0;
            /* Using getaddrinfo saves us from self-determining IPv4 vs IPv6 */
            if ((ret = rmt_getaddrinfo(tc->source_addr, NULL, &hints, &bservinfo)) != 0) {
                log_error("ERROR: can't get %s addr: %s", tc->source_addr, gai_strerror(ret));
                rmt_tcp_context_close_sd(tc);
                goto error;
            }

            if (reuseaddr) {
                n = 1;
                if (rmt_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*) &n,
                               sizeof(n)) < 0) 
                {
                    log_error("ERROR: set SO_REUSEADDR on socket %d on addr '%s:%d' failed: %s", 
                        tc->sd, tc->host, tc->port, strerror(errno));
                    rmt_tcp_context_close_sd(tc);
                    goto error;
                }
            }

            for (b = bservinfo; b != NULL; b = b->ai_next) {
                if (bind(s,b->ai_addr,b->ai_addrlen) != -1) {
                    bound = 1;
                    break;
                }
            }
            
            freeaddrinfo(bservinfo);
            
            if (!bound) {
                log_error("ERROR: can't bind socket: %s", strerror(errno));
                rmt_tcp_context_close_sd(tc);
                goto error;
            }
        }
        
        if (connect(s,p->ai_addr,p->ai_addrlen) == -1) {
            if (errno == EHOSTUNREACH) {
                rmt_tcp_context_close_sd(tc);
                continue;
            } else if (errno == EINPROGRESS && !blocking) {
                /* This is ok. */
            } else if (errno == EADDRNOTAVAIL && reuseaddr) {
                if (++reuses >= RMT_CONNECT_RETRIES) {
                    log_error("ERROR: retry too many times: %s", strerror(errno));
                    rmt_tcp_context_close_sd(tc);
                    goto error;
                } else {
                    goto addrretry;
                }
            } else {
                if (rmt_tcp_context_wait_ready(tc,tc->timeout) != RMT_OK)
                    goto error;
            }
        }
        
        if (blocking && rmt_set_blocking(tc->sd) < 0)
        {
            log_error("ERROR: set block on socket %d on addr '%s:%d' failed: %s", 
                tc->sd, tc->host, tc->port, strerror(errno));
            rmt_tcp_context_close_sd(tc);
            goto error;
        }

        if (rmt_setsockopt(tc->sd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) == -1)
        {
            log_error("ERROR: set TCP_NODELAY on socket %d on addr '%s:%d' failed: %s", 
                tc->sd, tc->host, tc->port, strerror(errno));
            rmt_tcp_context_close_sd(tc);
            goto error;
        }
        
        tc->flags |= RMT_CONNECTED;
        ret = RMT_OK;
        goto end;
    }
    
    if (p == NULL) {
        log_error("ERROR: can't create socket: %s", strerror(errno));
        goto error;
    }

error:
    ret = RMT_ERROR;
end:
    freeaddrinfo(servinfo);
    return ret;  // Need to return RMT_OK if alright
}

int rmt_tcp_context_connect(tcp_context *tc, const char *host, int port,
                                   const struct timeval *timeout,
                                   const char *source_addr) {
    tc->port = port;

    if(tc->host != NULL)
    {
        free(tc->host);
        tc->host = NULL;
    }

    tc->host = rmt_strdup(host);

    if (timeout) {
        if (tc->timeout == NULL) {
            tc->timeout = rmt_alloc(sizeof(struct timeval));
        }

        rmt_memcpy(tc->timeout, timeout, sizeof(struct timeval));
    } else {
        if (tc->timeout)
            rmt_free(tc->timeout);
        tc->timeout = NULL;
    }

    if (tc->source_addr != NULL) {
        free(tc->source_addr);
        tc->source_addr = NULL;
    }

    if (source_addr) {
        tc->source_addr = rmt_strdup(source_addr);
    }

    return _rmt_tcp_context_connect(tc);
}

int rmt_tcp_context_connect_addr(tcp_context *tc, const char *addr, int len,
    const struct timeval *timeout, const char *source_addr)
{
    int ret;
    int port;
    sds *ip_port = NULL;
    int ip_port_count = 0;

    ip_port = sdssplitlen(addr, len, IP_PORT_SEPARATOR, 
        rmt_strlen(IP_PORT_SEPARATOR), &ip_port_count);
    if(ip_port == NULL || ip_port_count != 2)
    {
        log_error("Error: ip port parsed error");
        goto error;
    }

    port = rmt_atoi(ip_port[1], sdslen(ip_port[1]));
    if(rmt_valid_port(port) == 0)
    {
        log_error("Error: port is invalid");
        goto error;
    }
    
    ret = rmt_tcp_context_connect(tc, ip_port[0], port, timeout, source_addr);
    if(ret != RMT_OK)
    {
        log_error("Error: can't connect to redis master");
        goto error;
    }

    sdsfreesplitres(ip_port, ip_port_count);
    ip_port = NULL;
    ip_port_count = 0;
    
    return RMT_OK;

error:

    if(ip_port != NULL)
    {
        sdsfreesplitres(ip_port, ip_port_count);
    }
    
    return RMT_ERROR;
}

int rmt_tcp_context_reconnect(tcp_context *tc) {
    if (tc == NULL) {
        return RMT_ERROR;
    }
    rmt_tcp_context_close_sd(tc);
    return _rmt_tcp_context_connect(tc);
}

ssize_t
rmt_sendv(int sd, struct array *sendv, size_t nsend)
{
    ssize_t n;
    
    ASSERT(array_n(sendv) > 0);
    ASSERT(nsend != 0);

    if(sd < 0)
    {
        return RMT_ERROR;
    }

    for (;;) {
        n = rmt_writev(sd, sendv->elem, sendv->nelem);

        log_debug(LOG_VERB, "sendv on sd %d %zd of %zu in %"PRIu32" buffers",
                  sd, n, nsend, sendv->nelem);

        if (n > 0) {
            if (n < (ssize_t) nsend) {
                log_debug(LOG_DEBUG, "sendv on sd %d need send %lld, but just send %lld", 
                    sd, (ssize_t)nsend, n);
            }
            
            return n;
        }

        if (n == 0) {
            log_warn("sendv on sd %d returned zero", sd);
            
            return 0;
        }

        if (errno == EINTR) {
            log_debug(LOG_VERB, "sendv on sd %d not ready - eintr", sd);
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            log_debug(LOG_VERB, "sendv on sd %d not ready - eagain", sd);
            return RMT_EAGAIN;
        } else {
            log_error("ERROR: sendv on sd %d failed: %s", sd, strerror(errno));
            return RMT_ERROR;
        }
    }

    NOT_REACHED();

    return RMT_ERROR;
}


