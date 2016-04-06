
#include <rmt_core.h>

#include <sys/utsname.h>

#define ERROR_RESPONSE_SYNTAX       "-ERR syntax error\r\n"
#define ERROR_RESPONSE_NOTSUPPORT   "-ERR command not support\r\n"

static int all_rdb_parse_finished(rmtContext *ctx)
{
    uint32_t i;
    int finished = 1;
    struct array *wdatas = ctx->wdatas;
    write_thread_data *wdata;

    for (i = 0; i < array_n(wdatas); i++) {
        wdata = array_get(wdatas, i);
        if (!wdata->stat_all_rdb_parsed) {
            finished = 0;
            break;
        }
    }

    return finished;
}

static uint64_t total_msgs_received(rmtContext *ctx)
{
    uint32_t i;
    uint64_t count = 0;
    struct array *wdatas = ctx->wdatas;
    write_thread_data *wdata;

    for (i = 0; i < array_n(wdatas); i++) {
        wdata = array_get(wdatas, i);
        count += wdata->stat_total_msgs_recv;
    }

    return count;
}

static uint64_t total_msgs_sent(rmtContext *ctx)
{
    uint32_t i;
    uint64_t count = 0;
    struct array *wdatas = ctx->wdatas;
    write_thread_data *wdata;

    for (i = 0; i < array_n(wdatas); i++) {
        wdata = array_get(wdatas, i);
        count += wdata->stat_total_msgs_sent;
    }

    return count;
}

static uint64_t total_bytes_received(rmtContext *ctx)
{
    uint32_t i;
    uint64_t bytes = 0;
    struct array *rdatas = ctx->rdatas;
    read_thread_data *rdata;

    for (i = 0; i < array_n(rdatas); i++) {
        rdata = array_get(rdatas, i);
        bytes += rdata->stat_total_net_input_bytes;
    }

    return bytes;
}

static uint64_t total_bytes_sent(rmtContext *ctx)
{
    uint32_t i;
    uint64_t bytes = 0;
    struct array *wdatas = ctx->wdatas;
    write_thread_data *wdata;

    for (i = 0; i < array_n(wdatas); i++) {
        wdata = array_get(wdatas, i);
        bytes += wdata->stat_total_net_output_bytes;
    }

    return bytes;
}

static uint64_t total_mbufs_inqueue(rmtContext *ctx)
{
    uint64_t count = 0;
    redis_node *srnode;
    dictEntry *de;
    dictIterator *di;
    dict *nodes = ctx->srgroup->nodes;

    di = dictGetIterator(nodes);
    while ((de = dictNext(di)) != NULL) {
        srnode = dictGetVal(de);
        count += (uint64_t)mttlist_length(srnode->cmd_data);
    }
    dictReleaseIterator(di);
    
    return count;
}

static uint64_t total_msgs_outqueue(rmtContext *ctx)
{
    uint32_t i;
    uint64_t count = 0;
    struct array *wdatas = ctx->wdatas;
    write_thread_data *wdata;

    for (i = 0; i < array_n(wdatas); i++) {
        wdata = array_get(wdatas, i);
        count += wdata->stat_msgs_outqueue;
    }

    return count;
}

static sds gen_migrate_info_string(rmtContext *ctx, sds part)
{
    sds info = sdsempty();
    int allsections = 0, defsections = 0;
    char *section;
    int sections = 0;

    if (part == NULL) section = "default";
    else section = part;
    allsections = strcasecmp(section,"all") == 0;
    defsections = strcasecmp(section,"default") == 0;

    if (allsections || defsections || !strcasecmp(section,"server")) {
        long long uptime = rmt_msec_now() - ctx->starttime;
        static int call_uname = 1;
        static struct utsname name;

        if (sections++) info = sdscat(info,"\r\n");
        
        if (call_uname) {
            /* Uname can be slow and is always the same output. Cache it. */
            uname(&name);
            call_uname = 0;
        }
        
        info = sdscatprintf(info,
            "# Server\r\n"
            "version:%s\r\n"
            "os:%s %s %s\r\n"
            "multiplexing_api:%s\r\n"
            "gcc_version:%d.%d.%d\r\n"
            "process_id:%ld\r\n"
            "tcp_port:%d\r\n"
            "uptime_in_seconds:%lld\r\n"
            "uptime_in_days:%lld\r\n"
            "config_file:%s\r\n",
            RMT_VERSION_STRING,
            name.sysname, name.release, name.machine,
            aeGetApiName(),
#ifdef __GNUC__
            __GNUC__,__GNUC_MINOR__,__GNUC_PATCHLEVEL__,
#else
            0,0,0,
#endif
            (long) getpid(),
            ctx->lt.port,
            uptime/1000,
            uptime/(3600*24*1000),
            ctx->cf ? ctx->cf->fname : "");
    }

    /* Clients */
    if (allsections || defsections || !strcasecmp(section,"clients")) {
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info,
            "# Clients\r\n"
            "connected_clients:%"PRIu32"\r\n"
            "max_clients_limit:%"PRIu32"\r\n"
            "total_connections_received:%"PRIu64"\r\n",
            conn_ncurr_cconn(ctx),
            ctx->max_ncconn,
            conn_ntotal_cconn(ctx));
    }

    /* Stats */
    if (allsections || defsections || !strcasecmp(section,"stats")) {
        uint64_t total_input_bytes, total_output_bytes;
        char total_input_bytes_human[64], total_output_bytes_human[64];

        total_input_bytes = total_bytes_received(ctx);
        total_output_bytes = total_bytes_sent(ctx);
        integer_byte_to_size_string(total_input_bytes_human, total_input_bytes);
        integer_byte_to_size_string(total_output_bytes_human, total_output_bytes);
        
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info,
            "# Stats\r\n"
            "all_rdb_parsed:%d\r\n"
            "total_msgs_recv:%"PRIu64"\r\n"
            "total_msgs_sent:%"PRIu64"\r\n"
            "total_net_input_bytes:%"PRIu64"\r\n"
            "total_net_output_bytes:%"PRIu64"\r\n"
            "total_net_input_bytes_human:%s\r\n"
            "total_net_output_bytes_human:%s\r\n"
            "total_mbufs_inqueue:%"PRIu64"\r\n"
            "total_msgs_outqueue:%"PRIu64"\r\n",
            all_rdb_parse_finished(ctx),
            total_msgs_received(ctx),
            total_msgs_sent(ctx),
            total_input_bytes,
            total_output_bytes,
            total_input_bytes_human,
            total_output_bytes_human,
            total_mbufs_inqueue(ctx),
            total_msgs_outqueue(ctx));
    }

    return info;
}

static int
req_make_reply(rmtContext *ctx, rmt_connect *conn, struct msg *req)
{
    int ret;
    struct msg *msg;
    sds str;

    msg = msg_get(ctx->mb, 0, req->kind); /* replay */
    if (msg == NULL) {
        return RMT_ENOMEM;
    }

    switch (req->type) {
    case MSG_REQ_REDIS_PING:
    {
        str = sdsnew("+PONG\r\n");
        ret = msg_append(msg, (uint8_t *)str, sdslen(str));
        sdsfree(str);
        break;
    }
    case MSG_REQ_REDIS_INFO:
    {
        struct keypos *kp;
        sds section = NULL;
        if (array_n(req->keys) > 1) {
            str = sdsnew(ERROR_RESPONSE_SYNTAX);
            ret = msg_append(msg, (uint8_t *)str, sdslen(str));
            sdsfree(str);
            break;
        } else if (array_n(req->keys) == 1) {
            kp = array_get(req->keys, 0);
            section = sdsnewlen(kp->start, (size_t)(kp->end-kp->start));
        }
        
        str = gen_migrate_info_string(ctx, section);
        if (section) sdsfree(section);
        ret = redis_msg_append_bulk_full(msg, str, (uint32_t)sdslen(str));
        sdsfree(str);
        break;
    }
    default:
        str = sdsnew(ERROR_RESPONSE_NOTSUPPORT);
        ret = msg_append(msg, (uint8_t *)str, sdslen(str));
        sdsfree(str);
        break;
    }

    if (ret != RMT_OK) {
        log_error("ERROR: generate response for command %s to client %s failed.", 
            msg_type_string(req->type), rmt_unresolve_peer_desc(conn->sd));
        return RMT_ERROR;
    }

    req->peer = msg;
    msg->peer = req;

    listAddNodeTail(&conn->omsg_q, req);

    ret = aeCreateFileEvent(ctx->loop, conn->sd, AE_WRITABLE, conn->send, conn);
    if (ret != AE_OK) {
        return RMT_ERROR;
    }
    conn->send_active = 1;
    
    return RMT_OK;
}

int rmt_listen_init(rmt_listen *lt, char *address)
{
    int ret;
    sds *ip_port = NULL;
    int ip_port_count = 0;
    int port;

    lt->addr = NULL;
    lt->host = NULL;
    lt->port = 0;
    rmt_memset(&lt->si, 0, sizeof(struct sockinfo));

    if (address == NULL) {
        return RMT_ERROR;
    }

    lt->addr = sdsnew(address);
    if (lt->addr == NULL) {
        log_error("ERROR: out of memory");
        goto error;
    }

    ip_port = sdssplitlen(lt->addr, sdslen(lt->addr), 
        IP_PORT_SEPARATOR, rmt_strlen(IP_PORT_SEPARATOR), &ip_port_count);
    if (ip_port == NULL || ip_port_count != 2) {
        log_error("ERROR: listen address %s is error.", address);
        goto error;
    }

    lt->host = ip_port[0];
    ip_port[0] = NULL;

    port = rmt_atoi(ip_port[1], sdslen(ip_port[1]));
    if (!rmt_valid_port(port)) {
        log_error("ERROR: listen port is invalid.");
        goto error;
    }
    lt->port = port;

    sdsfreesplitres(ip_port, ip_port_count);
    ip_port = NULL;
    ip_port_count = 0;

    ret = rmt_resolve(lt->host, lt->port, &lt->si);
    if (ret != RMT_OK) {
        log_error("ERROR: resolve listen address failed.");
        goto error;
    }

    return RMT_OK;

error:

    if(ip_port != NULL) sdsfreesplitres(ip_port, ip_port_count);

    rmt_listen_deinit(lt);
    
    return RMT_ERROR;
}

void rmt_listen_deinit(rmt_listen *lt)
{
    if (lt->addr != NULL) {
        sdsfree(lt->addr);
        lt->addr = NULL;
    }

    if (lt->host != NULL) {
        sdsfree(lt->host);
        lt->host = NULL;
    }

    lt->port = 0;
    
    rmt_memset(&lt->si, 0, sizeof(struct sockinfo));
}

static rmt_connect *
_conn_get(void)
{
    rmt_connect *conn;

    conn = rmt_alloc(sizeof(*conn));
    if (conn == NULL) {
        return NULL;
    }

    conn->ln = NULL;
    
    conn->owner = NULL;

    conn->sd = -1;
    /* {family, addrlen, addr} are initialized in enqueue handler */

    listInit(&conn->omsg_q);
    conn->rmsg = NULL;
    conn->smsg_node = NULL;

    conn->send_bytes = 0;
    conn->recv_bytes = 0;

    conn->err = 0;
    conn->recv_active = 0;
    conn->recv_ready = 0;
    conn->send_active = 0;
    conn->send_ready = 0;

    conn->client = 0;
    conn->connecting = 0;
    conn->connected = 0;
    conn->eof = 0;
    conn->done = 0;

    return conn;
}

rmt_connect *
conn_get(void *owner, int client)
{
    rmt_connect *conn;

    conn = _conn_get();
    if (conn == NULL) {
        return NULL;
    }

    conn->client = client ? 1 : 0;

    if (conn->client) {
        /*
         * client receives a request, possibly parsing it, and sends a
         * response downstream.
         */
        conn->recv = client_recv;
        conn->recv_next = req_recv_next;
        conn->recv_done = req_recv_done;

        conn->send = client_send;
        conn->send_next = rsp_send_next;
        conn->send_done = rsp_send_done;

        conn->close = client_close;
        conn->active = client_active;

        conn->ref = client_ref;
        conn->unref = client_unref;
    } else {
        conn->recv = proxy_recv;
        conn->recv_next = NULL;
        conn->recv_done = NULL;

        conn->send = NULL;
        conn->send_next = NULL;
        conn->send_done = NULL;

        conn->close = proxy_close;
        conn->active = NULL;

        conn->ref = proxy_ref;
        conn->unref = proxy_unref;
    }

    conn->ref(conn, owner);
    log_debug(LOG_VVERB, "get conn %p client %d", conn, conn->client);

    return conn;
}

void
conn_put(rmt_connect *conn)
{
    ASSERT(conn->sd < 0);
    ASSERT(conn->owner == NULL);

    log_debug(LOG_VVERB, "put conn %p", conn);

    rmt_free(conn);
}

static ssize_t
conn_recv(rmt_connect *conn, void *buf, size_t size)
{
    ssize_t n;

    ASSERT(buf != NULL);
    ASSERT(size > 0);
    ASSERT(conn->recv_ready);

    for (;;) {
        n = rmt_read(conn->sd, buf, size);

        log_debug(LOG_VERB, "recv on sd %d %zd of %zu", conn->sd, n, size);

        if (n > 0) {
            if (n < (ssize_t) size) {
                conn->recv_ready = 0;
            }
            conn->recv_bytes += (size_t)n;
            return n;
        }

        if (n == 0) {
            conn->recv_ready = 0;
            conn->eof = 1;
            log_debug(LOG_INFO, "recv on sd %d eof rb %zu sb %zu", conn->sd,
                      conn->recv_bytes, conn->send_bytes);
            return n;
        }

        if (errno == EINTR) {
            log_debug(LOG_VERB, "recv on sd %d not ready - eintr", conn->sd);
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            conn->recv_ready = 0;
            log_debug(LOG_VERB, "recv on sd %d not ready - eagain", conn->sd);
            return RMT_EAGAIN;
        } else {
            conn->recv_ready = 0;
            conn->err = errno;
            log_error("recv on sd %d failed: %s", conn->sd, strerror(errno));
            return RMT_ERROR;
        }
    }

    NOT_REACHED();

    return RMT_ERROR;
}

static ssize_t
conn_sendv(rmt_connect *conn, struct array *sendv, size_t nsend)
{
    ssize_t n;

    ASSERT(array_n(sendv) > 0);
    ASSERT(nsend != 0);
    ASSERT(conn->send_ready);

    for (;;) {
        n = rmt_writev(conn->sd, sendv->elem, sendv->nelem);

        log_debug(LOG_VERB, "sendv on sd %d %zd of %zu in %"PRIu32" buffers",
                  conn->sd, n, nsend, sendv->nelem);

        if (n > 0) {
            if (n < (ssize_t) nsend) {
                conn->send_ready = 0;
            }
            conn->send_bytes += (size_t)n;
            return n;
        }

        if (n == 0) {
            log_warn("sendv on sd %d returned zero", conn->sd);
            conn->send_ready = 0;
            return 0;
        }

        if (errno == EINTR) {
            log_debug(LOG_VERB, "sendv on sd %d not ready - eintr", conn->sd);
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            conn->send_ready = 0;
            log_debug(LOG_VERB, "sendv on sd %d not ready - eagain", conn->sd);
            return RMT_EAGAIN;
        } else {
            conn->send_ready = 0;
            conn->err = errno;
            log_error("sendv on sd %d failed: %s", conn->sd, strerror(errno));
            return RMT_ERROR;
        }
    }

    NOT_REACHED();

    return RMT_ERROR;
}

int
proxy_listen(rmtContext *ctx, rmt_connect *p)
{
    int ret;

    ASSERT(!p->client);

    p->sd = socket(p->family, SOCK_STREAM, 0);
    if (p->sd < 0) {
        log_error("ERROR: socket failed: %s", strerror(errno));
        return RMT_ERROR;
    }

    ret = rmt_set_reuseaddr(p->sd);
    if (ret < 0) {
        log_error("ERROR: reuse of addr '%s' for listening on p %d failed: %s",
                  ctx->lt.addr, p->sd, strerror(errno));
        return RMT_ERROR;
    }

    ret = bind(p->sd, p->addr, p->addrlen);
    if (ret < 0) {
        log_error("bind on p %d to addr '%s' failed: %s", 
            p->sd, ctx->lt.addr, strerror(errno));
        return RMT_ERROR;
    }

    ret = listen(p->sd, 512);
    if (ret < 0) {
        log_error("ERROR: listen on p %d on addr '%s' failed: %s", 
            p->sd, ctx->lt.addr, strerror(errno));
        return RMT_ERROR;
    }

    ret = rmt_set_nonblocking(p->sd);
    if (ret < 0) {
        log_error("ERROR: set nonblock on p %d on addr '%s' failed: %s", 
            p->sd, ctx->lt.addr, strerror(errno));
        return RMT_ERROR;
    }

    ret = aeCreateFileEvent(ctx->loop, p->sd, AE_READABLE, p->recv, p);
    if (ret != RMT_OK) {
        log_error("ERROR: add readable event failed.");
        return RMT_ERROR;
    }
    p->recv_active = 1;

    return RMT_OK;
}

static int
proxy_accept(rmtContext *ctx, rmt_connect *p)
{
    int ret;
    rmt_connect *c;
    int sd;

    ASSERT(!p->client);
    ASSERT(p->sd > 0);
    ASSERT(p->recv_active && p->recv_ready);

    for (;;) {
        sd = accept(p->sd, NULL, NULL);
        if (sd < 0) {
            if (errno == EINTR) {
                log_debug(LOG_VERB, "accept on p %d not ready - eintr", p->sd);
                continue;
            }

            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNABORTED) {
                log_debug(LOG_VERB, "accept on p %d not ready - eagain", p->sd);
                p->recv_ready = 0;
                return RMT_OK;
            }
            
            if (errno == EMFILE || errno == ENFILE) {
                log_debug(LOG_CRIT, "accept on p %d "
                          "max client connections %"PRIu32" "
                          "curr client connections %"PRIu32" failed: %s",
                          p->sd, ctx->max_ncconn, conn_ncurr_cconn(ctx), strerror(errno));

                p->recv_ready = 0;

                return RMT_OK;
            }

            log_error("accept on p %d failed: %s", p->sd, strerror(errno));

            return RMT_ERROR;
        }

        break;
    }

    if (conn_ncurr_cconn(ctx) >= ctx->max_ncconn) {
        log_debug(LOG_CRIT, "client connections %"PRIu32" exceed limit %"PRIu32,
                  conn_ncurr_cconn(ctx), ctx->max_ncconn);
        ret = close(sd);
        if (ret < 0) {
            log_error("close c %d failed, ignored: %s", sd, strerror(errno));
        }
        return RMT_OK;
    }

    c = conn_get(p->owner, 1);
    if (c == NULL) {
        log_error("get conn for c %d from p %d failed: %s", sd, p->sd,
                  strerror(errno));
        ret = close(sd);
        if (ret < 0) {
            log_error("close c %d failed, ignored: %s", sd, strerror(errno));
        }
        return RMT_ENOMEM;
    }
    c->sd = sd;

    ret = rmt_set_nonblocking(c->sd);
    if (ret < 0) {
        log_error("set nonblock on c %d from p %d failed: %s", c->sd, p->sd,
                  strerror(errno));
        c->close(ctx, c);
        return ret;
    }

    if (p->family == AF_INET || p->family == AF_INET6) {
        ret = rmt_set_tcpnodelay(c->sd);
        if (ret < 0) {
            log_warn("set tcpnodelay on c %d from p %d failed, ignored: %s",
                     c->sd, p->sd, strerror(errno));
        }
    }

    ret = aeCreateFileEvent(ctx->loop, c->sd, AE_READABLE, c->recv, c);
    if (ret < 0) {
        log_error("ERROR: event add conn from p %d failed: %s", p->sd,
                  strerror(errno));
        c->close(ctx, c);
        return ret;
    }
    c->recv_active = 1;

    log_debug(LOG_NOTICE, "accepted c %d on p %d from '%s'", c->sd, p->sd,
              rmt_unresolve_peer_desc(c->sd));

    ctx->ntotal_cconn ++;
    ctx->ncurr_cconn ++;

    return RMT_OK;
}

void
proxy_recv(aeEventLoop *el, int fd, void *privdata, int mask)
{
    int ret;
    rmt_connect *p = privdata;
    rmtContext *ctx = p->owner;
    
    RMT_NOTUSED(el);
    RMT_NOTUSED(fd);
    RMT_NOTUSED(privdata);
    RMT_NOTUSED(mask);

    ASSERT(!p->client);
    ASSERT(p->recv_active);

    p->recv_ready = 1;
    do {
        ret = proxy_accept(ctx, p);
        if (ret != RMT_OK) {
            return;
        }
    } while (p->recv_ready);
}

void
proxy_ref(rmt_connect *conn, void *owner)
{
    rmtContext *ctx = owner;

    ASSERT(!conn->client);
    ASSERT(conn->owner == NULL);

    conn->family = ctx->lt.si.family;
    conn->addrlen = ctx->lt.si.addrlen;
    conn->addr = (struct sockaddr *)&ctx->lt.si.addr;

    /* owner of the proxy connection is the server pool */
    conn->owner = owner;
}

void
proxy_unref(rmt_connect *conn)
{
    rmtContext *ctx;

    ASSERT(!conn->client);
    ASSERT(conn->owner != NULL);

    ctx = conn->owner;
    conn->owner = NULL;

    if (conn->sd > 0)
        aeDeleteFileEvent(ctx->loop, conn->sd, AE_READABLE);
}

void
proxy_close(rmtContext *ctx, rmt_connect *conn)
{
    int ret;

    ASSERT(!conn->client);

    if (conn->sd < 0) {
        conn->unref(conn);
        conn_put(conn);
        return;
    }

    ASSERT(conn->rmsg == NULL);
    ASSERT(conn->smsg_node == NULL);
    ASSERT(listLength(&conn->omsg_q) == 0);

    conn->unref(conn);

    ret = close(conn->sd);
    if (ret < 0) {
        log_error("close p %d failed, ignored: %s", conn->sd, strerror(errno));
    }
    conn->sd = -1;

    conn_put(conn);
}


void
client_ref(rmt_connect *conn, void *owner)
{
    rmtContext *ctx = owner;    

    ASSERT(conn->client);
    ASSERT(conn->owner == NULL);
    ASSERT(conn->ln == NULL);

    /*
     * We use null pointer as the sockaddr argument in the accept() call as
     * we are not interested in the address of the peer for the accepted
     * connection
     */
    conn->family = 0;
    conn->addrlen = 0;
    conn->addr = NULL;
    
    listAddNodeTail(&ctx->clients, conn);
    conn->ln = listLast(&ctx->clients);

    /* owner of the client connection is the server pool */
    conn->owner = owner;
}

void
client_unref(rmt_connect *conn)
{
    rmtContext *ctx;

    ASSERT(conn->client);
    ASSERT(conn->owner != NULL);
    ASSERT(conn->ln != NULL && listNodeValue(conn->ln) == conn);

    ctx = conn->owner;
    conn->owner = NULL;

    ASSERT(listLength(&ctx->clients) > 0);
    listDelNode(&ctx->clients, conn->ln);

    if (conn->sd > 0)
        aeDeleteFileEvent(ctx->loop, conn->sd, AE_READABLE|AE_WRITABLE);
}

int
client_active(rmt_connect *conn)
{
    ASSERT(conn->client);

    if (listLength(&conn->omsg_q) > 0) {
        log_debug(LOG_VVERB, "c %d is active", conn->sd);
        return 1;
    }

    if (conn->rmsg != NULL) {
        log_debug(LOG_VVERB, "c %d is active", conn->sd);
        return 1;
    }

    if (conn->smsg_node != NULL) {
        log_debug(LOG_VVERB, "c %d is active", conn->sd);
        return 1;
    }

    log_debug(LOG_VVERB, "c %d is inactive", conn->sd);

    return 0;
}

static int
conn_msg_parsed(rmtContext *ctx, rmt_connect *conn, struct msg *msg)
{
    struct msg *nmsg;
    struct mbuf *mbuf, *nbuf;

    mbuf = listLastValue(msg->data);
    if (msg->pos == mbuf->last) {
        /* no more data to parse */
        conn->recv_done(ctx, conn, msg, NULL);
        return RMT_OK;
    }

    nbuf = msg_split(msg, msg->pos);
    if (nbuf == NULL) {
        return RMT_ENOMEM;
    }

    nmsg = msg_get(msg->mb, msg->request, msg->kind);
    if (nmsg == NULL) {
        mbuf_put(nbuf);
        return RMT_ENOMEM;
    }
    listAddNodeTail(nmsg->data, nbuf);
    nmsg->pos = nbuf->pos;

    /* update length of current (msg) and new message (nmsg) */
    nmsg->mlen = mbuf_length(nbuf);
    msg->mlen -= nmsg->mlen;

    conn->recv_done(ctx, conn, msg, nmsg);

    return RMT_OK;
}

static int
conn_msg_repair(rmtContext *ctx, rmt_connect *conn, struct msg *msg)
{
    struct mbuf *nbuf;

    nbuf = msg_split(msg, msg->pos);
    if (nbuf == NULL) {
        return RMT_ENOMEM;
    }
    listAddNodeTail(msg->data, nbuf);
    msg->pos = nbuf->pos;

    return RMT_OK;
}

static int
conn_msg_parse(rmtContext *ctx, rmt_connect *conn, struct msg *msg)
{
    int ret;

    if (msg_empty(msg)) {
        /* no data to parse */
        conn->recv_done(ctx, conn, msg, NULL);
        return RMT_OK;
    }

    msg->parser(msg);

    switch (msg->result) {
    case MSG_PARSE_OK:
        ret = conn_msg_parsed(ctx, conn, msg);
        break;

    case MSG_PARSE_REPAIR:
        ret = conn_msg_repair(ctx, conn, msg);
        break;

    case MSG_PARSE_AGAIN:
        ret = RMT_OK;
        break;

    default:
        ret = RMT_ERROR;
        conn->err = errno;
        break;
    }

    return conn->err != 0 ? RMT_ERROR : ret;
}

static int
conn_recv_chain(rmtContext *ctx, rmt_connect *conn, struct msg *msg)
{
    int ret;
    struct msg *nmsg;
    struct mbuf *mbuf;
    size_t msize;
    ssize_t n;

    mbuf = listLastValue(msg->data);
    if (mbuf == NULL || mbuf_full(mbuf)) {
        mbuf = mbuf_get(msg->mb);
        if (mbuf == NULL) {
            return RMT_ENOMEM;
        }
        listAddNodeTail(msg->data, mbuf);
        msg->pos = mbuf->pos;
    }
    ASSERT(mbuf->end - mbuf->last > 0);

    msize = mbuf_size(mbuf);

    n = conn_recv(conn, mbuf->last, msize);
    if (n < 0) {
        if (n == RMT_EAGAIN) {
            return RMT_OK;
        }
        return RMT_ERROR;
    }

    ASSERT((mbuf->last + n) <= mbuf->end);
    mbuf->last += n;
    msg->mlen += (uint32_t)n;

    for (;;) {
        ret = conn_msg_parse(ctx, conn, msg);
        if (ret != RMT_OK) {
            return ret;
        }

        /* get next message to parse */
        nmsg = conn->recv_next(ctx, conn, 0);
        if (nmsg == NULL || nmsg == msg) {
            /* no more data to parse */
            break;
        }

        msg = nmsg;
    }

    return RMT_OK;
}

void
client_recv(aeEventLoop *el, int fd, void *privdata, int mask)
{
    int ret;
    rmt_connect *conn = privdata;
    rmtContext *ctx = conn->owner;
    struct msg *msg;

    RMT_NOTUSED(el);
    RMT_NOTUSED(fd);
    RMT_NOTUSED(privdata);
    RMT_NOTUSED(mask);

    ASSERT(conn->recv_active);

    conn->recv_ready = 1;
    do {
        msg = conn->recv_next(ctx, conn, 1);
        if (msg == NULL) {
            goto done;
        }

        ret = conn_recv_chain(ctx, conn, msg);
        if (ret != RMT_OK) {
            goto done;
        }
    } while (conn->recv_ready);

done:
    
    if (conn->err || conn->eof) {
        conn->close(ctx, conn);
    }

    return;
}

static struct msg *
req_get(rmt_connect *conn)
{
    rmtContext *ctx = conn->owner;
    struct msg *msg;

    ASSERT(conn->client);

    msg = msg_get(ctx->mb, 1, REDIS_DATA_TYPE_CMD);
    if (msg == NULL) {
        conn->err = errno;
    }
    return msg;
}

static void
req_put(struct msg *msg)
{
    struct msg *pmsg; /* peer message (response) */

    ASSERT(msg->request);

    pmsg = msg->peer;
    if (pmsg != NULL) {
        ASSERT(!pmsg->request && pmsg->peer == msg);
        msg->peer = NULL;
        pmsg->peer = NULL;
        msg_put(pmsg);
        msg_free(pmsg);
    }

    msg_put(msg);
    msg_free(msg);
}

struct msg *
req_recv_next(rmtContext *ctx, rmt_connect *conn, int alloc)
{
    struct msg *msg;

    ASSERT(conn->client);

    if (conn->eof) {
        msg = conn->rmsg;

        /* client sent eof before sending the entire request */
        if (msg != NULL) {
            conn->rmsg = NULL;

            ASSERT(msg->peer == NULL);
            ASSERT(msg->request);

            log_error("eof c %d discarding incomplete req %"PRIu64" len "
                      "%"PRIu32"", conn->sd, msg->id, msg->mlen);

            req_put(msg);
        }

        /*
         * TCP half-close enables the client to terminate its half of the
         * connection (i.e. the client no longer sends data), but it still
         * is able to receive data from the proxy. The proxy closes its
         * half (by sending the second FIN) when the client has no
         * outstanding requests
         */
        if (!conn->active(conn)) {
            conn->done = 1;
            log_debug(LOG_INFO, "c %d is done", conn->sd);
        }
        return NULL;
    }

    msg = conn->rmsg;
    if (msg != NULL) {
        ASSERT(msg->request);
        return msg;
    }

    if (!alloc) {
        return NULL;
    }

    msg = req_get(conn);
    if (msg != NULL) {
        conn->rmsg = msg;
    }

    return msg;
}

void
req_recv_done(rmtContext *ctx, rmt_connect *conn, struct msg *msg,
              struct msg *nmsg)
{
    int ret;

    ASSERT(conn->client);
    ASSERT(msg->request);
    ASSERT(conn->rmsg == msg);
    ASSERT(nmsg == NULL || nmsg->request);

    /* enqueue next message (request), if any */
    conn->rmsg = nmsg;

    ret = req_make_reply(ctx, conn, msg);
    if (ret != RMT_OK) {
        conn->err = errno;
        return;
    }
    
    return;
}

static int
conn_send_chain(rmtContext *ctx, rmt_connect *conn, struct msg *msg)
{
    list send_msgq;                      /* send msg q */
    struct mbuf *mbuf;                   /* current mbuf */
    size_t mlen;                         /* current mbuf data length */
    struct iovec *ciov, iov[RMT_IOV_MAX]; /* current iovec */
    struct array sendv;                  /* send iovec */
    size_t nsend, nsent;                 /* bytes to send; bytes sent */
    size_t limit;                        /* bytes to send limit */
    ssize_t n;                           /* bytes sent by sendv */
    listNode *lnode;

    listInit(&send_msgq);

    array_set(&sendv, iov, sizeof(iov[0]), RMT_IOV_MAX);

    /* preprocess - build iovec */

    nsend = 0;
    /*
     * readv() and writev() returns EINVAL if the sum of the iov_len values
     * overflows an ssize_t value Or, the vector count iovcnt is less than
     * zero or greater than the permitted maximum.
     */
    limit = SSIZE_MAX;

    for (;;) {
        ASSERT(listNodeValue(conn->smsg_node) == msg->peer);

        listAddNodeTail(&send_msgq, msg);

        lnode = listFirst(msg->data);
        while (lnode) {
            mbuf = listNodeValue(lnode);

            if (mbuf_empty(mbuf)) {
                lnode = listNextNode(lnode);
                continue;
            }

            mlen = mbuf_length(mbuf);
            if ((nsend + mlen) > limit) {
                mlen = limit - nsend;
            }

            ciov = array_push(&sendv);
            ciov->iov_base = mbuf->pos;
            ciov->iov_len = mlen;

            nsend += mlen;

            lnode = listNextNode(lnode);
        }

        if (array_n(&sendv) >= RMT_IOV_MAX || nsend >= limit) {
            break;
        }

        msg = conn->send_next(ctx, conn);
        if (msg == NULL) {
            break;
        }
    }

    conn->smsg_node = NULL;
    if (listLength(&send_msgq) > 0 && nsend != 0) {
        n = conn_sendv(conn, &sendv, nsend);
    } else {
        n = 0;
    }

    nsent = n > 0 ? (size_t)n : 0;

    /* postprocess - process sent messages in send_msgq */

    while (listLength(&send_msgq) > 0) {
        msg = listPop(&send_msgq);

        if (nsent == 0) {
            if (msg->mlen == 0) {
                conn->send_done(ctx, conn, msg);
            }
            continue;
        }

        lnode = listFirst(msg->data);
        while (lnode) {
            mbuf = listNodeValue(lnode);
            
            if (mbuf_empty(mbuf)) {
                lnode = listNextNode(lnode);
                continue;
            }

            mlen = mbuf_length(mbuf);
            if (nsent < mlen) {
                /* mbuf was sent partially; process remaining bytes later */
                mbuf->pos += nsent;
                ASSERT(mbuf->pos < mbuf->last);
                nsent = 0;
                break;
            }

            /* mbuf was sent completely; mark it empty */
            mbuf->pos = mbuf->last;
            nsent -= mlen;
            
            lnode = listNextNode(lnode);
        }

        /* message has been sent completely, finalize it */
        if (lnode == NULL) {
            conn->send_done(ctx, conn, msg);
        }
    }

    ASSERT(listLength(&send_msgq) == 0);

    if (n >= 0) {
        return RMT_OK;
    }

    return (n == RMT_EAGAIN) ? RMT_OK : RMT_ERROR;
}

void
client_send(aeEventLoop *el, int fd, void *privdata, int mask)
{
    int ret;
    rmt_connect *conn = privdata;
    rmtContext *ctx = conn->owner;
    struct msg *msg;

    RMT_NOTUSED(el);
    RMT_NOTUSED(fd);
    RMT_NOTUSED(privdata);
    RMT_NOTUSED(mask);

    ASSERT(conn->send_active);

    conn->send_ready = 1;
    do {
        msg = conn->send_next(ctx, conn);
        if (msg == NULL) {
            /* nothing to send */
            goto done;
        }

        ret = conn_send_chain(ctx, conn, msg);
        if (ret != RMT_OK) {
            goto done;
        }

    } while (conn->send_ready);

done:
    
    if (conn->err || conn->eof) {
        conn->close(ctx, conn);
    }

    return;
}

struct msg *
rsp_send_next(rmtContext *ctx, rmt_connect *conn)
{
    listNode *lnode;
    struct msg *msg, *pmsg; /* response and it's peer request */

    ASSERT(conn->client);

    if (listLength(&conn->omsg_q) == 0) {
        /* nothing is outstanding, initiate close? */
        if (conn->eof) {
            conn->done = 1;
            log_debug(LOG_INFO, "c %d is done", conn->sd);
        }

        aeDeleteFileEvent(ctx->loop, conn->sd, AE_WRITABLE);
        conn->send_active = 0;

        return NULL;
    }

    lnode = conn->smsg_node;
    if (lnode != NULL) {
        lnode = listNextNode(lnode);
        if (lnode == NULL) {
            conn->smsg_node = NULL;
            return NULL;
        }
    } else {
        lnode = listFirst(&conn->omsg_q);
        ASSERT(lnode != NULL);
    }
    
    pmsg = listNodeValue(lnode);
    ASSERT(pmsg != NULL);
    ASSERT(pmsg->request && pmsg->peer != NULL);

    msg = pmsg->peer;
    ASSERT(!msg->request);

    conn->smsg_node = lnode;

    log_debug(LOG_VVERB, "send next rsp %"PRIu64" on c %d", msg->id, conn->sd);

    return msg;
}

void
rsp_send_done(rmtContext *ctx, rmt_connect *conn, struct msg *msg)
{
    listNode *lnode;
    struct msg *pmsg; /* peer message (request) */

    ASSERT(conn->client);
    ASSERT(conn->smsg_node == NULL);

    log_debug(LOG_VVERB, "send done rsp %"PRIu64" on c %d", msg->id, conn->sd);

    pmsg = msg->peer;

    ASSERT(!msg->request && pmsg->request);
    ASSERT(pmsg->peer == msg);
    ASSERT(listLength(&conn->omsg_q) > 0);

    lnode = listFirst(&conn->omsg_q);

    ASSERT(lnode != NULL);
    ASSERT(listNodeValue(lnode) == pmsg);

    listDelNode(&conn->omsg_q, lnode);

    req_put(pmsg);
}

void
client_close(rmtContext *ctx, rmt_connect *conn)
{
    int ret;
    listNode *lnode;
    struct msg *msg;

    ASSERT(conn->client);

    if (conn->sd < 0) {
        conn->unref(conn);
        conn_put(conn);
        return;
    }

    msg = conn->rmsg;
    if (msg != NULL) {
        conn->rmsg = NULL;

        ASSERT(msg->peer == NULL);
        ASSERT(msg->request);

        log_debug(LOG_INFO, "close c %d discarding pending req %"PRIu64" len "
                  "%"PRIu32" type %d", conn->sd, msg->id, msg->mlen,
                  msg->type);

        req_put(msg);
    }

    ASSERT(conn->smsg_node == NULL);

    while (listLength(&conn->omsg_q) > 0) {
        lnode = listFirst(&conn->omsg_q);
        msg = listNodeValue(lnode);
        listDelNode(&conn->omsg_q, lnode);

        req_put(msg);
    }
    ASSERT(listLength(&conn->omsg_q) == 0);

    conn->unref(conn);

    log_debug(LOG_NOTICE, "close c %d from '%s'", 
        conn->sd, rmt_unresolve_peer_desc(conn->sd));

    ret = close(conn->sd);
    if (ret < 0) {
        log_error("close c %d failed, ignored: %s", conn->sd, strerror(errno));
    }
    conn->sd = -1;

    conn_put(conn);

    ASSERT(ctx->ncurr_cconn > 0);
    ctx->ncurr_cconn --;
}


uint64_t
conn_ntotal_cconn(rmtContext *ctx)
{
    return ctx->ntotal_cconn;
}

uint32_t
conn_ncurr_cconn(rmtContext *ctx)
{
    return ctx->ncurr_cconn;
}

int proxy_begin(rmtContext *ctx)
{
    int ret;
    rmt_connect *p;
    
    p = conn_get(ctx, 0);
    if (p == NULL) {
        log_error("ERROR: get proxy connect failed.");
        return RMT_ERROR;
    }
    
    ret = proxy_listen(ctx, p);
    if (ret != RMT_OK) {
        p->close(ctx, p);
        log_error("ERROR: get proxy connect failed.");
        return RMT_ERROR;
    }

    ctx->proxy = p;

    return RMT_OK;
}

