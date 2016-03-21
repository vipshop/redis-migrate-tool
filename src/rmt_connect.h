
#ifndef _RMT_CLIENT_H_
#define _RMT_CLIENT_H_

struct rmt_connect;
struct rmtContext;
struct aeEventLoop;

typedef void (*conn_recv_t)(struct aeEventLoop *, int, void *, int);
typedef struct msg* (*conn_recv_next_t)(struct rmtContext *, struct rmt_connect *, int);
typedef void (*conn_recv_done_t)(struct rmtContext *, struct rmt_connect *, struct msg *, struct msg *);

typedef void (*conn_send_t)(struct aeEventLoop *, int, void *, int);
typedef struct msg* (*conn_send_next_t)(struct rmtContext *, struct rmt_connect *);
typedef void (*conn_send_done_t)(struct rmtContext *, struct rmt_connect *, struct msg *);

typedef int (*conn_active_t)(struct rmt_connect *);

typedef void (*conn_ref_t)(struct rmt_connect *, void *);
typedef void (*conn_unref_t)(struct rmt_connect *);
typedef void (*conn_close_t)(struct rmtContext *, struct rmt_connect *);

typedef struct rmt_listen {
    sds addr;
    sds host;
    int port;
    struct sockinfo si;
} rmt_listen;

int rmt_listen_init(rmt_listen *lt, char *address);
void rmt_listen_deinit(rmt_listen *lt);


typedef struct rmt_connect {
    listNode           *ln;           /* listNode for this connect */
    void               *owner;        /* owner */
    int                sd;            /* socket descriptor */
    int                family;        /* socket address family */
    socklen_t          addrlen;       /* socket length */
    struct sockaddr    *addr;         /* socket address */
    
    size_t             recv_bytes;    /* received (read) bytes */
    size_t             send_bytes;    /* sent (written) bytes */

    conn_recv_t        recv;          /* recv (read) handler */
    conn_recv_next_t   recv_next;     /* recv next message handler */
    conn_recv_done_t   recv_done;     /* read done handler */
    conn_send_t        send;          /* send (write) handler */
    conn_send_next_t   send_next;     /* write next message handler */
    conn_send_done_t   send_done;     /* write done handler */
    conn_ref_t         ref;           /* connection reference handler */
    conn_unref_t       unref;         /* connection unreference handler */
    conn_active_t      active;        /* active? handler */
    conn_close_t       close;         /* close handler */
    
    err_t              err;           /* connection errno */

    list               omsg_q;        /* outstanding request Q */
    struct msg         *rmsg;         /* current message being rcvd */
    struct listNode    *smsg_node;    /* current message listNode being sent in the connect-> omsg_q list */

    unsigned           client:1;       /* proxy or client? */

    unsigned           recv_active:1; /* recv active? */
    unsigned           recv_ready:1;  /* recv ready? */
    unsigned           send_active:1; /* send active? */
    unsigned           send_ready:1;  /* send ready? */

    unsigned           connecting:1;  /* connecting? */
    unsigned           connected:1;   /* connected? */
    unsigned           eof:1;         /* eof? aka passive close? */
    unsigned           done:1;        /* done? aka close? */
} rmt_connect;

rmt_connect *conn_get(void *owner, int client);
void conn_put(rmt_connect *conn);

int proxy_listen(struct rmtContext *ctx, rmt_connect *p);

int proxy_recv(aeEventLoop *el, int fd, void *privdata, int mask);
void proxy_ref(rmt_connect *conn, void *owner);
void proxy_unref(rmt_connect *conn);
void proxy_close(struct rmtContext *ctx, rmt_connect *conn);


int client_active(rmt_connect *conn);
void client_recv(struct aeEventLoop *el, int fd, void *privdata, int mask);
struct msg *req_recv_next(struct rmtContext *ctx, rmt_connect *conn, int alloc);
void req_recv_done(struct rmtContext *ctx, rmt_connect *conn, struct msg *msg, struct msg *nmsg);
void client_send(struct aeEventLoop *el, int fd, void *privdata, int mask);
struct msg *rsp_send_next(struct rmtContext *ctx, rmt_connect *conn);
void rsp_send_done(struct rmtContext *ctx, rmt_connect *conn, struct msg *msg);
void client_ref(rmt_connect *conn, void *owner);
void client_unref(rmt_connect *conn);
void client_close(struct rmtContext *ctx, rmt_connect *conn);

uint64_t conn_ntotal_cconn(struct rmtContext *ctx);
uint32_t conn_ncurr_cconn(struct rmtContext *ctx);

int proxy_begin(struct rmtContext *ctx);

#endif
