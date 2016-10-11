
#ifndef _RMT_MESSAGE_H_
#define _RMT_MESSAGE_H_

struct msg;
struct rmtContext;
struct redis_group;
struct redis_node;

typedef void (*msg_parse_t)(struct msg *);
//typedef rstatus_t (*msg_add_auth_t)(struct context *ctx, struct conn *c_conn, struct conn *s_conn);
typedef int (*msg_add_auth_t)(void);
typedef int (*msg_fragment_t)(struct redis_group *, struct msg *, uint32_t, list *);
typedef void (*msg_coalesce_t)(struct msg *r);
typedef int (*msg_reply_t)(struct msg *r);
typedef int (*msg_resp_check_t)(struct redis_node *, struct msg *);

typedef enum msg_parse_result {
    MSG_PARSE_OK,                         /* parsing ok */
    MSG_PARSE_ERROR,                      /* parsing error */
    MSG_PARSE_REPAIR,                     /* more to parse -> repair parsed & unparsed data */
    MSG_PARSE_AGAIN,                      /* incomplete -> parse again */
} msg_parse_result_t;

#define MSG_TYPE_CODEC(ACTION)                                                                      \
    ACTION( UNKNOWN )                                                                               \
    ACTION( REQ_REDIS_SELECT )                                                                      \
    ACTION( REQ_REDIS_DEL )                    /* redis commands - keys */                            \
    ACTION( REQ_REDIS_EXISTS )                                                                      \
    ACTION( REQ_REDIS_EXPIRE )                                                                      \
    ACTION( REQ_REDIS_EXPIREAT )                                                                    \
    ACTION( REQ_REDIS_PEXPIRE )                                                                     \
    ACTION( REQ_REDIS_PEXPIREAT )                                                                   \
    ACTION( REQ_REDIS_PERSIST )                                                                     \
    ACTION( REQ_REDIS_PTTL )                                                                        \
    ACTION( REQ_REDIS_SORT )                                                                        \
    ACTION( REQ_REDIS_TTL )                                                                         \
    ACTION( REQ_REDIS_TYPE )                                                                        \
    ACTION( REQ_REDIS_APPEND )                 /* redis requests - string */                            \
    ACTION( REQ_REDIS_BITCOUNT )                                                                    \
    ACTION( REQ_REDIS_DECR )                                                                        \
    ACTION( REQ_REDIS_DECRBY )                                                                      \
    ACTION( REQ_REDIS_DUMP )                                                                        \
    ACTION( REQ_REDIS_GET )                                                                         \
    ACTION( REQ_REDIS_GETBIT )                                                                      \
    ACTION( REQ_REDIS_GETRANGE )                                                                    \
    ACTION( REQ_REDIS_GETSET )                                                                      \
    ACTION( REQ_REDIS_INCR )                                                                        \
    ACTION( REQ_REDIS_INCRBY )                                                                      \
    ACTION( REQ_REDIS_INCRBYFLOAT )                                                                 \
    ACTION( REQ_REDIS_MGET )                                                                        \
    ACTION( REQ_REDIS_MSET )                                                                        \
    ACTION( REQ_REDIS_PSETEX )                                                                      \
    ACTION( REQ_REDIS_RESTORE )                                                                     \
    ACTION( REQ_REDIS_SET )                                                                         \
    ACTION( REQ_REDIS_SETBIT )                                                                      \
    ACTION( REQ_REDIS_SETEX )                                                                       \
    ACTION( REQ_REDIS_SETNX )                                                                       \
    ACTION( REQ_REDIS_SETRANGE )                                                                    \
    ACTION( REQ_REDIS_STRLEN )                                                                      \
    ACTION( REQ_REDIS_HDEL )                   /* redis requests - hashes */                        \
    ACTION( REQ_REDIS_HEXISTS )                                                                     \
    ACTION( REQ_REDIS_HGET )                                                                        \
    ACTION( REQ_REDIS_HGETALL )                                                                     \
    ACTION( REQ_REDIS_HINCRBY )                                                                     \
    ACTION( REQ_REDIS_HINCRBYFLOAT )                                                                \
    ACTION( REQ_REDIS_HKEYS )                                                                       \
    ACTION( REQ_REDIS_HLEN )                                                                        \
    ACTION( REQ_REDIS_HMGET )                                                                       \
    ACTION( REQ_REDIS_HMSET )                                                                       \
    ACTION( REQ_REDIS_HSET )                                                                        \
    ACTION( REQ_REDIS_HSETNX )                                                                      \
    ACTION( REQ_REDIS_HSCAN)                                                                        \
    ACTION( REQ_REDIS_HVALS )                                                                       \
    ACTION( REQ_REDIS_LINDEX )                 /* redis requests - lists */                         \
    ACTION( REQ_REDIS_LINSERT )                                                                     \
    ACTION( REQ_REDIS_LLEN )                                                                        \
    ACTION( REQ_REDIS_LPOP )                                                                        \
    ACTION( REQ_REDIS_LPUSH )                                                                       \
    ACTION( REQ_REDIS_LPUSHX )                                                                      \
    ACTION( REQ_REDIS_LRANGE )                                                                      \
    ACTION( REQ_REDIS_LREM )                                                                        \
    ACTION( REQ_REDIS_LSET )                                                                        \
    ACTION( REQ_REDIS_LTRIM )                                                                       \
    ACTION( REQ_REDIS_PFADD )                  /* redis requests - hyperloglog */                   \
    ACTION( REQ_REDIS_PFCOUNT )                                                                     \
    ACTION( REQ_REDIS_PFMERGE )                                                                     \
    ACTION( REQ_REDIS_RPOP )                                                                        \
    ACTION( REQ_REDIS_RPOPLPUSH )                                                                   \
    ACTION( REQ_REDIS_RPUSH )                                                                       \
    ACTION( REQ_REDIS_RPUSHX )                                                                      \
    ACTION( REQ_REDIS_SADD )                   /* redis requests - sets */                          \
    ACTION( REQ_REDIS_SCARD )                                                                       \
    ACTION( REQ_REDIS_SDIFF )                                                                       \
    ACTION( REQ_REDIS_SDIFFSTORE )                                                                  \
    ACTION( REQ_REDIS_SINTER )                                                                      \
    ACTION( REQ_REDIS_SINTERSTORE )                                                                 \
    ACTION( REQ_REDIS_SISMEMBER )                                                                   \
    ACTION( REQ_REDIS_SMEMBERS )                                                                    \
    ACTION( REQ_REDIS_SMOVE )                                                                       \
    ACTION( REQ_REDIS_SPOP )                                                                        \
    ACTION( REQ_REDIS_SRANDMEMBER )                                                                 \
    ACTION( REQ_REDIS_SREM )                                                                        \
    ACTION( REQ_REDIS_SUNION )                                                                      \
    ACTION( REQ_REDIS_SUNIONSTORE )                                                                 \
    ACTION( REQ_REDIS_SSCAN)                                                                        \
    ACTION( REQ_REDIS_ZADD )                   /* redis requests - sorted sets */                   \
    ACTION( REQ_REDIS_ZCARD )                                                                       \
    ACTION( REQ_REDIS_ZCOUNT )                                                                      \
    ACTION( REQ_REDIS_ZINCRBY )                                                                     \
    ACTION( REQ_REDIS_ZINTERSTORE )                                                                 \
    ACTION( REQ_REDIS_ZLEXCOUNT )                                                                   \
    ACTION( REQ_REDIS_ZRANGE )                                                                      \
    ACTION( REQ_REDIS_ZRANGEBYLEX )                                                                 \
    ACTION( REQ_REDIS_ZRANGEBYSCORE )                                                               \
    ACTION( REQ_REDIS_ZRANK )                                                                       \
    ACTION( REQ_REDIS_ZREM )                                                                        \
    ACTION( REQ_REDIS_ZREMRANGEBYRANK )                                                             \
    ACTION( REQ_REDIS_ZREMRANGEBYLEX )                                                              \
    ACTION( REQ_REDIS_ZREMRANGEBYSCORE )                                                            \
    ACTION( REQ_REDIS_ZREVRANGE )                                                                   \
    ACTION( REQ_REDIS_ZREVRANGEBYSCORE )                                                            \
    ACTION( REQ_REDIS_ZREVRANK )                                                                    \
    ACTION( REQ_REDIS_ZSCORE )                                                                      \
    ACTION( REQ_REDIS_ZUNIONSTORE )                                                                 \
    ACTION( REQ_REDIS_ZSCAN )                                                                       \
    ACTION( REQ_REDIS_EVAL )                   /* redis requests - eval */                              \
    ACTION( REQ_REDIS_EVALSHA )                                                                     \
    ACTION( REQ_REDIS_PING )                   /* redis requests - ping/quit */                         \
	ACTION( REQ_REDIS_INFO )                                                                        \
	ACTION( REQ_REDIS_MULTI )                                                                        \
	ACTION( REQ_REDIS_EXEC )                                                                        \
    ACTION( REQ_REDIS_QUIT )                                                                        \
    ACTION( REQ_REDIS_AUTH )                                                                        \
    ACTION( REQ_REDIS_SHUTDOWN )                                                                    \
    ACTION( RSP_REDIS_STATUS )                 /* redis response */                                   \
    ACTION( RSP_REDIS_ERROR )                                                                       \
    ACTION( RSP_REDIS_INTEGER )                                                                     \
    ACTION( RSP_REDIS_BULK )                                                                        \
    ACTION( RSP_REDIS_MULTIBULK )                                                                   \
    ACTION( SENTINEL )                                                                              \

#define DEFINE_ACTION(_name) MSG_##_name,
typedef enum msg_type {
    MSG_TYPE_CODEC(DEFINE_ACTION)
} msg_type_t;
#undef DEFINE_ACTION

struct keypos {
    uint8_t             *start;           /* key start pos */
    uint8_t             *end;             /* key end pos */
};

struct msg {
    uint64_t             id;              /* message id */
    struct msg           *peer;           /* message peer */

    mbuf_base            *mb;
    list                 *data;           /* data in this message, type: mbuf */
    uint32_t             mlen;            /* message length */

    int                  state;           /* current parser state */
    uint8_t              *pos;            /* parser position marker */
    uint8_t              *token;          /* token marker */

    msg_parse_t          parser;          /* message parser */
    msg_parse_result_t   result;          /* message parsing result */

    msg_resp_check_t     resp_check;

    msg_fragment_t       fragment;        /* message fragment */
    msg_reply_t          reply;           /* gen message reply (example: ping) */
    msg_add_auth_t       add_auth;        /* add auth message when we forward msg */

    msg_coalesce_t       pre_coalesce;    /* message pre-coalesce */
    msg_coalesce_t       post_coalesce;   /* message post-coalesce */

    msg_type_t           type;            /* message type */

    struct array         *keys;           /* array of keypos, for req */

    uint32_t             vlen;            /* value length (memcache) */
    uint8_t              *end;            /* end marker (memcache) */

    uint8_t              *narg_start;     /* narg start (redis) */
    uint8_t              *narg_end;       /* narg end (redis) */
    uint32_t             narg;            /* # arguments (redis) */
    uint32_t             rnarg;           /* running # arg used by parsing fsa (redis) */
    uint32_t             rlen;            /* running length in parsing fsa (redis) */
    uint32_t             integer;         /* integer reply value (redis) */
    uint32_t             bulk_len;        /* bulk length in parsing fsa (redis) */
    uint8_t              *bulk_start;     /* bulk start (redis) */

    struct msg           *frag_owner;     /* owner of fragment message */
    uint32_t             nfrag;           /* # fragment */
    uint32_t             nfrag_done;      /* # fragment done */
    uint64_t             frag_id;         /* id of fragmented message */
    struct msg           **frag_seq;      /* sequence of fragment message, map from keys to fragments*/

    err_t                err;             /* errno on error? */
    unsigned             error:1;         /* error? */
    unsigned             ferror:1;        /* one or more fragments are in error? */
    unsigned             request:1;       /* request? or response? */
    unsigned             quit:1;          /* quit request? */
    unsigned             noreply:1;       /* noreply? */
    unsigned             noforward:1;     /* not need forward (example: ping) */

    unsigned             sent:1;          /* have send to target */

    int                  kind;

    void                 *ptr;
};

char *msg_type_string(msg_type_t type);
struct msg *msg_get(mbuf_base *mb, int request, int type);
void msg_free(struct msg *msg);
void msg_put(struct msg *msg);
int msg_empty(struct msg *msg);
uint64_t msg_gen_frag_id(void);
uint32_t msg_backend_idx(struct msg *msg, uint8_t *key, uint32_t keylen);
struct mbuf *msg_ensure_mbuf(struct msg *msg, size_t len);
int msg_append_full(struct msg *msg, const uint8_t *pos, uint32_t n);
int msg_append(struct msg *msg, uint8_t *pos, size_t n);
int msg_prepend(struct msg *msg, uint8_t *pos, size_t n);
int msg_prepend_format(struct msg *msg, const char *fmt, ...);

struct mbuf *msg_split(struct msg *msg, uint8_t *pos);

int msg_cmp_str(struct msg *msg, const uint8_t *str, uint32_t len);

#ifdef RMT_MEMORY_TEST
int msg_used_init(void);
void msg_used_deinit(void);
long long msg_used_count(void);
int msg_used_up(void);
int msg_used_down(void);
#endif

int _msg_check(const char *file, int line, struct rmtContext *ctx, struct msg *msg, int panic);
void _msg_dump(const char *file, int line, struct msg *msg, int level, int begin);

int msg_data_compare(struct msg *msg1, struct msg *msg2);

#ifdef RMT_ASSERT_PANIC
#define MSG_CHECK(_c, _x) do {                          \
    _msg_check(__FILE__, __LINE__, _c, _x, 1);           \
} while (0)
#elif RMT_ASSERT_LOG
#define MSG_CHECK(_c, _x) do {      \
    _msg_check(__FILE__, __LINE__, _c, _x, 0);           \
} while (0)
#else
#define MSG_CHECK(_c, _x)
#endif

#if (defined RMT_ASSERT_PANIC) || (defined RMT_ASSERT_LOG)
#define MSG_DUMP(_m, _l, _b) do {                           \
    _msg_dump(__FILE__, __LINE__, _m, _l, _b);              \
} while (0)
#else
#define MSG_DUMP(_m, _l, _b)
#endif

#define MSG_DUMP_ALL(_m, _l, _b) do {                       \
    _msg_dump(__FILE__, __LINE__, _m, _l, _b);              \
} while (0)

#endif
