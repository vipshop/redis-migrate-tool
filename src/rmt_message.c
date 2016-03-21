
#include <rmt_core.h>

#ifdef RMT_MEMORY_TEST
static volatile long long msg_used;
static pthread_mutex_t msg_mutex;
#endif

#define DEFINE_ACTION(_name) (char*)(#_name),
static char* msg_type_strings[] = {
    MSG_TYPE_CODEC( DEFINE_ACTION )
    NULL
};
#undef DEFINE_ACTION

static struct msg *
_msg_get(void)
{
    struct msg *msg;

    msg = rmt_alloc(sizeof(*msg));
    if (msg == NULL) {
        return NULL;
    }

#ifdef RMT_MEMORY_TEST
    msg_used_up();
#endif
    
    msg->id = 0;
    msg->peer = NULL;

    msg->mb = NULL;
    msg->data = NULL;
    msg->mlen = 0;

    msg->state = 0;
    msg->pos = NULL;
    msg->token = NULL;

    msg->parser = NULL;
    msg->add_auth = NULL;
    msg->result = MSG_PARSE_OK;

    msg->resp_check = NULL;

    msg->fragment = NULL;
    msg->reply = NULL;
    msg->pre_coalesce = NULL;
    msg->post_coalesce = NULL;

    msg->type = MSG_UNKNOWN;

    msg->keys = array_create(1, sizeof(struct keypos));
    if (msg->keys == NULL) {
        rmt_free(msg);
        return NULL;
    }

    msg->vlen = 0;
    msg->end = NULL;

    msg->frag_owner = NULL;
    msg->frag_seq = NULL;
    msg->nfrag = 0;
    msg->nfrag_done = 0;
    msg->frag_id = 0;

    msg->narg_start = NULL;
    msg->narg_end = NULL;
    msg->narg = 0;
    msg->rnarg = 0;
    msg->rlen = 0;
    msg->integer = 0;

    msg->err = 0;
    msg->error = 0;
    msg->ferror = 0;
    msg->request = 0;
    msg->quit = 0;
    msg->noreply = 0;
    msg->noforward = 0;

    msg->kind = 0;

    msg->sent = 0;

    return msg;
}

struct msg *
msg_get(mbuf_base *mb, int request, int kind)
{
    struct msg *msg;

    if (mb == NULL) {
        return NULL;
    }

    msg = _msg_get();
    if (msg == NULL) {
        return NULL;
    }

    msg->mb = mb;
    msg->request = request ? 1 : 0;

    if (request) {
        if (kind == REDIS_DATA_TYPE_RDB) {
            msg->parser = redis_parse_req_rdb;
        } else if(kind == REDIS_DATA_TYPE_CMD) {
            msg->parser = redis_parse_req;
        } else {
            msg_put(msg);
            msg_free(msg);
            return NULL;
        }

        msg->kind = kind;
    } else {
        msg->parser = redis_parse_rsp;
    }

    msg->data = listCreate();
    if (msg->data == NULL) {
        msg_put(msg);
        msg_free(msg);
        return NULL;
    }

    if (request) {
        msg->request = 1;
    } else {
        msg->request = 0;
    }

    msg->fragment = redis_fragment;
    msg->reply = redis_reply;
    msg->pre_coalesce = redis_pre_coalesce;
    msg->post_coalesce = redis_post_coalesce;

    msg->resp_check = redis_response_check;
    
    log_debug(LOG_VVERB, "get msg %p id %"PRIu64" request %d",
              msg, msg->id, msg->request);

    return msg;
}

void
msg_free(struct msg *msg)
{

#ifdef RMT_MEMORY_TEST
    msg_used_down();
#endif

    log_debug(LOG_VVERB, "free msg %p id %"PRIu64"", msg, msg->id);
    rmt_free(msg);
}

void
msg_put(struct msg *msg)
{
    listNode *node;
    struct mbuf *mbuf;

    log_debug(LOG_VVERB, "put msg %p id %"PRIu64"", msg, msg->id);

    while (listLength(msg->data) > 0) {

        node = listFirst(msg->data);
        mbuf = listNodeValue(node);

        listDelNode(msg->data, node);

        mbuf_put(mbuf);
    }

    listRelease(msg->data);
    msg->data = NULL;

    if (msg->frag_seq) {
        rmt_free(msg->frag_seq);
        msg->frag_seq = NULL;
    }

    if (msg->keys) {
        msg->keys->nelem = 0; /* a hack here */
        array_destroy(msg->keys);
        msg->keys = NULL;
    }

    msg->mb = NULL;
}

#ifdef RMT_DEBUG_LOG
void msg_dump(struct msg *msg, int level)
{
    struct mbuf *mbuf;
    listIter *iter;
    listNode *node;
    uint8_t *p, *q;
    long int len;

    if (log_loggable(level) == 0) {
        return;
    }

    loga("msg dump id %"PRIu64" request %d len %"PRIu32" type %d "
         "(err %d) kind %d result %d mbuf_count %u", 
         msg->id, msg->request, msg->mlen, 
         msg->type, msg->err, msg->kind, 
         msg->result, listLength(msg->data));


    iter = listGetIterator(msg->data, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        mbuf = listNodeValue(node);
        
        p = mbuf->start;
        q = mbuf->last;
        len = q - p;

        loga_hexdump(p, len, "mbuf [%p] with %ld bytes of data", p, len);
    }

    listReleaseIterator(iter);
}
#else
void
msg_dump(struct msg *msg, int level)
{
    RMT_NOTUSED(msg);
    RMT_NOTUSED(level);
}
#endif

void msg_dump_all(struct msg *msg, int level)
{
    struct mbuf *mbuf;
    listIter *iter;
    listNode *node;
    uint8_t *p, *q;
    long int len;

    if (log_loggable(level) == 0) {
        return;
    }

    loga("msg dump id %"PRIu64" request %d len %"PRIu32" type %d "
         "(err %d) kind %d result %d mbuf_count %u", 
         msg->id, msg->request, msg->mlen, 
         msg->type, msg->err, msg->kind, 
         msg->result, listLength(msg->data));

    iter = listGetIterator(msg->data, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        mbuf = listNodeValue(node);
        
        p = mbuf->start;
        q = mbuf->last;
        len = q - p;

        loga_hexdump(p, len, "mbuf [%p] with %ld bytes of data", p, len);
    }

    listReleaseIterator(iter);
}

char*
msg_type_string(msg_type_t type)
{
    return msg_type_strings[type];
}

int
msg_empty(struct msg *msg)
{
    return msg->mlen == 0 ? 1 : 0;
}

uint32_t
msg_backend_idx(struct msg *msg, uint8_t *key, uint32_t keylen)
{
    RMT_NOTUSED(msg);
    RMT_NOTUSED(key);    
    RMT_NOTUSED(keylen);

    return 0;
}

struct mbuf *
msg_ensure_mbuf(struct msg *msg, size_t len)
{
    listNode *node;
    mbuf_base *mb = msg->mb;
    struct mbuf *mbuf;

    node = listLast(msg->data);
    
    if(node == NULL ||
        mbuf_size(listNodeValue(node)) < len)
    {
        mbuf = mbuf_get(mb);
        if (mbuf == NULL) {
            return NULL;
        }

        listAddNodeTail(msg->data, mbuf);
    }
    else
    {
        mbuf = listNodeValue(node);
    }

    return mbuf;
}

/*
 * fill the mbuf in the msg with the content
 */
int
msg_append_full(struct msg *msg, const uint8_t *pos, size_t n)
{
    struct mbuf *mbuf;
    uint32_t mbuf_s;
    mbuf_base *mb = msg->mb;
    const uint8_t *start = pos;

    while(1){
        mbuf = listLastValue(msg->data);
        if(mbuf == NULL || mbuf_size(mbuf) == 0){
            mbuf = mbuf_get(mb);
            if(mbuf == NULL){
                log_error("ERROR: Mbuf get failed: out of memory");
                return RMT_ENOMEM;
            }

            listAddNodeTail(msg->data, mbuf);
        }

        mbuf_s = mbuf_size(mbuf);
        if(n > mbuf_s){
            mbuf_copy(mbuf, start, mbuf_s);
            msg->mlen += (uint32_t)mbuf_s;
            n -= mbuf_s;
            start += mbuf_s;
        }else{
            mbuf_copy(mbuf, start, n);
            msg->mlen += (uint32_t)n;
            break;
        }
    }
    
    return RMT_OK;
}

/*
 * append small(small than a mbuf) content into msg
 */
int
msg_append(struct msg *msg, uint8_t *pos, size_t n)
{
    struct mbuf *mbuf;

    ASSERT(n <= mbuf_data_size(msg->mb));

    mbuf = msg_ensure_mbuf(msg, n);
    if (mbuf == NULL) {
        return RMT_ENOMEM;
    }

    ASSERT(n <= mbuf_size(mbuf));

    mbuf_copy(mbuf, pos, n);
    msg->mlen += (uint32_t)n;
    return RMT_OK;
}

/*
 * prepend small(small than a mbuf) content into msg
 */
int
msg_prepend(struct msg *msg, uint8_t *pos, size_t n)
{
    mbuf_base *mb = msg->mb;
    struct mbuf *mbuf;

    mbuf = mbuf_get(mb);
    if (mbuf == NULL) {
        return RMT_ENOMEM;
    }

    ASSERT(n <= mbuf_size(mbuf));

    mbuf_copy(mbuf, pos, n);
    msg->mlen += (uint32_t)n;

    listAddNodeHead(msg->data, mbuf);

    return RMT_OK;
}

/*
 * prepend small(small than a mbuf) content into msg
 */
int
msg_prepend_format(struct msg *msg, const char *fmt, ...)
{
    mbuf_base *mb = msg->mb;
    struct mbuf *mbuf;
    int32_t n;
    va_list args;

    mbuf = mbuf_get(mb);
    if (mbuf == NULL) {
        return RMT_ENOMEM;
    }

    va_start(args, fmt);
    n = rmt_vscnprintf(mbuf->last, mbuf_size(mbuf), fmt, args);
    va_end(args);

    mbuf->last += n;
    msg->mlen += (uint32_t)n;

    listAddNodeHead(msg->data, mbuf);
    
    return RMT_OK;
}

inline uint64_t
msg_gen_frag_id(void)
{
    return 0;
}

/*
 * Split mbuf h into h and t by copying data from h to t. Before
 * the copy, we invoke a precopy handler cb that will copy a predefined
 * string to the head of t.
 *
 * Return new mbuf t, if the split was successful.
 */
struct mbuf *
msg_split(struct msg *msg, uint8_t *pos)
{
    struct mbuf *mbuf;

    ASSERT(listLength(msg->data) > 0);

    mbuf = listLastValue(msg->data);
    ASSERT(pos >= mbuf->pos && pos <= mbuf->last);

    return mbuf_split(mbuf, pos);
}

/* compare msg content with a string
  *
  * return 0  : equal
  * return 1  : msg content bigger than string
  * return -1: string bigger than msg content
  * return -2: error
  */
int
msg_cmp_str(struct msg *msg, const uint8_t *str, uint32_t len)
{
    int ret;
    struct mbuf *mbuf;
    listIter *iter;
    listNode *node;
    uint8_t *p, *q, *start;
    uint32_t mlen, left;  //mbuf len
    
    if(msg == NULL)
    {
        return -2;
    }

    if(str == NULL || len == 0)
    {
        return -2;
    }

    if(msg->mlen > len)
    {
        return  1;
    }
    else if(msg->mlen < len)
    {
        return -1;
    }

    start = (uint8_t *)str;
    left = len;

    iter = listGetIterator(msg->data, AL_START_HEAD);
    while((node = listNext(iter)) != NULL && left > 0) {
        mbuf = listNodeValue(node);
        
        p = mbuf->start;
        q = mbuf->last;
        mlen = (uint32_t)(q - p);

        ret = memcmp(p, start, mlen);
        if(ret != 0)
        {
            listReleaseIterator(iter);
            return ret;
        }

        left -= mlen;
    }

    listReleaseIterator(iter);
    
    return 0;
}

int msg_check(rmtContext *ctx, struct msg *msg, int panic)
{
    struct mbuf *mbuf;
    listIter *iter;
    listNode *node;
    uint32_t total_mbuf_len = 0;
    
    if (msg == NULL) {
        return RMT_ERROR;
    }

    //check msg length
    iter = listGetIterator(msg->data, AL_START_HEAD);
    while ((node = listNext(iter)) != NULL) {
        mbuf = listNodeValue(node);
        total_mbuf_len += mbuf_storage_length(mbuf);
    }
    listReleaseIterator(iter);
    
    if (msg->mlen != total_mbuf_len) {
        log_error("MSG CHECK Error: msg->mlen(%u) != total_mbuf_len(%u)", 
            msg->mlen, total_mbuf_len);
        goto error;
    }

    if (msg->request == 1) {
        if (msg->noreply != ctx->noreply) {
            log_error("MSG CHECK Error: msg->noreply(%u) != ctx->noreply(%d)", 
                msg->noreply, ctx->noreply);
            goto error;
        }
    }
    
    return RMT_OK;
    
error:
    msg_dump(msg, LOG_ERR);
    if (panic) {
        rmt_stacktrace(1);
        abort();
    }
    return RMT_ERROR;
}

#ifdef RMT_MEMORY_TEST
int msg_used_init(void)
{
    msg_used = 0;
    pthread_mutex_init(&msg_mutex,NULL);
    return RMT_OK;
}

void msg_used_deinit(void)
{
    msg_used = 0;
    pthread_mutex_destroy(&msg_mutex);
}

long long msg_used_count(void)
{
    return msg_used;
}

int msg_used_up(void)
{
    pthread_mutex_lock(&msg_mutex);    
    msg_used ++;
    pthread_mutex_unlock(&msg_mutex);
    return RMT_OK;
}

int msg_used_down(void)
{
    pthread_mutex_lock(&msg_mutex);    
    msg_used --;
    pthread_mutex_unlock(&msg_mutex);
    return RMT_OK;
}
#endif

