
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
    msg->bulk_len = 0;
    msg->bulk_start = NULL;

    msg->err = 0;
    msg->error = 0;
    msg->ferror = 0;
    msg->request = 0;
    msg->quit = 0;
    msg->noreply = 0;
    msg->noforward = 0;
    msg->not_support = 0;

    msg->kind = 0;

    msg->sent = 0;

    msg->ptr = NULL;
    
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

char*
msg_type_string(msg_type_t type)
{
    return msg_type_strings[type];
}

sds
msg_cmd_string(msg_type_t type)
{
    char *msg_string;
    sds *parts = NULL; 
    int parts_count = 0;
    sds command = NULL;

    msg_string = msg_type_string(type);
    parts = sdssplitlen(msg_string,strlen(msg_string),"_",1,&parts_count);
    if (parts == NULL) return command;

    if (parts_count != 3) {
        sdsfreesplitres(parts, parts_count);
        return command;
    }

    command = parts[2];
    parts[2] = NULL;
    sdsfreesplitres(parts, parts_count);

    return command;
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
    
    if (node == NULL ||
        mbuf_size(listNodeValue(node)) < len) {
        mbuf = mbuf_get(mb);
        if (mbuf == NULL) {
            return NULL;
        }

        listAddNodeTail(msg->data, mbuf);
    } else {
        mbuf = listNodeValue(node);
    }

    return mbuf;
}

/*
 * fill the mbuf in the msg with the content
 */
int msg_append_full(struct msg *msg, const uint8_t *pos, uint32_t n)
{
    struct mbuf *mbuf;
    uint32_t left, len;
    mbuf_base *mb = msg->mb;
    const uint8_t *start;

    start = pos;
    left = n;

    while (left > 0) {
        mbuf = listLastValue(msg->data);
        if (mbuf == NULL || mbuf_size(mbuf) == 0) {
            mbuf = mbuf_get(mb);
            if (mbuf == NULL) {
                log_error("ERROR: Mbuf get failed: out of memory");
                return RMT_ENOMEM;
            }
            listAddNodeTail(msg->data, mbuf);
        }

        len = MIN(left, mbuf_size(mbuf));
        mbuf_copy(mbuf, start, len);
        left -= len;
        start += len;
        msg->mlen += len;
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

int _msg_check(const char *file, int line, rmtContext *ctx, struct msg *msg, int panic)
{
    struct mbuf *mbuf;
    listIter *iter;
    listNode *node;
    uint32_t total_mbuf_len = 0;
    int err = 0;
    
    if (msg == NULL) {
        return RMT_ERROR;
    }

    //check msg length
    iter = listGetIterator(msg->data, AL_START_HEAD);
    while ((node = listNext(iter)) != NULL) {
        mbuf = listNodeValue(node);
        total_mbuf_len += mbuf_length(mbuf);

        if (mbuf->pos < mbuf->start) {
            _log(file, line, 0, "MSG CHECK Error: mbuf->pos(%p) < mbuf->start(%p)", 
                mbuf->pos, mbuf->start);
            err = 1;
        }

        if (mbuf->pos > mbuf->last) {
            _log(file, line, 0, "MSG CHECK Error: mbuf->pos(%p) > mbuf->last(%p)", 
                mbuf->pos, mbuf->last);
            err = 1;
        }
    }
    listReleaseIterator(iter);
    
    if (msg->mlen != total_mbuf_len) {
        _log(file, line, 0, "MSG CHECK Error: msg->mlen(%u) != total_mbuf_len(%u)", 
            msg->mlen, total_mbuf_len);
        err = 1;
    }

    if (msg->request == 1) {
        if (memcmp(ctx->cmd, RMT_CMD_REDIS_MIGRATE, 
            MIN(sdslen(ctx->cmd),strlen(RMT_CMD_REDIS_MIGRATE))) == 0 && 
            msg->noreply != ctx->noreply) {
            _log(file, line, 0, "MSG CHECK Error: msg->noreply(%u) != ctx->noreply(%d)", 
                msg->noreply, ctx->noreply);
            err = 1;
        }
    }

    if (err) goto error;
    
    return RMT_OK;
    
error:
    MSG_DUMP(msg, LOG_ERR, 0);
    if (panic) {
        rmt_stacktrace(1);
        abort();
    }
    return RMT_ERROR;
}

void _msg_dump(const char *file, int line, struct msg *msg, int level, int begin)
{
    struct mbuf *mbuf;
    listIter *iter;
    listNode *node;
    uint8_t *p, *q;
    long int len;

    if (log_loggable(level) == 0) {
        return;
    }

    _log(file, line, 0, "msg dump id %"PRIu64" request %d len %"PRIu32" type %d "
         "(err %d) kind %d result %d mbuf_count %u keys_count %u", 
         msg->id, msg->request, msg->mlen, 
         msg->type, msg->err, msg->kind, 
         msg->result, listLength(msg->data), 
         msg->keys == NULL?0:array_n(msg->keys));


    iter = listGetIterator(msg->data, AL_START_HEAD);
    ASSERT(iter != NULL);
    while((node = listNext(iter)) != NULL) {
        mbuf = listNodeValue(node);

        if (begin) {
            p = mbuf->start;
        } else {
            p = mbuf->pos;
        }
        q = mbuf->last;
        len = q - p;
        _log(file, line, 0, "mbuf [%p] with %ld bytes of data, pos %p last %p", 
            p, len, mbuf->pos, mbuf->last);
        _log_hexdump(file, line, p, len, NULL);
    }
    listReleaseIterator(iter);
}

int msg_data_compare(struct msg *msg1, struct msg *msg2)
{
    int ret;
    listNode *lnode1, *lnode2;
    struct mbuf *mbuf1, *mbuf2;
    uint32_t len;
    
    if (msg1 == NULL && msg2 == NULL) {
        return 0;
    } else if (msg1 == NULL && msg2 != NULL) {
        return -1;
    } else if (msg1 != NULL && msg2 == NULL) {
        return 1;
    }

    lnode1 = listFirst(msg1->data);
    lnode2 = listFirst(msg2->data);
    
    while (lnode1 && lnode2) {
        mbuf1 = listNodeValue(lnode1);
        mbuf2 = listNodeValue(lnode2);
        len = MIN(mbuf_length(mbuf1),mbuf_length(mbuf2));
        ret = memcmp(mbuf1->pos, mbuf2->pos, len);
        if (ret != 0) {
            return ret;
        }
        
        mbuf1->pos += len;
        mbuf2->pos += len;
        msg1->mlen -= len;
        msg2->mlen -= len;
        if (mbuf_length(mbuf1) == 0) {
            lnode1 = lnode1->next;
        }

        if (mbuf_length(mbuf2) == 0) {
            lnode2 = lnode2->next;
        }
    }

    if (msg1->mlen > 0) {
        return 1;
    } else if (msg2->mlen > 0) {
        return -1;
    }

    return 0;
}

void show_can_be_parsed_cmd(void)
{
    unsigned int j, len = sizeof(msg_type_strings)/sizeof(msg_type_strings[0]);
    char *msg_string;
    sds parsed_redis_cmd = sdsempty();
    int supported_redis_cmd_count = 0;
    sds *parts = NULL; 
    int parts_count = 0;

    for (j = 0; j < len; j ++) {
        msg_string = msg_type_strings[j];
        if (msg_string == NULL)
            break;
        
        parts = sdssplitlen(msg_string,strlen(msg_string),"_",1,&parts_count);
        if (parts == NULL) continue;
        if (parts_count != 3) {
            sdsfreesplitres(parts,parts_count);
            continue;
        }

        if (sdslen(parts[0]) != strlen("REQ") || strcmp(parts[0],"REQ")) {
            sdsfreesplitres(parts,parts_count);
            continue;
        }

        if (sdslen(parts[1]) == strlen("REDIS") && strcmp(parts[1],"REDIS") == 0) {
            if (sdslen(parsed_redis_cmd) > 0) {
                parsed_redis_cmd = sdscat(parsed_redis_cmd,",");
            }
            parsed_redis_cmd = sdscatsds(parsed_redis_cmd,parts[2]);
            supported_redis_cmd_count ++;
        }
        
        sdsfreesplitres(parts,parts_count);
    }

    log_stdout("Can Be Parsed Redis commands(%d): %s", supported_redis_cmd_count, parsed_redis_cmd);
    log_stdout("If you find any other commands that can't parsed, please report them on the github issues('https://github.com/vipshop/redis-migrate-tool/issues'), thank you!");
    sdsfree(parsed_redis_cmd);
}

void show_not_supported_cmd(void)
{
    int not_supported_redis_cmd_count = 0;
    sds not_supported_redis_cmd = sdsempty();

    not_supported_redis_cmd = sdscat(not_supported_redis_cmd,"RENAME");not_supported_redis_cmd_count++;
    not_supported_redis_cmd = sdscat(not_supported_redis_cmd,",RENAMENX");not_supported_redis_cmd_count++;
    not_supported_redis_cmd = sdscat(not_supported_redis_cmd,",RPOPLPUSH");not_supported_redis_cmd_count++;
    not_supported_redis_cmd = sdscat(not_supported_redis_cmd,",BRPOPLPUSH");not_supported_redis_cmd_count++;
    not_supported_redis_cmd = sdscat(not_supported_redis_cmd,",FLUSHALL");not_supported_redis_cmd_count++;
    not_supported_redis_cmd = sdscat(not_supported_redis_cmd,",FLUSHDB");not_supported_redis_cmd_count++;
    not_supported_redis_cmd = sdscat(not_supported_redis_cmd,",BITOP");not_supported_redis_cmd_count++;
    
    log_stdout("Not Supported Redis Commands(%d): %s", not_supported_redis_cmd_count, not_supported_redis_cmd);
    log_stdout("These not supported redis commands are parsed correctly, but will be discarded and not sent to the target redis.");
    sdsfree(not_supported_redis_cmd);
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

