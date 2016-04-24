#include <rmt_core.h>
#include <signal.h>

#define CHECK_UNIT_STATE_NULL           0
#define CHECK_UNIT_STATE_GET_KEY        1
#define CHECK_UNIT_STATE_GET_TYPE       2
#define CHECK_UNIT_STATE_GET_VALUE      3
#define CHECK_UNIT_STATE_GET_EXPIRE     4

typedef struct check_data {
    long long err_check_keys_count;
    long long err_inconsistent_value_keys_count;
    long long err_inconsistent_expire_keys_count;
}check_data;

typedef struct check_unit {
    redis_node *srnode;
    thread_data *cdata;
    
    sds key;
    int key_type;
    int state;
    struct msg *result1;
    struct msg *result2;
} check_unit;

static check_unit *check_unit_create(void)
{
    check_unit *cunit;

    cunit = rmt_alloc(sizeof(*cunit));
    if (cunit == NULL) {
        log_error("ERROR: out of memory.");
        return NULL;
    }

    cunit->srnode = NULL;
    cunit->cdata = NULL;
    
    cunit->key = NULL;
    cunit->key_type = -1;
    cunit->state = CHECK_UNIT_STATE_NULL;
    cunit->result1 = NULL;
    cunit->result2 = NULL;

    return cunit;
}

static void check_unit_destroy(check_unit *cunit)
{
    if (cunit->cdata != NULL) {
        cunit->cdata->finished_keys_count ++;
        if (cunit->cdata->finished_keys_count >= 
            cunit->cdata->keys_count) {
            aeStop(cunit->cdata->loop);
        }
    }

    if (cunit->key != NULL) {
        sdsfree(cunit->key);
        cunit->key = NULL;
    }

    if (cunit->result1 != NULL) {
        msg_put(cunit->result1);
        msg_free(cunit->result1);
        cunit->result1 = NULL;
    }

    if (cunit->result2 != NULL) {
        msg_put(cunit->result2);
        msg_free(cunit->result2);
        cunit->result2 = NULL;
    }

    rmt_free(cunit);
}

static void check_thread_data_destroy(thread_data *cdata);

static thread_data *check_thread_data_create(rmtContext *ctx)
{
    thread_data *cdata;
    int setsize = 100;

    cdata = rmt_alloc(sizeof(*cdata));
    if (cdata == NULL) {
        log_error("ERROR: out of memory");
        return NULL;
    }

    thread_data_init(cdata);

    cdata->ctx = ctx;

    cdata->srgroup = source_group_create(ctx);
    if(cdata->srgroup == NULL){
        log_error("Error: source redis group create failed.");
        goto error;
    }

    cdata->trgroup = target_group_create(ctx);
    if(cdata->trgroup == NULL){
        log_error("Error: target redis group create failed.");
        goto error;
    }

    /* use the ctx->mbuf_size */
    if (cdata->trgroup->mb != NULL) {
        mbuf_base_destroy(cdata->trgroup->mb);
        cdata->trgroup->mb = mbuf_base_create(
            ctx->mbuf_size, NULL);
        if (cdata->trgroup->mb == NULL) {
            log_error("ERROR: Create mbuf_base failed");
            goto error;
        }
    }

    setsize += ((int)dictSize(cdata->srgroup->nodes)*(1 + 1) + 
        (int)dictSize(cdata->trgroup->nodes)*1)*ctx->thread_count;
    cdata->loop = aeCreateEventLoop(setsize);
    if (cdata->loop == NULL) {
    	log_error("ERROR: create event loop failed");
        goto error;
    }

    cdata->data = rmt_zalloc(sizeof(check_data));
    if (cdata->data == NULL) {
        log_error("Error: out of memory.");
        goto error;
    }

    return cdata;

error:

    check_thread_data_destroy(cdata);

    return NULL;
}

static void check_thread_data_destroy(thread_data *cdata)
{
    check_unit * cunit;
    
    if (cdata == NULL) {
        return;
    }

    thread_data_deinit(cdata);

    if (cdata->data != NULL) {
        rmt_free(cdata->data);
        cdata->data = NULL;
    }

    rmt_free(cdata);
}

static int send_msg_to_all(check_unit *cunit, struct msg *msg)
{
    int ret;
    thread_data *cdata = cunit->cdata;
    redis_group *trgroup = cdata->trgroup;
    redis_node *trnode;
    struct msg *msg_same;
    listNode *lnode;
    struct mbuf *mbuf;
    
    if (cunit == NULL || msg == NULL) {
        return RMT_ERROR;
    }

    msg_same = msg_get(msg->mb, msg->request, msg->kind);
    if (msg_same == NULL) {
        log_error("ERROR: msg clone failed.");
        msg_put(msg);
        msg_free(msg);
        msg = NULL;
        return RMT_ERROR;
    }

    lnode = listFirst(msg->data);
    while (lnode) {
        mbuf = listNodeValue(lnode);
        lnode = lnode->next;

        ret = msg_append_full(msg_same, mbuf->pos, mbuf_length(mbuf));
        if (ret != RMT_OK) {
            log_error("ERROR: out of memory.");
            msg_put(msg_same);
            msg_free(msg_same);
            msg = NULL;
            return RMT_ERROR;
        }
    }

    msg_same->ptr = msg->ptr;
    msg_same->resp_check = msg->resp_check;

    ret = prepare_send_msg(cunit->srnode, msg, cunit->srnode);
    if (ret != RMT_OK) {
        msg_put(msg);
        msg_free(msg);
        msg = NULL;
        msg_put(msg_same);
        msg_free(msg_same);
        return RMT_ERROR;
    }

    msg = NULL;

    trnode = trgroup->get_backend_node(trgroup, (uint8_t *)cunit->key, (uint32_t)sdslen(cunit->key));
    if(prepare_send_msg(trnode, msg_same, trnode) != RMT_OK){
        msg_put(msg_same);
        msg_free(msg_same);
        return RMT_ERROR;
    }

    return RMT_OK;
}

static char *get_check_error(check_unit *cunit)
{
    if (cunit == NULL) {
        return "unknow";
    }

    if (cunit->state == CHECK_UNIT_STATE_NULL) {
        ASSERT(cunit->key == NULL);
        return "not begin";
    }

    if (cunit->state == CHECK_UNIT_STATE_GET_KEY) {
        return "get key failed";
    }

    if (cunit->state == CHECK_UNIT_STATE_GET_TYPE) {
        ASSERT(cunit->key != NULL);
        return "get key type error";
    }

    if (cunit->state == CHECK_UNIT_STATE_GET_VALUE) {
        ASSERT(cunit->key != NULL);
        return "check key's value error";
    }

    if (cunit->state == CHECK_UNIT_STATE_GET_EXPIRE) {
        ASSERT(cunit->key != NULL);
        return "check key's expire time error";
    }
}

#define TTL_MISTAKE_CAN_BE_ACCEPT   3
static int check_response(redis_node *rnode, struct msg *r)
{
    int ret;
    struct msg *resp, *msg = NULL;
    check_data *chdata;
    check_unit *cunit;
    char extra_err[50];

    if (r == NULL) {
        return RMT_ERROR;
    }

    extra_err[0] = '\0';

    resp = r->peer;
    r->peer = NULL;

    ASSERT(r->request && r->sent);
    ASSERT(resp != NULL && resp->request == 0);

    cunit = (check_unit *)r->ptr;
    chdata = cunit->cdata->data;

    if(resp->type == MSG_RSP_REDIS_ERROR){
        log_warn("Response from node[%s] for %s is error",
            rnode->addr, msg_type_string(r->type));
        goto error;
    }

    if (cunit->state == CHECK_UNIT_STATE_GET_KEY) {
        ASSERT(cunit->key == NULL);
        ASSERT(cunit->key_type == -1);
        ASSERT(cunit->result1 == NULL && cunit->result2 == NULL);
        ASSERT(cunit->srnode == rnode);

        if (resp->type != MSG_RSP_REDIS_BULK) {
            log_error("ERROR: the response type for command 'randomkey' from node[%s] is error: %s", 
                rnode->addr, msg_type_string(resp->type));
            goto error;
        }

        cunit->key = redis_msg_response_get_bulk_string(resp);
        if (cunit->key == NULL) {
            log_error("ERROR: get bulk string from response of node[%s] failed, "
                "bulk_len: %"PRIu32", bulk_start: %p", 
                rnode->addr, resp->bulk_len, resp->bulk_start);
            goto error;
        }

        ASSERT(sdslen(cunit->key) == resp->bulk_len);

        msg = msg_get(r->mb, 1, REDIS_DATA_TYPE_CMD);
        if (msg == NULL) {
            log_error("ERROR: out of memory.");
            goto error;
        }
        
        ret = redis_msg_append_command_full(msg, "type", cunit->key, NULL);
        if (ret != RMT_OK) {
            log_error("ERROR: msg append multi bulk len failed.");
            goto error;
        }
        
        msg->ptr = cunit;
        msg->resp_check = check_response;

        ret = prepare_send_msg(rnode, msg, rnode);
        if (ret != RMT_OK) {
            log_error("ERROR: prepare send msg node[%s] failed.", rnode->addr);
            goto error;
        }

        cunit->state = CHECK_UNIT_STATE_GET_TYPE;
        goto next_step;
    }

    if (cunit->state == CHECK_UNIT_STATE_GET_TYPE) {
        ASSERT(cunit->key != NULL);
        ASSERT(cunit->key_type == -1);
        ASSERT(cunit->result1 == NULL && cunit->result2 == NULL);
        ASSERT(cunit->srnode == rnode);
        
        if (resp->type != MSG_RSP_REDIS_STATUS) {
            log_error("ERROR: the response type for command 'type' from node[%s] is error: %s", 
                rnode->addr, msg_type_string(resp->type));
            goto error;
        }

        if (msg_cmp_str(resp, (const uint8_t*)REDIS_REPLY_STATUS_NONE, 
            rmt_strlen(REDIS_REPLY_STATUS_NONE)) == 0) {
            /* This key doesn't exit, may be expired or evicted */
            goto done;
        }

        msg = msg_get(r->mb, 1, REDIS_DATA_TYPE_CMD);
        if (msg == NULL) {
            log_error("ERROR: out of memory.");
            goto error;
        }

        if (msg_cmp_str(resp, (const uint8_t*)REDIS_REPLY_STATUS_STRING, 
            rmt_strlen(REDIS_REPLY_STATUS_STRING)) == 0) {
            cunit->key_type = REDIS_STRING;

            ret = redis_msg_append_command_full(msg, "get", cunit->key, NULL);
            if (ret != RMT_OK) {
                log_error("ERROR: msg append multi bulk len failed.");
                goto error;
            }
        } else if (msg_cmp_str(resp, (const uint8_t*)REDIS_REPLY_STATUS_LIST, 
            rmt_strlen(REDIS_REPLY_STATUS_LIST)) == 0) {
            cunit->key_type = REDIS_LIST;

            ret = redis_msg_append_command_full(msg, "lrange", cunit->key, "0", "-1", NULL);
            if (ret != RMT_OK) {
                log_error("ERROR: msg append multi bulk len failed.");
                goto error;
            }
        } else if (msg_cmp_str(resp, (const uint8_t*)REDIS_REPLY_STATUS_SET, 
            rmt_strlen(REDIS_REPLY_STATUS_SET)) == 0) {
            cunit->key_type = REDIS_SET;

            //ret = redis_msg_append_command_full(msg, "smembers", cunit->key, NULL);
            ret = redis_msg_append_command_full(msg, "sort", cunit->key, "ALPHA", NULL);
            if (ret != RMT_OK) {
                log_error("ERROR: msg append multi bulk len failed.");
                goto error;
            }
        } else if (msg_cmp_str(resp, (const uint8_t*)REDIS_REPLY_STATUS_ZSET, 
            rmt_strlen(REDIS_REPLY_STATUS_ZSET)) == 0) {
            cunit->key_type = REDIS_ZSET;

            ret = redis_msg_append_command_full(msg, "zrange", cunit->key, "0", "-1", NULL);
            if (ret != RMT_OK) {
                log_error("ERROR: msg append multi bulk len failed.");
                goto error;
            }
        } else if (msg_cmp_str(resp, (const uint8_t*)REDIS_REPLY_STATUS_HASH, 
            rmt_strlen(REDIS_REPLY_STATUS_HASH)) == 0) {
            cunit->key_type = REDIS_HASH;

            ret = redis_msg_append_command_full(msg, "hgetall", cunit->key, NULL);
            if (ret != RMT_OK) {
                log_error("ERROR: msg append multi bulk len failed.");
                goto error;
            }
        } else {
            log_error("ERROR: response key type from node[%s] is error: ",
                rnode->addr);
            goto error;
        }

        msg->ptr = cunit;
        msg->resp_check = check_response;
        
        ret = send_msg_to_all(cunit, msg);
        if (ret != RMT_OK) {
            log_error("ERROR: send msg to source and target group failed.");
            goto error;
        }

        cunit->state = CHECK_UNIT_STATE_GET_VALUE;
        goto next_step;
    }

    if (cunit->state == CHECK_UNIT_STATE_GET_VALUE) {
        ASSERT(cunit->key != NULL);
        ASSERT(cunit->key_type >= 0);
        ASSERT(cunit->result1 == NULL || cunit->result2 == NULL);
        
        if (cunit->key_type == REDIS_STRING) {
            if (resp->type != MSG_RSP_REDIS_BULK) {
                log_error("ERROR: the response type for %s from node[%s] is error: %s", 
                    rnode->addr, msg_type_string(r->type), msg_type_string(resp->type));
                goto error;
            }
        } else if (cunit->key_type == REDIS_LIST) {
            
        } else if (cunit->key_type == REDIS_SET) {
            
        } else if (cunit->key_type == REDIS_ZSET) {
            
        } else if (cunit->key_type == REDIS_HASH) {
            
        } else {
            NOT_REACHED();
        }

        if (cunit->result1 == NULL) {
            cunit->result1 = resp;
            resp = NULL;
        } else if (cunit->result2 == NULL) {
            cunit->result2 = resp;
            resp = NULL;
        } else {
            NOT_REACHED();
        }
    
        if (cunit->result1 != NULL && cunit->result2 != NULL) {
            if (msg_data_compare(cunit->result1, cunit->result2) != 0) {
                chdata->err_inconsistent_value_keys_count ++;
                rmt_safe_snprintf(extra_err, 50, ", value is inconsistent\0");
                goto error;
            }

            msg_put(cunit->result1);
            msg_free(cunit->result1);
            cunit->result1 = NULL;
            msg_put(cunit->result2);
            msg_free(cunit->result2);
            cunit->result2 = NULL;

            msg = msg_get(r->mb, 1, REDIS_DATA_TYPE_CMD);
            if (msg == NULL) {
                log_error("ERROR: out of memory.");
                goto error;
            }
            
            ret = redis_msg_append_command_full(msg, "ttl", cunit->key, NULL);
            if (ret != RMT_OK) {
                log_error("ERROR: msg append multi bulk len failed.");
                goto error;
            }
            
            msg->ptr = cunit;
            msg->resp_check = check_response;
            
            ret = send_msg_to_all(cunit, msg);
            if (ret != RMT_OK) {
                log_error("ERROR: send msg to source and target group failed.");
                goto error;
            }
            cunit->state = CHECK_UNIT_STATE_GET_EXPIRE;
        }

        goto next_step;
    }

    if (cunit->state == CHECK_UNIT_STATE_GET_EXPIRE) {
        ASSERT(cunit->key != NULL);
        ASSERT(cunit->key_type >= 0);
        ASSERT(cunit->result1 == NULL || cunit->result2 == NULL);

        if (resp->type != MSG_RSP_REDIS_INTEGER) {
            log_error("ERROR: the response type for command 'ttl' from node[%s] is error: %s", 
                rnode->addr, msg_type_string(resp->type));
            goto error;
        }

        if (cunit->result1 == NULL) {
            cunit->result1 = resp;
            resp = NULL;
        } else if (cunit->result2 == NULL) {
            cunit->result2 = resp;
            resp = NULL;
        } else {
            NOT_REACHED();
        }

        if (cunit->result1 != NULL && cunit->result2 != NULL) {
            if (msg_data_compare(cunit->result1, cunit->result2) != 0) { 
                int mistake = (int)cunit->result1->integer - (int)cunit->result2->integer;
                ASSERT(mistake != 0);

                if (abs(mistake) > TTL_MISTAKE_CAN_BE_ACCEPT) {
                    chdata->err_inconsistent_expire_keys_count ++;
                    rmt_safe_snprintf(extra_err, 50, 
                        ", remaining time are %"PRIu32" and %"PRIu32"\0", 
                        cunit->result1->integer, cunit->result2->integer);
                    goto error;
                }
            }

            /* OK, this key is consistent between source group and target group */
            goto done;
        }

        goto next_step;
    }

done:

    check_unit_destroy(cunit);

next_step:
    
    msg_put(r);
    msg_free(r);
    if (resp != NULL) {
        msg_put(resp);
        msg_free(resp);
    }
    
    return RMT_OK;

error:

    chdata->err_check_keys_count ++;

    if (cunit->key != NULL) {        
        log_error("ERROR: key checked failed: %s%s. key(len:%zu): %.*s",  
            get_check_error(cunit), extra_err, 
            sdslen(cunit->key), sdslen(cunit->key), cunit->key);
    } else {
        log_error("ERROR: key checked failed: %s%s.", 
            get_check_error(cunit), extra_err);
    }
    MSG_DUMP(r, LOG_ERR, 1);
    msg_put(r);
    msg_free(r);
    if (resp != NULL) {
        MSG_DUMP(resp, LOG_ERR, 1);
        msg_put(resp);
        msg_free(resp);
    }

    if (msg != NULL) {
        msg_put(msg);
        msg_free(msg);
    }

    check_unit_destroy(cunit);
    
    return RMT_OK;
}


#define REDIS_RANDOMKEY "*1\r\n$9\r\nRANDOMKEY\r\n"
#define MAX_UNITS_HOLD_PER_THREAD   1000
static void check_begin(aeEventLoop *el, int fd, void *privdata, int mask)
{
    int ret;
    redis_node *srnode = privdata;
    thread_data *cdata = srnode->write_data;
    mbuf_base *mb = cdata->srgroup->mb;
    struct msg *msg;
    check_unit *cunit;
    
    RMT_NOTUSED(el);
    RMT_NOTUSED(fd);
    RMT_NOTUSED(privdata);
    RMT_NOTUSED(mask);

    ASSERT(el == cdata->loop);
    ASSERT(fd == srnode->sk_event);

    if (cdata->sent_keys_count - 
        cdata->finished_keys_count > 
        MAX_UNITS_HOLD_PER_THREAD) {
        return;
    }

    if (cdata->sent_keys_count >= cdata->keys_count) {
         aeDeleteFileEvent(cdata->loop,srnode->sk_event,AE_WRITABLE);
         return;
    }
    
    cunit = check_unit_create();
    if (cunit == NULL) {
        log_error("Error: out of memory.");
        goto error;
    }
    cunit->srnode = srnode;
    cunit->cdata = cdata;
    cunit->state = CHECK_UNIT_STATE_GET_KEY;
    cdata->sent_keys_count ++;

    msg = msg_get(mb, 1, REDIS_DATA_TYPE_CMD);
    if (msg == NULL) {
        log_error("ERROR: msg get failed.");
        goto error;
    }
    ret = msg_append_full(msg, (uint8_t *)REDIS_RANDOMKEY, strlen(REDIS_RANDOMKEY));
    if (ret != RMT_OK) {
        log_error("ERROR: msg append REDIS_RANDOMKEY failed.");
        goto error;
    }
    msg->ptr = cunit;
    msg->resp_check = check_response;

    /*send msg to source msg*/
    ret = prepare_send_msg(srnode, msg, srnode);
    if (ret != RMT_OK) {
        goto error;
    }

    return;
    
error:

    aeDeleteFileEvent(cdata->loop,srnode->sk_event,AE_READABLE|AE_WRITABLE);
    aeStop(cdata->loop);
}

static void *check_thread_run(void *args)
{
    int ret;
    thread_data *cdata = args;
    redis_group *srgroup = cdata->srgroup;
    redis_group *trgroup = cdata->trgroup;
    dict *nodes;
    dictEntry *de;
    dictIterator *di;
    redis_node *rnode;
    struct mbuf *mbuf;

    nodes = srgroup->nodes;
    di = dictGetIterator(nodes);
    while ((de = dictNext(di)) != NULL) {
    	rnode = dictGetVal(de);

        rnode->write_data = cdata;

        /* remove the not used part for source redis node */
        if (rnode->rdb != NULL) {
            redis_rdb_deinit(rnode->rdb);
            rmt_free(rnode->rdb);
            rnode->rdb = NULL;
        }
        
        if (rnode->cmd_data != NULL) {
            while (!mttlist_empty(rnode->cmd_data)) {
                mbuf = mttlist_pop(rnode->cmd_data);
                mbuf_put(mbuf);
            }
            
            mttlist_destroy(rnode->cmd_data);
            rnode->cmd_data = NULL;
        }

        if (rnode->sockpairfds[0] > 0) {
            close(rnode->sockpairfds[0]);
            rnode->sockpairfds[0] = -1;
        }

        if (rnode->sockpairfds[1] > 0) {
            close(rnode->sockpairfds[1]);
            rnode->sockpairfds[1] = -1;
        }

        if (rnode->rr != NULL) {
            redis_replication_deinit(rnode->rr);
            rmt_free(rnode->rr);
            rnode->rr = NULL;
        }

        if (rnode->piece_data != NULL) {
            while ((mbuf = listPop(rnode->piece_data)) != NULL) {
                mbuf_put(mbuf);
            }
            
            listRelease(rnode->piece_data);
            rnode->piece_data = NULL;
        }

        /* add the used part for source redis node */
        if (rnode->send_data == NULL) {
            rnode->send_data = listCreate();
            if (rnode->send_data == NULL) {
                log_error("ERROR: Create msg list failed: out of memory");
                return 0;
            }
        }

        if (rnode->sent_data == NULL) {
            rnode->sent_data = listCreate();
            if (rnode->sent_data == NULL) {
                log_error("ERROR: Create msg list failed: out of memory");
                return 0;
            }
        }

        if (rnode->sk_event < 0) {
            rnode->sk_event = socket(AF_INET, SOCK_STREAM, 0);
            if(rnode->sk_event < 0){
                log_error("ERROR: Create sk_event for node[%s] failed: %s", 
                    rnode->addr, strerror(errno));
                return 0;
            }
        }
        ret = aeCreateFileEvent(cdata->loop, rnode->sk_event, 
            AE_WRITABLE, check_begin, rnode);
        if (ret != AE_OK) {
            log_error("ERROR: send_data event create %ld failed: %s",
                cdata->thread_id, strerror(errno));
            return 0;
        }
    }
    dictReleaseIterator(di);

    nodes = trgroup->nodes;
    di = dictGetIterator(nodes);
    while ((de = dictNext(di)) != NULL) {
    	rnode = dictGetVal(de);

        rnode->write_data = cdata;
    }
    dictReleaseIterator(di);

    aeMain(cdata->loop);
    return 0;
}

void redis_check_data(rmtContext *ctx, int type)
{
    int i;
    int threads_count;
    long long keys_count, keys_count_per_thread;
    long long keys_count_left, keys_count_threads_hold;
    thread_data **threads = NULL;
    long long starttime, endtime;
    long long checked_keys_count = 0;
    long long err_check_keys_count = 0;
    long long err_others_keys_count = 0;
    long long err_inconsistent_value_keys_count = 0;
    long long err_inconsistent_expire_keys_count = 0;

    RMT_NOTUSED(type);

    if (ctx == NULL || ctx->source_addr == NULL) {
        goto error;
    }

    signal(SIGPIPE, SIG_IGN);

    keys_count = 1000;
    if (array_n(&ctx->args) == 1) {
        sds *str = array_get(&ctx->args, 0);
        keys_count = rmt_atoll(*str,sdslen(*str));
    }
    
    keys_count_threads_hold = 0;
    keys_count_left = keys_count;

    if (keys_count <= 0) {
        log_error("ERROR: keys count is less than 0");
        goto error;
    }
    
    threads_count = ctx->thread_count;
    if (threads_count <= 0) {
        log_error("ERROR: thread count is less than 0.");
        goto error;
    }

    if (keys_count < threads_count) {
        threads_count = (int)keys_count;
    }

    if (keys_count <= 100) {
        threads_count = 1;
    }

    ctx->thread_count = threads_count;
    threads = rmt_zalloc(threads_count * sizeof(*threads));
    if (threads == NULL) {
        log_error("Error: out of memory.");
        goto error;
    }

    keys_count_per_thread = keys_count/threads_count;

    //Create the thread data
    for(i = 0; i < threads_count; i ++){
    	threads[i] = check_thread_data_create(ctx);
        if (threads[i] == NULL) {
            log_error("ERROR: create check thread %d failed.", i);
            goto error;
        }

        threads[i]->id = i;
        threads[i]->keys_count = keys_count_per_thread;
        keys_count_left -= threads[i]->keys_count;
    }
    i = 0;
    while (keys_count_left > 0) {
        threads[i]->keys_count ++;
        keys_count_left --;
        i ++;
        if(i >= threads_count)   i = 0;
    }

    for (i = 0; i < threads_count; i ++) {
        keys_count_threads_hold += threads[i]->keys_count;
    }
    if(keys_count_threads_hold != keys_count) {
        log_error("ERROR: keys_count_threads_hold %lld != keys_count %lld", 
            keys_count_threads_hold, keys_count);
        goto error;
    }

    log_stdout("Check job is running...");
    starttime = rmt_msec_now();
    
    //Run the job
    for(i = 0; i < threads_count; i ++){
    	pthread_create(&threads[i]->thread_id, 
        	NULL, check_thread_run, threads[i]);
    }

	//Wait for the job finish
	for(i = 0; i < threads_count; i ++){
		pthread_join(threads[i]->thread_id, NULL);
	}

    endtime = rmt_msec_now();

    for(i = 0; i < threads_count; i ++){
        checked_keys_count += 
            threads[i]->finished_keys_count;

        check_data *chdata = threads[i]->data;
		err_check_keys_count += 
            chdata->err_check_keys_count;
        err_inconsistent_value_keys_count += 
            chdata->err_inconsistent_value_keys_count;
        err_inconsistent_expire_keys_count += 
            chdata->err_inconsistent_expire_keys_count;
	}

    err_others_keys_count = err_check_keys_count - 
        err_inconsistent_value_keys_count - 
        err_inconsistent_expire_keys_count;

    /* Show the check result */
    log_stdout("");
    log_stdout("Checked keys: %lld", checked_keys_count);
    log_stdout("\033[%dmInconsistent value keys: %lld\033[0m", 
        err_inconsistent_value_keys_count == 0?0:31, 
        err_inconsistent_value_keys_count);
    log_stdout("\033[%dmInconsistent expire keys : %lld\033[0m", 
        err_inconsistent_expire_keys_count == 0?0:33, 
        err_inconsistent_expire_keys_count);
    log_stdout("\033[%dmOther check error keys: %lld\033[0m", 
        err_others_keys_count == 0?0:31, 
        err_others_keys_count);
    log_stdout("Checked OK keys: %lld", 
        checked_keys_count - err_check_keys_count);
    log_stdout("");
    if (err_check_keys_count == 0) {
        log_stdout("\033[32mAll keys checked OK!\033[0m");
    }
    log_stdout("Check job finished, used %.3fs", 
        (float)(endtime-starttime)/1000);
    
error:

    if (threads != NULL) {
        for(i = 0; i < threads_count; i ++){
        	check_thread_data_destroy(threads[i]);
        }
        rmt_free(threads);
    }
}


