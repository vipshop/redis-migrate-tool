#include <rmt_core.h>
#include <signal.h>

#define TEST_MAX_KEY_LEN    64
#define TEST_MAX_STRING_LEN 128
#define TEST_MAX_FIELD_LEN  128

/* Object types */
#define TEST_TYPE_REDIS_STRING    (1<<0)
#define TEST_TYPE_REDIS_LIST      (1<<1)
#define TEST_TYPE_REDIS_SET       (1<<2)
#define TEST_TYPE_REDIS_ZSET      (1<<3)
#define TEST_TYPE_REDIS_HASH      (1<<4)

static int data_types       = 0;
static int data_types_count = 0;
static int data_type_string_mark = 0;
static int data_type_list_mark = 0;
static int data_type_set_mark = 0;
static int data_type_zset_mark = 0;
static int data_type_hash_mark = 0;

typedef struct testinsert_data {
    long long counter;
    
    long long string_keys;
    long long list_keys;
    long long set_keys;
    long long zset_keys;
    long long hash_keys;
}testinsert_data;

typedef struct data_unit{
    sds key;
    int data_type;
    struct array *value;
    int expiretime_type;
    long long expiretime;
}data_unit;

static uint32_t get_random_num(void)
{
    return (uint32_t)rand();
}

static uint8_t get_random_char(void)
{
    return (uint8_t)rand()%92 + 32;
}

static sds get_random_key(int data_type)
{
    uint32_t i, len;
    sds str = sdsempty();
    
    len = (uint32_t)get_random_num()%TEST_MAX_KEY_LEN;
    if (len == 0) len ++;
    str = sdsMakeRoomFor(str,(size_t)len);
    sdsIncrLen(str, (int)len);

    /* Make sure different value type has different key */
    str[0] = (char)data_type;
    for (i = 1; i < len; i ++) {
        str[i] = (char)get_random_char();
    }

    return str;
}

static sds get_random_string(void)
{
    uint32_t i, len;
    sds str = sdsempty();
    
    len = (uint32_t)get_random_num()%TEST_MAX_STRING_LEN;
    str = sdsMakeRoomFor(str,(size_t)len);
    sdsIncrLen(str, (int)len);

    for (i = 0; i < len; i ++) {
        str[i] = (char)get_random_char();
    }

    return str;
}

static data_unit *data_unit_create(thread_data *tdata)
{
    data_unit *dunit;
    uint32_t i, value_counter;
    sds *value;
    testinsert_data *tidata = tdata->data;

    dunit = rmt_zalloc(sizeof(*dunit));
    if (dunit == NULL) {
        log_error("ERROR: out of memory");
        return NULL;
    }

    dunit->key = NULL;
    dunit->data_type = -1;
    dunit->value = NULL;
    dunit->expiretime_type = RMT_TIME_NONE;
    dunit->expiretime = 0;

    if (data_types&TEST_TYPE_REDIS_STRING) {
        if (tidata->counter%data_types_count == data_type_string_mark) {
            dunit->data_type = REDIS_STRING;
            tidata->string_keys ++;
        }

        if (dunit->data_type >= 0) goto done;
    }

    if (data_types&TEST_TYPE_REDIS_LIST) {
        if (tidata->counter%data_types_count == data_type_list_mark) {
            dunit->data_type = REDIS_LIST;
            tidata->list_keys ++;
        }
        
        if (dunit->data_type >= 0) goto done;
    }

    if (data_types&TEST_TYPE_REDIS_SET) {
        if (tidata->counter%data_types_count == data_type_set_mark) {
            dunit->data_type = REDIS_SET;
            tidata->set_keys ++;
        }
        if (dunit->data_type >= 0) goto done;
    }

    if (data_types&TEST_TYPE_REDIS_ZSET) {
        if (tidata->counter%data_types_count == data_type_zset_mark) {
            dunit->data_type = REDIS_ZSET;
            tidata->zset_keys ++;
        }
        
        if (dunit->data_type >= 0) goto done;
    }

    if (data_types&TEST_TYPE_REDIS_HASH) {
        if (tidata->counter%data_types_count == data_type_hash_mark) {
            dunit->data_type = REDIS_HASH;
            tidata->hash_keys ++;
        }
        
        if (dunit->data_type >= 0) goto done;
    }

done:

    tidata->counter ++;
    
    dunit->key = get_random_key(dunit->data_type);

    if (dunit->data_type == REDIS_STRING) {
        value_counter = 1;
    } else if(dunit->data_type == REDIS_LIST) {
        value_counter = (uint32_t)get_random_num()%TEST_MAX_FIELD_LEN + 1;
    } else {
        value_counter = (uint32_t)get_random_num()%TEST_MAX_FIELD_LEN + 1;
        if (value_counter%2 != 0) {
            value_counter ++;
        }
    }

    dunit->value = redis_value_create(value_counter);

    for (i = 0; i < value_counter; i ++) {
        value = array_push(dunit->value);
        if (dunit->data_type == REDIS_ZSET) {
            if (i%2 != 0) {
                *value = get_random_string();
            } else {
                *value = sdsfromlonglong((long long)get_random_num());
            }
        } else {
            *value = get_random_string();
        }
    }
    
    return dunit;
}

static void data_unit_destroy(data_unit *dunit)
{
    if (dunit == NULL) {
        return;
    }

    if (dunit->key) {
        sdsfree(dunit->key);
        dunit->key = NULL;
    }

    redis_value_destroy(dunit->value);
    dunit->value = NULL;

    rmt_free(dunit);
}

static void testinsert_thread_data_destroy(thread_data *cdata);

static thread_data *testinsert_thread_data_create(rmtContext *ctx)
{
    thread_data *cdata;
    int setsize = 100;
    uint64_t *counter;

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

    setsize += (int)dictSize(cdata->srgroup->nodes)*(1 + 1)*ctx->thread_count;
    cdata->loop = aeCreateEventLoop(setsize);
    if (cdata->loop == NULL) {
    	log_error("ERROR: create event loop failed");
        goto error;
    }

    cdata->data = rmt_zalloc(sizeof(testinsert_data));

    return cdata;

error:

    testinsert_thread_data_destroy(cdata);

    return NULL;
}

static void testinsert_thread_data_destroy(thread_data *cdata)
{    
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

#define MAX_KEYS_HOLD_PER_THREAD   1000
static void testinsert_begin(aeEventLoop *el, int fd, void *privdata, int mask)
{
    redis_node *srnode = privdata;
    thread_data *cdata = srnode->write_data;
    data_unit *dunit;

    RMT_NOTUSED(el);
    RMT_NOTUSED(fd);
    RMT_NOTUSED(privdata);
    RMT_NOTUSED(mask);

    ASSERT(el == cdata->loop);
    ASSERT(fd == srnode->sk_event);

    if (cdata->sent_keys_count >= cdata->keys_count) {
         aeDeleteFileEvent(cdata->loop,srnode->sk_event,AE_WRITABLE);
         return;
    }

    if (cdata->sent_keys_count - 
        cdata->finished_keys_count > 
        MAX_KEYS_HOLD_PER_THREAD) {
        return;
    }
    
    cdata->sent_keys_count ++;

    dunit = data_unit_create(cdata);
    
    redis_key_value_send(srnode, dunit->key, dunit->data_type, dunit->value, 
        dunit->expiretime_type, dunit->expiretime, srnode->owner);

    data_unit_destroy(dunit);

    return;
    
error:

    aeDeleteFileEvent(cdata->loop,srnode->sk_event,AE_READABLE|AE_WRITABLE);
    aeStop(cdata->loop);
}

static void *testinsert_thread_run(void *args)
{
    int ret;
    thread_data *cdata = args;
    redis_group *srgroup = cdata->srgroup;
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
            AE_WRITABLE, testinsert_begin, rnode);
        if (ret != AE_OK) {
            log_error("ERROR: send_data event create %ld failed: %s",
                cdata->thread_id, strerror(errno));
            return 0;
        }
    }
    dictReleaseIterator(di);

    srand(time(NULL)^cdata->id);
    aeMain(cdata->loop);
    return 0;
}

void redis_testinsert_data(rmtContext *ctx, int type)
{
    int i;
    int threads_count;
    long long keys_count, keys_count_per_thread;
    long long keys_count_left, keys_count_threads_hold;
    long long insert_keys_count = 0;
    long long inserted_keys_count = 0;
    long long string_keys, list_keys, set_keys, zset_keys, hash_keys;
    thread_data **threads = NULL;
    long long starttime, endtime;
    sds *key_types_str = NULL;
    int key_types_str_count = 0;
    sds *str = NULL;

    RMT_NOTUSED(type);

    if (ctx == NULL || ctx->source_addr == NULL) {
        goto error;
    }

    signal(SIGPIPE, SIG_IGN);

    /* Init the key count */
    keys_count = 1000;

    if (array_n(&ctx->args) == 0) {
        keys_count = 1000;
        
        data_types |= TEST_TYPE_REDIS_STRING;
        data_types |= TEST_TYPE_REDIS_LIST;
        data_types |= TEST_TYPE_REDIS_SET;
        data_types |= TEST_TYPE_REDIS_ZSET;
        /* redis_check command sometimes does not work for*/
        /* hash type, so we don't insert hash by default. */
        //data_types |= TEST_TYPE_REDIS_HASH;

        goto parse_done;
    } else if (array_n(&ctx->args) == 1) {
        str = array_get(&ctx->args, 0);
        if (sdsIsNum(*str)) {
            keys_count = rmt_atoll(*str,sdslen(*str));

            data_types |= TEST_TYPE_REDIS_STRING;
            data_types |= TEST_TYPE_REDIS_LIST;
            data_types |= TEST_TYPE_REDIS_SET;
            data_types |= TEST_TYPE_REDIS_ZSET;
            /* redis_check command sometimes does not work for*/
            /* hash type, so we don't insert hash by default. */
            //data_types |= TEST_TYPE_REDIS_HASH;

            goto parse_done;
        } else {
            keys_count = 1000;
        }
    } else if (array_n(&ctx->args) == 2) {
        str = array_get(&ctx->args, 0);
        if (sdsIsNum(*str)) {
            keys_count = rmt_atoll(*str,sdslen(*str));
            str = array_get(&ctx->args, 1);
        } else {
            str = array_get(&ctx->args, 1);
            if (!sdsIsNum(*str)) {
                log_error("ERROR: arguments must have a number for key count");
                goto error;
            }
            keys_count = rmt_atoll(*str,sdslen(*str));
            str = array_get(&ctx->args, 0);
        }
    }

    /* Init the key type */
    ASSERT(str != NULL);
        
    key_types_str = sdssplitlen(*str,sdslen(*str),"|",1,&key_types_str_count);
    if (key_types_str == NULL || key_types_str_count < 1) {
        log_error("ERROR: key type error");
        goto error;
    }

    for (i = 0; i < key_types_str_count; i ++) {
        if (!strcasecmp(key_types_str[i], "string")) {
            data_types |= TEST_TYPE_REDIS_STRING;
        } else if (!strcasecmp(key_types_str[i], "list")) {
            data_types |= TEST_TYPE_REDIS_LIST;
        } else if (!strcasecmp(key_types_str[i], "set")) {
            data_types |= TEST_TYPE_REDIS_SET;
        } else if (!strcasecmp(key_types_str[i], "zset")) {
            data_types |= TEST_TYPE_REDIS_ZSET;
        } else if (!strcasecmp(key_types_str[i], "hash")) {
            data_types |= TEST_TYPE_REDIS_HASH;
        } else if (!strcasecmp(key_types_str[i], "all")) {
            data_types |= TEST_TYPE_REDIS_STRING;
            data_types |= TEST_TYPE_REDIS_LIST;
            data_types |= TEST_TYPE_REDIS_SET;
            data_types |= TEST_TYPE_REDIS_ZSET;
            data_types |= TEST_TYPE_REDIS_HASH;
        } else {
            log_error("ERROR: value type is error");
            goto error;
        }
    }

    sdsfreesplitres(key_types_str, key_types_str_count);

parse_done:
    if (data_types&TEST_TYPE_REDIS_STRING) {
        data_type_string_mark = data_types_count;
        data_types_count ++;
    }
    if (data_types&TEST_TYPE_REDIS_LIST) {
        data_type_list_mark = data_types_count;
        data_types_count ++;
    }
    if (data_types&TEST_TYPE_REDIS_SET) {
        data_type_set_mark = data_types_count;
        data_types_count ++;
    }
    if (data_types&TEST_TYPE_REDIS_ZSET) {
        data_type_zset_mark = data_types_count;
        data_types_count ++;
    }
    if (data_types&TEST_TYPE_REDIS_HASH) {
        data_type_hash_mark = data_types_count;
        data_types_count ++;
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
    threads = rmt_alloc(threads_count * sizeof(*threads));
    if (threads == NULL) {
        log_error("Error: out of memory.");
        goto error;
    }

    keys_count_per_thread = keys_count/threads_count;

    //Create the thread data
    for(i = 0; i < threads_count; i ++){
    	threads[i] = testinsert_thread_data_create(ctx);
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

    log_stdout("Test insert job is running...");
    starttime = rmt_msec_now();
    
    //Run the job
    for(i = 0; i < threads_count; i ++){
    	pthread_create(&threads[i]->thread_id, 
        	NULL, testinsert_thread_run, threads[i]);
    }

	//Wait for the job finish
	for(i = 0; i < threads_count; i ++){
		pthread_join(threads[i]->thread_id, NULL);
	}

    endtime = rmt_msec_now();

    inserted_keys_count = 0;
    string_keys = list_keys = set_keys = zset_keys = hash_keys = 0;
    for (i = 0; i < threads_count; i ++) {
        insert_keys_count += threads[i]->finished_keys_count;
        inserted_keys_count += threads[i]->correct_keys_count;

        testinsert_data *tidata = threads[i]->data;
        string_keys += tidata->string_keys;
        list_keys += tidata->list_keys;
        set_keys += tidata->set_keys;
        zset_keys += tidata->zset_keys;
        hash_keys += tidata->hash_keys;
    }

    /* Show the check result */
    log_stdout("");
    log_stdout("Insert string keys: %lld", string_keys);
    log_stdout("Insert list keys  : %lld", list_keys);
    log_stdout("Insert set keys   : %lld", set_keys);
    log_stdout("Insert zset keys  : %lld", zset_keys);
    log_stdout("Insert hash keys  : %lld", hash_keys);
    log_stdout("Insert total keys : %lld", insert_keys_count);
    
    log_stdout("");
    log_stdout("Correct inserted keys: %lld", inserted_keys_count);
    log_stdout("Test insert job finished, used %.3fs", 
        (float)(endtime-starttime)/1000);
    
error:

    if (threads != NULL) {
        for(i = 0; i < threads_count; i ++){
        	testinsert_thread_data_destroy(threads[i]);
        }
        rmt_free(threads);
    }
}


