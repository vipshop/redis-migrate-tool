#include <rmt_core.h>

#define DEFAULT_SOURCE_GROUP_TIMEOUT    120000

/* Client flags */
#define REDIS_SLAVE (1<<0)   /* This client is a slave server */
#define REDIS_MASTER (1<<1)  /* This client is a master server */
#define REDIS_MONITOR (1<<2) /* This client is a slave monitor, see MONITOR */
#define REDIS_MULTI (1<<3)   /* This client is in a MULTI context */
#define REDIS_BLOCKED (1<<4) /* The client is waiting in a blocking operation */
#define REDIS_DIRTY_CAS (1<<5) /* Watched keys modified. EXEC will fail. */
#define REDIS_CLOSE_AFTER_REPLY (1<<6) /* Close after writing entire reply. */
#define REDIS_UNBLOCKED (1<<7) /* This client was unblocked and is stored in
                                  server.unblocked_clients */
#define REDIS_LUA_CLIENT (1<<8) /* This is a non connected client used by Lua */
#define REDIS_ASKING (1<<9)     /* Client issued the ASKING command */
#define REDIS_CLOSE_ASAP (1<<10)/* Close this client ASAP */
#define REDIS_UNIX_SOCKET (1<<11) /* Client connected via Unix domain socket */
#define REDIS_DIRTY_EXEC (1<<12)  /* EXEC will fail for errors while queueing */
#define REDIS_MASTER_FORCE_REPLY (1<<13)  /* Queue replies even if is master */
#define REDIS_FORCE_AOF (1<<14)   /* Force AOF propagation of current cmd. */
#define REDIS_FORCE_REPL (1<<15)  /* Force replication of current cmd. */
#define REDIS_PRE_PSYNC (1<<16)   /* Instance don't understand PSYNC. */
#define REDIS_READONLY (1<<17)    /* Cluster client is in read-only state. */
#define REDIS_PUBSUB (1<<18)      /* Client is in Pub/Sub mode. */

#define REDIS_RDB_USED_USEMARK (1<<19); /* RDB file recieved from master is usemark. */

/* ========================== Redis RDB ============================ */

/* The current RDB version. When the format changes in a way that is no longer
 * backward compatible this number gets incremented. */
#define REDIS_RDB_VERSION 7

/* Defines related to the dump file format. To store 32 bits lengths for short
 * keys requires a lot of space, so we check the most significant 2 bits of
 * the first byte to interpreter the length:
 *
 * 00|000000 => if the two MSB are 00 the len is the 6 bits of this byte
 * 01|000000 00000000 =>  01, the len is 14 byes, 6 bits + 8 bits of next byte
 * 10|000000 [32 bit integer] => if it's 01, a full 32 bit len will follow
 * 11|000000 this means: specially encoded object will follow. The six bits
 *           number specify the kind of object that follows.
 *           See the REDIS_RDB_ENC_* defines.
 *
 * Lengths up to 63 are stored using a single byte, most DB keys, and may
 * values, will fit inside. */
#define REDIS_RDB_6BITLEN 0
#define REDIS_RDB_14BITLEN 1
#define REDIS_RDB_32BITLEN 2
#define REDIS_RDB_ENCVAL 3
#define REDIS_RDB_LENERR UINT_MAX

/* When a length of a string object stored on disk has the first two bits
 * set, the remaining two bits specify a special encoding for the object
 * accordingly to the following defines: */
#define REDIS_RDB_ENC_INT8 0        /* 8 bit signed integer */
#define REDIS_RDB_ENC_INT16 1       /* 16 bit signed integer */
#define REDIS_RDB_ENC_INT32 2       /* 32 bit signed integer */
#define REDIS_RDB_ENC_LZF 3         /* string compressed with FASTLZ */

/* Dup object types to RDB object types. Only reason is readability (are we
 * dealing with RDB types or with in-memory object types?). */
#define REDIS_RDB_TYPE_STRING 0
#define REDIS_RDB_TYPE_LIST   1
#define REDIS_RDB_TYPE_SET    2
#define REDIS_RDB_TYPE_ZSET   3
#define REDIS_RDB_TYPE_HASH   4

/* Object types for encoded objects. */
#define REDIS_RDB_TYPE_HASH_ZIPMAP    9
#define REDIS_RDB_TYPE_LIST_ZIPLIST  10
#define REDIS_RDB_TYPE_SET_INTSET    11
#define REDIS_RDB_TYPE_ZSET_ZIPLIST  12
#define REDIS_RDB_TYPE_HASH_ZIPLIST  13
#define REDIS_RDB_TYPE_LIST_QUICKLIST 14

/* Test if a type is an object type. */
#define rdbIsObjectType(t) ((t >= 0 && t <= 4) || (t >= 9 && t <= 13))

/* Special RDB opcodes (saved/loaded with rdbSaveType/rdbLoadType). */
#define REDIS_RDB_OPCODE_AUX        250
#define REDIS_RDB_OPCODE_RESIZEDB   251
#define REDIS_RDB_OPCODE_EXPIRETIME_MS 252
#define REDIS_RDB_OPCODE_EXPIRETIME 253
#define REDIS_RDB_OPCODE_SELECTDB   254
#define REDIS_RDB_OPCODE_EOF        255

#define REDIS_RDB_MAGIC_STR    "REDIS"

/* ========================== Redis RDB END ============================ */

/* ======================== Redis TWEMPROXY ========================== */

#define TWEM_KETAMA_CONTINUUM_ADDITION   10  /* # extra slots to build into continuum */
#define TWEM_KETAMA_POINTS_PER_SERVER    160 /* 40 points per hash */
#define TWEM_KETAMA_MAX_HOSTLEN          86

#define TWEM_RANDOM_CONTINUUM_ADDITION   10  /* # extra slots to build into continuum */
#define TWEM_RANDOM_POINTS_PER_SERVER    1

#define TWEM_MODULA_CONTINUUM_ADDITION   10  /* # extra slots to build into continuum */
#define TWEM_MODULA_POINTS_PER_SERVER    1

struct continuum {
    uint32_t index;  /* server index */
    uint32_t value;  /* hash value */
    redis_node *node;
};

struct node_twem{
    sds name;
    uint32_t weight;
    redis_node *node;
};

/* ======================= Redis TWEMPROXY END ========================= */

/* Insert command for every object */
#define REDIS_INSERT_STRING    "set"
#define REDIS_INSERT_LIST      "rpush"
#define REDIS_INSERT_SET       "sadd"
#define REDIS_INSERT_ZSET      "zadd"
#define REDIS_INSERT_HASH      "hmset"

/* Prefix for the set command expire time */
#define REDIS_SET_CMD_EXPIRE_SECOND_PREFIX      "EX"
#define REDIS_SET_CMD_EXPIRE_MILLISECOND_PREFIX "PX"

/* Redis data type for replication. 
 */
#define RMT_REDIS_REPL_DATA_TYPE_UNKNOW 0
#define RMT_REDIS_REPL_DATA_TYPE_RDB 1
#define RMT_REDIS_REPL_DATA_TYPE_CMD 2

#define REDIS_CLUSTER_SLOTS 16384

//#define REDIS_COMMAND_CLUSTER_NODES "*1\r\n$13\r\nCLUSTER NODES\r\n"
#define REDIS_COMMAND_CLUSTER_NODES "CLUSTER NODES\r\n"
#define REDIS_COMMAND_CLUSTER_SLOTS "*1\r\n$13\r\nCLUSTER SLOTS\r\n"

#define REDIS_MAX_ELEMS_PER_COMMAND 1024*1024

#define DEFINE_ACTION(_hash, _name) hash_##_name,
static hash_t hash_algos[] = {
    HASH_CODEC( DEFINE_ACTION )
    NULL
};
#undef DEFINE_ACTION

/* Cluster nodes hash table, mapping nodes 
 * name(437c719f50dc9d0745032f3b280ce7ecc40792ac)  
 * or addresses(1.2.3.4:6379) to clusterNode structures.
 * Those nodes need destroy.
 */
static dictType groupNodesDictType = {
    dictSdsHash,                /* hash function */
    NULL,                       /* key dup */
    NULL,                       /* val dup */
    dictSdsKeyCompare,          /* key compare */
    dictSdsDestructor,          /* key destructor */
    dictGroupNodeDestructor   /* val destructor */
};

static int rmtRedisSlaveAgainOnline(redis_node *srnode);

int redis_replication_init(redis_repl *rr)
{
    if (rr == NULL) {
        return RMT_ERROR;
    }

    rmt_memset(rr->eofmark, 0, REDIS_RUN_ID_SIZE);
    rmt_memset(rr->lastbytes, 0, REDIS_RUN_ID_SIZE);
    rr->usemark = 0;

    rr->flags = REDIS_SLAVE;
    rr->repl_state = REDIS_REPL_NONE;
    
    rr->reploff = 0;
    rmt_memset(rr->replrunid,0,REDIS_RUN_ID_SIZE+1);
    
    rr->repl_master_initial_offset = -1;
    rmt_memset(rr->repl_master_runid,0,REDIS_RUN_ID_SIZE+1);

    rr->repl_transfer_size = -1;
    rr->repl_transfer_read = 0;
    rr->repl_transfer_last_fsync_off = 0;
    rr->repl_lastio = 0;

    return RMT_OK;
}

void redis_replication_deinit(redis_repl *rr)
{
    if (rr == NULL) {
        return;
    }

    rmt_memset(rr->eofmark, 0, REDIS_RUN_ID_SIZE);
    rmt_memset(rr->lastbytes, 0, REDIS_RUN_ID_SIZE);
    rr->usemark = 0;

    rr->flags = REDIS_SLAVE;
    rr->repl_state = REDIS_REPL_NONE;

    rr->reploff = 0;
    rmt_memset(rr->replrunid,0,REDIS_RUN_ID_SIZE+1);
    
    rr->repl_master_initial_offset = -1;
    rmt_memset(rr->repl_master_runid,0,REDIS_RUN_ID_SIZE+1);

    rr->repl_transfer_size = -1;
    rr->repl_transfer_read = 0;
    rr->repl_transfer_last_fsync_off = 0;
    rr->repl_lastio = 0;
}

int redis_node_init(redis_node *rnode, const char *addr, redis_group *rgroup)
{
    int ret;
    rmtContext *ctx = rgroup->ctx;

    if (rnode == NULL || addr == NULL 
        || rgroup == NULL) {
        return RMT_ERROR;
    }
    
    rnode->ctx = NULL;
    rnode->id = 0;
    rnode->owner = NULL;
    
    rnode->state = 0;
    rnode->addr = NULL;
    rnode->tc = NULL;

    rnode->read_data = NULL;
    rnode->write_data = NULL;

    rnode->rr = NULL;

    rnode->rdb = NULL;
    rnode->mbuf_in = NULL;
    rnode->cmd_data = NULL;

    rnode->piece_data = NULL;
    rnode->msg = NULL;

    rnode->send_data = NULL;
    rnode->sent_data = NULL;
    rnode->msg_rcv = NULL;

    rnode->sockpairfds[0] = -1;
    rnode->sockpairfds[1] = -1;

    rnode->timestamp = 0;

    rnode->sk_event = -1;
    
    rnode->next = NULL;

    rnode->owner = rgroup;

    rnode->addr = rmt_strdup(addr);
    if (rnode->addr == NULL) {
        log_error("ERROR: Out of memory");
        goto error;
    }

    rnode->tc = rmt_tcp_context_create();
    if (rnode->tc == NULL) {
        log_error("ERROR: create tcp_context failed: out of memory");
        goto error;
    }

    rnode->ctx = ctx;

    if (rgroup->source) {
        rnode->rdb = rmt_alloc(sizeof(*rnode->rdb));
        if (rnode->rdb == NULL) {
            log_error("ERROR: Create rdb failed: out of memory");
            goto error;
        }
        ret = redis_rdb_init(rnode->rdb, addr, REDIS_RDB_TYPE_FILE);
        if (ret != RMT_OK) {
            log_error("ERROR: Init srnode->rdb failed");
            goto error;
        }
        if (!strcasecmp(ctx->cmd, RMT_CMD_REDIS_MIGRATE)) {
            rnode->rdb->handler = redis_key_value_send;
        }

        if (rgroup->kind == GROUP_TYPE_RDBFILE) {
            sdsrange(rnode->rdb->fname,0,0);
            rnode->rdb->fname = sdscat(rnode->rdb->fname, addr);
            log_debug(LOG_DEBUG, "rdb->fname: %s", rnode->rdb->fname);
            rnode->rdb->deleted = 0;
        }

        rnode->rr = rmt_alloc(sizeof(*rnode->rr));
        if (rnode->rr == NULL) {
            log_error("ERROR: Create redis_repl failed: out of memory");
            goto error;
        }

        ret = redis_replication_init(rnode->rr);
        if (ret != RMT_OK) {
            log_error("ERROR: Init redis replication failed");
            goto error;
        }        
        
        rnode->cmd_data = mttlist_create();
        if (rnode->cmd_data == NULL) {
            log_error("ERROR: Create cmd_data list failed: out of memory");
            goto error;
        }

        rnode->piece_data = listCreate();
        if (rnode->piece_data == NULL) {
            log_error("ERROR: Create piece data for source node failed: out of memory");
            goto error;
        }

        ret = mttlist_init_with_locklist(rnode->cmd_data);
        if (ret != RMT_OK) {
            log_error("ERROR: Init cmd_data list failed: out of memory");
            goto error;
        }

        ret = socketpair(AF_LOCAL, SOCK_STREAM, 0, rnode->sockpairfds);
        if (ret < 0) {
            log_error("ERROR: sockpairfds init failed: %s", strerror(errno));
            goto error;
        }

        ret = rmt_set_nonblocking(rnode->sockpairfds[0]);
        if (ret < 0) {
            log_error("ERROR: Set sockpairfds[0] %d nonblock failed: %s", 
                rnode->sockpairfds[0], strerror(errno));
            goto error;
        }

        ret = rmt_set_nonblocking(rnode->sockpairfds[1]);
        if (ret < 0) {
            log_error("ERROR: Set sockpairfds[1] %d nonblock failed: %s", 
                rnode->sockpairfds[1], strerror(errno));
            goto error;
        }
    }else { 
        rnode->send_data = listCreate();
        if (rnode->send_data == NULL) {
            log_error("ERROR: Create msg list failed: out of memory");
            goto error;
        }

        rnode->sent_data = listCreate();
        if (rnode->sent_data == NULL) {
            log_error("ERROR: Create msg list failed: out of memory");
            goto error;
        }
    }

    rnode->id = rgroup->node_id;
    rgroup->node_id ++;
    
    return RMT_OK;
    
error:

    redis_node_deinit(rnode);
    return RMT_ERROR;
}

void redis_node_deinit(redis_node *rnode)
{
    struct mbuf *mbuf;
    struct msg *msg;

    if (rnode == NULL) {
        return;
    }

    if (rnode->ctx != NULL) {
        rnode->ctx = NULL;
    }   

    if (rnode->owner != NULL) {
        rnode->owner = NULL;
    }

    if (rnode->addr != NULL) {
        free(rnode->addr);
        rnode->addr = NULL;
    }

    if (rnode->tc != NULL) {
        rmt_tcp_context_destroy(rnode->tc);
        rnode->tc = NULL;
    }

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

    if (rnode->mbuf_in != NULL) {
        mbuf_put(rnode->mbuf_in);
        rnode->mbuf_in = NULL;
    }

    if (rnode->rr != NULL) {
        redis_replication_deinit(rnode->rr);
        rmt_free(rnode->rr);
        rnode->rr = NULL;
    }

    if (rnode->send_data != NULL) {
        while ((msg = listPop(rnode->send_data)) != NULL) {
            ASSERT(msg->request);
            ASSERT(msg->sent == 0);
            msg_put(msg);
            msg_free(msg);
        }
    
        listRelease(rnode->send_data);
        rnode->send_data = NULL;
    }

    if (rnode->sent_data != NULL) {
        while ((msg = listPop(rnode->sent_data)) != NULL) {
            ASSERT(msg->request);
            ASSERT(msg->sent == 1);
            msg_put(msg);
            msg_free(msg);
        }
    
        listRelease(rnode->sent_data);
        rnode->sent_data = NULL;
    }

    if (rnode->msg_rcv != NULL) {
        msg_put(rnode->msg_rcv);
        msg_free(rnode->msg_rcv);
        rnode->msg_rcv = NULL;
    }

    if (rnode->piece_data != NULL) {
        while ((mbuf = listPop(rnode->piece_data)) != NULL) {
            mbuf_put(mbuf);
        }
        
        listRelease(rnode->piece_data);
        rnode->piece_data = NULL;
    }

    if (rnode->msg != NULL) {
        msg_put(rnode->msg);
        msg_free(rnode->msg);
        rnode->msg = NULL;
    }

    rnode->read_data = NULL;
    rnode->write_data = NULL;
    rnode->state = 0;
    
    rnode->timestamp = 0;

    if (rnode->sk_event > 0) {
        close(rnode->sk_event);
        rnode->sk_event = -1;
    }

    rnode->next = NULL;

}

int redis_group_init(rmtContext *ctx, redis_group *rgroup, 
    conf_pool *cp, int source)
{
    int ret;

    if (rgroup == NULL) {
        return RMT_ERROR;
    }

    rgroup->ctx = NULL;
    rgroup->nodes = NULL;
    rgroup->node_id = 0;
    rgroup->kind = GROUP_TYPE_UNKNOW;

    rgroup->source = 0;
    rgroup->password = NULL;
    rgroup->timeout = 0;
    
    rgroup->mb = NULL;

    rgroup->route = NULL;
    rgroup->get_backend_idx = NULL;
    rgroup->get_backend_node = NULL;
    rgroup->key_hash = NULL;
    rgroup->ncontinuum = 0;

    rgroup->distribution = CONF_UNSET_DIST;

    rgroup->ctx = ctx;

    if(source) {
        rgroup->source = 1;
        rgroup->mb = mbuf_base_create(
            ctx->mbuf_size, NULL);
        if (rgroup->mb == NULL) {
            log_error("ERROR: Create mbuf_base failed");
            goto error;
        }

        rgroup->timeout = DEFAULT_SOURCE_GROUP_TIMEOUT;
    } else {
        rgroup->mb = mbuf_base_create(
            REDIS_RESPONSE_MBUF_BASE_SIZE, 
            mttlist_init_with_unlocklist);
        if (rgroup->mb == NULL) {
            log_error("ERROR: Create mbuf_base failed");
            goto error;
        }
    }

    rgroup->nodes = dictCreate(&groupNodesDictType, NULL);
    if (rgroup->nodes == NULL) {
        log_error("ERROR: Create nodes dict failed: out of memory");
        goto error;
    }

    if (cp != NULL) {
        rgroup->kind = cp->type;

        if (cp->redis_auth != CONF_UNSET_PTR) {
            rgroup->password = sdsdup(cp->redis_auth);
        }

        switch(cp->type) {
        case GROUP_TYPE_SINGLE:
            ret = redis_single_init_from_conf(rgroup, cp);
            if (ret != RMT_OK) {
                log_error("ERROR: Redis single init failed");
                goto error;
            }

            rgroup->get_backend_idx = redis_single_backend_idx;
            rgroup->get_backend_node = redis_single_backend_node;
            break;
        case GROUP_TYPE_TWEM:
            ret = redis_twem_init_from_conf(rgroup, cp);
            if (ret != RMT_OK) {
                log_error("ERROR: Redis twemproxy init failed");
                goto error;
            }

            rgroup->get_backend_idx = redis_twem_backend_idx;
            rgroup->get_backend_node = redis_twem_backend_node;
            break;
        case GROUP_TYPE_RCLUSTER:
            ret = redis_cluster_init_from_conf(rgroup, cp);
            if (ret != RMT_OK) {
                log_error("ERROR: Redis cluster init failed");
                goto error;
            }

            rgroup->get_backend_idx = redis_cluster_backend_idx;
            rgroup->get_backend_node = redis_cluster_backend_node;
            break;
        case GROUP_TYPE_RDBFILE:
            ret = redis_rdb_file_init_from_conf(rgroup, cp);
            if (ret != RMT_OK) {
                log_error("ERROR: Rdb file init failed");
                goto error;
            }

            rgroup->get_backend_idx = NULL;
            rgroup->get_backend_node = NULL;
            break;
        case GROUP_TYPE_AOFFILE:
            ret = redis_aof_file_init_from_conf(rgroup, cp);
            if (ret != RMT_OK) {
                log_error("ERROR: Aof file init failed");
                goto error;
            }

            rgroup->get_backend_idx = NULL;
            rgroup->get_backend_node = NULL;
            break;
        default:
            log_error("ERROR: Unknown group type");
            goto error;
            break;
        }

        if (cp->hash != CONF_UNSET_HASH) {
            rgroup->key_hash = hash_algos[cp->hash];
        }

        if (cp->timeout != CONF_UNSET_NUM) {
            rgroup->timeout= cp->timeout;
        }
    }

    return RMT_OK;
    
error:

    redis_group_deinit(rgroup);
    return RMT_ERROR;
}

void redis_group_deinit(redis_group *rgroup)
{
    if (rgroup == NULL) {
        return;
    }

    if (rgroup->ctx != NULL && rgroup->ctx->srgroup == rgroup) {
        rgroup->ctx->srgroup = NULL;
    }

    if (rgroup->kind != GROUP_TYPE_UNKNOW) {
        rgroup->kind = GROUP_TYPE_UNKNOW;
    }

    if (rgroup->nodes != NULL) {
        dictRelease(rgroup->nodes);
        rgroup->nodes = NULL;
    }

    if (rgroup->route != NULL) {
        rgroup->route->nelem = 0;
        array_destroy(rgroup->route);
        rgroup->route = NULL;
    }

    if (rgroup->mb != NULL) {
        mbuf_base_destroy(rgroup->mb);
        rgroup->mb = NULL;
    }

    if (rgroup->password != NULL) {
        sdsfree(rgroup->password);
        rgroup->password = NULL;
    }

    rgroup->ncontinuum = 0;
    rgroup->ctx = NULL;
    rgroup->distribution = CONF_UNSET_DIST;
}

int redis_rdb_init(redis_rdb *rdb, const char *addr, int type)
{
    int ret;

    if (rdb == NULL) {
        return RMT_ERROR;
    }

    if (type != REDIS_RDB_TYPE_FILE && 
        type != REDIS_RDB_TYPE_MEM) {
        return RMT_ERROR;
    }

    rdb->type = REDIS_RDB_TYPE_UNKNOW;
    rdb->rdbver = 0;
    rdb->mb = NULL;
    rdb->mbuf = NULL;
    rdb->data = NULL;
    rdb->fname = NULL;
    rdb->fd = -1;

    rdb->fp = NULL;
    rdb->cksum = 0;
    rdb->update_cksum = NULL;

    rdb->state = 0;

    rdb->deleted = 0;
    rdb->received = 0;

    rdb->handler = NULL;

    rdb->update_cksum = redis_rdb_update_checksum;

    rdb->mb = mbuf_base_create(
        REDIS_RDB_MBUF_BASE_SIZE, NULL);
    if (rdb->mb == NULL) {
        log_error("ERROR: create mbuf_base failed");
        goto error;
    }

    if (type == REDIS_RDB_TYPE_FILE) {
        rdb->fname = sdsempty();
        if (rdb->fname == NULL) {
            log_error("ERROR: out of memory");
            goto error;            
        }
    } else if(REDIS_RDB_TYPE_MEM) {
        rdb->data = mttlist_create();
        if (rdb->data == NULL) {
            log_error("ERROR: create rdb data list failed: out of memory");
            goto error;
        }

        ret = mttlist_init_with_locklist(rdb->data);
        if (ret != RMT_OK) {
            log_error("ERROR: init rdb data list failed: out of memory");
            goto error;
        }
    }

    rdb->type = type;
    rdb->deleted = 1;

    return RMT_OK;
    
error:
    
    redis_rdb_deinit(rdb);

    return RMT_ERROR;
}

void redis_rdb_deinit(redis_rdb *rdb)
{
    struct mbuf *mbuf;

    if (rdb->data != NULL) {
        if (rdb->mb != NULL) {
            while (!mttlist_empty(rdb->data)) {
                mbuf = mttlist_pop(rdb->data);
                mbuf_put(mbuf);
            }
        }
        
        mttlist_destroy(rdb->data);
        rdb->data = NULL;
    }

    if (rdb->fd > 0) {
        close(rdb->fd);
        rdb->fd = -1;
    }

    if (rdb->fname != NULL) {
        redis_delete_rdb_file(rdb, 0);
    }

    if (rdb->mbuf != NULL) {
        if(rdb->mb != NULL)
        {
            mbuf_put(rdb->mbuf);
        }

        rdb->mbuf = NULL;
    }

    if (rdb->mb != NULL) {
        mbuf_base_destroy(rdb->mb);
        rdb->mb = NULL;
    }

    if (rdb->fp != NULL) {
        fclose(rdb->fp);
        rdb->fp = NULL;
    }

    if (rdb->cksum > 0) {
        rdb->cksum = 0;
    }
    
    if (rdb->update_cksum != NULL) {
        rdb->update_cksum = NULL;
    }

    rdb->state = 0;

    rdb->deleted = 0;

    if (rdb->handler != NULL) {
        rdb->handler = NULL;
    }
}

/* Send a synchronous command to a redis. Used to send AUTH
 * commands before starting the migrate.
 *
 * The command returns an sds string representing the result of the
 * operation. On error the first byte is a "-".
 */
char *rmt_send_sync_cmd_read_line(int fd, ...) {
    va_list ap;
    sds cmd = sdsempty();
    char *arg, buf[256];

    /* Create the command to send to the master, we use simple inline
     * protocol for simplicity as currently we only send simple strings. */
    va_start(ap,fd);
    while(1) {
        arg = va_arg(ap, char*);
        if(arg == NULL) break;

        if (sdslen(cmd) != 0) cmd = sdscatlen(cmd," ",1);
        cmd = sdscat(cmd,arg);
    }
    cmd = sdscatlen(cmd,"\r\n",2);

    va_end(ap);

    /* Transfer command to the server. */
    if (rmt_sync_write(fd,cmd,(ssize_t)sdslen(cmd),1000) == -1) {
        sdsfree(cmd);
        return sdscatprintf(sdsempty(),"-Writing to redis: %s",
                strerror(errno));
    }
    sdsfree(cmd);

    /* Read the reply from the server. */
    if (rmt_sync_readline(fd,buf,sizeof(buf),1000) == -1)
    {
        return sdscatprintf(sdsempty(),"-Reading from redis: %s",
                strerror(errno));
    }
    return sdsnew(buf);
}

/* ========================== Redis Replication ============================ */

/* Send a short redis command to master. 
 */
static int rmt_redis_send_cmd(int fd, ...) {
    va_list ap;
    sds cmd = sdsempty();
    char *arg;

    /* Create the command to send to the master, we use simple inline
     * protocol for simplicity as currently we only send simple strings. */
    va_start(ap,fd);
    while(1) {
        arg = va_arg(ap, char*);
        if(arg == NULL) break;

        if (sdslen(cmd) != 0) cmd = sdscatlen(cmd," ",1);
        cmd = sdscat(cmd,arg);
    }
    cmd = sdscatlen(cmd,"\r\n",2);

    va_end(ap);

    /* Transfer command to the server. */
    if (rmt_sync_write(fd,cmd,(ssize_t)sdslen(cmd),1000) == -1) {
        sdsfree(cmd);
        log_error("ERROR: writing to master failed: %s", strerror(errno));
        return RMT_ERROR;
    }
    sdsfree(cmd);
    
    return RMT_OK;
}

static int redisRplicationReset(redis_node *srnode)
{
    int ret;
    redis_repl *rr = srnode->rr;

    rmt_memset(rr->eofmark, 0, REDIS_RUN_ID_SIZE);
    rmt_memset(rr->lastbytes, 0, REDIS_RUN_ID_SIZE);
    rr->usemark = 0;

    rr->flags = REDIS_SLAVE;
    
    rr->reploff = 0;
    rmt_memset(rr->replrunid,0,REDIS_RUN_ID_SIZE+1);
    
    rr->repl_master_initial_offset = -1;
    rmt_memset(rr->repl_master_runid,0,REDIS_RUN_ID_SIZE+1);

    rr->repl_transfer_size = -1;
    rr->repl_transfer_read = 0;
    rr->repl_transfer_last_fsync_off = 0;
    rr->repl_lastio = 0;
    
    return RMT_OK;
}

/* Send a synchronous command to the master. Used to send AUTH and
 * REPLCONF commands before starting the replication with SYNC.
 *
 * The command returns an sds string representing the result of the
 * operation. On error the first byte is a "-".
 */
#define SYNC_CMD_READ (1<<0)
#define SYNC_CMD_WRITE (1<<1)
#define SYNC_CMD_FULL (SYNC_CMD_READ|SYNC_CMD_WRITE)
static char *sendReplSyncCommand(int flags, redis_node *srnode, ...) {
    tcp_context *tc = srnode->tc;
    redis_repl *rr = srnode->rr;
    thread_data *rdata = srnode->read_data;
    
    /* Create the command to send to the master, we use simple inline
     * protocol for simplicity as currently we only send simple strings. */
    if (flags & SYNC_CMD_WRITE) {
        char *arg;
        va_list ap;
        sds cmd = sdsempty();
        va_start(ap,srnode);

        while(1) {
            arg = va_arg(ap, char*);
            if (arg == NULL) break;

            if (sdslen(cmd) != 0) cmd = sdscatlen(cmd," ",1);
            cmd = sdscat(cmd,arg);
        }
        cmd = sdscatlen(cmd,"\r\n",2);

        /* Transfer command to the server. */
        if (rmt_sync_write(tc->sd,cmd,sdslen(cmd),1000)
            == -1)
        {
            sdsfree(cmd);
            return sdscatprintf(sdsempty(),"-Writing to master: %s",
                    strerror(errno));
        }
        sdsfree(cmd);
        va_end(ap);
    }

    /* Read the reply from the server. */
    if (flags & SYNC_CMD_READ) {
        ssize_t nread;
        char buf[256];

        nread = rmt_sync_readline(tc->sd,buf,sizeof(buf),1000);
        if (nread == -1) {
            return sdscatprintf(sdsempty(),"-Reading from master: %s",
                    strerror(errno));
        }
        rr->repl_lastio = rdata->unixtime;
        return sdsnew(buf);
    }
    return NULL;
}

/* Returns 1 if the given replication state is a handshake state,
 * 0 otherwise. */
static int rmtSlaveIsInHandshakeState(redis_node *srnode) {
    redis_repl *rr = srnode->rr;
    return rr->repl_state >= REDIS_REPL_RECEIVE_PONG &&
           rr->repl_state <= REDIS_REPL_RECEIVE_PSYNC;
}

/* Try a partial resynchronization with the master if we are about to reconnect.
 * If there is no cached master structure, at least try to issue a
 * "PSYNC ? -1" command in order to trigger a full resync using the PSYNC
 * command in order to obtain the master run id and the master replication
 * global offset.
 *
 * This function is designed to be called from syncWithMaster(), so the
 * following assumptions are made:
 *
 * 1) We pass the function an already connected socket "fd".
 * 2) This function does not close the file descriptor "fd". However in case
 *    of successful partial resynchronization, the function will reuse
 *    'fd' as file descriptor of the server.master client structure.
 *
 * The function is split in two halves: if read_reply is 0, the function
 * writes the PSYNC command on the socket, and a new function call is
 * needed, with read_reply set to 1, in order to read the reply of the
 * command. This is useful in order to support non blocking operations, so
 * that we write, return into the event loop, and read when there are data.
 *
 * When read_reply is 0 the function returns PSYNC_WRITE_ERR if there
 * was a write error, or PSYNC_WAIT_REPLY to signal we need another call
 * with read_reply set to 1. However even when read_reply is set to 1
 * the function may return PSYNC_WAIT_REPLY again to signal there were
 * insufficient data to read to complete its work. We should re-enter
 * into the event loop and wait in such a case.
 *
 * The function returns:
 *
 * PSYNC_CONTINUE: If the PSYNC command succeded and we can continue.
 * PSYNC_FULLRESYNC: If PSYNC is supported but a full resync is needed.
 *                   In this case the master run_id and global replication
 *                   offset is saved.
 * PSYNC_NOT_SUPPORTED: If the server does not understand PSYNC at all and
 *                      the caller should fall back to SYNC.
 * PSYNC_WRITE_ERR: There was an error writing the command to the socket.
 * PSYNC_WAIT_REPLY: Call again the function with read_reply set to 1.
 *
 * Notable side effects:
 *
 * 1) As a side effect of the function call the function removes the readable
 *    event handler from "fd", unless the return value is PSYNC_WAIT_REPLY.
 * 2) server.repl_master_initial_offset is set to the right value according
 *    to the master reply. This will be used to populate the 'server.master'
 *    structure replication offset.
 */
#define RMT_PSYNC_ERROR -1
#define RMT_PSYNC_WRITE_ERROR 0
#define RMT_PSYNC_WAIT_REPLY 1
#define RMT_PSYNC_CONTINUE 2
#define RMT_PSYNC_FULLRESYNC 3
#define RMT_PSYNC_NOT_SUPPORTED 4
static int rmtTryPartialResynchronization(redis_node *srnode, int read_reply) {
    int ret;
    tcp_context *tc = srnode->tc;
    redis_repl *rr = srnode->rr;
    thread_data *rdata = srnode->read_data;
    char *psync_runid;
    char psync_offset[32];
    sds reply;

    /* Writing half */
    if (!read_reply) {
        /* Initially set repl_master_initial_offset to -1 to mark the current
         * master run_id and offset as not valid. Later if we'll be able to do
         * a FULL resync using the PSYNC command we'll set the offset at the
         * right value, so that this information will be propagated to the
         * client structure representing the master into server.master. */
        rr->repl_master_initial_offset = -1;

        if (rr->reploff > 0) {
            psync_runid = rr->replrunid;
            rmt_snprintf(psync_offset,sizeof(psync_offset),"%lld", rr->reploff+1);
            log_notice("Trying a partial resynchronization with MASTER[%s] (request %s:%s).", 
                srnode->addr, psync_runid, psync_offset);
        } else {
            log_notice("Partial resynchronization for MASTER[%s] not possible (no cached master).", 
                srnode->addr);
            psync_runid = (char *)"?";
            rmt_memcpy(psync_offset,"-1",3);
        }

        /* Issue the PSYNC command */
        reply = sendReplSyncCommand(SYNC_CMD_WRITE,srnode,"PSYNC",psync_runid,psync_offset,NULL);
        if (reply != NULL) {
            log_error("ERROR: Unable to send PSYNC to master[%s]: %s", 
                srnode->addr, reply);
            sdsfree(reply);
            return RMT_PSYNC_WRITE_ERROR;
        }
        return RMT_PSYNC_WAIT_REPLY;
    }

    /* Reading half */
    reply = sendReplSyncCommand(SYNC_CMD_READ,srnode,NULL);
    if (sdslen(reply) == 0) {
        /* The master may send empty newlines after it receives PSYNC
         * and before to reply, just to keep the connection alive. */
        sdsfree(reply);
        return RMT_PSYNC_WAIT_REPLY;
    }

    aeDeleteFileEvent(rdata->loop,tc->sd,AE_READABLE);

    if (!rmt_strncmp(reply,"+FULLRESYNC",11)) {
        char *runid = NULL, *offset = NULL;

        /* Reset redis replication */
        ret = redisRplicationReset(srnode);
        if (ret != RMT_OK) {
            return RMT_PSYNC_ERROR;
        }

        /* FULL RESYNC, parse the reply in order to extract the run id
         * and the replication offset. */
        runid = rmt_strchr(reply, reply+sdslen(reply), ' ');
        if (runid) {
            runid++;
            offset = rmt_strchr(runid, reply+sdslen(reply),' ');
            if (offset) offset++;
        }
        if (!runid || !offset || (offset-runid-1) != REDIS_RUN_ID_SIZE) {
            log_warn("Warning: Master[%s] replied with wrong +FULLRESYNC syntax.", 
                srnode->addr);
            /* This is an unexpected condition, actually the +FULLRESYNC
             * reply means that the master supports PSYNC, but the reply
             * format seems wrong. To stay safe we blank the master
             * runid to make sure next PSYNCs will fail. */
            rmt_memset(rr->repl_master_runid,0,REDIS_RUN_ID_SIZE+1);
        } else {
            rmt_memcpy(rr->repl_master_runid, runid, offset-runid-1);
            rr->repl_master_runid[REDIS_RUN_ID_SIZE] = '\0';
            rr->repl_master_initial_offset = strtoll(offset,NULL,10);
            log_notice("Full resync from MASTER[%s]: %s:%lld",
                srnode->addr, 
                rr->repl_master_runid,
                rr->repl_master_initial_offset);
        }
        
        sdsfree(reply);
        return RMT_PSYNC_FULLRESYNC;
    }

    if (!rmt_strncmp(reply,"+CONTINUE",9)) {
        /* Partial resync was accepted, set the replication state accordingly */
        log_notice("Successful partial resynchronization with MASTER[%s].", 
            srnode->addr);
        sdsfree(reply);
        rmtRedisSlaveAgainOnline(srnode);
        return RMT_PSYNC_CONTINUE;
    }

    /* If we reach this point we received either an error since the master does
     * not understand PSYNC, or an unexpected reply from the master.
     * Return PSYNC_NOT_SUPPORTED to the caller in both cases. */

    if (rmt_strncmp(reply,"-ERR",4)) {
        /* If it's not an error, log the unexpected event. */
        log_warn("Warning: Unexpected reply to PSYNC from MASTER[%s]: %s", 
            srnode->addr, reply);
    } else {
        log_notice("Master[%s] does not support PSYNC or is in "
            "error state (reply: %s)", srnode->addr, reply);
    }
    sdsfree(reply);
    
    /* Reset redis replication */
    ret = redisRplicationReset(srnode);
    if (ret != RMT_OK) {
        return RMT_PSYNC_ERROR;
    }
    
    return RMT_PSYNC_NOT_SUPPORTED;
}

/* Insert master replication data into list.
 * data_type: rdb data from master or commands from master.
 * partial: when >0, mbuf is not full, also insert into the list. 
 */
static int rmtRedisReplDataInsert(redis_node *srnode, 
    char *buf, ssize_t len, int data_type, int partial)
{
    mbuf_base *mb;
    struct mbuf *m1;
    uint32_t m1_s;
    uint32_t len_copy, len_left;
    mttlist *mbufs;
    redis_group *srgroup = srnode->owner;
    redis_rdb *rdb = srnode->rdb;
    
    if(srnode == NULL)
    {
        return RMT_ERROR;
    }

    if(data_type == RMT_REDIS_REPL_DATA_TYPE_RDB)
    {
        mbufs = rdb->data;
    }
    else if(data_type == RMT_REDIS_REPL_DATA_TYPE_CMD)
    {
        mbufs = srnode->cmd_data;
    }
    else
    {
        return RMT_ERROR;
    }

    mb = srgroup->mb;
    if(mb == NULL)
    {
        return RMT_ERROR;
    }

    m1 = srnode->mbuf_in;
    if(m1 == NULL)
    {
        if(len == 0)
        {
            return RMT_OK;
        }
    
        srnode->mbuf_in = mbuf_get(mb);
        m1 = srnode->mbuf_in;

        if(m1 != NULL)
        {
            ASSERT(mbuf_size(m1) > 0);
        }
    }

    if(m1 == NULL)
    {
        log_error("ERROR: get mbuf failed");
        return RMT_ERROR;
    }

    m1_s = mbuf_size(m1);
    if(m1_s == 0)
    {
        //mbufs->lock_push(mbufs->l, m1);
        mttlist_push(mbufs, m1);
        notice_write_thread(srnode);
        log_debug(LOG_VVERB, "mbuf(used:%d) inputed", mbuf_storage_length(m1));
        srnode->mbuf_in = NULL;
        return rmtRedisReplDataInsert(srnode, buf, len, data_type, partial);
    }

    len_copy = (m1_s < (uint32_t)len)?m1_s:(uint32_t)len;
    len_left = (uint32_t)len - len_copy;
    mbuf_copy(m1, (uint8_t*) buf, len_copy);

    if(len_left > 0)
    {
        buf += len_copy;
        return rmtRedisReplDataInsert(srnode, buf, len_left, data_type, partial);
    }

    if(partial && mbuf_storage_length(srnode->mbuf_in))
    {
        //mbufs->lock_push(mbufs->l, m1);
        mttlist_push(mbufs, m1);
        notice_write_thread(srnode);
        log_debug(LOG_VVERB, "mbuf(used:%d) inputed", mbuf_storage_length(m1));
        srnode->mbuf_in = NULL;
    }

    return RMT_OK;
}

static void rmtRedisSlaveReadQueryFromMaster(aeEventLoop *el, int fd, void *privdata, int mask) 
{
    int ret;
    ssize_t nread;
    redis_node *srnode = privdata;
    redis_group *srgroup = srnode->owner;
    thread_data *rdata = srnode->read_data;
    redis_repl *rr = srnode->rr;
    tcp_context *tc = srnode->tc;
    
    RMT_NOTUSED(el);
    RMT_NOTUSED(fd);
    RMT_NOTUSED(privdata);
    RMT_NOTUSED(mask);
    
    ASSERT(el == rdata->loop);
    ASSERT(fd == tc->sd);

    if(srnode->mbuf_in == NULL){
        srnode->mbuf_in = mbuf_get(srgroup->mb);
        if(srnode->mbuf_in == NULL){
            log_error("ERROR: Mbuf get failed: Out of memory");
            return;
        }
    }else if(mbuf_size(srnode->mbuf_in) == 0){
        mttlist_push(srnode->cmd_data, srnode->mbuf_in);
        srnode->mbuf_in = NULL;
        notice_write_thread(srnode);

        srnode->mbuf_in = mbuf_get(srgroup->mb);
        if(srnode->mbuf_in == NULL){
            log_error("ERROR: Mbuf get failed: Out of memory");
            return;
        }
    }
    
    nread = rmt_read(fd,srnode->mbuf_in->last,
        mbuf_size(srnode->mbuf_in));
    if (nread < 0) {
        if (errno == EAGAIN) {
            log_warn("Warn: I/O error read query from MASTER[%s]: %s", 
                srnode->addr, strerror(errno));
            nread = 0;
        } else {
            log_error("ERROR: I/O error read query from MASTER[%s]: %s", 
                srnode->addr, strerror(errno));
            goto error;
        }
    } else if(nread == 0) {
        log_error("ERROR: I/O error read query from MASTER[%s]: lost connection", 
            srnode->addr);
        goto error;
    } else {
        rdata->stat_total_net_input_bytes += (uint64_t)nread;
        rr->reploff += nread;
        srnode->mbuf_in->last += nread;
        mttlist_push(srnode->cmd_data, srnode->mbuf_in);
        srnode->mbuf_in = NULL;
        notice_write_thread(srnode);
        rr->repl_lastio = rdata->unixtime;
    }

    return;
    
error:
    
    rmtRedisSlaveOffline(srnode);
}

static void rmtRedisRdbDataPost(redis_node *srnode)
{
    redis_rdb *rdb = srnode->rdb;
    struct mbuf *mbuf;
    uint32_t len, write_len;
    
    if (rdb == NULL) {
        return;
    }

    mbuf = rdb->mbuf;
    ASSERT(mbuf != NULL);

    if (rdb->type == REDIS_RDB_TYPE_FILE) {
        len = mbuf_length(mbuf);
        ASSERT(len > 0);

        ASSERT(rdb->fname != NULL);
        ASSERT(rdb->fd > 0);

        write_len = (uint32_t)rmt_write(rdb->fd,mbuf->pos,len);
        if (write_len != len) {
            ASSERT(write_len < len);
            mbuf->pos += write_len;
            log_warn("write error or short write writing to the DB dump file: %s", 
                strerror(errno));
            return;
        }

        mbuf->pos = mbuf->last = mbuf->start;
    } else if(rdb->type == REDIS_RDB_TYPE_MEM) {
        ASSERT(rdb->mb != NULL);
        ASSERT(rdb->data != NULL);
        
        mttlist_push(rdb->data, mbuf);
        rdb->mbuf = NULL;
        notice_write_thread(srnode);
    } else {
        NOT_REACHED();
    }
    
}

static int rmtRedisSlavePrepareOnline(redis_node *srnode)
{
    thread_data *rdata = srnode->read_data;
    tcp_context *tc = srnode->tc;
    redis_repl *rr = srnode->rr;

    rr->repl_state = REDIS_REPL_CONNECTED;
    rr->reploff = rr->repl_master_initial_offset;
    rmt_memcpy(rr->replrunid, rr->repl_master_runid,
            sizeof(rr->repl_master_runid));
    
    /* If master offset is set to -1, this master is old and is not
     * PSYNC capable, so we flag it accordingly. */
    if (rr->reploff == -1) {
        rr->flags |= REDIS_PRE_PSYNC;
    }
    
    log_debug(LOG_NOTICE, "MASTER <-> SLAVE sync: Finished with success");
    
    rmt_set_nonblocking(tc->sd);
    rmt_set_tcpnodelay(tc->sd);

    if (aeCreateFileEvent(rdata->loop,tc->sd,AE_READABLE,
        rmtRedisSlaveReadQueryFromMaster, srnode) == AE_ERR) {
        log_error("ERROR: can't create the rmtRedisSlaveReadQueryFromMaster file event.");
        return RMT_ERROR;
    }

    return RMT_OK;
}

void rmtRedisSlaveOffline(redis_node *srnode)
{
    tcp_context *tc = srnode->tc;
    thread_data *rdata = srnode->read_data;
    redis_repl *rr = srnode->rr;
    
    aeDeleteFileEvent(rdata->loop,tc->sd,AE_READABLE|AE_WRITABLE);
    rmt_tcp_context_close_sd(tc);
    rr->repl_state = REDIS_REPL_CONNECT;
}

static int rmtRedisSlaveAgainOnline(redis_node *srnode)
{
    thread_data *rdata = srnode->read_data;
    tcp_context *tc = srnode->tc;
    redis_repl *rr = srnode->rr;

    rr->repl_state = REDIS_REPL_CONNECTED;
    
    log_notice("Again online for node[%s] replication.", 
        srnode->addr);
    
    rmt_set_nonblocking(tc->sd);
    rmt_set_tcpnodelay(tc->sd);

    if (aeCreateFileEvent(rdata->loop,tc->sd,AE_READABLE,
        rmtRedisSlaveReadQueryFromMaster, srnode) == AE_ERR) {
        log_error("ERROR: can't create the node[%s] rmtRedisSlaveReadQueryFromMaster file event.", 
            srnode->addr);
        rmtRedisSlaveOffline(srnode);
        return RMT_ERROR;
    }

    return RMT_OK;
}

void rmtReceiveRdbAbort(redis_node *srnode)
{
    thread_data *rdata = srnode->read_data;
    tcp_context *tc = srnode->tc;
    redis_rdb *rdb = srnode->rdb;
    redis_repl *rr = srnode->rr;

    if (rdb->mbuf != NULL) {
        if (rdb->mb != NULL) {
            mbuf_put(rdb->mbuf);
        }

        rdb->mbuf = NULL;
    }
    
    aeDeleteFileEvent(rdata->loop, tc->sd, AE_READABLE);
    rmt_tcp_context_close_sd(tc);
    redis_delete_rdb_file(rdb, 1);
    redisRplicationReset(srnode);
    rr->repl_state = REDIS_REPL_CONNECT;
}

static void rmtReceiveRdb(aeEventLoop *el, int fd, void *privdata, int mask) 
{
    int ret;
    char buf[4096];
    ssize_t nread, readlen;
    off_t left;
    redis_node *srnode = privdata;
    thread_data *rdata = srnode->read_data;
    redis_repl *rr = srnode->rr;
    redis_rdb *rdb = srnode->rdb;
    char *eofmark = rr->eofmark;
    char *lastbytes = rr->lastbytes;
    int usemark = rr->usemark;
    struct mbuf *mbuf;
    uint32_t mbuf_s;
    
    RMT_NOTUSED(el);
    RMT_NOTUSED(fd);
    RMT_NOTUSED(privdata);
    RMT_NOTUSED(mask);
    
    ASSERT(el == rdata->loop);
    ASSERT(fd == srnode->tc->sd);

    /* If repl_transfer_size == -1 we still have to read the bulk length
     * from the master reply. */
    if (rr->repl_transfer_size == -1) {
        if (rmt_sync_readline(fd,buf,1024,1000) == -1) {
            log_error("Error: I/O error reading bulk count from MASTER[%s]: %s",
                srnode->addr, strerror(errno));
            goto error;
        }

        if (buf[0] == '-') {
            log_error("Error: MASTER[%s] aborted replication with an error: %s",
                srnode->addr, buf+1);
            goto error;
        } else if (buf[0] == '\0') {
            /* At this stage just a newline works as a PING in order to take
             * the connection live. So we refresh our last interaction
             * timestamp. */
            rr->repl_lastio = rdata->unixtime;
            return;
        } else if (buf[0] != '$') {
            log_error("Error: Bad protocol from MASTER, the first byte is not '$' (we received '%s'), are you sure the adrress %s are right?", 
                buf, srnode->addr);
            goto error;
        }

        /* There are two possible forms for the bulk payload. One is the
         * usual $<count> bulk format. The other is used for diskless transfers
         * when the master does not know beforehand the size of the file to
         * transfer. In the latter case, the following format is used:
         *
         * $EOF:<40 bytes delimiter>
         *
         * At the end of the file the announced delimiter is transmitted. The
         * delimiter is long and random enough that the probability of a
         * collision with the actual file content can be ignored. */
        if (rmt_strncmp(buf+1,"EOF:",4) == 0 && rmt_strlen(buf+5) >= REDIS_RUN_ID_SIZE) {
            usemark = 1;
            rmt_memcpy(eofmark,buf+5,REDIS_RUN_ID_SIZE);
            rmt_memset(lastbytes,0,REDIS_RUN_ID_SIZE);
            /* Set any repl_transfer_size to avoid entering this code path
             * at the next call. */
            rr->repl_transfer_size = 0;
            log_notice("MASTER <-> SLAVE sync: receiving streamed RDB from master[%s]", 
                srnode->addr);
        } else {
            usemark = 0;
            rr->repl_transfer_size = strtol(buf+1,NULL,10);
            log_notice("MASTER <-> SLAVE sync: receiving %lld bytes from master[%s]",
                (long long) rr->repl_transfer_size, srnode->addr);
        }
        return;
    }

    mbuf = rdb->mbuf;
    if (mbuf == NULL) {
        rdb->mbuf = mbuf_get(rdb->mb);
        mbuf = rdb->mbuf;
        if (mbuf == NULL) {
            log_error("ERROR: mbuf_get NULL: out of memory");
            return;
        }
    } else if(mbuf_size(mbuf) == 0) {
        rmtRedisRdbDataPost(srnode);
    }

    mbuf_s = mbuf_size(mbuf);
    ASSERT(mbuf_s > 0);

     /* Read bulk data */
    if (usemark) {
        readlen = mbuf_s;
    } else {
        left = rr->repl_transfer_size - rr->repl_transfer_read;
        readlen = (left < (signed)mbuf_s) ? left : (signed)mbuf_s;
    }
    
    nread = rmt_read(fd,mbuf->last,readlen);
    if (nread <= 0) {
        log_error("Error: I/O error trying to sync with MASTER[%s]: %s",
            srnode->addr, (nread == -1) ? strerror(errno) : "connection lost");
        rmtReceiveRdbAbort(srnode);
        return;
    }

    ASSERT((ssize_t)mbuf_size >= nread);

    rdata->stat_total_net_input_bytes += (uint64_t)nread;
    mbuf->last += nread;
    if (mbuf_size(mbuf) == 0) {
        rmtRedisRdbDataPost(srnode);
    }

    /* When a mark is used, we want to detect EOF asap in order to avoid
     * writing the EOF mark into the file... */
    int eof_reached = 0;

    if (usemark) {
        /* Update the last bytes array, and check if it matches our delimiter.*/
        if (nread >= REDIS_RUN_ID_SIZE) {
            rmt_memcpy(lastbytes,buf+nread-REDIS_RUN_ID_SIZE,REDIS_RUN_ID_SIZE);
        } else {
            int rem = REDIS_RUN_ID_SIZE-(int)nread;
            rmt_memmove(lastbytes,lastbytes+nread,rem);
            rmt_memcpy(lastbytes+rem,buf,nread);
        }
        if (memcmp(lastbytes,eofmark,REDIS_RUN_ID_SIZE) == 0) eof_reached = 1;
    }

    rr->repl_lastio = rdata->unixtime;
    
    rr->repl_transfer_read += nread;

    /* Delete the last 40 bytes from the file if we reached EOF. */
    if (usemark && eof_reached) {
        if (rdb->type == REDIS_RDB_TYPE_FILE) {
            if (ftruncate(rdb->fd,
                rr->repl_transfer_read - REDIS_RUN_ID_SIZE) == -1) {
                log_error("Error: truncating the RDB file %s failed: %s", 
                    rdb->fname, strerror(errno));
                goto error;
            }
        } else if(rdb->type == REDIS_RDB_TYPE_MEM) {
            rr->flags |= REDIS_RDB_USED_USEMARK;
        } else {
            NOT_REACHED();
        }
    }

    if (rdb->type == REDIS_RDB_TYPE_FILE) {
        /* Sync data on disk from time to time, otherwise at the end of the transfer
         * we may suffer a big delay as the memory buffers are copied into the
         * actual disk. */
        if (rr->repl_transfer_read >=
            rr->repl_transfer_last_fsync_off + RMT_MAX_WRITTEN_BEFORE_FSYNC){
            off_t sync_size = rr->repl_transfer_read -
                              rr->repl_transfer_last_fsync_off;
            rmt_fsync_range(rdb->fd,
                rr->repl_transfer_last_fsync_off, sync_size);
            rr->repl_transfer_last_fsync_off += sync_size;
        }
    }
    
    /* Check if the transfer is now complete */
    if (!usemark) {
        if (rr->repl_transfer_read == rr->repl_transfer_size)
            eof_reached = 1;
    }

    if (eof_reached) {
        long long now;
        now = rmt_msec_now();
        
        aeDeleteFileEvent(rdata->loop, fd, AE_READABLE);
        log_notice("MASTER <-> SLAVE sync: RDB data for node[%s] is received, used: %lld s", 
            srnode->addr, (now - srnode->timestamp)/1000);

        rdb->received = 1;

        /* complete the rdb data */
        mbuf = rdb->mbuf;
        if (mbuf != NULL && mbuf_length(mbuf) > 0) {
            rmtRedisRdbDataPost(srnode);
        }
        if (rdb->mbuf != NULL) {
            if(rdb->mb != NULL) {
                mbuf_put(rdb->mbuf);
            }

            rdb->mbuf = NULL;
        }
        if (rdb->type == REDIS_RDB_TYPE_FILE) {
            close(rdb->fd);
            rdb->fd = -1;
            log_notice("rdb file %s write complete", 
                rdb->fname);
            notice_write_thread(srnode);
        }
        rdata->stat_rdb_received_count ++;
        
        if (srnode->ctx->target_type == GROUP_TYPE_RDBFILE) {
            rmtRedisSlaveOffline(srnode);
            rr->repl_state = REDIS_REPL_NONE;   /* Never reconnect to the master */
            log_notice("Rdb file received, disconnect from the node[%s]", 
                srnode->addr);
            notice_write_thread(srnode);    /* Let the next node begin replication */
            return;
        }

        srnode->timestamp = now;
        ret = rmtRedisSlavePrepareOnline(srnode);
        if (ret != RMT_OK) {
            goto error;
        }
    }

    return;

error:

    rmtReceiveRdbAbort(srnode);
    return;
}

static void rmtSyncRedisMaster(aeEventLoop *el, int fd, void *privdata, int mask)
{
	int ret;
    redis_node *srnode = privdata;
    thread_data *rdata = srnode->read_data;
    tcp_context *tc = srnode->tc;
    redis_repl *rr = srnode->rr;
    redis_rdb *rdb = srnode->rdb;
    redis_group *srgroup = srnode->owner;
    rmtContext *ctx = srgroup->ctx;
    int sockerr = 0;
    int psync_result;
    char *err = NULL;

    RMT_NOTUSED(el);
    RMT_NOTUSED(fd);
    RMT_NOTUSED(privdata);
    RMT_NOTUSED(mask);
    
    ASSERT(el == rdata->loop);
    ASSERT(fd == tc->sd);
    ASSERT(srgroup->source == 1);

    if (rmt_tcp_context_check_socket_error(tc) != RMT_OK) {
        sockerr = errno;
    }

    if (sockerr) {
        log_error("ERROR: error condition on MASTER[%s] socket %d for SYNC: %s",
            srnode->addr, tc->sd, strerror(sockerr));
        goto error;
    }

    if (rr->repl_state == REDIS_REPL_CONNECTING) {
        log_notice("Start connecting to MASTER[%s].", srnode->addr);
        aeDeleteFileEvent(rdata->loop,fd,AE_WRITABLE);        
        rr->repl_state = REDIS_REPL_RECEIVE_PONG;

        /* Send the PING, don't check for errors at all, we have the timeout
         * that will take care about this. */
        err = sendReplSyncCommand(SYNC_CMD_WRITE,srnode,"PING",NULL);
        if (err) goto write_error;
        return;
    }

    if (rr->repl_state == REDIS_REPL_RECEIVE_PONG) {
        err = sendReplSyncCommand(SYNC_CMD_READ,srnode,NULL);

        /* We accept only two replies as valid, a positive +PONG reply
             * (we just check for "+") or an authentication error.
             * Note that older versions of Redis replied with "operation not
             * permitted" instead of using a proper error code, so we test
             * both. */
        if (err[0] != '+' &&
            strncmp(err,"-NOAUTH",7) != 0 &&
            strncmp(err,"-ERR operation not permitted",28) != 0) {
            log_error("ERROR: error reply to PING from MASTER[%s]: '%s'", 
                srnode->addr, err);
            sdsfree(err);
            goto error;
        } else {
            if (!strncmp(err,"-NOAUTH",7) && srgroup->password == NULL) {
                log_error("ERROR: source group redis password is required: '%s'", err);
                sdsfree(err);
                goto error;
            }
            
            log_notice("Master[%s] replied to PING, replication can continue...", 
                srnode->addr);
        }
        sdsfree(err);
        rr->repl_state = REDIS_REPL_SEND_AUTH;
    }

    /* AUTH with the master if required. */
    if (rr->repl_state == REDIS_REPL_SEND_AUTH) {
        if (srgroup->password) {
            err = sendReplSyncCommand(SYNC_CMD_WRITE,srnode,"AUTH",srgroup->password,NULL);
            if (err) goto write_error;
            rr->repl_state = REDIS_REPL_RECEIVE_AUTH;
            return;
        } else {
            rr->repl_state = REDIS_REPL_SEND_PORT;
        }
    }

    /* Receive AUTH reply. */
    if (rr->repl_state == REDIS_REPL_RECEIVE_AUTH) {
        err = sendReplSyncCommand(SYNC_CMD_READ,srnode,NULL);
        if (err[0] == '-') {
            log_error("ERROR: Unable to AUTH to MASTER[%s]: %s", 
                srnode->addr, err);
            sdsfree(err);
            goto error;
        }
        sdsfree(err);
        rr->repl_state = REDIS_REPL_SEND_PORT;
    }

    /* Set the slave port, so that Master's INFO command can list the
     * slave listening port correctly. */
    if (rr->repl_state == REDIS_REPL_SEND_PORT) {
        int port = 0;
        sds port_str = NULL;

        ret = rmt_get_socket_local_ip_port(fd, NULL, &port);
	    if (ret < 0 || !rmt_valid_port(port)) {
	        log_warn("Warning: Get sd %d addr failed, used 12345 instead.", fd);
			port_str = sdsfromlonglong(12345);
	    } else {
            port_str = sdsfromlonglong(port);
        }

        err = sendReplSyncCommand(SYNC_CMD_WRITE,srnode,"REPLCONF",
                "listening-port",port_str, NULL);
        sdsfree(port_str);
        if (err) goto write_error;
        sdsfree(err);
        rr->repl_state = REDIS_REPL_RECEIVE_PORT;
        return;
    }

    /* Receive REPLCONF listening-port reply. */
    if (rr->repl_state == REDIS_REPL_RECEIVE_PORT) {
        err = sendReplSyncCommand(SYNC_CMD_READ,srnode,NULL);        
        /* Ignore the error if any, not all the Redis versions support
         * REPLCONF listening-port. */
        if (err[0] == '-') {
            log_info("(Non critical) Master[%s] does not understand "
                "REPLCONF listening-port: %s", srnode->addr, err);
        }
        sdsfree(err);
        rr->repl_state = REDIS_REPL_SEND_CAPA;
    }

    /* Inform the master of our capabilities. While we currently send
     * just one capability, it is possible to chain new capabilities here
     * in the form of REPLCONF capa X capa Y capa Z ...
     * The master will ignore capabilities it does not understand. */
    if (rr->repl_state == REDIS_REPL_SEND_CAPA) {
        err = sendReplSyncCommand(SYNC_CMD_WRITE,srnode,"REPLCONF",
                "capa","eof",NULL);
        if (err) goto write_error;
        sdsfree(err);
        rr->repl_state = REDIS_REPL_RECEIVE_CAPA;
        return;
    }

    /* Receive CAPA reply. */
    if (rr->repl_state == REDIS_REPL_RECEIVE_CAPA) {
        err = sendReplSyncCommand(SYNC_CMD_READ,srnode,NULL);
        /* Ignore the error if any, not all the Redis versions support
         * REPLCONF capa. */
        if (err[0] == '-') {
            log_info("(Non critical) Master[%s] does not understand "
                "REPLCONF capa: %s", srnode->addr, err);
        }
        sdsfree(err);
        rr->repl_state = REDIS_REPL_SEND_PSYNC;
    }

    /* Try a partial resynchonization. If we don't have a cached master
     * slaveTryPartialResynchronization() will at least try to use PSYNC
     * to start a full resynchronization so that we get the master run id
     * and the global offset, to try a partial resync at the next
     * reconnection attempt. */
    if (rr->repl_state == REDIS_REPL_SEND_PSYNC) {
        if (rmtTryPartialResynchronization(srnode,0) == RMT_PSYNC_WRITE_ERROR) {
            err = sdsnew("Write error sending the PSYNC command.");
            goto write_error;
        }
        rr->repl_state = REDIS_REPL_RECEIVE_PSYNC;
        return;
    }

    /* If reached this point, we should be in REDIS_REPL_RECEIVE_PSYNC. */
    if (rr->repl_state != REDIS_REPL_RECEIVE_PSYNC) {
        log_error("Error: state machine error, "
            "state should be RECEIVE_PSYNC but is %d",
            rr->repl_state);
        goto error;
    }

    psync_result = rmtTryPartialResynchronization(srnode,1);
    if (psync_result == RMT_PSYNC_WAIT_REPLY) return; /* Try again later... */

    if (psync_result == RMT_PSYNC_CONTINUE) {
        log_notice("MASTER <-> SLAVE sync: Master[%s] accepted a Partial Resynchronization.", 
            srnode->addr);
        return;
    }

    /* Fall back to SYNC if needed. Otherwise psync_result == PSYNC_FULLRESYNC
     * and the server.repl_master_runid and repl_master_initial_offset are
     * already populated. */
    if (psync_result == RMT_PSYNC_NOT_SUPPORTED) {
        log_notice("Retrying with SYNC to MASTER[%s]...", srnode->addr);
        if (rmt_sync_write(fd,"SYNC\r\n",6,1000) == -1) {
            log_error("ERROR: I/O error writing to MASTER[%s]: %s",
                srnode->addr, strerror(errno));
            goto error;
        }
    }

    /* Setup the non blocking download of the bulk file. */
    if (aeCreateFileEvent(rdata->loop,fd,AE_READABLE,rmtReceiveRdb,srnode)
            == AE_ERR) {
        log_error("ERROR: Can't create readable event for node[%s] SYNC: %s (fd=%d)",
            srnode->addr, strerror(errno), fd);
        goto error;
    }

    rr->repl_state = REDIS_REPL_TRANSFER;
    rr->repl_transfer_size = -1;
    rr->repl_transfer_read = 0;
    rr->repl_transfer_last_fsync_off = 0;
    rr->repl_lastio = rdata->unixtime;

    //Prepare rdb file for recieve rdb data
    if(rdb->type == REDIS_RDB_TYPE_FILE && rdb->fd < 0){
        if (rdb->fname == NULL) {
            rdb->fname = sdsempty();
            if (rdb->fname == NULL) {
                log_error("Error: out of memory.");
                goto error;
            }
        } else {
            sdsrange(rdb->fname, 0, 0);
        }
        
        if (ctx->dir != NULL) {
            rdb->fname = sdscatsds(rdb->fname, ctx->dir);
            rdb->fname = sdscat(rdb->fname, "/");
        }
        rdb->fname = sdscatfmt(rdb->fname, 
            "node%s-%I-%i.rdb",
            srnode->addr==NULL?"unknow":srnode->addr,
            rmt_usec_now(),
            (long int)getpid());
        log_debug(LOG_DEBUG, "rdb->fname: %s", rdb->fname);
        
        rdb->fd = open(rdb->fname,O_CREAT|O_WRONLY|O_EXCL,0644);
        if(rdb->fd == -1){
            log_error("ERROR: open rdb file %s failed: %s", 
                rdb->fname, strerror(errno));
            goto error;
        }
    }

    srnode->timestamp = rmt_msec_now();
    
    return;
    
error:

    rmtRedisSlaveOffline(srnode);
    return;

write_error:

    log_error("Error: Sending command to master[%s] in replication handshake failed: %s", 
        srnode->addr, err);
    sdsfree(err);
    goto error;
}

int rmtConnectRedisMaster(redis_node *srnode) 
{
    int ret;
    int port;
    sds *ip_port = NULL;
    int ip_port_count = 0;
    thread_data *rdata = srnode->read_data;
    redis_repl *rr = srnode->rr;
    tcp_context *tc = srnode->tc;

    ip_port = sdssplitlen(srnode->addr, (int)strlen(srnode->addr),
        IP_PORT_SEPARATOR, rmt_strlen(IP_PORT_SEPARATOR), &ip_port_count);
    if (ip_port == NULL || ip_port_count != 2) {
        log_error("ERROR: ip port parsed error");
        goto error;
    }

    port = rmt_atoi(ip_port[1], sdslen(ip_port[1]));
    if (rmt_valid_port(port) == 0) {
        log_error("ERROR: port is invalid");
        goto error;
    }
    
    tc->flags &= ~RMT_BLOCK;
    ret = rmt_tcp_context_connect(tc, ip_port[0], port, NULL, NULL);
    if (ret != RMT_OK) {
        log_error("ERROR: can't context to redis master");
        goto error;
    }

    sdsfreesplitres(ip_port, ip_port_count);
    ip_port = NULL;
    ip_port_count = 0;
    
    if (aeCreateFileEvent(rdata->loop, tc->sd, 
        AE_READABLE|AE_WRITABLE,rmtSyncRedisMaster,srnode) == AE_ERR) {
        log_error("ERROR: can't create readable event for %s rmtSyncRedisMaster.", 
                srnode->addr);
        goto error;
    }

    rr->repl_state = REDIS_REPL_CONNECTING;
    rr->repl_lastio = rdata->unixtime;
    
    return RMT_OK;

error:

    if (ip_port != NULL) {
        sdsfreesplitres(ip_port, ip_port_count);
    }
    
    return RMT_ERROR;
}

void redisSlaveReplCorn(redis_node *srnode)
{
    int ret;
    thread_data *rdata = srnode->read_data;
    tcp_context *tc = srnode->tc;
    redis_repl *rr = srnode->rr;
    redis_group *srgroup = srnode->owner;

    log_debug(LOG_VERB, "redisSlaveReplCorn()");

    /* Non blocking connection timeout? */
    if ((rr->repl_state == REDIS_REPL_CONNECTING ||
        rmtSlaveIsInHandshakeState(srnode)) && 
        (rmt_msec_now() - rr->repl_lastio) > srgroup->timeout) {
        log_error("ERROR: Timeout connecting to the MASTER[%s]", srnode->addr);
        rmtRedisSlaveOffline(srnode);
    }

    /* Bulk transfer I/O timeout? */
    if (rr->repl_state == REDIS_REPL_TRANSFER &&
        (rmt_msec_now() - rr->repl_lastio) > srgroup->timeout) {
        log_error("ERROR: Timeout receiving bulk data from MASTER[%s]."
            "If the problem persists try to set the 'timeout' parameter(now is %d)"
            "of source group in rmt.conf to a larger value.", 
            srnode->addr, srgroup->timeout);
        rmtReceiveRdbAbort(srnode);
    }

    /* Timed out master when we are an already connected slave? */
    if (rr->repl_state == REDIS_REPL_CONNECTED &&
        (rmt_msec_now() - rr->repl_lastio) > srgroup->timeout) {
        log_error("ERROR: MASTER[%s] timeout, no data nor PING received.", 
            srnode->addr);
        rmtRedisSlaveOffline(srnode);
        /* !!here we need to note the error in info command */
    }

    /* Check if we should connect to a MASTER */
    if (rr->repl_state == REDIS_REPL_CONNECT) {
        ASSERT(tc->sd < 0);
        ASSERT((tc->flags & RMT_CONNECTED) == 0);

        /* target type is rdb file, and rdb file already received, avoid reconnect the master  */
        log_notice("srnode->ctx->target_type: %d, srnode->rdb->received: %d", 
        srnode->ctx->target_type, srnode->rdb->received);
        if (srnode->ctx->target_type == GROUP_TYPE_RDBFILE && 
            srnode->rdb->received == 1) {
            return;
        }

        log_notice("Reconnect to node[%s] for replication", 
            srnode->addr);
        
        ret = rmt_tcp_context_reconnect(tc);
        if (ret != RMT_OK) {
            log_error("ERROR: reconnect to %s failed", srnode->addr);
            return;
        }
        
        if (aeCreateFileEvent(rdata->loop, tc->sd, 
            AE_READABLE|AE_WRITABLE,rmtSyncRedisMaster,srnode) == AE_ERR) {
            log_error("ERROR: can't create readable event for %s rmtSyncRedisMaster.", 
                srnode->addr);
            return;
        }

        rr->repl_state = REDIS_REPL_CONNECTING;
        rr->repl_lastio = rdata->unixtime;
    }

    /* Send ACK to master from time to time. */
    if (rr->repl_state == REDIS_REPL_CONNECTED && 
        !(rr->flags & REDIS_PRE_PSYNC)) {
        char buf[64];
        int len;
        len = rmt_lltoa(buf, 64, rr->reploff);
        log_debug(LOG_VERB, "len: %d buf: %s", len, buf);

        ret = rmt_redis_send_cmd(tc->sd, "replconf", "ack", buf, NULL);
        if(ret != RMT_OK){
            log_error("ERROR: Send replconf ack to node[%s] failed", srnode->addr);
        }
    }
}


/* ========================== Redis Protocol ============================ */

/*
 * Return 1, if the redis command take no key, otherwise
 * return 0
 */
static int
redis_argz(struct msg *r)
{
    switch (r->type) {
    case MSG_REQ_REDIS_PING:
    case MSG_REQ_REDIS_QUIT:
    case MSG_REQ_REDIS_FLUSHALL:
    case MSG_REQ_REDIS_FLUSHDB:

    case MSG_REQ_REDIS_MULTI:
    case MSG_REQ_REDIS_EXEC:
        return 1;

    default:
        break;
    }

    return 0;
}

/*
 * Return true, if the redis command accepts no arguments, otherwise
 * return false
 */
static int
redis_arg0(struct msg *r)
{
    switch (r->type) {
    case MSG_REQ_REDIS_EXISTS:
    case MSG_REQ_REDIS_PERSIST:
    case MSG_REQ_REDIS_PTTL:
    case MSG_REQ_REDIS_SORT:
    case MSG_REQ_REDIS_TTL:
    case MSG_REQ_REDIS_TYPE:
    case MSG_REQ_REDIS_DUMP:

    case MSG_REQ_REDIS_DECR:
    case MSG_REQ_REDIS_GET:
    case MSG_REQ_REDIS_INCR:
    case MSG_REQ_REDIS_STRLEN:

    case MSG_REQ_REDIS_HGETALL:
    case MSG_REQ_REDIS_HKEYS:
    case MSG_REQ_REDIS_HLEN:
    case MSG_REQ_REDIS_HVALS:

    case MSG_REQ_REDIS_LLEN:
    case MSG_REQ_REDIS_LPOP:
    case MSG_REQ_REDIS_RPOP:

    case MSG_REQ_REDIS_SCARD:
    case MSG_REQ_REDIS_SMEMBERS:
    case MSG_REQ_REDIS_SPOP:

    case MSG_REQ_REDIS_ZCARD:
    case MSG_REQ_REDIS_PFCOUNT:
    case MSG_REQ_REDIS_AUTH:
        return 1;

    default:
        break;
    }

    return 0;
}

/*
 * Return true, if the redis command accepts exactly 1 argument, otherwise
 * return false
 */
static int
redis_arg1(struct msg *r)
{
    switch (r->type) {
    case MSG_REQ_REDIS_EXPIRE:
    case MSG_REQ_REDIS_EXPIREAT:
    case MSG_REQ_REDIS_PEXPIRE:
    case MSG_REQ_REDIS_PEXPIREAT:

    case MSG_REQ_REDIS_APPEND:
    case MSG_REQ_REDIS_DECRBY:
    case MSG_REQ_REDIS_GETBIT:
    case MSG_REQ_REDIS_GETSET:
    case MSG_REQ_REDIS_INCRBY:
    case MSG_REQ_REDIS_INCRBYFLOAT:
    case MSG_REQ_REDIS_SETNX:

    case MSG_REQ_REDIS_HEXISTS:
    case MSG_REQ_REDIS_HGET:

    case MSG_REQ_REDIS_LINDEX:
    case MSG_REQ_REDIS_LPUSHX:
    case MSG_REQ_REDIS_RPUSHX:

    case MSG_REQ_REDIS_SISMEMBER:

    case MSG_REQ_REDIS_ZRANK:
    case MSG_REQ_REDIS_ZREVRANK:
    case MSG_REQ_REDIS_ZSCORE:

    case MSG_REQ_REDIS_PUBLISH:

    case MSG_REQ_REDIS_MOVE:
        return 1;

    default:
        break;
    }

    return 0;
}

/*
 * Return true, if the redis command accepts exactly 2 arguments, otherwise
 * return false
 */
static int
redis_arg2(struct msg *r)
{
    switch (r->type) {
    case MSG_REQ_REDIS_GETRANGE:
    case MSG_REQ_REDIS_PSETEX:
    case MSG_REQ_REDIS_SETBIT:
    case MSG_REQ_REDIS_SETEX:
    case MSG_REQ_REDIS_SETRANGE:

    case MSG_REQ_REDIS_HINCRBY:
    case MSG_REQ_REDIS_HINCRBYFLOAT:
    case MSG_REQ_REDIS_HSET:
    case MSG_REQ_REDIS_HSETNX:

    case MSG_REQ_REDIS_LRANGE:
    case MSG_REQ_REDIS_LREM:
    case MSG_REQ_REDIS_LSET:
    case MSG_REQ_REDIS_LTRIM:

    case MSG_REQ_REDIS_SMOVE:

    case MSG_REQ_REDIS_ZCOUNT:
    case MSG_REQ_REDIS_ZLEXCOUNT:
    case MSG_REQ_REDIS_ZINCRBY:
    case MSG_REQ_REDIS_ZREMRANGEBYLEX:
    case MSG_REQ_REDIS_ZREMRANGEBYRANK:
    case MSG_REQ_REDIS_ZREMRANGEBYSCORE:

    case MSG_REQ_REDIS_RESTORE:
    case MSG_REQ_REDIS_RESTOREASKING:

    case MSG_REQ_REDIS_BRPOPLPUSH:
        return 1;

    default:
        break;
    }

    return 0;
}

/*
 * Return true, if the redis command accepts exactly 3 arguments, otherwise
 * return false
 */
static int
redis_arg3(struct msg *r)
{
    switch (r->type) {
    case MSG_REQ_REDIS_LINSERT:
        return 1;

    default:
        break;
    }

    return 0;
}

/*
 * Return true, if the redis command accepts 0 or more arguments, otherwise
 * return false
 */
static int
redis_argn(struct msg *r)
{
    switch (r->type) {
    case MSG_REQ_REDIS_BITCOUNT:
    case MSG_REQ_REDIS_BITFIELD:

    case MSG_REQ_REDIS_SET:
    case MSG_REQ_REDIS_HDEL:
    case MSG_REQ_REDIS_HMGET:
    case MSG_REQ_REDIS_HMSET:
    case MSG_REQ_REDIS_HSCAN:

    case MSG_REQ_REDIS_LPUSH:
    case MSG_REQ_REDIS_RPUSH:

    case MSG_REQ_REDIS_SADD:
    case MSG_REQ_REDIS_SDIFF:
    case MSG_REQ_REDIS_SDIFFSTORE:
    case MSG_REQ_REDIS_SINTER:
    case MSG_REQ_REDIS_SINTERSTORE:
    case MSG_REQ_REDIS_SREM:
    case MSG_REQ_REDIS_SUNION:
    case MSG_REQ_REDIS_SUNIONSTORE:
    case MSG_REQ_REDIS_SRANDMEMBER:
    case MSG_REQ_REDIS_SSCAN:

    case MSG_REQ_REDIS_PFADD:
    case MSG_REQ_REDIS_PFMERGE:

    case MSG_REQ_REDIS_ZADD:
    case MSG_REQ_REDIS_ZINTERSTORE:
    case MSG_REQ_REDIS_ZRANGE:
    case MSG_REQ_REDIS_ZRANGEBYSCORE:
    case MSG_REQ_REDIS_ZREM:
    case MSG_REQ_REDIS_ZREVRANGE:
    case MSG_REQ_REDIS_ZRANGEBYLEX:
    case MSG_REQ_REDIS_ZREVRANGEBYSCORE:
    case MSG_REQ_REDIS_ZUNIONSTORE:
    case MSG_REQ_REDIS_ZSCAN:

    case MSG_REQ_REDIS_SELECT:
    case MSG_REQ_REDIS_GEOADD:
    case MSG_REQ_REDIS_GEORADIUS:
    case MSG_REQ_REDIS_GEORADIUSBYMEMBER:
    case MSG_REQ_REDIS_SCRIPT:
        return 1;

    default:
        break;
    }

    return 0;
}

/*
 * Return true, if the redis command is a vector command accepting one or
 * more keys, otherwise return false
 */
static int
redis_argx(struct msg *r)
{
    switch (r->type) {
    case MSG_REQ_REDIS_MGET:
    case MSG_REQ_REDIS_DEL:

    case MSG_REQ_REDIS_RENAME:
    case MSG_REQ_REDIS_RENAMENX:
    case MSG_REQ_REDIS_RPOPLPUSH:

    case MSG_REQ_REDIS_BITOP:
        return 1;

    default:
        break;
    }

    return 0;
}

/*
 * Return true, if the redis command is a vector command accepting one or
 * more key-value pairs, otherwise return false
 */
static int
redis_argkvx(struct msg *r)
{
    switch (r->type) {
    case MSG_REQ_REDIS_MSET:
    case MSG_REQ_REDIS_MSETNX:
        return 1;

    default:
        break;
    }

    return 0;
}

/*
 * Return true, if the redis command is either EVAL or EVALSHA. These commands
 * have a special format with exactly 2 arguments, followed by one or more keys,
 * followed by zero or more arguments (the documentation online seems to suggest
 * that at least one argument is required, but that shouldn't be the case).
 */
static int
redis_argeval(struct msg *r)
{
    switch (r->type) {
    case MSG_REQ_REDIS_EVAL:
    case MSG_REQ_REDIS_EVALSHA:
        return 1;

    default:
        break;
    }

    return 0;
}

/*
 * Return true, if the redis command accepts 0 or more keys,
 * otherwise return false
 */
static int
redis_argzormore(struct msg *r)
{
    switch (r->type) {
    case MSG_REQ_REDIS_INFO:
    case MSG_REQ_REDIS_SHUTDOWN:

    case MSG_REQ_REDIS_COMMAND:
        return 1;

    default:
        break;
    }

    return 0;
}

/*
 * Return true, if the redis command accepts one subcommand, then one key, 
 * and 0 or more arguments, otherwise return false
 */
static int
redis_subcmd_onekey_argzormore(struct msg *r)
{
    switch (r->type) {
    case MSG_REQ_REDIS_PFDEBUG:
        return 1;

    default:
        break;
    }

    return 0;
}


/*
 * Reference: http://redis.io/topics/protocol
 *
 * Redis >= 1.2 uses the unified protocol to send requests to the Redis
 * server. In the unified protocol all the arguments sent to the server
 * are binary safe and every request has the following general form:
 *
 *   *<number of arguments> CR LF
 *   $<number of bytes of argument 1> CR LF
 *   <argument data> CR LF
 *   ...
 *   $<number of bytes of argument N> CR LF
 *   <argument data> CR LF
 *
 * Before the unified request protocol, redis protocol for requests supported
 * the following commands
 * 1). Inline commands: simple commands where arguments are just space
 *     separated strings. No binary safeness is possible.
 * 2). Bulk commands: bulk commands are exactly like inline commands, but
 *     the last argument is handled in a special way in order to allow for
 *     a binary-safe last argument.
 *
 * Nutcracker only supports the Redis unified protocol for requests.
 */
void
redis_parse_req(struct msg *r)
{
    struct mbuf *b;
    uint8_t *p, *m;
    uint8_t ch;
    enum {
        SW_START,
        SW_NARG,
        SW_NARG_LF,
        SW_REQ_TYPE_LEN,
        SW_REQ_TYPE_LEN_LF,
        SW_REQ_TYPE,
        SW_REQ_TYPE_LF,
        SW_SUBCMD_LEN,
        SW_SUBCMD_LEN_LF,
        SW_SUBCMD,
        SW_SUBCMD_LF,
        SW_KEY_LEN,
        SW_KEY_LEN_LF,
        SW_KEY,
        SW_KEY_LF,  //10
        SW_ARG1_LEN,
        SW_ARG1_LEN_LF,
        SW_ARG1,
        SW_ARG1_LF,
        SW_ARG2_LEN,
        SW_ARG2_LEN_LF,
        SW_ARG2,
        SW_ARG2_LF,
        SW_ARG3_LEN,
        SW_ARG3_LEN_LF, //20
        SW_ARG3,
        SW_ARG3_LF,
        SW_ARGN_LEN,
        SW_ARGN_LEN_LF,
        SW_ARGN,
        SW_ARGN_LF, //26
        SW_SENTINEL
    } state;

    state = r->state;
    b = listLastValue(r->data);

    ASSERT(r->request);
    ASSERT(state < SW_SENTINEL);
    ASSERT(b != NULL);
    ASSERT(b->pos <= b->last);

    /* validate the parsing maker */
    ASSERT(r->pos != NULL);
    ASSERT(r->pos >= b->pos && r->pos <= b->last);

    for (p = r->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        case SW_START:
        case SW_NARG:
            if (r->token == NULL) {
                if (ch != '*') {
                    goto error;
                }
                r->token = p;
                /* req_start <- p */
                r->narg_start = p;
                r->rnarg = 0;
                state = SW_NARG;
            } else if (isdigit(ch)) {
                r->rnarg = r->rnarg * 10 + (uint32_t)(ch - '0');
            } else if (ch == CR) {
                if (r->rnarg == 0) {
                    goto error;
                }
                r->narg = r->rnarg;
                r->narg_end = p;
                r->token = NULL;
                state = SW_NARG_LF;
            } else {
                goto error;
            }

            break;

        case SW_NARG_LF:
            switch (ch) {
            case LF:
                state = SW_REQ_TYPE_LEN;
                break;

            default:
                goto error;
            }

            break;

        case SW_REQ_TYPE_LEN:
            if (r->token == NULL) {
                if (ch != '$') {
                    goto error;
                }
                r->token = p;
                r->rlen = 0;
            } else if (isdigit(ch)) {
                r->rlen = r->rlen * 10 + (uint32_t)(ch - '0');
            } else if (ch == CR) {
                if (r->rlen == 0 || r->rnarg == 0) {
                    goto error;
                }
                r->rnarg--;
                r->token = NULL;
                state = SW_REQ_TYPE_LEN_LF;
            } else {
                goto error;
            }

            break;

        case SW_REQ_TYPE_LEN_LF:
            switch (ch) {
            case LF:
                state = SW_REQ_TYPE;
                break;

            default:
                goto error;
            }

            break;

        case SW_REQ_TYPE:
            if (r->token == NULL) {
                r->token = p;
            }

            m = r->token + r->rlen;
            if (m >= b->last) {
                m = b->last - 1;
                p = m;
                break;
            }

            if (*m != CR) {
                goto error;
            }

            p = m; /* move forward by rlen bytes */
            r->rlen = 0;
            m = r->token;
            r->token = NULL;
            r->type = MSG_UNKNOWN;

            switch (p - m) {

            case 3:
                if (str3icmp(m, 'g', 'e', 't')) {
                    r->type = MSG_REQ_REDIS_GET;
                    break;
                }

                if (str3icmp(m, 's', 'e', 't')) {
                    r->type = MSG_REQ_REDIS_SET;
                    break;
                }

                if (str3icmp(m, 't', 't', 'l')) {
                    r->type = MSG_REQ_REDIS_TTL;
                    break;
                }

                if (str3icmp(m, 'd', 'e', 'l')) {
                    r->type = MSG_REQ_REDIS_DEL;
                    break;
                }

                break;

            case 4:
                if (str4icmp(m, 'p', 't', 't', 'l')) {
                    r->type = MSG_REQ_REDIS_PTTL;
                    break;
                }

                if (str4icmp(m, 'd', 'e', 'c', 'r')) {
                    r->type = MSG_REQ_REDIS_DECR;
                    break;
                }

                if (str4icmp(m, 'd', 'u', 'm', 'p')) {
                    r->type = MSG_REQ_REDIS_DUMP;
                    break;
                }

                if (str4icmp(m, 'h', 'd', 'e', 'l')) {
                    r->type = MSG_REQ_REDIS_HDEL;
                    break;
                }

                if (str4icmp(m, 'h', 'g', 'e', 't')) {
                    r->type = MSG_REQ_REDIS_HGET;
                    break;
                }

                if (str4icmp(m, 'h', 'l', 'e', 'n')) {
                    r->type = MSG_REQ_REDIS_HLEN;
                    break;
                }

                if (str4icmp(m, 'h', 's', 'e', 't')) {
                    r->type = MSG_REQ_REDIS_HSET;
                    break;
                }

                if (str4icmp(m, 'i', 'n', 'c', 'r')) {
                    r->type = MSG_REQ_REDIS_INCR;
                    break;
                }

                if (str4icmp(m, 'l', 'l', 'e', 'n')) {
                    r->type = MSG_REQ_REDIS_LLEN;
                    break;
                }

                if (str4icmp(m, 'l', 'p', 'o', 'p')) {
                    r->type = MSG_REQ_REDIS_LPOP;
                    break;
                }

                if (str4icmp(m, 'l', 'r', 'e', 'm')) {
                    r->type = MSG_REQ_REDIS_LREM;
                    break;
                }

                if (str4icmp(m, 'l', 's', 'e', 't')) {
                    r->type = MSG_REQ_REDIS_LSET;
                    break;
                }

                if (str4icmp(m, 'r', 'p', 'o', 'p')) {
                    r->type = MSG_REQ_REDIS_RPOP;
                    break;
                }

                if (str4icmp(m, 's', 'a', 'd', 'd')) {
                    r->type = MSG_REQ_REDIS_SADD;
                    break;
                }

                if (str4icmp(m, 's', 'p', 'o', 'p')) {
                    r->type = MSG_REQ_REDIS_SPOP;
                    break;
                }

                if (str4icmp(m, 's', 'r', 'e', 'm')) {
                    r->type = MSG_REQ_REDIS_SREM;
                    break;
                }

                if (str4icmp(m, 't', 'y', 'p', 'e')) {
                    r->type = MSG_REQ_REDIS_TYPE;
                    break;
                }

                if (str4icmp(m, 'm', 'g', 'e', 't')) {
                    r->type = MSG_REQ_REDIS_MGET;
                    break;
                }
                if (str4icmp(m, 'm', 's', 'e', 't')) {
                    r->type = MSG_REQ_REDIS_MSET;
                    break;
                }

                if (str4icmp(m, 'z', 'a', 'd', 'd')) {
                    r->type = MSG_REQ_REDIS_ZADD;
                    break;
                }

                if (str4icmp(m, 'z', 'r', 'e', 'm')) {
                    r->type = MSG_REQ_REDIS_ZREM;
                    break;
                }

                if (str4icmp(m, 'e', 'v', 'a', 'l')) {
                    r->type = MSG_REQ_REDIS_EVAL;
                    r->noforward = 1;
                    r->not_support = 1;
                    break;
                }

                if (str4icmp(m, 's', 'o', 'r', 't')) {
                    r->type = MSG_REQ_REDIS_SORT;
                    break;
                }

                if (str4icmp(m, 'p', 'i', 'n', 'g')) {
                    r->type = MSG_REQ_REDIS_PING;
                    r->noforward = 1;
                    break;
                }

                if (str4icmp(m, 'i', 'n', 'f', 'o')) {
                    r->type = MSG_REQ_REDIS_INFO;
                    r->noforward = 1;
                    break;
                }

                if (str4icmp(m, 'q', 'u', 'i', 't')) {
                    r->type = MSG_REQ_REDIS_QUIT;
                    r->quit = 1;
                    break;
                }

                if (str4icmp(m, 'a', 'u', 't', 'h')) {
                    r->type = MSG_REQ_REDIS_AUTH;
                    r->noforward = 1;
                    break;
                }

                if (str4icmp(m, 'm', 'o', 'v', 'e')) {
                    r->type = MSG_REQ_REDIS_MOVE;
                    r->noforward = 1;
                    r->not_support = 1;
                    break;
                }

                if (str4icmp(m, 'e', 'x', 'e', 'c')) {
                    r->type = MSG_REQ_REDIS_EXEC;
                    r->noforward = 1;
                    break;
                }

                break;

            case 5:
                if (str5icmp(m, 'h', 'k', 'e', 'y', 's')) {
                    r->type = MSG_REQ_REDIS_HKEYS;
                    break;
                }

                if (str5icmp(m, 'h', 'm', 'g', 'e', 't')) {
                    r->type = MSG_REQ_REDIS_HMGET;
                    break;
                }

                if (str5icmp(m, 'h', 'm', 's', 'e', 't')) {
                    r->type = MSG_REQ_REDIS_HMSET;
                    break;
                }

                if (str5icmp(m, 'h', 'v', 'a', 'l', 's')) {
                    r->type = MSG_REQ_REDIS_HVALS;
                    break;
                }

                if (str5icmp(m, 'h', 's', 'c', 'a', 'n')) {
                    r->type = MSG_REQ_REDIS_HSCAN;
                    break;
                }

                if (str5icmp(m, 'l', 'p', 'u', 's', 'h')) {
                    r->type = MSG_REQ_REDIS_LPUSH;
                    break;
                }

                if (str5icmp(m, 'l', 't', 'r', 'i', 'm')) {
                    r->type = MSG_REQ_REDIS_LTRIM;
                    break;
                }

                if (str5icmp(m, 'r', 'p', 'u', 's', 'h')) {
                    r->type = MSG_REQ_REDIS_RPUSH;
                    break;
                }

                if (str5icmp(m, 's', 'c', 'a', 'r', 'd')) {
                    r->type = MSG_REQ_REDIS_SCARD;
                    break;
                }

                if (str5icmp(m, 's', 'd', 'i', 'f', 'f')) {
                    r->type = MSG_REQ_REDIS_SDIFF;
                    break;
                }

                if (str5icmp(m, 's', 'e', 't', 'e', 'x')) {
                    r->type = MSG_REQ_REDIS_SETEX;
                    break;
                }

                if (str5icmp(m, 's', 'e', 't', 'n', 'x')) {
                    r->type = MSG_REQ_REDIS_SETNX;
                    break;
                }

                if (str5icmp(m, 's', 'm', 'o', 'v', 'e')) {
                    r->type = MSG_REQ_REDIS_SMOVE;
                    break;
                }

                if (str5icmp(m, 's', 's', 'c', 'a', 'n')) {
                    r->type = MSG_REQ_REDIS_SSCAN;
                    break;
                }

                if (str5icmp(m, 'z', 'c', 'a', 'r', 'd')) {
                    r->type = MSG_REQ_REDIS_ZCARD;
                    break;
                }

                if (str5icmp(m, 'z', 'r', 'a', 'n', 'k')) {
                    r->type = MSG_REQ_REDIS_ZRANK;
                    break;
                }

                if (str5icmp(m, 'z', 's', 'c', 'a', 'n')) {
                    r->type = MSG_REQ_REDIS_ZSCAN;
                    break;
                }

                if (str5icmp(m, 'p', 'f', 'a', 'd', 'd')) {
                    r->type = MSG_REQ_REDIS_PFADD;
                    break;
                }

                if (str5icmp(m, 'b', 'i', 't', 'o', 'p')) {
                    r->type = MSG_REQ_REDIS_BITOP;
                    r->noforward = 1;
                    r->not_support = 1;
                    break;
                }

                if (str5icmp(m, 'm', 'u', 'l', 't', 'i')) {
                    r->type = MSG_REQ_REDIS_MULTI;
                    r->noforward = 1;
                    break;
                }

                break;

            case 6:                
                if (str6icmp(m, 'a', 'p', 'p', 'e', 'n', 'd')) {
                    r->type = MSG_REQ_REDIS_APPEND;
                    break;
                }

                if (str6icmp(m, 'd', 'e', 'c', 'r', 'b', 'y')) {
                    r->type = MSG_REQ_REDIS_DECRBY;
                    break;
                }

                if (str6icmp(m, 'e', 'x', 'i', 's', 't', 's')) {
                    r->type = MSG_REQ_REDIS_EXISTS;
                    break;
                }

                if (str6icmp(m, 'e', 'x', 'p', 'i', 'r', 'e')) {
                    r->type = MSG_REQ_REDIS_EXPIRE;
                    break;
                }

                if (str6icmp(m, 'g', 'e', 't', 'b', 'i', 't')) {
                    r->type = MSG_REQ_REDIS_GETBIT;
                    break;
                }

                if (str6icmp(m, 'g', 'e', 't', 's', 'e', 't')) {
                    r->type = MSG_REQ_REDIS_GETSET;
                    break;
                }

                if (str6icmp(m, 'p', 's', 'e', 't', 'e', 'x')) {
                    r->type = MSG_REQ_REDIS_PSETEX;
                    break;
                }

                if (str6icmp(m, 'h', 's', 'e', 't', 'n', 'x')) {
                    r->type = MSG_REQ_REDIS_HSETNX;
                    break;
                }

                if (str6icmp(m, 'i', 'n', 'c', 'r', 'b', 'y')) {
                    r->type = MSG_REQ_REDIS_INCRBY;
                    break;
                }

                if (str6icmp(m, 'l', 'i', 'n', 'd', 'e', 'x')) {
                    r->type = MSG_REQ_REDIS_LINDEX;
                    break;
                }

                if (str6icmp(m, 'l', 'p', 'u', 's', 'h', 'x')) {
                    r->type = MSG_REQ_REDIS_LPUSHX;
                    break;
                }

                if (str6icmp(m, 'l', 'r', 'a', 'n', 'g', 'e')) {
                    r->type = MSG_REQ_REDIS_LRANGE;
                    break;
                }

                if (str6icmp(m, 'r', 'p', 'u', 's', 'h', 'x')) {
                    r->type = MSG_REQ_REDIS_RPUSHX;
                    break;
                }

                if (str6icmp(m, 's', 'e', 't', 'b', 'i', 't')) {
                    r->type = MSG_REQ_REDIS_SETBIT;
                    break;
                }

                if (str6icmp(m, 's', 'i', 'n', 't', 'e', 'r')) {
                    r->type = MSG_REQ_REDIS_SINTER;
                    break;
                }

                if (str6icmp(m, 's', 't', 'r', 'l', 'e', 'n')) {
                    r->type = MSG_REQ_REDIS_STRLEN;
                    break;
                }

                if (str6icmp(m, 's', 'u', 'n', 'i', 'o', 'n')) {
                    r->type = MSG_REQ_REDIS_SUNION;
                    break;
                }

                if (str6icmp(m, 'z', 'c', 'o', 'u', 'n', 't')) {
                    r->type = MSG_REQ_REDIS_ZCOUNT;
                    break;
                }

                if (str6icmp(m, 'z', 'r', 'a', 'n', 'g', 'e')) {
                    r->type = MSG_REQ_REDIS_ZRANGE;
                    break;
                }

                if (str6icmp(m, 'z', 's', 'c', 'o', 'r', 'e')) {
                    r->type = MSG_REQ_REDIS_ZSCORE;
                    break;
                }
                
                if (str6icmp(m, 's', 'e', 'l', 'e', 'c', 't')) {
                    r->type = MSG_REQ_REDIS_SELECT;
                    r->noforward = 1;
                    break;
                }

                if (str6icmp(m, 'r', 'e', 'n', 'a', 'm', 'e')) {
                    r->type = MSG_REQ_REDIS_RENAME;
                    r->noforward = 1;
                    r->not_support = 1;
                    break;
                }

                if (str6icmp(m, 'm', 's', 'e', 't', 'n', 'x')) {
                    r->type = MSG_REQ_REDIS_MSETNX;
                    break;
                }

                if (str6icmp(m, 'g', 'e', 'o', 'a', 'd', 'd')) {
                    r->type = MSG_REQ_REDIS_GEOADD;
                    break;
                }

                if (str6icmp(m, 's', 'c', 'r', 'i', 'p', 't')) {
                    r->type = MSG_REQ_REDIS_SCRIPT;
                    r->noforward = 1;
                    r->not_support = 1;
                    break;
                }
                
                break;

            case 7:
                if (str7icmp(m, 'p', 'e', 'r', 's', 'i', 's', 't')) {
                    r->type = MSG_REQ_REDIS_PERSIST;
                    break;
                }

                if (str7icmp(m, 'p', 'e', 'x', 'p', 'i', 'r', 'e')) {
                    r->type = MSG_REQ_REDIS_PEXPIRE;
                    break;
                }

                if (str7icmp(m, 'h', 'e', 'x', 'i', 's', 't', 's')) {
                    r->type = MSG_REQ_REDIS_HEXISTS;
                    break;
                }

                if (str7icmp(m, 'h', 'g', 'e', 't', 'a', 'l', 'l')) {
                    r->type = MSG_REQ_REDIS_HGETALL;
                    break;
                }

                if (str7icmp(m, 'h', 'i', 'n', 'c', 'r', 'b', 'y')) {
                    r->type = MSG_REQ_REDIS_HINCRBY;
                    break;
                }

                if (str7icmp(m, 'l', 'i', 'n', 's', 'e', 'r', 't')) {
                    r->type = MSG_REQ_REDIS_LINSERT;
                    break;
                }

                if (str7icmp(m, 'z', 'i', 'n', 'c', 'r', 'b', 'y')) {
                    r->type = MSG_REQ_REDIS_ZINCRBY;
                    break;
                }

                if (str7icmp(m, 'e', 'v', 'a', 'l', 's', 'h', 'a')) {
                    r->type = MSG_REQ_REDIS_EVALSHA;
                    r->noforward = 1;
                    r->not_support = 1;
                    break;
                }

                if (str7icmp(m, 'r', 'e', 's', 't', 'o', 'r', 'e')) {
                    r->type = MSG_REQ_REDIS_RESTORE;
                    break;
                }

                if (str7icmp(m, 'p', 'f', 'c', 'o', 'u', 'n', 't')) {
                    r->type = MSG_REQ_REDIS_PFCOUNT;
                    break;
                }

                if (str7icmp(m, 'p', 'f', 'm', 'e', 'r', 'g', 'e')) {
                    r->type = MSG_REQ_REDIS_PFMERGE;
                    r->noforward = 1;
                    r->not_support = 1;
                    break;
                }

                if (str7icmp(m, 'c', 'o', 'm', 'm', 'a', 'n', 'd')) {
                    r->type = MSG_REQ_REDIS_COMMAND;
                    break;
                }

                if (str7icmp(m, 'f', 'l', 'u', 's', 'h', 'd', 'b')) {
                    r->type = MSG_REQ_REDIS_FLUSHDB;
                    r->noforward = 1;
                    r->not_support = 1;
                    break;
                }

                if (str7icmp(m, 'p', 'u', 'b', 'l', 'i', 's', 'h')) {
                    r->type = MSG_REQ_REDIS_PUBLISH;
                    /* PUBLISH command will not sent to the target group. */
                    r->noforward = 1;
                    break;
                }

                if (str7icmp(m, 'p', 'f', 'd', 'e', 'b', 'u', 'g')) {
                    r->type = MSG_REQ_REDIS_PFDEBUG;
                    break;
                }

                break;

            case 8:
                if (str8icmp(m, 'e', 'x', 'p', 'i', 'r', 'e', 'a', 't')) {
                    r->type = MSG_REQ_REDIS_EXPIREAT;
                    break;
                }

                if (str8icmp(m, 'b', 'i', 't', 'c', 'o', 'u', 'n', 't')) {
                    r->type = MSG_REQ_REDIS_BITCOUNT;
                    break;
                }

                if (str8icmp(m, 'g', 'e', 't', 'r', 'a', 'n', 'g', 'e')) {
                    r->type = MSG_REQ_REDIS_GETRANGE;
                    break;
                }

                if (str8icmp(m, 's', 'e', 't', 'r', 'a', 'n', 'g', 'e')) {
                    r->type = MSG_REQ_REDIS_SETRANGE;
                    break;
                }

                if (str8icmp(m, 's', 'm', 'e', 'm', 'b', 'e', 'r', 's')) {
                    r->type = MSG_REQ_REDIS_SMEMBERS;
                    break;
                }

                if (str8icmp(m, 'z', 'r', 'e', 'v', 'r', 'a', 'n', 'k')) {
                    r->type = MSG_REQ_REDIS_ZREVRANK;
                    break;
                }

                if (str8icmp(m, 's', 'h', 'u', 't', 'd', 'o', 'w', 'n')) {
                    r->type = MSG_REQ_REDIS_SHUTDOWN;
                    r->noforward = 1;
                    break;
                }

                if (str8icmp(m, 'f', 'l', 'u', 's', 'h', 'a', 'l', 'l')) {
                    r->type = MSG_REQ_REDIS_FLUSHALL;
                    r->noforward = 1;
                    r->not_support = 1;
                    break;
                }

                if (str8icmp(m, 'r', 'e', 'n', 'a', 'm', 'e', 'n', 'x')) {
                    r->type = MSG_REQ_REDIS_RENAMENX;
                    r->noforward = 1;
                    r->not_support = 1;
                    break;
                }

                if (str8icmp(m, 'b', 'i', 't', 'f', 'i', 'e', 'l', 'd')) {
                    r->type = MSG_REQ_REDIS_BITFIELD;
                    break;
                }

                break;

            case 9:
                if (str9icmp(m, 'p', 'e', 'x', 'p', 'i', 'r', 'e', 'a', 't')) {
                    r->type = MSG_REQ_REDIS_PEXPIREAT;
                    break;
                }

                if (str9icmp(m, 'r', 'p', 'o', 'p', 'l', 'p', 'u', 's', 'h')) {
                    r->type = MSG_REQ_REDIS_RPOPLPUSH;
                    r->noforward = 1;
                    r->not_support = 1;
                    break;
                }

                if (str9icmp(m, 's', 'i', 's', 'm', 'e', 'm', 'b', 'e', 'r')) {
                    r->type = MSG_REQ_REDIS_SISMEMBER;
                    break;
                }

                if (str9icmp(m, 'z', 'r', 'e', 'v', 'r', 'a', 'n', 'g', 'e')) {
                    r->type = MSG_REQ_REDIS_ZREVRANGE;
                    break;
                }

                if (str9icmp(m, 'z', 'l', 'e', 'x', 'c', 'o', 'u', 'n', 't')) {
                    r->type = MSG_REQ_REDIS_ZLEXCOUNT;
                    break;
                }

                if (str9icmp(m, 'g', 'e', 'o', 'r', 'a', 'd', 'i', 'u', 's')) {
                    r->type = MSG_REQ_REDIS_GEORADIUS;
                    r->noforward = 1;
                    r->not_support = 1;
                    break;
                }

                break;

            case 10:
                if (str10icmp(m, 's', 'd', 'i', 'f', 'f', 's', 't', 'o', 'r', 'e')) {
                    r->type = MSG_REQ_REDIS_SDIFFSTORE;
                    break;
                }

                if (str10icmp(m, 'b', 'r', 'p', 'o', 'p', 'l', 'p', 'u', 's', 'h')) {
                    r->type = MSG_REQ_REDIS_BRPOPLPUSH;
                    r->noforward = 1;
                    r->not_support = 1;
                    break;
                }

                break;
            case 11:
                if (str11icmp(m, 'i', 'n', 'c', 'r', 'b', 'y', 'f', 'l', 'o', 'a', 't')) {
                    r->type = MSG_REQ_REDIS_INCRBYFLOAT;
                    break;
                }

                if (str11icmp(m, 's', 'i', 'n', 't', 'e', 'r', 's', 't', 'o', 'r', 'e')) {
                    r->type = MSG_REQ_REDIS_SINTERSTORE;
                    break;
                }

                if (str11icmp(m, 's', 'r', 'a', 'n', 'd', 'm', 'e', 'm', 'b', 'e', 'r')) {
                    r->type = MSG_REQ_REDIS_SRANDMEMBER;
                    break;
                }

                if (str11icmp(m, 's', 'u', 'n', 'i', 'o', 'n', 's', 't', 'o', 'r', 'e')) {
                    r->type = MSG_REQ_REDIS_SUNIONSTORE;
                    break;
                }

                if (str11icmp(m, 'z', 'i', 'n', 't', 'e', 'r', 's', 't', 'o', 'r', 'e')) {
                    r->type = MSG_REQ_REDIS_ZINTERSTORE;
                    break;
                }

                if (str11icmp(m, 'z', 'u', 'n', 'i', 'o', 'n', 's', 't', 'o', 'r', 'e')) {
                    r->type = MSG_REQ_REDIS_ZUNIONSTORE;
                    break;
                }

                if (str11icmp(m, 'z', 'r', 'a', 'n', 'g', 'e', 'b', 'y', 'l', 'e', 'x')) {
                    r->type = MSG_REQ_REDIS_ZRANGEBYLEX;
                    break;
                }

                break;

            case 12:
                if (str12icmp(m, 'h', 'i', 'n', 'c', 'r', 'b', 'y', 'f', 'l', 'o', 'a', 't')) {
                    r->type = MSG_REQ_REDIS_HINCRBYFLOAT;
                    break;
                }


                break;

            case 13:
                if (str13icmp(m, 'z', 'r', 'a', 'n', 'g', 'e', 'b', 'y', 's', 'c', 'o', 'r', 'e')) {
                    r->type = MSG_REQ_REDIS_ZRANGEBYSCORE;
                    break;
                }

                break;

            case 14:
                if (str14icmp(m, 'z', 'r', 'e', 'm', 'r', 'a', 'n', 'g', 'e', 'b', 'y', 'l', 'e', 'x')) {
                    r->type = MSG_REQ_REDIS_ZREMRANGEBYLEX;
                    break;
                }

                if (str14icmp(m, 'r', 'e', 's', 't', 'o', 'r', 'e', '-', 'a', 's', 'k', 'i', 'n', 'g')) {
                    r->type = MSG_REQ_REDIS_RESTOREASKING;
                    break;
                }

                break;

            case 15:
                if (str15icmp(m, 'z', 'r', 'e', 'm', 'r', 'a', 'n', 'g', 'e', 'b', 'y', 'r', 'a', 'n', 'k')) {
                    r->type = MSG_REQ_REDIS_ZREMRANGEBYRANK;
                    break;
                }

                break;

            case 16:
                if (str16icmp(m, 'z', 'r', 'e', 'm', 'r', 'a', 'n', 'g', 'e', 'b', 'y', 's', 'c', 'o', 'r', 'e')) {
                    r->type = MSG_REQ_REDIS_ZREMRANGEBYSCORE;
                    break;
                }

                if (str16icmp(m, 'z', 'r', 'e', 'v', 'r', 'a', 'n', 'g', 'e', 'b', 'y', 's', 'c', 'o', 'r', 'e')) {
                    r->type = MSG_REQ_REDIS_ZREVRANGEBYSCORE;
                    break;
                }

                break;

            case 17:
                if (str17icmp(m, 'g', 'e', 'o', 'r', 'a', 'd', 'i', 'u', 's', 'b', 'y', 'm', 'e', 'm', 'b', 'e', 'r')) {
                    r->type = MSG_REQ_REDIS_GEORADIUSBYMEMBER;
                    r->noforward = 1;
                    r->not_support = 1;
                    break;
                }

                break;

            default:
                break;
            }

            if (r->type == MSG_UNKNOWN) {
                log_error("ERROR: parsed unsupported command '%.*s'", p - m, m);
                goto error;
            }

            log_debug(LOG_VERB, "parsed command '%.*s'", p - m, m);

            state = SW_REQ_TYPE_LF;
            break;

        case SW_REQ_TYPE_LF:
            switch (ch) {
            case LF:
                if (redis_argz(r)) {
                    goto done;
                } else if (redis_argeval(r)) {
                    state = SW_ARG1_LEN;
                } else if (redis_subcmd_onekey_argzormore(r)) {
                    state = SW_SUBCMD_LEN;
                } else if (redis_argzormore(r)) {
                    if (r->narg == 1) {
                        goto done;
                    }
                    state = SW_KEY_LEN;
                } else {
                    state = SW_KEY_LEN;
                }
                break;

            default:
                goto error;
            }

            break;

        case SW_SUBCMD_LEN:
            if (r->token == NULL) {
                if (ch != '$') {
                    goto error;
                }
                r->rlen = 0;
                r->token = p;
            } else if (isdigit(ch)) {
                r->rlen = r->rlen * 10 + (uint32_t)(ch - '0');
            } else if (ch == CR) {
                if ((p - r->token) <= 1 || r->rnarg == 0) {
                    goto error;
                }
                r->rnarg--;
                r->token = NULL;
                state = SW_SUBCMD_LEN_LF;
            } else {
                goto error;
            }
            break;
            
        case SW_SUBCMD_LEN_LF:
            switch (ch) {
            case LF:
                state = SW_SUBCMD;
                break;

            default:
                goto error;
            }
            break;

        case SW_SUBCMD:
            m = p + r->rlen;
            if (m >= b->last) {
                r->rlen -= (uint32_t)(b->last - p);
                m = b->last - 1;
                p = m;
                break;
            }

            if (*m != CR) {
                goto error;
            }

            p = m; /* move forward by rlen bytes */
            r->rlen = 0;

            state = SW_SUBCMD_LF;
            break;

        case SW_SUBCMD_LF:
            switch (ch) {
            case LF:
                if (redis_subcmd_onekey_argzormore(r)) {
                    if (r->rnarg == 0) {
                        goto error;
                    }
                    state = SW_KEY_LEN;
                } else {
                    goto error;
                }

                break;

            default:
                goto error;
            }
            break;

        case SW_KEY_LEN:
            if (r->token == NULL) {
                if (ch != '$') {
                    goto error;
                }
                r->token = p;
                r->rlen = 0;
            } else if (isdigit(ch)) {
                r->rlen = r->rlen * 10 + (uint32_t)(ch - '0');
            } else if (ch == CR) {
                if (r->rlen >= mbuf_data_size(r->mb)) {
                    log_error("ERROR: parsed bad req %"PRIu64" of type %d with key "
                              "length %d that greater than or equal to maximum"
                              " redis key length of %d", r->id, r->type,
                              r->rlen, mbuf_data_size(r->mb));
                    goto error;
                }
                if (r->rnarg == 0) {
                    goto error;
                }
                r->rnarg--;
                r->token = NULL;
                state = SW_KEY_LEN_LF;
            } else {
                goto error;
            }

            break;

        case SW_KEY_LEN_LF:
            switch (ch) {
            case LF:
                state = SW_KEY;
                break;

            default:
                goto error;
            }

            break;

        case SW_KEY:
            if (r->token == NULL) {
                r->token = p;
            }

            m = r->token + r->rlen;
            if (m >= b->last) {
                m = b->last - 1;
                p = m;
                break;
            }

            if (*m != CR) {
                goto error;
            } else {        /* got a key */
                struct keypos *kpos;

                p = m;      /* move forward by rlen bytes */
                r->rlen = 0;
                m = r->token;
                r->token = NULL;

                kpos = array_push(r->keys);
                if (kpos == NULL) {
                    goto enomem;
                }
                kpos->start = m;
                kpos->end = p;

                state = SW_KEY_LF;
            }

            break;

        case SW_KEY_LF:
            switch (ch) {
            case LF:
                if (redis_arg0(r)) {
                    if (r->rnarg != 0) {
                        goto error;
                    }
                    goto done;
                } else if (redis_arg1(r)) {
                    if (r->rnarg != 1) {
                        goto error;
                    }
                    state = SW_ARG1_LEN;
                } else if (redis_arg2(r)) {
                    if (r->rnarg != 2) {
                        goto error;
                    }
                    state = SW_ARG1_LEN;
                } else if (redis_arg3(r)) {
                    if (r->rnarg != 3) {
                        goto error;
                    }
                    state = SW_ARG1_LEN;
                } else if (redis_argn(r)) {
                    if (r->rnarg == 0) {
                        goto done;
                    }
                    state = SW_ARG1_LEN;
                } else if (redis_argx(r)) {
                    if (r->rnarg == 0) {
                        goto done;
                    }
                    state = SW_KEY_LEN;
                } else if (redis_argzormore(r)) {
                    if (r->rnarg == 0) {
                        goto done;
                    }
                    state = SW_KEY_LEN;
                } else if (redis_argkvx(r)) {
                    if (r->rnarg == 0) {
                        goto done;
                    }
                    if (r->narg % 2 == 0) {
                        goto error;
                    }
                    state = SW_ARG1_LEN;
                } else if (redis_argeval(r)) {
                    if (r->rnarg == 0) {
                        goto done;
                    }
                    state = SW_ARGN_LEN;
                } else if (redis_subcmd_onekey_argzormore(r)) {
                    if (r->rnarg == 0) {
                        goto done;
                    }
                    state = SW_ARGN_LEN;
                } else {
                    goto error;
                }

                break;

            default:
                goto error;
            }

            break;

        case SW_ARG1_LEN:
            if (r->token == NULL) {
                if (ch != '$') {
                    goto error;
                }
                r->rlen = 0;
                r->token = p;
            } else if (isdigit(ch)) {
                r->rlen = r->rlen * 10 + (uint32_t)(ch - '0');
            } else if (ch == CR) {
                if ((p - r->token) <= 1 || r->rnarg == 0) {
                    goto error;
                }
                r->rnarg--;
                r->token = NULL;
                state = SW_ARG1_LEN_LF;
            } else {
                goto error;
            }

            break;

        case SW_ARG1_LEN_LF:
            switch (ch) {
            case LF:
                state = SW_ARG1;
                break;

            default:
                goto error;
            }

            break;

        case SW_ARG1:
            m = p + r->rlen;
            if (m >= b->last) {
                r->rlen -= (uint32_t)(b->last - p);
                m = b->last - 1;
                p = m;
                break;
            }

            if (*m != CR) {
                goto error;
            }

            p = m; /* move forward by rlen bytes */
            r->rlen = 0;

            state = SW_ARG1_LF;

            break;

        case SW_ARG1_LF:
            switch (ch) {
            case LF:
                if (redis_arg1(r)) {
                    if (r->rnarg != 0) {
                        goto error;
                    }
                    goto done;
                } else if (redis_arg2(r)) {
                    if (r->rnarg != 1) {
                        goto error;
                    }
                    state = SW_ARG2_LEN;
                } else if (redis_arg3(r)) {
                    if (r->rnarg != 2) {
                        goto error;
                    }
                    state = SW_ARG2_LEN;
                } else if (redis_argn(r)) {
                    if (r->rnarg == 0) {
                        goto done;
                    }
                    state = SW_ARGN_LEN;
                } else if (redis_argeval(r)) {
                    if (r->rnarg < 2) {
                        goto error;
                    }
                    state = SW_ARG2_LEN;
                } else if (redis_argkvx(r)) {
                    if (r->rnarg == 0) {
                        goto done;
                    }
                    state = SW_KEY_LEN;
                } else {
                    goto error;
                }

                break;

            default:
                goto error;
            }

            break;

        case SW_ARG2_LEN:
            if (r->token == NULL) {
                if (ch != '$') {
                    goto error;
                }
                r->rlen = 0;
                r->token = p;
            } else if (isdigit(ch)) {
                r->rlen = r->rlen * 10 + (uint32_t)(ch - '0');
            } else if (ch == CR) {
                if ((p - r->token) <= 1 || r->rnarg == 0) {
                    goto error;
                }
                r->rnarg--;
                r->token = NULL;
                state = SW_ARG2_LEN_LF;
            } else {
                goto error;
            }

            break;

        case SW_ARG2_LEN_LF:
            switch (ch) {
            case LF:
                state = SW_ARG2;
                break;

            default:
                goto error;
            }

            break;

        case SW_ARG2:
            if (r->token == NULL && redis_argeval(r)) {
                /*
                 * For EVAL/EVALSHA, ARG2 represents the # key/arg pairs which must
                 * be tokenized and stored in contiguous memory.
                 */
                r->token = p;
            }

            m = p + r->rlen;
            if (m >= b->last) {
                r->rlen -= (uint32_t)(b->last - p);
                m = b->last - 1;
                p = m;
                break;
            }

            if (*m != CR) {
                goto error;
            }

            p = m; /* move forward by rlen bytes */
            r->rlen = 0;

            if (redis_argeval(r)) {
                uint32_t nkey;
                uint8_t *chp;

                /*
                 * For EVAL/EVALSHA, we need to find the integer value of this
                 * argument. It tells us the number of keys in the script, and
                 * we need to error out if number of keys is 0. At this point,
                 * both p and m point to the end of the argument and r->token
                 * points to the start.
                 */
                if (p - r->token < 1) {
                    goto error;
                }

                for (nkey = 0, chp = r->token; chp < p; chp++) {
                    if (isdigit(*chp)) {
                        nkey = nkey * 10 + (uint32_t)(*chp - '0');
                    } else {
                        goto error;
                    }
                }
                if (nkey == 0) {
                    goto error;
                }

                r->token = NULL;
            }

            state = SW_ARG2_LF;

            break;

        case SW_ARG2_LF:
            switch (ch) {
            case LF:
                if (redis_arg2(r)) {
                    if (r->rnarg != 0) {
                        goto error;
                    }
                    goto done;
                } else if (redis_arg3(r)) {
                    if (r->rnarg != 1) {
                        goto error;
                    }
                    state = SW_ARG3_LEN;
                } else if (redis_argn(r)) {
                    if (r->rnarg == 0) {
                        goto done;
                    }
                    state = SW_ARGN_LEN;
                } else if (redis_argeval(r)) {
                    if (r->rnarg < 1) {
                        goto error;
                    }
                    state = SW_KEY_LEN;
                } else {
                    goto error;
                }

                break;

            default:
                goto error;
            }

            break;

        case SW_ARG3_LEN:
            if (r->token == NULL) {
                if (ch != '$') {
                    goto error;
                }
                r->rlen = 0;
                r->token = p;
            } else if (isdigit(ch)) {
                r->rlen = r->rlen * 10 + (uint32_t)(ch - '0');
            } else if (ch == CR) {
                if ((p - r->token) <= 1 || r->rnarg == 0) {
                    goto error;
                }
                r->rnarg--;
                r->token = NULL;
                state = SW_ARG3_LEN_LF;
            } else {
                goto error;
            }

            break;

        case SW_ARG3_LEN_LF:
            switch (ch) {
            case LF:
                state = SW_ARG3;
                break;

            default:
                goto error;
            }

            break;

        case SW_ARG3:
            m = p + r->rlen;
            if (m >= b->last) {
                r->rlen -= (uint32_t)(b->last - p);
                m = b->last - 1;
                p = m;
                break;
            }

            if (*m != CR) {
                goto error;
            }

            p = m; /* move forward by rlen bytes */
            r->rlen = 0;
            state = SW_ARG3_LF;

            break;

        case SW_ARG3_LF:
            switch (ch) {
            case LF:
                if (redis_arg3(r)) {
                    if (r->rnarg != 0) {
                        goto error;
                    }
                    goto done;
                } else if (redis_argn(r)) {
                    if (r->rnarg == 0) {
                        goto done;
                    }
                    state = SW_ARGN_LEN;
                } else {
                    goto error;
                }

                break;

            default:
                goto error;
            }

            break;

        case SW_ARGN_LEN:
            if (r->token == NULL) {
                if (ch != '$') {
                    goto error;
                }
                r->rlen = 0;
                r->token = p;
            } else if (isdigit(ch)) {
                r->rlen = r->rlen * 10 + (uint32_t)(ch - '0');
            } else if (ch == CR) {
                if ((p - r->token) <= 1 || r->rnarg == 0) {
                    goto error;
                }
                r->rnarg--;
                r->token = NULL;
                state = SW_ARGN_LEN_LF;
            } else {
                goto error;
            }

            break;

        case SW_ARGN_LEN_LF:
            switch (ch) {
            case LF:
                state = SW_ARGN;
                break;

            default:
                goto error;
            }

            break;

        case SW_ARGN:
            m = p + r->rlen;
            if (m >= b->last) {
                r->rlen -= (uint32_t)(b->last - p);
                m = b->last - 1;
                p = m;
                break;
            }

            if (*m != CR) {
                goto error;
            }

            p = m; /* move forward by rlen bytes */
            r->rlen = 0;
            state = SW_ARGN_LF;

            break;

        case SW_ARGN_LF:
            switch (ch) {
            case LF:
                if (redis_argn(r) || redis_argeval(r) || redis_subcmd_onekey_argzormore(r)) {
                    if (r->rnarg == 0) {
                        goto done;
                    }
                    state = SW_ARGN_LEN;
                } else {
                    goto error;
                }

                break;

            default:
                goto error;
            }

            break;

        case SW_SENTINEL:
        default:
            NOT_REACHED();
            break;
        }
    }

    ASSERT(p == b->last);
    r->pos = p;
    r->state = state;

    //if (b->last == b->end && r->token != NULL) {
    if (r->token != NULL) {
        r->pos = r->token;
        r->token = NULL;
        r->result = MSG_PARSE_REPAIR;
    } else {
        r->result = MSG_PARSE_AGAIN;
    }

    log_hexdump(LOG_VERB, b->pos, mbuf_length(b), "parsed req %"PRIu64" res %d "
                "type %d state %d rpos %d of %d", r->id, r->result, r->type,
                r->state, r->pos - b->pos, b->last - b->pos);
    return;

done:
    ASSERT(r->type > MSG_UNKNOWN && r->type < MSG_SENTINEL);
    r->pos = p + 1;
    ASSERT(r->pos <= b->last);
    r->state = SW_START;
    r->token = NULL;
    r->result = MSG_PARSE_OK;

    log_hexdump(LOG_VERB, b->pos, mbuf_length(b), "parsed req %"PRIu64" res %d "
                "type %d state %d rpos %d of %d", r->id, r->result, r->type,
                r->state, r->pos - b->pos, b->last - b->pos);
    return;

enomem:
    r->result = MSG_PARSE_ERROR;
    r->state = state;

    log_hexdump(LOG_INFO, b->pos, mbuf_length(b), "out of memory on parse req %"PRIu64" "
                "res %d type %d state %d", r->id, r->result, r->type, r->state);

    return;

error:
    r->result = MSG_PARSE_ERROR;
    r->state = state;
    errno = EINVAL;

    log_hexdump(LOG_NOTICE, b->pos, mbuf_length(b), "parsed bad req %"PRIu64" "
                "res %d type %d state %d", r->id, r->result, r->type,
                r->state);
}

/*
 * Reference: http://redis.io/topics/protocol
 *
 * Redis will reply to commands with different kinds of replies. It is
 * possible to check the kind of reply from the first byte sent by the
 * server:
 *  - with a single line reply the first byte of the reply will be "+"
 *  - with an error message the first byte of the reply will be "-"
 *  - with an integer number the first byte of the reply will be ":"
 *  - with bulk reply the first byte of the reply will be "$"
 *  - with multi-bulk reply the first byte of the reply will be "*"
 *
 * 1). Status reply (or single line reply) is in the form of a single line
 *     string starting with "+" terminated by "\r\n".
 * 2). Error reply are similar to status replies. The only difference is
 *     that the first byte is "-" instead of "+".
 * 3). Integer reply is just a CRLF terminated string representing an
 *     integer, and prefixed by a ":" byte.
 * 4). Bulk reply is used by server to return a single binary safe string.
 *     The first reply line is a "$" byte followed by the number of bytes
 *     of the actual reply, followed by CRLF, then the actual data bytes,
 *     followed by additional two bytes for the final CRLF. If the requested
 *     value does not exist the bulk reply will use the special value '-1'
 *     as the data length.
 * 5). Multi-bulk reply is used by the server to return many binary safe
 *     strings (bulks) with the initial line indicating how many bulks that
 *     will follow. The first byte of a multi bulk reply is always *.
 */
void
redis_parse_rsp(struct msg *r)
{
    struct mbuf *b;
    uint8_t *p, *m;
    uint8_t ch;

    enum {
        SW_START,
        SW_STATUS,
        SW_ERROR,
        SW_INTEGER,
        SW_INTEGER_START,
        SW_BULK,
        SW_BULK_LF,
        SW_BULK_ARG,
        SW_BULK_ARG_LF,
        SW_MULTIBULK,
        SW_MULTIBULK_NARG_LF,
        SW_MULTIBULK_ARGN_LEN,
        SW_MULTIBULK_ARGN_LEN_LF,
        SW_MULTIBULK_ARGN,
        SW_MULTIBULK_ARGN_LF,
        SW_RUNTO_CRLF,
        SW_ALMOST_DONE,
        SW_SENTINEL
    } state;

    state = r->state;
    b = listLastValue(r->data);

    ASSERT(!r->request);
    ASSERT(state < SW_SENTINEL);
    ASSERT(b != NULL);
    ASSERT(b->pos <= b->last);

    /* validate the parsing marker */
    ASSERT(r->pos != NULL);
    ASSERT(r->pos >= b->pos && r->pos <= b->last);

    for (p = r->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {
        case SW_START:
            r->type = MSG_UNKNOWN;
            switch (ch) {
            case '+':
                p = p - 1; /* go back by 1 byte */
                r->type = MSG_RSP_REDIS_STATUS;
                state = SW_STATUS;
                break;

            case '-':
                r->type = MSG_RSP_REDIS_ERROR;
                p = p - 1; /* go back by 1 byte */
                state = SW_ERROR;
                break;

            case ':':
                r->type = MSG_RSP_REDIS_INTEGER;
                p = p - 1; /* go back by 1 byte */
                state = SW_INTEGER;
                break;

            case '$':
                r->type = MSG_RSP_REDIS_BULK;
                p = p - 1; /* go back by 1 byte */
                state = SW_BULK;
                break;

            case '*':
                r->type = MSG_RSP_REDIS_MULTIBULK;
                p = p - 1; /* go back by 1 byte */
                state = SW_MULTIBULK;
                break;

            default:
                goto error;
            }

            break;

        case SW_STATUS:
            /* rsp_start <- p */
            state = SW_RUNTO_CRLF;
            break;

        case SW_ERROR:
            /* rsp_start <- p */
            state = SW_RUNTO_CRLF;
            break;

        case SW_INTEGER:
            /* rsp_start <- p */
            state = SW_INTEGER_START;
            r->integer = 0;
            break;

        case SW_INTEGER_START:
            if (ch == CR) {
                state = SW_ALMOST_DONE;
            } else if (ch == '-') {
                ;
            } else if (isdigit(ch)) {
                r->integer = r->integer * 10 + (uint32_t)(ch - '0');
            } else {
                goto error;
            }
            break;

        case SW_RUNTO_CRLF:
            switch (ch) {
            case CR:
                state = SW_ALMOST_DONE;
                break;

            default:
                break;
            }

            break;

        case SW_ALMOST_DONE:
            switch (ch) {
            case LF:
                /* rsp_end <- p */
                goto done;

            default:
                goto error;
            }

            break;

        case SW_BULK:
            if (r->token == NULL) {
                if (ch != '$') {
                    goto error;
                }
                /* rsp_start <- p */
                r->token = p;
                r->rlen = 0;
            } else if (ch == '-') {
                /* handles null bulk reply = '$-1' */
                state = SW_RUNTO_CRLF;
            } else if (isdigit(ch)) {
                r->rlen = r->rlen * 10 + (uint32_t)(ch - '0');
            } else if (ch == CR) {
                if ((p - r->token) <= 1) {
                    goto error;
                }
                r->bulk_len = r->rlen;
                r->token = NULL;
                state = SW_BULK_LF;
            } else {
                goto error;
            }

            break;

        case SW_BULK_LF:
            switch (ch) {
            case LF:
                state = SW_BULK_ARG;
                break;

            default:
                goto error;
            }

            break;

        case SW_BULK_ARG:
            if (r->bulk_start == NULL) {
                r->bulk_start = p;
            }
            
            m = p + r->rlen;
            if (m >= b->last) {
                r->rlen -= (uint32_t)(b->last - p);
                m = b->last - 1;
                p = m;
                break;
            }

            if (*m != CR) {
                goto error;
            }

            p = m; /* move forward by rlen bytes */
            r->rlen = 0;

            state = SW_BULK_ARG_LF;

            break;

        case SW_BULK_ARG_LF:
            switch (ch) {
            case LF:
                goto done;

            default:
                goto error;
            }

            break;

        case SW_MULTIBULK:
            if (r->token == NULL) {
                if (ch != '*') {
                    goto error;
                }
                r->token = p;
                /* rsp_start <- p */
                r->narg_start = p;
                r->rnarg = 0;
            } else if (ch == '-') {
                state = SW_RUNTO_CRLF;
            } else if (isdigit(ch)) {
                r->rnarg = r->rnarg * 10 + (uint32_t)(ch - '0');
            } else if (ch == CR) {
                if ((p - r->token) <= 1) {
                    goto error;
                }

                r->narg = r->rnarg;
                r->narg_end = p;
                r->token = NULL;
                state = SW_MULTIBULK_NARG_LF;
            } else {
                goto error;
            }

            break;

        case SW_MULTIBULK_NARG_LF:
            switch (ch) {
            case LF:
                if (r->rnarg == 0) {
                    /* response is '*0\r\n' */
                    goto done;
                }
                state = SW_MULTIBULK_ARGN_LEN;
                break;

            default:
                goto error;
            }

            break;

        case SW_MULTIBULK_ARGN_LEN:
            if (r->token == NULL) {
                /*
                 * From: http://redis.io/topics/protocol, a multi bulk reply
                 * is used to return an array of other replies. Every element
                 * of a multi bulk reply can be of any kind, including a
                 * nested multi bulk reply.
                 *
                 * Here, we only handle a multi bulk reply element that
                 * are either integer reply or bulk reply.
                 *
                 * there is a special case for sscan/hscan/zscan, these command
                 * replay a nested multi-bulk with a number and a multi bulk like this:
                 *
                 * - mulit-bulk
                 *    - cursor
                 *    - mulit-bulk
                 *       - val1
                 *       - val2
                 *       - val3
                 *
                 * in this case, there is only one sub-multi-bulk,
                 * and it's the last element of parent,
                 * we can handle it like tail-recursive.
                 *
                 */
                if (ch == '*') {    /* for sscan/hscan/zscan only */
                    p = p - 1;      /* go back by 1 byte */
                    state = SW_MULTIBULK;
                    break;
                }

                if (ch != '$' && ch != ':') {
                    goto error;
                }
                r->token = p;
                r->rlen = 0;
            } else if (isdigit(ch)) {
                r->rlen = r->rlen * 10 + (uint32_t)(ch - '0');
            } else if (ch == '-') {
                ;
            } else if (ch == CR) {
                if ((p - r->token) <= 1 || r->rnarg == 0) {
                    goto error;
                }

                if ((r->rlen == 1 && (p - r->token) == 3) || *r->token == ':') {
                    /* handles not-found reply = '$-1' or integer reply = ':<num>' */
                    r->rlen = 0;
                    state = SW_MULTIBULK_ARGN_LF;
                } else {
                    state = SW_MULTIBULK_ARGN_LEN_LF;
                }
                r->rnarg--;
                r->token = NULL;
            } else {
                goto error;
            }

            break;

        case SW_MULTIBULK_ARGN_LEN_LF:
            switch (ch) {
            case LF:
                state = SW_MULTIBULK_ARGN;
                break;

            default:
                goto error;
            }

            break;

        case SW_MULTIBULK_ARGN:
            m = p + r->rlen;
            if (m >= b->last) {
                r->rlen -= (uint32_t)(b->last - p);
                m = b->last - 1;
                p = m;
                break;
            }

            if (*m != CR) {
                goto error;
            }

            p += r->rlen; /* move forward by rlen bytes */
            r->rlen = 0;

            state = SW_MULTIBULK_ARGN_LF;

            break;

        case SW_MULTIBULK_ARGN_LF:
            switch (ch) {
            case LF:
                if (r->rnarg == 0) {
                    goto done;
                }

                state = SW_MULTIBULK_ARGN_LEN;
                break;

            default:
                goto error;
            }

            break;

        case SW_SENTINEL:
        default:
            NOT_REACHED();
            break;
        }
    }

    ASSERT(p == b->last);
    r->pos = p;
    r->state = state;

    if (b->last == b->end && r->token != NULL) {
        r->pos = r->token;
        r->token = NULL;
        r->result = MSG_PARSE_REPAIR;
    } else {
        r->result = MSG_PARSE_AGAIN;
    }

    log_hexdump(LOG_VERB, b->pos, mbuf_length(b), "parsed rsp %"PRIu64" res %d "
                "type %d state %d rpos %d of %d", r->id, r->result, r->type,
                r->state, r->pos - b->pos, b->last - b->pos);
    return;

done:
    ASSERT(r->type > MSG_UNKNOWN && r->type < MSG_SENTINEL);
    r->pos = p + 1;
    ASSERT(r->pos <= b->last);
    r->state = SW_START;
    r->token = NULL;
    r->result = MSG_PARSE_OK;

    log_hexdump(LOG_VERB, b->pos, mbuf_length(b), "parsed rsp %"PRIu64" res %d "
                "type %d state %d rpos %d of %d", r->id, r->result, r->type,
                r->state, r->pos - b->pos, b->last - b->pos);
    return;

error:
    r->result = MSG_PARSE_ERROR;
    r->state = state;
    errno = EINVAL;

    log_hexdump(LOG_INFO, b->pos, mbuf_length(b), "parsed bad rsp %"PRIu64" "
                "res %d type %d state %d", r->id, r->result, r->type,
                r->state);
}

int redis_response_check(redis_node *rnode, struct msg *r)
{
    struct msg *resp;
    uint32_t key_num;
    struct keypos *kp;
    thread_data *tdata = rnode->write_data;

    if (r == NULL) {
        return RMT_ERROR;
    }

    resp = r->peer;

    ASSERT(r->request && r->sent);
    ASSERT(resp != NULL && resp->request == 0);

    if (resp->type == MSG_RSP_REDIS_ERROR) {
        log_warn("Response from node[%s] for %s is error.",
            rnode->addr, msg_type_string(r->type));
        MSG_DUMP_ALL(resp, LOG_WARN, 0);
        goto error;
    }

    switch(r->type){
    case MSG_REQ_REDIS_SET:
        if (resp->type != MSG_RSP_REDIS_STATUS) {
            goto error;
        }

        if (msg_cmp_str(resp, (const uint8_t*)REDIS_REPLY_STATUS_OK, 
            rmt_strlen(REDIS_REPLY_STATUS_OK)) != 0) {
            goto error;
        }
        
        break;
    case MSG_REQ_REDIS_APPEND:
    case MSG_REQ_REDIS_DEL:
        if (resp->type != MSG_RSP_REDIS_INTEGER) {
            goto error;
        }
        
        break;
    case MSG_REQ_REDIS_MSETNX:
        if (resp->type != MSG_RSP_REDIS_INTEGER || resp->integer != 1) {
            goto error;
        }
        break;
    default:

        break;
    }
    
    MSG_DUMP(resp, LOG_VVERB, 0);
    
    msg_put(r);
    msg_free(r);
    msg_put(resp);
    msg_free(resp);

    if (tdata->keys_count > 0) {
        tdata->correct_keys_count ++;
        tdata->finished_keys_count ++;
        if (tdata->finished_keys_count >= tdata->keys_count) {
            aeStop(tdata->loop);
        }
    }
    
    return RMT_OK;

error:

    key_num = array_n(r->keys);
    if (key_num == 0) {
        kp = NULL;
    } else {
        kp = array_get(r->keys, 0);
    }
    
    log_warn("response %s from node[%s] for request %s is error", 
        msg_type_string(resp->type), rnode->addr, msg_type_string(r->type));
    MSG_DUMP(r, LOG_WARN, 1);

    msg_put(r);
    msg_free(r);
    msg_put(resp);
    msg_free(resp);

    
    if (tdata->keys_count > 0) {
        tdata->finished_keys_count ++;
        if (tdata->finished_keys_count >= tdata->keys_count) {
            aeStop(tdata->loop);
        }
    }

    return RMT_ERROR;
}

/*
 * copy one bulk from src to dst
 *
 * if dst == NULL, we just eat the bulk
 *
 * */
static int redis_copy_bulk(struct msg *dst, struct msg *src)
{
    int ret;
    struct mbuf *mbuf;
    listNode *node, *nnode;
    uint8_t *p;
    uint32_t len = 0;
    uint32_t bytes = 0;
    
    for (node = listFirst(src->data); 
        node != NULL;
        node = listFirst(src->data)) {
        mbuf = listNodeValue(node);
        if (mbuf == NULL || !mbuf_empty(mbuf)) {
            break;
        }

        listDelNode(src->data, node);
        mbuf_put(mbuf);
    }

    node = listFirst(src->data);
    if (node == NULL) {
        return RMT_ERROR;
    }
    
    mbuf = listNodeValue(node);
    if (mbuf == NULL) {
        return RMT_ERROR;
    }

    log_debug(LOG_DEBUG, "mbuf: %.*s",
        mbuf_length(mbuf), mbuf->pos);

    p = mbuf->pos;
    if (*p != '$') {
        MSG_DUMP_ALL(src,LOG_ERR,0);
        ASSERT(*p == '$');
    }
    p++;

    if (p[0] == '-' && p[1] == '1') {
        len = 1 + 2 + CRLF_LEN;             /* $-1\r\n */
        p = mbuf->pos + len;
    } else {
        len = 0;
        for (; p < mbuf->last && isdigit(*p); p++) {
            len = len * 10 + (uint32_t)(*p - '0');
        }
        len += (uint32_t)(CRLF_LEN * 2);
        len += (uint32_t)(p - mbuf->pos);
    }
    bytes = len;

    /* copy len bytes to dst */
    for (; mbuf && len > 0;) {
        if (mbuf_length(mbuf) <= len) {     /* steal this buf from src to dst */
            nnode = listNextNode(node);
            
            listDelNode(src->data, node);
            len -= mbuf_length(mbuf);
            if (dst != NULL) {
                listAddNodeTail(dst->data, mbuf);
                dst->mlen += mbuf_length(mbuf);
            } else {
                mbuf_put(mbuf);
            }

            if (nnode == NULL) {
                break;
            }

            mbuf = listNodeValue(nnode);
            node = nnode;
        } else {                             /* split it */
            if (dst != NULL) {
                ret = msg_append(dst, mbuf->pos, len);
                if (ret != RMT_OK) {
                    return ret;
                }
            }
            mbuf->pos += len;
            len = 0;
            break;
        }
    }

    ASSERT(len == 0);

    src->mlen -= bytes;
    log_debug(LOG_VVERB, "redis_copy_bulk copy bytes: %d", bytes);
    return RMT_OK;
}

/*
 * Pre-coalesce handler is invoked when the message is a response to
 * the fragmented multi vector request - 'mget' or 'del' and all the
 * responses to the fragmented request vector hasn't been received
 */
void redis_pre_coalesce(struct msg *r)
{
    struct msg *pr = r->peer; /* peer request */
    struct mbuf *mbuf;

    ASSERT(!r->request);
    ASSERT(pr->request);

    if (pr->frag_id == 0) {
        /* do nothing, if not a response to a fragmented request */
        return;
    }
    pr->frag_owner->nfrag_done++;

    switch (r->type) {
    case MSG_RSP_REDIS_INTEGER:
        /* only redis 'del' fragmented request sends back integer reply */
        ASSERT(pr->type == MSG_REQ_REDIS_DEL);

        mbuf = listFirstValue(r->data);
        /*
         * Our response parser guarantees that the integer reply will be
         * completely encapsulated in a single mbuf and we should skip over
         * all the mbuf contents and discard it as the parser has already
         * parsed the integer reply and stored it in msg->integer
         */
        ASSERT(mbuf == listLastValue(r->data));
        ASSERT(r->mlen == mbuf_length(mbuf));

        r->mlen -= mbuf_length(mbuf);
        mbuf_rewind(mbuf);

        /* accumulate the integer value in frag_owner of peer request */
        pr->frag_owner->integer += r->integer;
        break;

    case MSG_RSP_REDIS_MULTIBULK:
        /* only redis 'mget' fragmented request sends back multi-bulk reply */
        ASSERT(pr->type == MSG_REQ_REDIS_MGET);

        mbuf = listFirstValue(r->data);
        /*
         * Muti-bulk reply can span over multiple mbufs and in each reply
         * we should skip over the narg token. Our response parser
         * guarantees thaat the narg token and the immediately following
         * '\r\n' will exist in a contiguous region in the first mbuf
         */
        ASSERT(r->narg_start == mbuf->pos);
        ASSERT(r->narg_start < r->narg_end);

        r->narg_end += CRLF_LEN;
        r->mlen -= (uint32_t)(r->narg_end - r->narg_start);
        mbuf->pos = r->narg_end;

        break;

    case MSG_RSP_REDIS_STATUS:
        if (pr->type == MSG_REQ_REDIS_MSET || pr->type == MSG_REQ_REDIS_MSETNX) {       /* MSET segments */
            mbuf = listFirstValue(r->data);
            r->mlen -= mbuf_length(mbuf);
            mbuf_rewind(mbuf);
        }
        break;

    default:
        /*
         * Valid responses for a fragmented request are MSG_RSP_REDIS_INTEGER or,
         * MSG_RSP_REDIS_MULTIBULK. For an invalid response, we send out -ERR
         * with EINVAL errno
         */
        mbuf = listFirstValue(r->data);
        log_hexdump(LOG_ERR, mbuf->pos, mbuf_length(mbuf), "rsp fragment "
                    "with unknown type %d", r->type);
        pr->error = 1;
        pr->err = EINVAL;
        break;
    }
}

static int redis_append_key(struct msg *r, uint8_t *key, uint32_t keylen)
{
    uint32_t len;
    struct mbuf *mbuf;
    uint8_t printbuf[32];
    struct keypos *kpos;

    /* 1. keylen */
    len = (uint32_t)rmt_snprintf(printbuf, sizeof(printbuf), "$%d\r\n", keylen);
    mbuf = msg_ensure_mbuf(r, len);
    if (mbuf == NULL) {
        return RMT_ENOMEM;
    }
    mbuf_copy(mbuf, printbuf, len);
    r->mlen += len;

    /* 2. key */
    mbuf = msg_ensure_mbuf(r, keylen);
    if (mbuf == NULL) {
        return RMT_ENOMEM;
    }

    kpos = array_push(r->keys);
    if (kpos == NULL) {
        return RMT_ENOMEM;
    }

    kpos->start = mbuf->last;
    kpos->end = mbuf->last + keylen;
    mbuf_copy(mbuf, key, keylen);
    r->mlen += keylen;

    /* 3. CRLF */
    mbuf = msg_ensure_mbuf(r, CRLF_LEN);
    if (mbuf == NULL) {
        return RMT_ENOMEM;
    }
    mbuf_copy(mbuf, (uint8_t *)CRLF, CRLF_LEN);
    r->mlen += (uint32_t)CRLF_LEN;

    return RMT_OK;
}

int redis_append_bulk(struct msg *r, uint8_t *str, uint32_t str_len)
{
    int ret;
    uint32_t len;
    struct mbuf *mbuf;
    uint8_t printbuf[32];

    /* 1. str_len */
    len = (uint32_t)rmt_snprintf(printbuf, sizeof(printbuf), "$%u\r\n", str_len);
    ret = msg_append_full(r, (const uint8_t*)printbuf, len);
    if (ret != RMT_OK) {
        return RMT_ENOMEM;
    }

    /* 2. key */
    ret = msg_append_full(r, (const uint8_t*)str, str_len);
    if (ret != RMT_OK) {
        return RMT_ENOMEM;
    }

    /* 3. CRLF */
    ret = msg_append_full(r, (const uint8_t*)CRLF, CRLF_LEN);
    if (ret != RMT_OK) {
        return RMT_ENOMEM;
    }

    return RMT_OK;
}

/* This function just used the last position '\n' to get a bulk */
static void redis_erase_one_head_bulk(struct msg *msg)
{
    listNode *lnode, *nlnode;
    struct mbuf *mbuf;

    lnode = listFirst(msg->data);
    mbuf = listNodeValue(lnode);
    
    while (lnode != NULL) {
        while (lnode != NULL && mbuf->pos >= mbuf->last) {
            nlnode = listNextNode(lnode);

            mbuf_put(mbuf);
            listDelNode(msg->data, lnode);

            if (nlnode == NULL) return;
            
            lnode = nlnode;
            mbuf = listNodeValue(lnode);
            ASSERT(mbuf->pos == mbuf->start);
        }

        if (lnode == NULL) return;

        if (*(mbuf->pos) == '\n') {
            mbuf->pos ++;
            msg->mlen --;
            return;
        }

        mbuf->pos ++;
        msg->mlen --;
    }
}

/*
 * input a msg, return a msg chain.
 * ncontinuum is the number of backend redis/memcache server
 *
 * the original msg will be fragment into at most ncontinuum fragments.
 * all the keys map to the same backend will group into one fragment.
 *
 * frag_id:
 * a unique fragment id for all fragments of the message vector. including the orig msg.
 *
 * frag_owner:
 * All fragments of the message use frag_owner point to the orig msg
 *
 * frag_seq:
 * the map from each key to it's fragment, (only in the orig msg)
 *
 * For example, a message vector with 3 keys:
 *
 *     get key1 key2 key3
 *
 * suppose we have 2 backend server, and the map is:
 *
 *     key1  => backend 0
 *     key2  => backend 1
 *     key3  => backend 0
 *
 * it will fragment like this:
 *
 *   +-----------------+
 *   |  msg vector     |
 *   |(original msg)   |
 *   |key1, key2, key3 |
 *   +-----------------+
 *
 *                                             frag_owner
 *                        /--------------------------------------+
 *       frag_owner      /                                       |
 *     /-----------+    | /------------+ frag_owner              |
 *     |           |    | |            |                         |
 *     |           v    v v            |                         |
 *   +--------------------+     +---------------------+     +----+----------------+
 *   |   frag_id = 10     |     |   frag_id = 10      |     |   frag_id = 10      |
 *   |     nfrag = 3      |     |      nfrag = 0      |     |      nfrag = 0      |
 *   | frag_seq = x x x   |     |     key1, key3      |     |         key2        |
 *   +------------|-|-|---+     +---------------------+     +---------------------+
 *                | | |          ^    ^                          ^
 *                | \ \          |    |                          |
 *                |  \ ----------+    |                          |
 *                +---\---------------+                          |
 *                     ------------------------------------------+
 *
 */
static int redis_fragment_argx(redis_group *rgroup, 
    struct msg *r, uint32_t ncontinuum, list *frag_msgl, uint32_t key_step)
{
    int ret;
    rmtContext *ctx = rgroup->ctx;
    struct msg **sub_msgs;
    uint32_t i;

    ASSERT(array_n(r->keys) == (r->narg - 1) / key_step);

    sub_msgs = rmt_zalloc(ncontinuum * sizeof(*sub_msgs));
    if (sub_msgs == NULL) {
        log_error("ERROR: Out of memory");
        return RMT_ENOMEM;
    }

    ASSERT(r->frag_seq == NULL);
    r->frag_seq = rmt_alloc(array_n(r->keys) * sizeof(*r->frag_seq));
    if (r->frag_seq == NULL) {
        rmt_free(sub_msgs);
        log_error("ERROR: Out of memory");
        return RMT_ENOMEM;
    }

    for (i = 0; i < 3; i++) {           /* eat *narg\r\n$4\r\nMGET\r\n */
        redis_erase_one_head_bulk(r);
    }

    r->frag_id = msg_gen_frag_id();
    r->nfrag = 0;
    r->frag_owner = r;
    for (i = 0; i < array_n(r->keys); i++) {        /* for each key */
        struct msg *sub_msg;
        struct keypos *kpos = array_get(r->keys, i);

        if (ctx->filter != NULL && !stringmatchlen(ctx->filter, sdslen(ctx->filter), 
            kpos->start, (int)(kpos->end - kpos->start), 0)) {
            if (key_step == 1) {                            /* mget,del */
                /* do nothing */
            } else {                                        /* mset */
                ret = redis_copy_bulk(NULL, r);             /* eat key */
                if (ret != RMT_OK) {
                    rmt_free(sub_msgs);
                    log_error("ERROR: Eat key for mset failed");
                    return ret;
                }

                ret = redis_copy_bulk(NULL, r);
                if (ret != RMT_OK) {
                    rmt_free(sub_msgs);
                    log_error("ERROR: Eat value for mset failed");
                    return ret;
                }
            }
            continue;
        }
        
        uint32_t idx = rgroup->get_backend_idx(rgroup, kpos->start, (uint32_t)(kpos->end - kpos->start));

        if (sub_msgs[idx] == NULL) {
            sub_msgs[idx] = msg_get(r->mb, r->request, REDIS_DATA_TYPE_CMD);
            if (sub_msgs[idx] == NULL) {
                rmt_free(sub_msgs);
                log_error("ERROR: Out of memory");
                return RMT_ENOMEM;
            }
        }
        r->frag_seq[i] = sub_msg = sub_msgs[idx];

        sub_msg->narg++;
        ret = redis_append_key(sub_msg, kpos->start, (uint32_t)(kpos->end - kpos->start));
        if (ret != RMT_OK) {
            rmt_free(sub_msgs);
            log_error("ERROR: Msg append redis key failed");
            return ret;
        }

        if (key_step == 1) {                            /* mget,del */
            continue;
        } else {                                        /* mset */
            ret = redis_copy_bulk(NULL, r);             /* eat key */
            if (ret != RMT_OK) {
                rmt_free(sub_msgs);
                log_error("ERROR: Eat key for mset failed");
                return ret;
            }

            ret = redis_copy_bulk(sub_msg, r);
            if (ret != RMT_OK) {
                rmt_free(sub_msgs);
                log_error("ERROR: Msg append bulk failed");
                return ret;
            }

            sub_msg->narg++;
        }
    }

    if (key_step == 2) {
        ASSERT(r->mlen == 0);
    }

    for (i = 0; i < ncontinuum; i++) {     /* prepend mget header, and forward it */
        struct msg *sub_msg = sub_msgs[i];
        if (sub_msg == NULL) {
            continue;
        }
        
        if (r->type == MSG_REQ_REDIS_MGET) {
            ret = msg_prepend_format(sub_msg, "*%d\r\n$4\r\nmget\r\n",
                                        sub_msg->narg + 1);
        } else if (r->type == MSG_REQ_REDIS_DEL) {
            ret = msg_prepend_format(sub_msg, "*%d\r\n$3\r\ndel\r\n",
                                        sub_msg->narg + 1);
        } else if (r->type == MSG_REQ_REDIS_MSET) {
            ret = msg_prepend_format(sub_msg, "*%d\r\n$4\r\nmset\r\n",
                                        sub_msg->narg + 1);
        } else if (r->type == MSG_REQ_REDIS_MSETNX) {
            ret = msg_prepend_format(sub_msg, "*%d\r\n$6\r\nmsetnx\r\n",
                                        sub_msg->narg + 1);
        } else {
            ret = RMT_ERROR;
            NOT_REACHED();
        }
        if (ret != RMT_OK) {
            rmt_free(sub_msgs);
            log_error("ERROR: Msg prepend command head failed");
            return ret;
        }

        sub_msg->type = r->type;
        sub_msg->frag_id = r->frag_id;
        sub_msg->frag_owner = r->frag_owner;
        sub_msg->noreply = r->noreply;

        listAddNodeTail(frag_msgl, sub_msg);
        r->nfrag++;
    }

    rmt_free(sub_msgs);
    return RMT_OK;
}

int redis_fragment(redis_group *rgroup, 
    struct msg *r, uint32_t ncontinuum, list *frag_msgl)
{
    switch (r->type) {
    case MSG_REQ_REDIS_MGET:
    case MSG_REQ_REDIS_DEL:
        return redis_fragment_argx(rgroup, r, ncontinuum, frag_msgl, 1);
    case MSG_REQ_REDIS_MSET:
    case MSG_REQ_REDIS_MSETNX:
        return redis_fragment_argx(rgroup, r, ncontinuum, frag_msgl, 2);
    default:
        return RMT_OK;
    }
}

int redis_reply(struct msg *r)
{
    struct msg *response = r->peer;

    ASSERT(response != NULL);

    if (r->type == MSG_REQ_REDIS_AUTH) {
        return 0;
    }

    switch (r->type) {
    case MSG_REQ_REDIS_PING:
        return msg_append(response, (uint8_t *)REDIS_REPLY_STATUS_PONG, 
            rmt_strlen(REDIS_REPLY_STATUS_PONG));

    default:
        NOT_REACHED();
        return RMT_ERROR;
    }
}

static void redis_post_coalesce_mset(struct msg *request)
{
    int ret;
    struct msg *response = request->peer;

    ret = msg_append(response, (uint8_t *)REDIS_REPLY_STATUS_OK, 
        rmt_strlen(REDIS_REPLY_STATUS_OK));
    if (ret != RMT_OK) {
        response->err = errno;
    }
}

static void redis_post_coalesce_del(struct msg *request)
{
    int ret;
    struct msg *response = request->peer;

    ret = msg_prepend_format(response, ":%d\r\n", request->integer);
    if (ret != RMT_OK) {
        response->err = errno;
    }
}

static void redis_post_coalesce_mget(struct msg *request)
{
    int ret;
    struct msg *response = request->peer;
    struct msg *sub_msg;
    uint32_t i;

    ret = msg_prepend_format(response, "*%d\r\n", request->narg - 1);
    if (ret != RMT_OK) {
        /*
         * the fragments is still in c_conn->omsg_q, we have to discard all of them,
         * we just close the conn here
         */
        //response->owner->err = 1;
        return;
    }

    for (i = 0; i < array_n(request->keys); i++) {      /* for each key */
        sub_msg = request->frag_seq[i]->peer;           /* get it's peer response */
        if (sub_msg == NULL) {
            //response->owner->err = 1;
            return;
        }
        ret = redis_copy_bulk(response, sub_msg);
        if (ret != RMT_OK) {
            //response->owner->err = 1;
            return;
        }
    }
}

/*
 * Post-coalesce handler is invoked when the message is a response to
 * the fragmented multi vector request - 'mget' or 'del' and all the
 * responses to the fragmented request vector has been received and
 * the fragmented request is consider to be done
 */
void redis_post_coalesce(struct msg *r)
{
    struct msg *pr = r->peer; /* peer response */

    ASSERT(!pr->request);
    ASSERT(r->request && (r->frag_owner == r));
    if (r->error || r->ferror) {
        /* do nothing, if msg is in error */
        return;
    }

    switch (r->type) {
    case MSG_REQ_REDIS_MGET:
        return redis_post_coalesce_mget(r);
    case MSG_REQ_REDIS_DEL:
        return redis_post_coalesce_del(r);
    case MSG_REQ_REDIS_MSET:
    case MSG_REQ_REDIS_MSETNX:
        return redis_post_coalesce_mset(r);
    default:
        NOT_REACHED();
    }
}

char *
get_redis_type_string(int type)
{
    switch (type) {
    case REDIS_STRING:
        return "string";
        break;
    case REDIS_LIST:
        return "list";
        break;
    case REDIS_SET:
        return "set";
        break;
    case REDIS_ZSET:
        return "zset";
        break;
    case REDIS_HASH:
        return "hash";
        break;
    default:
        return "unknow";
        break;
    }

    return "unknow";
}

/* ========================== Redis RDB ============================ */

void
redis_parse_req_rdb(struct msg *r)
{
    struct mbuf *b;
    
    enum {
        RDB_START,
        RDB_MAGIC,
        RDB_VERSION,
        RDB_TYPE,
        RDB_EXPIRETIME,
        RDB_EXPIRETIME_MS,
        RDB_SELECTDB,
        RDB_KEY,
        RDB_VALUE,
        RDB_SENTINEL
    } state;

    b = listLastValue(r->data);
    state = r->state;

    ASSERT(r->request);
    ASSERT(state < RDB_SENTINEL);
    ASSERT(b != NULL);
    ASSERT(b->pos <= b->last);

    /* validate the parsing maker */
    ASSERT(r->pos != NULL);
    ASSERT(r->pos >= b->pos && r->pos <= b->last);

    while(1){
    switch (state) {
    case RDB_START:
        
        break;
    case RDB_MAGIC:
        
        
        break;
    case RDB_VERSION:

        break;

    default:
        NOT_REACHED();
        break;
    }
    }

    r->pos = b->last;    
    r->state = state;
    
    if (r->token != NULL) {
        r->pos = r->token;
        r->token = NULL;
        r->result = MSG_PARSE_REPAIR;
    } else {
        r->result = MSG_PARSE_AGAIN;
    }

    log_hexdump(LOG_VERB, b->pos, mbuf_length(b), "parsed req %"PRIu64" res %d "
                "type %d state %d rpos %d of %d", r->id, r->result, r->type,
                r->state, r->pos - b->pos, b->last - b->pos);
    return;
}

sds redis_msg_response_get_bulk_string(struct msg *msg)
{
    sds str;
    listNode *lnode;
    struct mbuf *mbuf;
    uint32_t len, len_left;
    uint8_t *pos;
    int find = 0;

    if (msg == NULL || listLength(msg->data) == 0) {
        return NULL;
    }

    pos = msg->bulk_start;
    if (pos == NULL) {
        log_error("ERROR: bulk start in msg is NULL.");
        return NULL;
    }
    len_left = msg->bulk_len;
    lnode = listFirst(msg->data);
    while (lnode) {
        mbuf = listNodeValue(lnode);
        if (pos >= mbuf->pos && pos < mbuf->last) {
            find = 1;
            break;
        }

        lnode = lnode->next;
    }

    if (find == 0) {
        log_error("ERROR: can't find the correct position[%p] in msg.", pos);
        return NULL;
    }

    str = sdsempty();

    len = MIN(len_left, mbuf->last - pos);
    str = sdscatlen(str, pos, len);
    len_left -= len;
    lnode = lnode->next;
    
    while (lnode && len_left > 0) {
        mbuf = listNodeValue(lnode);
        len = MIN(len_left, mbuf_length(mbuf));
        str = sdscatlen(str, mbuf->pos, len);
        len_left -= len;
        lnode = lnode->next;
    }

    return str;
}

int redis_msg_append_multi_bulk_len_full(struct msg *msg, uint32_t integer)
{
    int ret;
    sds str;
    
    if (msg == NULL) {
        return RMT_ERROR;
    }

    str = sdsfromlonglong((long long)integer);
    if (str == NULL) {
        return RMT_ENOMEM;
    }

    ret = msg_append_full(msg, (const uint8_t*)"*", 1);
    if (ret != RMT_OK) {
        sdsfree(str);
        return RMT_ENOMEM;
    }

    ret = msg_append_full(msg, (const uint8_t*)str, sdslen(str));
    if (ret != RMT_OK) {
        sdsfree(str);
        return RMT_ENOMEM;
    }

    ret = msg_append_full(msg, (const uint8_t*)CRLF, CRLF_LEN);
    if (ret != RMT_OK) {
        sdsfree(str);
        return RMT_ENOMEM;
    }

    sdsfree(str);
    
    return RMT_OK;
}

int redis_msg_append_bulk_full(struct msg *msg, const char *str, uint32_t len)
{
    int ret;
    sds len_str;
    
    if (msg == NULL || str == NULL) {
        return RMT_ERROR;
    }

    ret = msg_append_full(msg, (const uint8_t*)"$", 1);
    if (ret != RMT_OK) {
        return RMT_ENOMEM;
    }

    len_str = sdsfromlonglong((long long)len);
    if (len_str == NULL) {
        return RMT_ENOMEM;
    }

    ret = msg_append_full(msg, (const uint8_t*)len_str, sdslen(len_str));
    if (ret != RMT_OK) {
        sdsfree(len_str);
        return RMT_ENOMEM;
    }

    sdsfree(len_str);

    ret = msg_append_full(msg, (const uint8_t*)CRLF, CRLF_LEN);
    if (ret != RMT_OK) {
       return RMT_ENOMEM;
    }

    ret = msg_append_full(msg, (const uint8_t*)str, len);
    if (ret != RMT_OK) {
        return RMT_ENOMEM;
    }

    ret = msg_append_full(msg, (const uint8_t*)CRLF, CRLF_LEN);
    if (ret != RMT_OK) {
       return RMT_ENOMEM;
    }

    return RMT_OK;
}

int redis_msg_append_command_full(struct msg * msg, ...)
{
    int ret;
    char *arg;
    va_list ap;
    uint32_t count;

    count = 0;
    va_start(ap,msg);
    while(1) {
        arg = va_arg(ap, char*);
        if (arg == NULL) break;
        count ++;
    }
    va_end(ap);

    ret = redis_msg_append_multi_bulk_len_full(msg, count);
    if (ret != RMT_OK) {
        log_error("ERROR: msg append multi bulk len failed.");
        return RMT_ERROR;
    }
    
    va_start(ap,msg);
    while(1) {
        arg = va_arg(ap, char*);
        if (arg == NULL) break;
        ret = redis_msg_append_bulk_full(msg, arg, (uint32_t)strlen(arg));
        if (ret != RMT_OK) {
            log_error("ERROR: msg append multi bulk failed.");
            va_end(ap);
            return RMT_ERROR;
        }
    }
    va_end(ap);

    return RMT_OK;
}

/* sds in args */
int redis_msg_append_command_full_safe(struct msg * msg, struct array *args)
{
    int ret;
    sds *arg;
    uint32_t j, count;

    count = array_n(args);

    ret = redis_msg_append_multi_bulk_len_full(msg, count);
    if (ret != RMT_OK) {
        log_error("ERROR: msg append multi bulk len failed.");
        return RMT_ERROR;
    }

    for (j = 0; j < count; j ++) {
        arg = array_get(args, j);
        ret = redis_msg_append_bulk_full(msg, *arg, (uint32_t)sdslen(*arg));
        if (ret != RMT_OK) {
            log_error("ERROR: msg append multi bulk failed.");
            return RMT_ERROR;
        }
    }

    return RMT_OK;
}

struct msg *redis_generate_msg_with_key_value(rmtContext *ctx, mbuf_base *mb, 
    int data_type, sds key, struct array *value, int expiretime_type, sds expiretime)
{
    int ret;
    struct msg *msg, *msg_owner;
    uint32_t sub_msg_count;
    uint32_t i, start, end;
    uint32_t left_values, field_count;
    sds *elem;

    RMT_NOTUSED(mb);
    RMT_NOTUSED(data_type);
    RMT_NOTUSED(key);
    RMT_NOTUSED(value);
    RMT_NOTUSED(expiretime_type);
    RMT_NOTUSED(expiretime);

    start = 0;
    msg_owner = NULL;
    msg = NULL;
    sub_msg_count = 0;

    if(array_n(value) > REDIS_MAX_ELEMS_PER_COMMAND - 2){
        sub_msg_count = array_n(value)/(REDIS_MAX_ELEMS_PER_COMMAND - 2);
        ASSERT(sub_msg_count > 0);
        if(array_n(value)%(REDIS_MAX_ELEMS_PER_COMMAND - 2) > 0){
            sub_msg_count ++;
        }
        
        msg_owner = msg_get(mb, 1, REDIS_DATA_TYPE_RDB);
        if(msg_owner == NULL){
            goto enomem;
        }

        msg_owner->nfrag = 0;
        msg_owner->frag_seq = rmt_alloc(sub_msg_count * sizeof(msg));
        if(msg_owner->frag_seq == NULL){
            goto enomem;
        }
    }

next:

    msg = msg_get(mb, 1, REDIS_DATA_TYPE_RDB);
    if(msg == NULL){
        goto enomem;
    }

    left_values = array_n(value) - start;

    if(left_values > REDIS_MAX_ELEMS_PER_COMMAND - 2){
        field_count = 1 + 1 + REDIS_MAX_ELEMS_PER_COMMAND - 2;
        end = start + REDIS_MAX_ELEMS_PER_COMMAND - 2;
    }else{
        field_count = 1 + 1 + left_values;
        end = start + left_values;
    }

    log_debug(LOG_DEBUG, "start: %u, end: %u, field_count: %u, left_values: %u", 
        start, end, field_count, left_values);
    
    ret = redis_msg_append_multi_bulk_len_full(msg, field_count);
    if(ret != RMT_OK){
        log_error("ERROR: Redis msg append bulk len %lld error.",
            field_count);
        if(ret == RMT_ENOMEM){
            goto enomem;
        }
        
        goto error;
    }

    switch (data_type)
    {
    case REDIS_STRING:
        ASSERT(array_n(value) == 1);
        ret = redis_msg_append_bulk_full(msg, REDIS_INSERT_STRING, 
            rmt_strlen(REDIS_INSERT_STRING));
        msg->type = MSG_REQ_REDIS_SET;
        break;
    case REDIS_LIST:
        ret = redis_msg_append_bulk_full(msg, REDIS_INSERT_LIST, 
            rmt_strlen(REDIS_INSERT_LIST));
        msg->type = MSG_REQ_REDIS_LPUSH;
        break;
    case REDIS_SET:
        ret = redis_msg_append_bulk_full(msg, REDIS_INSERT_SET, 
            rmt_strlen(REDIS_INSERT_SET));
        msg->type = MSG_REQ_REDIS_SADD;
        break;
    case REDIS_ZSET:
        ret = redis_msg_append_bulk_full(msg, REDIS_INSERT_ZSET, 
            rmt_strlen(REDIS_INSERT_ZSET));
        msg->type = MSG_REQ_REDIS_ZADD;
        break;
    case REDIS_HASH:
        ret = redis_msg_append_bulk_full(msg, REDIS_INSERT_HASH, 
            rmt_strlen(REDIS_INSERT_HASH));
        msg->type = MSG_REQ_REDIS_HMSET;
        break;
    default:
        NOT_REACHED();
        ret = RMT_ERROR;
        break;
    }

    if(ret != RMT_OK){
        log_error("ERROR: Redis msg append bulk %s error.",
            msg_type_string(msg->type));
        if(ret == RMT_ENOMEM){
            goto enomem;
        }
        
        goto error;
    }

    ret = redis_msg_append_bulk_full(msg, key, (uint32_t)sdslen(key));
    if(ret != RMT_OK){
        log_error("ERROR: Redis msg append bulk key error.");
        if(ret == RMT_ENOMEM){
            goto enomem;
        }
        
        goto error;
    }
    
    for(i = start; i < end; i ++){
        elem = array_get(value, i);

        ret = redis_msg_append_bulk_full(msg, *elem, (uint32_t)sdslen(*elem));
        if(ret != RMT_OK){
            log_error("ERROR: Redis msg append bulk the %d value error(key is %.*s).", 
                i, (uint32_t)sdslen(key), key);
            if(ret == RMT_ENOMEM){
                goto enomem;
            }
            
            goto error;
        }
    }

    if(ctx->noreply){
        msg->noreply = 1;
    }

    if(msg_owner == NULL){
        return msg;
    }else{
        ASSERT(msg_owner->nfrag < sub_msg_count);
        msg_owner->frag_seq[msg_owner->nfrag] = msg;
        msg_owner->nfrag ++;
        msg = NULL;
    }

    if(end < array_n(value)){
        start = end;
        goto next;
    }

    ASSERT(msg_owner->nfrag == sub_msg_count);

    return msg_owner;
    
enomem:
    log_error("ERROR: Out of memory");
    
error: 

    if(msg != NULL){
        msg_put(msg);
        msg_free(msg);
    }

    if(msg_owner != NULL){
        for (i = 0; i < msg_owner->nfrag; i ++) {
            msg_put(msg_owner->frag_seq[i]);
            msg_free(msg_owner->frag_seq[i]);
        }
        msg_put(msg_owner);
        msg_free(msg_owner);
    }

    return NULL;
}

struct msg *redis_generate_msg_with_key_expire(rmtContext *ctx, mbuf_base *mb, 
    sds key, int expiretime_type, sds expiretime)
{
    int ret;
    struct msg *msg = NULL;
    long long field_count;
    
    msg = msg_get(mb, 1, REDIS_DATA_TYPE_RDB);
    if(msg == NULL)
    {
        goto enomem;
    }

    field_count = 3;
    
    ret = redis_msg_append_multi_bulk_len_full(msg, field_count);
    if(ret != RMT_OK)
    {
        goto error;
    }

    if(expiretime_type == RMT_TIME_SECOND)
    {
        ret = redis_msg_append_bulk_full(msg, "EXPIREAT", 8);
    }
    else if(expiretime_type == RMT_TIME_MILLISECOND)
    {
        ret = redis_msg_append_bulk_full(msg, "PEXPIREAT", 9);
    }
    else
    {
        NOT_REACHED();
        ret = RMT_ERROR;
    }

    if(ret != RMT_OK)
    {
        goto error;
    }

    ret = redis_msg_append_bulk_full(msg, key, (uint32_t)sdslen(key));
    if(ret != RMT_OK)
    {
        goto error;
    }

    ret = redis_msg_append_bulk_full(msg, expiretime, (uint32_t)sdslen(expiretime));
    if(ret != RMT_OK)
    {
        goto error;
    }

    if(ctx->noreply){
        msg->noreply = 1;
    }
    
    return msg;

enomem:
    log_error("ERROR: Out of memory");
    
error: 

    if(msg != NULL)
    {
        msg_put(msg);
        msg_free(msg);
    }

    return NULL;

}

struct array *redis_value_create(uint32_t nelem)
{
    struct array *value;

    value = array_create(nelem, sizeof(sds));
    if(value == NULL)
    {
        return NULL;
    }
    
    return value;
}

void redis_value_destroy(struct array *value)
{
    sds *str;
    
    if(value == NULL)
    {
        return;
    }

    while(array_n(value) > 0)
    {
        str = array_pop(value);
        if(*str == NULL) continue;
        sdsfree(*str);
    }

    array_destroy(value);
}

void
redis_rdb_update_checksum(redis_rdb *rdb, 
    const void *buf, size_t len)
{
    rdb->cksum = hash_crc64(rdb->cksum,buf,len);
}

static int redis_rdb_file_read(redis_rdb *rdb, void *buf, size_t len)
{
    if (rmt_fread(rdb->fp, buf, len) != len){
        return RMT_ERROR;
    }

    if(rdb->update_cksum)
    {
        rdb->update_cksum(rdb, buf, len);
    }

    return RMT_OK;
}

static uint32_t redis_rdb_file_load_len(redis_rdb *rdb, int *isencoded)
{
    unsigned char buf[2];
    uint32_t len;
    int type;
    
    if(rdb->fp == NULL)
    {
        return REDIS_RDB_LENERR;
    }

    if (isencoded){
        *isencoded = 0;
    }
    
    if(redis_rdb_file_read(rdb, buf, 1) != RMT_OK){
        return REDIS_RDB_LENERR;
    }
    
    type = (buf[0]&0xC0)>>6;
    if (type == REDIS_RDB_ENCVAL) {
        /* Read a 6 bit encoding type. */
        if (isencoded) *isencoded = 1;
        return buf[0]&0x3F;
    } else if (type == REDIS_RDB_6BITLEN) {
        /* Read a 6 bit len. */
        return buf[0]&0x3F;
    } else if (type == REDIS_RDB_14BITLEN) {
        /* Read a 14 bit len. */
        if (redis_rdb_file_read(rdb, buf+1, 1) != RMT_OK){
            return REDIS_RDB_LENERR;
        }

        return (uint32_t)(((buf[0]&0x3F)<<8)|buf[1]);
    } else {
        /* Read a 32 bit len. */
        if (redis_rdb_file_read(rdb, &len, 4) != RMT_OK){
            return REDIS_RDB_LENERR;
        }

        return ntohl(len);
    }
}

/* Loads an integer-encoded object with the specified encoding type "enctype".
 * If the "encode" argument is set the function may return an integer-encoded
 * string object, otherwise it always returns a raw string object. */
static long long redis_rdb_file_load_int(redis_rdb *rdb, int enctype) {
    unsigned char enc[4];
    long long val;

    if (enctype == REDIS_RDB_ENC_INT8) {
        if (redis_rdb_file_read(rdb,enc,1) != RMT_OK) return 0;
        val = (signed char)enc[0];
    } else if (enctype == REDIS_RDB_ENC_INT16) {
        uint16_t v;
        if (redis_rdb_file_read(rdb,enc,2) != RMT_OK) return 0;
        v = (uint32_t)(enc[0]|(enc[1]<<8));
        val = (int16_t)v;
    } else if (enctype == REDIS_RDB_ENC_INT32) {
        uint32_t v;
        if (redis_rdb_file_read(rdb,enc,4) != RMT_OK) return 0;
        v = (uint32_t)(enc[0]|(enc[1]<<8)|(enc[2]<<16)|(enc[3]<<24));
        val = (int32_t)v;
    } else {
        val = 0; /* anti-warning */
        log_error("ERROR: Unknown RDB integer encoding type");
    }

    return val;
}

static sds redis_rdb_file_load_double_str(redis_rdb *rdb) {
    char buf[256];
    unsigned char len;

    if (redis_rdb_file_read(rdb,&len,1) != RMT_OK) return NULL;
    switch(len) {
    case 255: return NULL;  //need to handle later
    case 254: return NULL;  //need to handle later
    case 253: return sdsnew("0");
    default:
        if (redis_rdb_file_read(rdb,buf,len) != RMT_OK) return NULL;
        return sdsnewlen(buf, len);
    }
}

static sds redis_rdb_file_load_lzf_str(redis_rdb *rdb) {
    unsigned int len, clen;
    unsigned char *c = NULL;
    sds val = NULL;

    if ((clen = redis_rdb_file_load_len(rdb,NULL)) == REDIS_RDB_LENERR) return NULL;
    if ((len = redis_rdb_file_load_len(rdb,NULL)) == REDIS_RDB_LENERR) return NULL;
    if ((c = rmt_alloc(clen)) == NULL) goto err;
    if ((val = sdsnewlen(NULL,len)) == NULL) goto err;
    if (redis_rdb_file_read(rdb,c,clen) != RMT_OK) goto err;
    if (lzf_decompress(c,clen,val,len) == 0) goto err;
    rmt_free(c);
    return val;
err:
    rmt_free(c);
    sdsfree(val);
    return NULL;
}

static sds redis_rdb_file_load_str(redis_rdb *rdb)
{
    int isencoded;
    uint32_t len;
    sds str;

    if((len = redis_rdb_file_load_len(rdb, &isencoded)) 
        == REDIS_RDB_LENERR)
    {
        log_error("ERROR: Short read or OOM loading DB. Unrecoverable error, aborting now.");
        return NULL;
    }

    if (isencoded) {
        switch(len) {
        case REDIS_RDB_ENC_INT8:
        case REDIS_RDB_ENC_INT16:
        case REDIS_RDB_ENC_INT32:
            return sdsfromlonglong(redis_rdb_file_load_int(rdb, (int)len));
            break;
        case REDIS_RDB_ENC_LZF:
            return redis_rdb_file_load_lzf_str(rdb);
            break;
        default:
            log_error("ERROR: Unknown RDB encoding type %"PRIu32"", len);
            return NULL;
            break;
        }
    }

    str = sdsnewlen(NULL, len);
    if(str == NULL)
    {
        log_error("ERROR: Out of memory");
        return NULL;
    }

    if(redis_rdb_file_read(rdb, str, len) != RMT_OK){
        log_error("ERROR: Short read or OOM loading DB. Unrecoverable error, aborting now.");
        return NULL;
    }

    return str;
}

static struct array *redis_rdb_file_load_value(redis_rdb *rdb, int rdbtype)
{
    struct array *value;
    sds *str;
    sds elem1, elem2, elems;
    size_t len;
    uint32_t i;

    str = NULL;
    value = NULL;
    elems = NULL;

    log_debug(LOG_DEBUG, "rdbtype: %d", rdbtype);

    if (rdbtype == REDIS_RDB_TYPE_STRING) {
        value = redis_value_create(1);
        if(value == NULL)
        {
            log_error("ERROR: Out of memory");
            goto error;
        }

        str = array_push(value);
        if((*str = redis_rdb_file_load_str(rdb)) == NULL){
            goto error;
        }

    }else if (rdbtype == REDIS_RDB_TYPE_LIST || 
        rdbtype == REDIS_RDB_TYPE_SET) {
        if ((len = redis_rdb_file_load_len(rdb,NULL)) 
            == REDIS_RDB_LENERR) goto error;

        value = redis_value_create((uint32_t)len);
        if(value == NULL)
        {
            log_error("ERROR: Out of memory");
            goto error;
        }
        
        while(len--) {
            str = array_push(value);
            if ((*str = redis_rdb_file_load_str(rdb)) == NULL) goto error;
        }
    }else if (rdbtype == REDIS_RDB_TYPE_ZSET) {
        if ((len = redis_rdb_file_load_len(rdb,NULL)) == REDIS_RDB_LENERR) goto error;

        value = redis_value_create((uint32_t)(2*len));
        if (value == NULL) {
            log_error("ERROR: Out of memory");
            goto error;
        }
        
        while(len--) {
            if ((elem1 = redis_rdb_file_load_str(rdb)) == NULL) goto error;
            if ((elem2 = redis_rdb_file_load_double_str(rdb)) == NULL) {
                sdsfree(elem1);
                goto error;
            }

            str = array_push(value);
            *str = elem2;
            ASSERT(sdsIsNum(*str) == 1);
            str = array_push(value);
            *str = elem1;
        }
    }else if (rdbtype == REDIS_RDB_TYPE_HASH) {
        if ((len = redis_rdb_file_load_len(rdb,NULL)) == REDIS_RDB_LENERR) goto error;

        value = redis_value_create((uint32_t)(2*len));
        if(value == NULL)
        {
            log_error("ERROR: Out of memory");
            goto error;
        }

        while(len--) {
            str = array_push(value);
            if ((*str = redis_rdb_file_load_str(rdb)) == NULL) goto error;
            str = array_push(value);
            if ((*str = redis_rdb_file_load_str(rdb)) == NULL) goto error;
        }
    } else if (rdbtype == REDIS_RDB_TYPE_LIST_QUICKLIST) {
        if ((len = redis_rdb_file_load_len(rdb,NULL)) == REDIS_RDB_LENERR) goto error;

        value = redis_value_create((uint32_t)(len));
        if (value == NULL) {
            log_error("ERROR: Out of memory");
            goto error;
        }

        while (len--) {
            unsigned char *zl;
            unsigned int count;
            unsigned char *eptr, *sptr;
            unsigned char *vstr;
            unsigned int vlen;
            long long vlong;

            zl = redis_rdb_file_load_str(rdb);
            
            count = ziplistLen(zl);
            eptr = ziplistIndex(zl,0);
            while (eptr != NULL) {
                ziplistGet(eptr,&vstr,&vlen,&vlong);

                str = array_push(value);

                if (vstr == NULL) {
                    *str = sdsfromlonglong(vlong);
                } else {
                    *str = sdsnewlen(vstr, vlen);
                }
                
                eptr = ziplistNext(zl,eptr);
            }
        }
    } else if (rdbtype == REDIS_RDB_TYPE_HASH_ZIPMAP  ||
               rdbtype == REDIS_RDB_TYPE_LIST_ZIPLIST ||
               rdbtype == REDIS_RDB_TYPE_SET_INTSET   ||
               rdbtype == REDIS_RDB_TYPE_ZSET_ZIPLIST ||
               rdbtype == REDIS_RDB_TYPE_HASH_ZIPLIST) {
        if ((elems = redis_rdb_file_load_str(rdb)) == NULL) goto error;

        switch(rdbtype) {
        case REDIS_RDB_TYPE_HASH_ZIPMAP:
        {
            unsigned char * zm = (unsigned char *)elems;
            unsigned char *zi = zipmapRewind(zm);
            unsigned char *fstr, *vstr;
            unsigned int flen, vlen;
            
            len = zipmapLen(zm);
            
            value = redis_value_create((uint32_t)(2*len));
            if (value == NULL) {
                log_error("ERROR: Out of memory");
                goto error;
            }

            while ((zi = zipmapNext(zi, &fstr, &flen, &vstr, &vlen)) != NULL) {
                str = array_push(value);
                *str = sdsnewlen(fstr, flen);

                str = array_push(value);
                *str = sdsnewlen(vstr, vlen);
            }
            
            break;
        }
        case REDIS_RDB_TYPE_LIST_ZIPLIST:
        case REDIS_RDB_TYPE_HASH_ZIPLIST:
        {
            unsigned char *zl = (unsigned char *)elems;
            unsigned char *eptr, *sptr;
            unsigned char *vstr;
            unsigned int vlen;
            long long vlong;
            
            len = ziplistLen(zl);
            if (rdbtype == REDIS_RDB_TYPE_HASH_ZIPLIST && len%2 != 0) {
                log_error("ERROR: hash value length from rdb must be an even number");
                goto error;
            }

            value = redis_value_create((uint32_t)len);
            if (value == NULL) {
                log_error("ERROR: Out of memory");
                goto error;
            }

            eptr = ziplistIndex(zl,0);
            
            while (eptr != NULL) {
                ziplistGet(eptr,&vstr,&vlen,&vlong);

                str = array_push(value);

                if (vstr == NULL) {
                    *str = sdsfromlonglong(vlong);
                } else {
                    *str = sdsnewlen(vstr, vlen);
                }
                
                eptr = ziplistNext(zl,eptr);
            }
            
            break;
        }
        case REDIS_RDB_TYPE_ZSET_ZIPLIST:
        {
            unsigned char *zl = (unsigned char *)elems;
            unsigned char *eptr, *sptr;
            unsigned char *vstr;
            unsigned int vlen;
            long long vlong;
            uint32_t k = 0;
            sds *score, *data;
            sds field;
            
            len = ziplistLen(zl);
            if (len%2 != 0) {
                log_error("ERROR: zset value length from rdb must be an even number");
                goto error;
            }

            value = redis_value_create((uint32_t)len);
            if (value == NULL) {
                log_error("ERROR: Out of memory");
                goto error;
            }

            eptr = ziplistIndex(zl,0);
            
            while (eptr != NULL) {
                ziplistGet(eptr,&vstr,&vlen,&vlong);

                if (vstr == NULL) {
                    field = sdsfromlonglong(vlong);
                } else {
                    field = sdsnewlen(vstr, vlen);
                }

                if (k%2 == 0) {
                    score = array_push(value);
                    data = array_push(value);

                    *data = field;
                } else {
                    *score = field;
                }
                
                eptr = ziplistNext(zl,eptr);
                k ++;
            }
            break;
        }
        case REDIS_RDB_TYPE_SET_INTSET:
        {
            intset *is = (intset *)elems;
            int64_t integer;
            
            len = intsetLen(is);

            value = redis_value_create((uint32_t)len);
            if (value == NULL) {
                log_error("ERROR: Out of memory");
                goto error;
            }

            for (i = 0; i < len; i ++) {
                if (intsetGet(is, i, &integer) == 0) {
                    log_error("ERROR: intset get failed");
                    goto error;
                }

                elem1 = sdsfromlonglong(integer);

                str = array_push(value);
                *str = elem1;
            }
            
            break;
        }
        default:
            NOT_REACHED();
            break;
        }

        sdsfree(elems);
    }else {
        
        log_error("ERROR: Unknown object type");
        goto error;
    }

    return value;

error:

    if(value != NULL)
    {
        redis_value_destroy(value);
    }

    if(elems != NULL)
    {
        sdsfree(elems);
    }

    return NULL;
}

static int redis_object_type_get_by_rdbtype(int dbtype)
{
    switch(dbtype)
    {
    case REDIS_RDB_TYPE_STRING:

        return REDIS_STRING;
        break;
    case REDIS_RDB_TYPE_LIST:
    case REDIS_RDB_TYPE_LIST_ZIPLIST:
    case REDIS_RDB_TYPE_LIST_QUICKLIST:

        return REDIS_LIST;
        break;
    case REDIS_RDB_TYPE_SET:
    case REDIS_RDB_TYPE_SET_INTSET:

        return REDIS_SET;
        break;
    case REDIS_RDB_TYPE_ZSET:
    case REDIS_RDB_TYPE_ZSET_ZIPLIST:
        
        return REDIS_ZSET;
        break;
    case REDIS_RDB_TYPE_HASH:
    case REDIS_RDB_TYPE_HASH_ZIPMAP:
    case REDIS_RDB_TYPE_HASH_ZIPLIST:
        
        return REDIS_HASH;
        break;
    default:
        
        return -1;
        break;
    }

    return -1;
}

void redis_delete_rdb_file(redis_rdb *rdb, int always)
{
    if (rdb == NULL) {
        return;
    }

    if (always) {
        goto del;
    }

    if (rdb->deleted) {
        goto del;
    }

    return;

del:
    if (rdb->fd > 0) {
        close(rdb->fd);
        rdb->fd = -1;
    }

    if (rdb->fp != NULL) {
        fclose(rdb->fp);
        rdb->fp = NULL;
    }

    if (rdb->fname != NULL) {
        unlink(rdb->fname);
        sdsfree(rdb->fname);
        rdb->fname = NULL;
    }
}

/*
  * return: 
  * -1 error
  * 0 no msg sent
  * >0 mbuf count sent 
  */
int redis_key_value_send(redis_node *srnode, sds key, 
    int data_type, struct array *value, 
    int expiretime_type, long long expiretime, 
    void *data)
{
    int ret;
    rmtContext *ctx = srnode->ctx;
    redis_group *srgroup = srnode->owner;
    mbuf_base *mb = srgroup->mb;
    redis_group *trgroup = data;
    long long now = rmt_msec_now();
    redis_node *trnode;
    sds expiretime_str = NULL;
    struct msg *msg = NULL;
    uint32_t i;
    int mbuf_count = 0;

    if (expiretime_type == RMT_TIME_SECOND) {
        if(expiretime * 1000 < now){
            return 0;
        }

        expiretime_str = sdsfromlonglong(expiretime);
    } else if(expiretime_type == RMT_TIME_MILLISECOND) {
        if (expiretime < now) {
            return 0;
        }

        expiretime_str = sdsfromlonglong(expiretime);
    }

    trnode = trgroup->get_backend_node(trgroup, (uint8_t *)key, (uint32_t)sdslen(key));
    if (trnode == NULL) {
        log_error("ERROR: Get key %s backend node is NULL", key);
        goto error;
    }

    msg = redis_generate_msg_with_key_value(ctx, mb, data_type, 
        key, value, expiretime_type, expiretime_str);
    if (msg == NULL) {
        log_error("ERROR: generate msg with key value failed");
        goto error;
    }

    if (msg->frag_seq == NULL) {
        mbuf_count += listLength(msg->data);
        ret = prepare_send_msg(srnode, msg, trnode);
        if (ret != RMT_OK) {
            log_error("ERROR: prepare send msg to node[%s] failed.", 
                trnode->addr);
            goto error;
        }
        msg = NULL;
    } else {
        for (i = 0; i < msg->nfrag; i ++) {
            mbuf_count += listLength(msg->frag_seq[i]->data);
            ret = prepare_send_msg(srnode, msg->frag_seq[i], trnode);
            if (ret != RMT_OK) {
                log_error("ERROR: prepare send msg to node[%s] failed.", 
                    trnode->addr);
                goto error;
            }
            msg->frag_seq[i] = NULL;
        }
        
        msg_put(msg);
        msg_free(msg);
        msg = NULL;
    }

    if (expiretime_type != RMT_TIME_NONE) {
        msg = redis_generate_msg_with_key_expire(ctx, mb, key, 
            expiretime_type, expiretime_str);
        if (msg == NULL) {
            log_error("ERROR: generate msg with key value failed");
            goto error;
        }

        ret = prepare_send_msg(srnode, msg, trnode);
        if (ret != RMT_OK) {
            log_error("ERROR: prepare send msg to node[%s] failed.", 
                trnode->addr);
            goto error;
        }

        mbuf_count += listLength(msg->data);
        msg = NULL;
    }

    return mbuf_count;
        
error:

    if (expiretime_str != NULL) {
        sdsfree(expiretime_str);
        expiretime_str = NULL;
    }

    if (msg != NULL) {
        if (msg->frag_seq!= NULL) {
            for (i = 0; i < msg->nfrag; i ++) {
                if (msg->frag_seq[i] != NULL) {
                    msg_put(msg->frag_seq[i]);
                    msg_free(msg->frag_seq[i]);
                    msg->frag_seq[i] = NULL;
                }
            }
        }
        msg_put(msg);
        msg_free(msg);
    }
    
    return -1;
}

int redis_parse_rdb_file(redis_node *srnode, int mbuf_count_one_time)
{
    int ret;
    uint32_t i;
    rmtContext *ctx = srnode->ctx;
    redis_rdb *rdb = srnode->rdb;
    thread_data *wdata = srnode->write_data;
    redis_group *srgroup = srnode->owner;
    redis_group *trgroup = wdata->trgroup;
    char buf[20];
    size_t len;
    uint32_t dbid;
    unsigned char type;
    int32_t t32;
    int64_t t64;
    long long expiretime = -1, now;
    int expiretime_type;
    sds key;
    struct array *value;
    int data_type;
    int mbuf_count, mbuf_count_max;

    ASSERT(rdb->type == REDIS_RDB_TYPE_FILE);

    key = NULL;
    value = NULL;
    mbuf_count = 0;
    mbuf_count_max = mbuf_count_one_time;

    enum {
        RDB_FILE_PARSE_START,
        RDB_FILE_PARSE_AGAIN,
        RDB_FILE_PARSE_END,
        SW_SENTINEL
    } state;

    state = rdb->state;

    if (state == RDB_FILE_PARSE_START) {
        if ((rdb->fp = fopen(rdb->fname,"r")) == NULL){
            log_error("ERROR: Open rdb file %s failed: %s", 
                rdb->fname, strerror(errno));
            goto error;
        }

        if (redis_rdb_file_read(rdb, buf, 9) != RMT_OK) {
            log_error("ERROR: redis rdb file %s read first 9 char error", 
                rdb->fname);
            goto eoferr;
        }
        
        len = rmt_strlen(REDIS_RDB_MAGIC_STR);
        if (memcmp(buf, REDIS_RDB_MAGIC_STR, len) != 0) {
            log_error("ERROR: Redis rdb file %s magic string is error: %.*s",
                rdb->fname, len, buf);
            goto error;
        }

        rdb->rdbver = rmt_atoi(buf+len, 4);
        if (rdb->rdbver < 1 || rdb->rdbver > REDIS_RDB_VERSION) {
            log_error("ERROR: Can't handle RDB format version %d",
                rdb->fname, rdb->rdbver);
            goto error;
        }

        rdb->state = RDB_FILE_PARSE_AGAIN;
    }

    while(1) {
        expiretime_type = RMT_TIME_NONE;
        data_type = -1;
        
        if (redis_rdb_file_read(rdb, &type, 1) != RMT_OK) {
            log_error("ERROR: redis rdb file %s read type error", 
                rdb->fname);
            goto eoferr;
        }

        if (type == REDIS_RDB_OPCODE_EXPIRETIME) {
            if (redis_rdb_file_read(rdb, (&t32), 4) != RMT_OK) {
                log_error("ERROR: redis rdb file %s read 4 expiretime error", 
                    rdb->fname);
                goto eoferr;
            }

            expiretime = (time_t)t32;
            
            if (redis_rdb_file_read(rdb, (unsigned char*)(&type), 1) != RMT_OK) {
                log_error("ERROR: redis rdb file %s read type error", 
                    rdb->fname);
                goto eoferr;
            }

            expiretime_type = RMT_TIME_SECOND;
        } else if (type == REDIS_RDB_OPCODE_EXPIRETIME_MS) {
            if (redis_rdb_file_read(rdb, (&t64), 8) != RMT_OK) {
                log_error("ERROR: redis rdb file %s read 8 expiretime error", 
                    rdb->fname);
                goto eoferr;
            }

            expiretime = (long long)t64;
            
            if (redis_rdb_file_read(rdb, (unsigned char*)(&type), 1) != RMT_OK) {
                log_error("ERROR: redis rdb file %s read type error", 
                    rdb->fname);
                goto eoferr;
            }

            expiretime_type = RMT_TIME_MILLISECOND;
        } else if (type == REDIS_RDB_OPCODE_EOF) {
            break;
        } else if (type == REDIS_RDB_OPCODE_SELECTDB) {
            if ((dbid = redis_rdb_file_load_len(rdb, NULL)) 
                == REDIS_RDB_LENERR) {
                log_error("ERROR: redis rdb file %s read db num error", 
                    rdb->fname);
                goto eoferr;
            }

            log_debug(LOG_INFO, "dbid: %d", dbid);
            continue;
        } else if (type == REDIS_RDB_OPCODE_RESIZEDB) {
            uint32_t db_size, expires_size;
            if ((db_size = redis_rdb_file_load_len(rdb, NULL)) 
                == REDIS_RDB_LENERR) {
                log_error("ERROR: redis rdb file %s read db num error", 
                    rdb->fname);
                goto eoferr;
            }
            if ((expires_size = redis_rdb_file_load_len(rdb, NULL)) 
                == REDIS_RDB_LENERR) {
                log_error("ERROR: redis rdb file %s read db num error", 
                    rdb->fname);
                goto eoferr;
            }
            continue;
        } else if (type == REDIS_RDB_OPCODE_AUX) {
            sds auxkey, auxval;
            if ((auxkey = redis_rdb_file_load_str(rdb)) == NULL) goto eoferr;
            if ((auxval = redis_rdb_file_load_str(rdb)) == NULL) {
                sdsfree(auxkey);
                goto eoferr;
            }
            sdsfree(auxkey);
            sdsfree(auxval);
            continue;
        }

        if ((key = redis_rdb_file_load_str(rdb)) == NULL) {
            log_error("ERROR: redis rdb file %s read key error", 
                rdb->fname);
            goto eoferr;
        }

        if ((value = redis_rdb_file_load_value(rdb, type)) == NULL) {
            log_error("ERROR: redis rdb file %s read value error", 
                rdb->fname);
            goto eoferr;
        }

        data_type = redis_object_type_get_by_rdbtype(type);
        if (data_type < 0) {
            log_error("ERROR: get redis object type by rdbtype failed");
            goto error;
        }

        log_debug(LOG_DEBUG, "key: %s, value array length: %u", 
            key, array_n(value));

        if (rdb->handler != NULL 
            && (srgroup->kind == GROUP_TYPE_SINGLE 
                || srgroup->get_backend_node == NULL 
                || (srgroup->distribution != DIST_RANDOM && srgroup->get_backend_node(srgroup, key, sdslen(key)) == srnode)
                || srgroup->distribution == DIST_RANDOM)
            && (ctx->filter == NULL 
                || stringmatchlen(ctx->filter, sdslen(ctx->filter), key, sdslen(key), 0))) {
            ret = rdb->handler(srnode, key, data_type, value, 
                expiretime_type, expiretime, trgroup);
            if (ret < 0) {
                goto error;
            }

            mbuf_count += ret;
        }
        
        sdsfree(key);
        key = NULL;
        redis_value_destroy(value);
        value = NULL;

        if (mbuf_count_max > 0 && mbuf_count >= mbuf_count_max) {
            goto again;
        }
    }

    if (rdb->rdbver >= 5 && rdb->update_cksum) {
        uint64_t cksum, expected = rdb->cksum;
        if (redis_rdb_file_read(rdb,&cksum,8) != RMT_OK) goto eoferr;

        memrev64ifbe(&cksum);
        if (cksum == 0) {
            log_warn("RDB file was saved with checksum disabled: no check performed.");
        } else if (cksum != expected) {
            log_warn("Wrong RDB checksum. Aborting now.");
            exit(1);
        }
    }

    rdb->state = RDB_FILE_PARSE_END;

    if (rdb->fp != NULL) {
        fclose(rdb->fp);
        rdb->fp = NULL;
    }

    now = rmt_msec_now();
    log_notice("Rdb file for node[%s] parsed finished, use: %lld s.",
        srnode->addr, (now - srnode->timestamp)/1000);
    srnode->timestamp = now;

    redis_delete_rdb_file(rdb, 0);

    wdata->stat_rdb_parsed_count ++;

    return RMT_OK;

again:

    return RMT_AGAIN;

eoferr: /* unexpected end of file is handled here with a fatal exit */
    
    log_error("ERROR: Short read or OOM loading DB. Unrecoverable error, aborting now.");

error:

    if (rdb->fp != NULL) {
        fclose(rdb->fp);
        rdb->fp = NULL;
    }

    if (key != NULL) {
        sdsfree(key);
    }

    if (value != NULL) {
        redis_value_destroy(value);
    }

    redis_delete_rdb_file(rdb, 0);
    
    return RMT_ERROR;
}

int redis_parse_rdb_time(aeEventLoop *el, long long id, void *privdata)
{
    int ret;
    redis_node *srnode = privdata;
    thread_data *wdata = srnode->write_data;
    redis_rdb *rdb = srnode->rdb;

    ret = redis_parse_rdb_file(srnode, 10);
    if(ret == RMT_AGAIN){
        return 1;
    }else if(ret == RMT_OK){
        ret = aeCreateFileEvent(wdata->loop, srnode->sockpairfds[1], 
            AE_READABLE, parse_request, srnode);
        if(ret != AE_OK){
            log_error("ERROR: Create ae read event for node %s parse_request failed", 
                srnode->addr);
            return AE_NOMORE;
        }

        notice_write_thread(srnode);
    }else{
        log_error("ERROR: Rdb file for node[%s] parsed failed", srnode->addr);
    }

    return AE_NOMORE;
}

void redis_parse_rdb(aeEventLoop *el, int fd, void *privdata, int mask)
{
    int ret;
    redis_node *srnode = privdata;
    thread_data *wdata = srnode->write_data;
    redis_rdb *rdb = srnode->rdb;
    rmtContext *ctx = srnode->ctx;

    RMT_NOTUSED(el);
    RMT_NOTUSED(fd);
    RMT_NOTUSED(privdata);
    RMT_NOTUSED(mask);

    ASSERT(fd == srnode->sk_event);
    ASSERT(el == wdata->loop);

    ret = redis_parse_rdb_file(srnode, ctx->step);
    if(ret == RMT_AGAIN){
        return;
    } else if(ret == RMT_OK) {
        redis_group *srgroup = srnode->owner;
        
        aeDeleteFileEvent(wdata->loop, 
            srnode->sk_event, AE_WRITABLE);

        if (srgroup->kind == GROUP_TYPE_RDBFILE) {
            return;
        }

        ret = aeCreateFileEvent(wdata->loop, srnode->sockpairfds[1], 
            AE_READABLE, parse_request, srnode);
        if(ret != AE_OK){
            log_error("ERROR: Create ae read event for node %s parse_request failed", 
                srnode->addr);
            return;
        }

        notice_write_thread(srnode);

        //notice the read thread to begin replication for the next redis_node
        if (srnode->next != NULL) {
            rmt_write(srnode->next->sockpairfds[1], " ", 1);
        } else {
            log_notice("All nodes' rdb file parsed finished for this write thread(%d).",
                wdata->id);
            ASSERT(wdata->stat_rdb_parsed_count == wdata->nodes_count);
        }
    }else{
        aeDeleteFileEvent(wdata->loop, 
            srnode->sk_event, AE_WRITABLE);
        log_error("ERROR: Rdb file for node[%s] parsed failed", srnode->addr);
    }

    close(srnode->sk_event);
    srnode->sk_event = -1;
}
/* ======================== Redis RDB END ========================== */

/* ======================== Redis AOF ========================== */

int redis_load_aof_file(redis_node *srnode, char *aof_file)
{
    int ret;
    rmtContext *ctx = srnode->ctx;
    redis_group *srgroup = srnode->owner;
    thread_data *rdata = srnode->read_data;
    int fd = -1;
    size_t len;
    ssize_t nread;

    fd = open(aof_file, O_RDONLY);
    if (fd < 0) {
        log_error("ERROR: open %s failed: %s", 
            aof_file, strerror(errno));
        return RMT_ERROR;
    }    
    
    while (1) {
        if (srnode->mbuf_in == NULL) {
            srnode->mbuf_in = mbuf_get(srgroup->mb);
            if (srnode->mbuf_in == NULL) {
                log_error("ERROR: Mbuf get failed: Out of memory");
                return RMT_ERROR;
            }
        } else if(mbuf_size(srnode->mbuf_in) == 0) {
            mttlist_push(srnode->cmd_data, srnode->mbuf_in);
            srnode->mbuf_in = NULL;
            notice_write_thread(srnode);

            srnode->mbuf_in = mbuf_get(srgroup->mb);
            if (srnode->mbuf_in == NULL) {
                log_error("ERROR: Mbuf get failed: Out of memory");
                return RMT_ERROR;
            }
        }
        
        len = mbuf_size(srnode->mbuf_in);
        nread = read(fd, srnode->mbuf_in->last, len);
        if (nread > 0) {
            srnode->mbuf_in->last += nread;
        }
        
        if (nread == 0 || nread < len) {
            rdata->stat_aof_loaded_count ++;
            
            if (mbuf_length(srnode->mbuf_in) > 0) {
                mttlist_push(srnode->cmd_data, srnode->mbuf_in);
                srnode->mbuf_in = NULL;
                notice_write_thread(srnode);
            }

            log_notice("Aof file %s load finished", aof_file);
            break;
        }

        if (nread < 0) {
            log_error("ERROR: read data from %s failed: %s", 
                aof_file, strerror(errno));
            close(fd);
            return RMT_ERROR;
        }

        usleep(100/ctx->step);
    }

    close(fd);
    return RMT_OK;
}

/* ======================== Redis AOF END ========================== */

/* ========================== Redis Cluster ============================ */

/* We have 16384 hash slots. The hash slot of a given key is obtained
 * as the least significant 14 bits of the crc16 of the key.
 *
 * However if the key contains the {...} pattern, only the part between
 * { and } is hashed. This may be useful in the future to force certain
 * keys to be in the same node (assuming no resharding is in progress). */
static unsigned int clusterKeyHashSlot(char *key, int keylen) {
    int s, e; /* start-end indexes of { and } */

    for (s = 0; s < keylen; s++)
        if (key[s] == '{') break;

    /* No '{' ? Hash the whole key. This is the base case. */
    if (s == keylen) return hash_crc16(key,(size_t)keylen) & 0x3FFF;

    /* '{' found? Check if we have the corresponding '}'. */
    for (e = s+1; e < keylen; e++)
        if (key[e] == '}') break;

    /* No '}' or nothing betweeen {} ? Hash the whole key. */
    if (e == keylen || e == s+1) return hash_crc16(key,(size_t)keylen) & 0x3FFF;

    /* If we are here there is both a { and a } on its right. Hash
     * what is in the middle between { and }. */
    return hash_crc16(key+s+1,(size_t)(e-s-1)) & 0x3FFF;
}

static void cluster_nodes_swap_tc(dict *nodes_f, dict *nodes_t)
{
    dictIterator *di;
    dictEntry *de_f, *de_t;
    redis_node *node_f, *node_t;
    tcp_context *tc;

    if(nodes_f == NULL || nodes_t == NULL)
    {
        return;
    }

    di = dictGetIterator(nodes_t);
    while((de_t = dictNext(di)) != NULL)
    {
        node_t = dictGetVal(de_t);
        if(node_t == NULL)
        {
            continue;
        }
        
        de_f = dictFind(nodes_f, node_t->addr);
        if(de_f == NULL)
        {
            continue;
        }

        node_f = dictGetVal(de_f);
        if(node_f->tc != NULL)
        {
            tc = node_f->tc;
            node_f->tc = node_t->tc;
            node_t->tc = tc;
        }

    }

    dictReleaseIterator(di);
    
}

static ssize_t rmt_redis_sync_read_string(int fd, char *ptr, long long timeout) {
    ssize_t size = 0;
    char c;

    if (rmt_sync_read(fd,&c,1,timeout) == -1) return -1;
    
    if (c != '$') {
        errno = ENOPROTOOPT;
        return -1;
    }

    do {
        if (rmt_sync_read(fd,&c,1,timeout) == -1) return -1;

        if (isdigit(c)) {
            size = size * 10 + (ssize_t)(c - '0');
        } else if(c != CR) {
            errno = ENOPROTOOPT;
            return -1;
        }           
    } while(isdigit(c));

    if (rmt_sync_read(fd,&c,1,timeout) == -1) return -1;
    if (c != LF) {
        errno = ENOPROTOOPT;
        return -1;
    }

    if (rmt_sync_read(fd,ptr,size,timeout) == -1) return -1;

    if (rmt_sync_read(fd,&c,1,timeout) == -1) return -1;
    if (c != CR) {
        errno = ENOPROTOOPT;
        return -1;
    }

    if (rmt_sync_read(fd,&c,1,timeout) == -1) return -1;
    if (c != LF) {
        errno = ENOPROTOOPT;
        return -1;
    }

    return size;
}


/**
  * Update route with the "cluster nodes" command reply.
  */
static int cluster_update_route_with_nodes(
    redis_group *rgroup, redis_node *node)
{
    int ret;
    tcp_context *tc = NULL;
    char *buf = NULL;
    int buf_len = 0;
    struct array *table = NULL;
    redis_node *master, **trnode;
    dict *nodes = NULL;
    char *pos, *start, *end, *line_start, *line_end;
    char *role;
    int role_len;
    uint8_t myself = 0;
    int slot_start, slot_end;
    sds *part = NULL, *slot_start_end = NULL;
    int count_part = 0, count_slot_start_end = 0;
    int j, k;
    int len;

    if(rgroup == NULL){
        return RMT_ERROR;
    }

    tc = rmt_tcp_context_create();
    if(tc == NULL){
        log_error("ERROR: create tcp_context failed: out of memory");
        goto error;
    }

    tc->flags |= RMT_BLOCK;    
    ret = rmt_tcp_context_connect_addr(tc, node->addr, 
        (int)rmt_strlen(node->addr), NULL, NULL);
    if(ret != RMT_OK){
        log_error("ERROR: connect to %s failed", node->addr);
        goto error;
    }

    buf = rmt_alloc(102400*sizeof(*buf));
    if(buf == NULL){
        log_error("ERROR: out of memory");
        goto error;
    }

    if (rgroup->password) {
        sds reply;
        reply = rmt_send_sync_cmd_read_line(tc->sd, "auth", rgroup->password, NULL);
        if (sdslen(reply) == 0 || reply[0] == '-') {
            log_error("ERROR: password to %s is wrong", node->addr);
            sdsfree(reply);
            goto error;
        }
        sdsfree(reply);
    }

    if (rmt_sync_write(tc->sd,REDIS_COMMAND_CLUSTER_NODES,
        rmt_strlen(REDIS_COMMAND_CLUSTER_NODES),1000) == -1){
        log_error("ERROR: send to %s for command '%s' failed", 
            node->addr, "CLUSTER NODES");
        goto error;
    }

    /* Read the reply from the server. */
    if ((buf_len = (int)rmt_redis_sync_read_string(tc->sd,buf,1000)) == -1){
        log_error("ERROR: read from %s for command '%s' failed: %s", 
            node->addr, "CLUSTER NODES", strerror(errno));
        goto error;
    }

    log_debug(LOG_DEBUG, "nodes info %d : %.*s", buf_len, buf_len, buf);

    nodes = dictCreate(&groupNodesDictType, NULL);
    if(nodes == NULL){
        log_error("ERROR: create nodes dict failed: out of memory");
        goto error;
    }

    table = array_create(REDIS_CLUSTER_SLOTS, sizeof(redis_node *));
    if(table == NULL){
        log_error("ERROR: create cluster route table array failed: out of memory");
        goto error;
    }

    for(j = 0; j < REDIS_CLUSTER_SLOTS; j ++){
        trnode = array_push(table);
        *trnode = NULL;
    }

    start = buf;
    end = start + buf_len;
    
    line_start = start;

    for(pos = start; pos < end; pos ++){
        if(*pos == '\n'){
            line_end = pos - 1;
            len = (int)(line_end - line_start);
            
            part = sdssplitlen(line_start, len + 1, " ", 1, &count_part);

            if(part == NULL || count_part < 8){
                log_error("ERROR: split cluster nodes error");
                goto error;
            }

            //the address string is ":0", skip this node.
            if(sdslen(part[1]) == 2 && strcmp(part[1], ":0") == 0){
                sdsfreesplitres(part, count_part);
                count_part = 0;
                part = NULL;
                
                start = pos + 1;
                line_start = start;
                pos = start;
                
                continue;
            }

            if(sdslen(part[2]) >= 7 && memcmp(part[2], "myself,", 7) == 0){
                role_len = (int)sdslen(part[2]) - 7;
                role = part[2] + 7;
                myself = 1;
            }else{
                role_len = (int)sdslen(part[2]);
                role = part[2];
            }

            //add master node
            if(role_len >= 6 && memcmp(role, "master", 6) == 0){
                if(count_part < 8){
                    log_error("ERROR: master node part number error");
                    goto error;
                }
                
                master = rmt_alloc(sizeof(*master));
                if(master == NULL){
                    log_error("ERROR: out of memory");
                    goto error;
                }

                ret = redis_node_init(master, part[1], rgroup);
                if(ret != RMT_OK){
                    log_error("ERROR: target redis node init failed");
                    goto error;
                }

                ret = dictAdd(nodes, sdsnewlen(master->addr, 
                    sdslen(master->addr)), master);
                if(ret != DICT_OK){
                    log_error("ERROR: the address already exists in the nodes");
                    redis_node_deinit(master);
                    rmt_free(master);
                    goto error;
                }
                
                for(k = 8; k < count_part; k ++){
                    slot_start_end = sdssplitlen(part[k], 
                        (int)sdslen(part[k]), "-", 1, &count_slot_start_end);
                    
                    if(slot_start_end == NULL){
                        log_error("ERROR: split slot start end error(NULL)");
                        goto error;
                    }else if(count_slot_start_end == 1){
                        slot_start = 
                            rmt_atoi(slot_start_end[0], sdslen(slot_start_end[0]));
                        slot_end = slot_start;
                    }else if(count_slot_start_end == 2){
                        slot_start = 
                            rmt_atoi(slot_start_end[0], sdslen(slot_start_end[0]));;
                        slot_end = 
                            rmt_atoi(slot_start_end[1], sdslen(slot_start_end[1]));;
                    }else{
                        slot_start = -1;
                        slot_end = -1;
                    }
                    
                    sdsfreesplitres(slot_start_end, count_slot_start_end);
                    count_slot_start_end = 0;
                    slot_start_end = NULL;

                    if(slot_start < 0 || slot_end < 0 || 
                        slot_start > slot_end || slot_end >= REDIS_CLUSTER_SLOTS){
                        continue;
                    }

                    for(j = slot_start; j <= slot_end; j ++){
                        trnode = array_get(table, (uint32_t)j);
                        if(*trnode != NULL){
                            log_error("ERROR: nodes %s and %s hold a same slot %d",
                                (*trnode)->addr, master->addr, j);
                            goto error;
                        }
                        
                        *trnode = master;
                    }
                    
                }

            }

            if(myself == 1){
                myself = 0;
            }

            sdsfreesplitres(part, count_part);
            count_part = 0;
            part = NULL;
            
            start = pos + 1;
            line_start = start;
            pos = start;
        }
    }

    cluster_nodes_swap_tc(rgroup->nodes, nodes);

    if(rgroup->nodes != NULL){
        dictRelease(rgroup->nodes);
        rgroup->nodes = NULL;
    }
    
    rgroup->nodes = nodes;

    if(rgroup->route != NULL){
        rgroup->route->nelem = 0;
        array_destroy(rgroup->route);
        rgroup->route = NULL;
    }

    rgroup->route = table;

    if(tc != NULL){
        rmt_tcp_context_destroy(tc);
    }

    if(buf != NULL){
        rmt_free(buf);
    }
    
    return RMT_OK;

error:

    if(tc != NULL){
        rmt_tcp_context_destroy(tc);
    }

    if(buf != NULL){
        rmt_free(buf);
    }
    
    if(part != NULL){
        sdsfreesplitres(part, count_part);
        count_part = 0;
        part = NULL;
    }

    if(slot_start_end != NULL){
        sdsfreesplitres(slot_start_end, count_slot_start_end);
        count_slot_start_end = 0;
        slot_start_end = NULL;
    }

    if(nodes != NULL){
        if(nodes == rgroup->nodes){
            rgroup->nodes = NULL;
        }

        dictRelease(nodes);
    }

    if(table != NULL){
        if(table == rgroup->route){
            rgroup->route = NULL;
        }
    
        rgroup->route->nelem = 0;
        array_destroy(table);
    }
    
    return RMT_ERROR;
}

static int cluster_update_route(redis_group *rgroup)
{
    int ret;
    redis_node *node;
    dictIterator *it;
    dictEntry *de;
    
    if(rgroup == NULL){
        return RMT_ERROR;
    }

    if(rgroup->nodes == NULL){
        log_error("ERROR: redis_group->nodes is NULL");
        return RMT_ERROR;
    }

    it = dictGetSafeIterator(rgroup->nodes);
    while ((de = dictNext(it)) != NULL){
        node = dictGetVal(de);
        if(node == NULL){
            continue;
        }

        ret = cluster_update_route_with_nodes(rgroup, node);
        if(ret == RMT_OK){
            dictReleaseIterator(it);
            return RMT_OK;
        }
    }
    dictReleaseIterator(it);

    log_error("ERROR: no valid server address in the target redis cluster");

    return RMT_ERROR;
}

redis_node * 
redis_group_add_node(redis_group *rgroup, const char *name, const char *addr)
{
    int ret;
    dictEntry *node_entry;
    redis_node *node;
    
    if(rgroup == NULL){
        return NULL;
    }

    if(rgroup->nodes == NULL){
        rgroup->nodes = dictCreate(&groupNodesDictType, NULL);
        if(rgroup->nodes == NULL){
            log_error("ERROR: Create nodes dict failed");
            return NULL;
        }
    }

    node_entry = dictFind(rgroup->nodes, name);
    if(node_entry != NULL){
        log_error("ERROR: Add node to redis group failed: node %s already exits",
            name);
        return NULL;
    }
    
    node = rmt_alloc(sizeof(*node));
    if(node == NULL){
        log_error("ERROR: create redis_node failed: out of memory");
        return NULL;
    }

    ret = redis_node_init(node, addr, rgroup);
    if(ret != RMT_OK){
        log_error("ERROR: Redis node init failed");
        rmt_free(node);
        return NULL;
    }

    dictAdd(rgroup->nodes, sdsnewlen(name, rmt_strlen(name)), node);
    
    return node;
}

int redis_cluster_init_from_addrs(redis_group *rgroup, const char *addrs)
{
    int ret;
    int i;
    sds *address = NULL;
    int address_count = 0;
    
    if(rgroup == NULL || addrs == NULL){
        return RMT_ERROR;
    }

    address = sdssplitlen(addrs, (int)rmt_strlen(addrs), ADDRESS_SEPARATOR, 
        (int)rmt_strlen(ADDRESS_SEPARATOR), &address_count);
    if(address == NULL || address_count <= 0){
        log_error("ERROR: Redis cluster address is error");
        goto error;
    }

    for(i = 0; i < address_count; i ++){
        if(redis_group_add_node(rgroup, 
            address[i], address[i]) == NULL){
            log_error("ERROR: Redis group add node[%s] failed", 
                address[i]);
            goto error;
        }
    }

    sdsfreesplitres(address, address_count);
    
    ret = cluster_update_route(rgroup);
    if(ret != RMT_OK){
        return ret;
    }
    
    return RMT_OK;

error:

    if(address != NULL){
        sdsfreesplitres(address, address_count);
    }

    return RMT_ERROR;
}

int redis_cluster_init_from_conf(redis_group *rgroup, conf_pool *cp)
{
    int ret;
    uint32_t i;
    sds *str;
    
    if(rgroup == NULL || cp == NULL || 
        cp->servers == NULL){
        return RMT_ERROR;
    }

    for(i = 0; i < array_n(cp->servers); i ++){
        str = array_get(cp->servers, i);
        if(redis_group_add_node(rgroup, *str, *str) == NULL)
        {
            log_error("ERROR: Redis group add node[%s] failed", 
                *str);
            return RMT_ERROR;
        }
    }
    
    ret = cluster_update_route(rgroup);
    if(ret != RMT_OK){
        return ret;
    }
    
    return RMT_OK;
}

uint32_t 
redis_cluster_backend_idx(redis_group *rgroup, uint8_t *key, uint32_t keylen)
{
    uint32_t idx;

    RMT_NOTUSED(rgroup);
    RMT_NOTUSED(key);
    RMT_NOTUSED(keylen);
    
    idx = clusterKeyHashSlot((char *)key, (int)keylen);

    return idx;
}

redis_node *
redis_cluster_backend_node(redis_group *rgroup, uint8_t *key, uint32_t keylen)
{
    uint32_t idx;
    redis_node **node;
    
    RMT_NOTUSED(rgroup);
    RMT_NOTUSED(key);
    RMT_NOTUSED(keylen);

    idx = redis_cluster_backend_idx(rgroup, key, keylen);

    ASSERT(idx < array_n(rgroup->route));

    node = array_get(rgroup->route, idx);
    return *node;
}

/* ======================== Redis Cluster END ========================== */

/* ======================== Redis Single ========================== */

int 
redis_single_init_from_conf(redis_group *rgroup, conf_pool *cp)
{
    uint32_t i;
    sds *str;
    redis_node *rnode = NULL, **node;

    RMT_NOTUSED(rgroup);
    RMT_NOTUSED(cp);

    if(rgroup == NULL || cp == NULL || 
        cp->servers == NULL){
        return RMT_ERROR;
    }
    
    for(i = 0; i < array_n(cp->servers); i ++){
        str = array_get(cp->servers, i);
        rnode = redis_group_add_node(rgroup, *str, *str);
        if(rnode == NULL)
        {
            log_error("ERROR: Redis group add node[%s] failed", 
                *str);
            return RMT_ERROR;
        }
    }

    if(rnode == NULL){
        log_error("ERROR: No servers in the conf file");
        return RMT_ERROR;
    }

    // Only the target group used route for single type, 
    // and now we just allowed one server exits for 
    // target group for single type.
    ASSERT(rgroup->route == NULL);
    rgroup->route = array_create(1, sizeof(redis_node *));
    if(rgroup->route == NULL){
        log_error("ERROR: Create single route failed: out of memory");
        return RMT_ENOMEM;
    }

    node = array_push(rgroup->route);
    *node = rnode;

    return RMT_OK;
}

uint32_t 
redis_single_backend_idx(redis_group *rgroup, uint8_t *key, uint32_t keylen)
{
    RMT_NOTUSED(rgroup);
    RMT_NOTUSED(key);
    RMT_NOTUSED(keylen);

    return 0;
}

redis_node *
redis_single_backend_node(redis_group *rgroup, uint8_t *key, uint32_t keylen)
{
    uint32_t node_count;
    redis_node **rnode;
    
    RMT_NOTUSED(rgroup);
    RMT_NOTUSED(key);
    RMT_NOTUSED(keylen);

    ASSERT(rgroup->nodes != NULL && rgroup->route != NULL);
    
    node_count = array_n(rgroup->route);
    ASSERT(node_count == 1);

    rnode = array_get(rgroup->route, 0);
    
    return *rnode;
}


/* ======================== Redis Single END ========================== */

/* ======================== Redis Twemproxy ========================== */

static uint32_t
redis_twem_ketama_hash(const char *key, size_t key_length, uint32_t alignment)
{
    unsigned char results[16];

    md5_signature((unsigned char*)key, key_length, results);

    return ((uint32_t) (results[3 + alignment * 4] & 0xFF) << 24)
        | ((uint32_t) (results[2 + alignment * 4] & 0xFF) << 16)
        | ((uint32_t) (results[1 + alignment * 4] & 0xFF) << 8)
        | (results[0 + alignment * 4] & 0xFF);
}

static int
redis_twem_ketama_item_cmp(const void *t1, const void *t2)
{
    const struct continuum *ct1 = t1, *ct2 = t2;

    if (ct1->value == ct2->value) {
        return 0;
    } else if (ct1->value > ct2->value) {
        return 1;
    } else {
        return -1;
    }
}

static int 
redis_twem_init_route_with_ketama(redis_group *rgroup, struct array *nodes, uint32_t total_weight)
{
    struct node_twem *node;
    struct continuum *continuum;
    uint32_t node_count;
    uint32_t server_index;
    uint32_t continuum_addition;  /* extra space in the continuum */
    uint32_t points_per_server;   /* points per server */
    uint32_t nserver_continuum;
    uint32_t ncontinuum;
    uint32_t pointer_per_hash;    /* pointers per hash */    
    uint32_t pointer_per_server;  /* pointers per server proportional to weight */
    uint32_t pointer_counter;     /* # pointers on continuum */
    uint32_t continuum_index;     /* continuum index */
    uint32_t pointer_index;       /* pointer index */
    uint32_t value;               /* continuum value */
    float pct;

    node_count = array_n(nodes);
    ASSERT(node_count > 0);

    continuum_addition = TWEM_KETAMA_CONTINUUM_ADDITION;
    points_per_server = TWEM_KETAMA_POINTS_PER_SERVER;
    
    nserver_continuum = node_count + continuum_addition;
    ncontinuum = nserver_continuum * points_per_server;

    ASSERT(rgroup->route == NULL);
    rgroup->route = array_create(ncontinuum, sizeof(struct continuum));
    if(rgroup->route == NULL){
        log_error("ERROR: Create twemproxy route failed: out of memory");
        return RMT_ENOMEM;
    }
 
    pointer_counter = 0;
    for(server_index = 0; server_index < node_count; server_index ++){
        node = array_get(nodes, server_index);
        
        pct = (float)node->weight / (float)total_weight;
        pointer_per_server = (uint32_t)((floorf((float) (pct * TWEM_KETAMA_POINTS_PER_SERVER / 4 * (float)node_count + 0.0000000001))) * 4);
        pointer_per_hash = 4;

        for (pointer_index = 1;
             pointer_index <= pointer_per_server / pointer_per_hash;
             pointer_index++) {

            char host[TWEM_KETAMA_MAX_HOSTLEN]= "";
            size_t hostlen;
            uint32_t x;

            hostlen = snprintf(host, TWEM_KETAMA_MAX_HOSTLEN, "%.*s-%u",
                               (int)sdslen(node->name), node->name,
                               (pointer_index - 1));
            
            for (x = 0; x < pointer_per_hash; x++) {
                value = redis_twem_ketama_hash(host, hostlen, x); 
                continuum = array_push(rgroup->route); 
                continuum->index = server_index;
                continuum->value = value;
                continuum->node = node->node; 
            }
        }
 
        pointer_counter += pointer_per_server;
    }
    
    for(continuum_index = 0; continuum_index < array_n(rgroup->route); continuum_index ++){
        continuum = array_get(rgroup->route, continuum_index);
        log_debug(LOG_DEBUG,"%u: %u, %u, %d", continuum_index, continuum->index, continuum->value, continuum->node);
    }

    log_debug(LOG_DEBUG, "pointer_counter: %u", pointer_counter);

    rgroup->ncontinuum = pointer_counter;
    array_sort(rgroup->route,redis_twem_ketama_item_cmp);
    
    return RMT_OK;
}

static int 
redis_twem_init_route_with_modula(redis_group *rgroup, struct array *nodes, uint32_t total_weight)
{
    struct node_twem *node;
    struct continuum *continuum;
    uint32_t node_count;
    uint32_t pointer_per_server;  /* pointers per server proportional to weight */
    uint32_t pointer_counter;     /* # pointers on continuum */
    uint32_t points_per_server;   /* points per server */
    uint32_t continuum_index;     /* continuum index */
    uint32_t continuum_addition;  /* extra space in the continuum */
    uint32_t server_index;        /* server index */
    uint32_t weight_index;        /* weight index */
    uint32_t nserver_continuum;
    uint32_t ncontinuum;
    
    RMT_NOTUSED(rgroup);
    RMT_NOTUSED(nodes);
    RMT_NOTUSED(total_weight);

    node_count = array_n(nodes);
    ASSERT(node_count > 0);

    continuum_addition = TWEM_MODULA_CONTINUUM_ADDITION;
    points_per_server = TWEM_MODULA_POINTS_PER_SERVER;

    nserver_continuum = total_weight + TWEM_MODULA_CONTINUUM_ADDITION;
    ncontinuum = nserver_continuum *  TWEM_MODULA_POINTS_PER_SERVER;

    ASSERT(rgroup->route == NULL);
    rgroup->route = array_create(ncontinuum, sizeof(struct continuum));
    if(rgroup->route == NULL){
        log_error("ERROR: Create twemproxy route failed: out of memory");
        return RMT_ENOMEM;
    }
    
    pointer_counter = 0;
    for (server_index = 0; server_index < node_count; server_index++) {
        node = array_get(nodes, server_index);

        for (weight_index = 0; weight_index < node->weight; weight_index++) {
            pointer_per_server = 1;            

            continuum = array_push(rgroup->route); 
            continuum->index = server_index;
            continuum->value = 0;
            continuum->node = node->node;

            pointer_counter += pointer_per_server;
        }
    }
    
    for(continuum_index = 0; continuum_index < array_n(rgroup->route); continuum_index ++){
        continuum = array_get(rgroup->route, continuum_index);
        log_debug(LOG_DEBUG,"%u: %u, %u, %d", continuum_index, continuum->index, continuum->value, continuum->node);
    }

    log_debug(LOG_DEBUG, "pointer_counter: %u", pointer_counter);
    
    rgroup->ncontinuum = pointer_counter;
    
    return RMT_OK;
}

static int 
redis_twem_init_route_with_random(redis_group *rgroup, struct array *nodes, uint32_t total_weight)
{   
    struct node_twem *node;
    struct continuum *continuum;
    uint32_t node_count;
    uint32_t pointer_per_server;  /* pointers per server proportional to weight */
    uint32_t pointer_counter;     /* # pointers on continuum */
    uint32_t points_per_server;   /* points per server */
    uint32_t continuum_index;     /* continuum index */
    uint32_t continuum_addition;  /* extra space in the continuum */
    uint32_t server_index;        /* server index */
    uint32_t nserver_continuum;
    uint32_t ncontinuum;
    
    RMT_NOTUSED(rgroup);
    RMT_NOTUSED(nodes);
    RMT_NOTUSED(total_weight);

    node_count = array_n(nodes);
    ASSERT(node_count > 0);
    
    continuum_addition = TWEM_RANDOM_CONTINUUM_ADDITION;
    points_per_server = TWEM_RANDOM_POINTS_PER_SERVER;

    nserver_continuum = node_count + TWEM_RANDOM_CONTINUUM_ADDITION;
    ncontinuum = nserver_continuum * TWEM_RANDOM_POINTS_PER_SERVER;

    ASSERT(rgroup->route == NULL);
    rgroup->route = array_create(ncontinuum, sizeof(struct continuum));
    if(rgroup->route == NULL){
        log_error("ERROR: Create twemproxy route failed: out of memory");
        return RMT_ENOMEM;
    }

    pointer_counter = 0;
    for (server_index = 0; server_index < node_count; server_index++) {
        node = array_get(nodes, server_index);
        
        pointer_per_server = 1;

        continuum = array_push(rgroup->route); 
        continuum->index = server_index;
        continuum->value = 0;
        continuum->node = node->node;

        pointer_counter += pointer_per_server;
    }

    for(continuum_index = 0; continuum_index < array_n(rgroup->route); continuum_index ++){
        continuum = array_get(rgroup->route, continuum_index);
        log_debug(LOG_DEBUG,"%u: %u, %u, %d", continuum_index, continuum->index, continuum->value, continuum->node);
    }

    log_debug(LOG_DEBUG, "pointer_counter: %u", pointer_counter);

    rgroup->ncontinuum = pointer_counter;

    return RMT_OK;
}

int 
redis_twem_init_from_conf(redis_group *rgroup, conf_pool *cp)
{
    int ret;
    uint32_t node_count;
    uint32_t i;
    uint32_t total_weight;        /* total live server weight */
    sds *str_server;
    sds *parts = NULL;
    int parts_count = 0;
    sds *ip_port_weight = NULL;
    int ip_port_weight_count = 0;
    struct array nodes;
    struct node_twem *node;
    
    ASSERT(cp->type == GROUP_TYPE_TWEM);

    RMT_NOTUSED(rgroup);
    RMT_NOTUSED(cp);

    array_null(&nodes);
    total_weight = 0;

    node_count = array_n(cp->servers);
    ASSERT(node_count > 0);

    ret = array_init(&nodes, node_count, sizeof(*node));
    if(ret != RMT_OK){
        log_error("ERROR: Init nodes array failed: out of memory");
        goto error;
    }
    
    for(i = 0; i < node_count; i++){
        node = array_push(&nodes);
        node->name = NULL;
        str_server = array_get(cp->servers, i);
        parts = sdssplitlen(*str_server,(int)sdslen(*str_server)," ",1,&parts_count);
        if(parts == NULL || parts_count == 0){
            log_error("ERROR: Server %s in twemproxy split by space error",
                *str_server);
            goto error;
        }

        if(parts_count == 1){
            node->name = sdsempty(); /*set node name latter*/
        }else if(parts_count == 2){
            node->name = parts[1];
            parts[1] = NULL;
        }else{
            log_error("ERROR: Server %s in twemproxy split by space error",
                *str_server);
            goto error;
        }

        ip_port_weight = sdssplitlen(parts[0],(int)sdslen(parts[0]),
            ":", 1, &ip_port_weight_count);
        if(ip_port_weight == NULL || ip_port_weight_count != 3){
            log_error("ERROR: Server %s in twemproxy split by : error",
                *str_server);
            goto error;
        }

        /* If there are no server name in the twemproxy conf, set 'host:port' as the node name. */
        if (parts_count == 1) {
            node->name = sdscatfmt(node->name, "%S:%S",ip_port_weight[0],ip_port_weight[1]);
        }

        node->weight = (uint32_t)rmt_atoi(ip_port_weight[2],sdslen(ip_port_weight[2]));
        total_weight += node->weight;
        
        //trim the weight
        sdsrange(parts[0],0,sdslen(ip_port_weight[0]) + 
            sdslen(ip_port_weight[1]) - sdslen(parts[0]));
        
        node->node = redis_group_add_node(rgroup, node->name, parts[0]);
        if(node->node == NULL){
            log_error("ERROR: Redis group add node[%s] failed", 
                parts[0]);
            goto error;
        }

        sdsfreesplitres(ip_port_weight, ip_port_weight_count);
        ip_port_weight = NULL;
        sdsfreesplitres(parts, parts_count);
        parts = NULL;
    }

    rgroup->distribution = cp->distribution;

    switch(cp->distribution){
    case DIST_KETAMA:
        ret = redis_twem_init_route_with_ketama(rgroup, &nodes, total_weight);
        break;
    case DIST_MODULA:
        ret = redis_twem_init_route_with_modula(rgroup, &nodes, total_weight);
        break;
    case DIST_RANDOM:
        ret = redis_twem_init_route_with_random(rgroup, &nodes, total_weight);
        break;
    default:
        log_error("ERROR: Unknow distribution");
        goto error;
        break;
    }

    if(ret != RMT_OK){
        log_error("ERROR: Init route table failed");
        goto error;
    }

    while(array_n(&nodes) > 0){
        node = array_pop(&nodes);
        sdsfree(node->name);
    }
    array_deinit(&nodes);

    return RMT_OK;

error:

    if(parts != NULL){
        sdsfreesplitres(parts, parts_count);
    }

    if(ip_port_weight != NULL){
        sdsfreesplitres(ip_port_weight, ip_port_weight_count);
    }

    while(array_n(&nodes) > 0){
        node = array_pop(&nodes);
        if (node->name) sdsfree(node->name);
    }
    array_deinit(&nodes);
    
    return RMT_ERROR;
}

static uint32_t
redis_twem_ketama_dispatch(struct array *continuums, uint32_t ncontinuum, uint32_t hash)
{
    uint32_t begin, end, left, right, middle;
    struct continuum *continuum_m;

    RMT_NOTUSED(continuums);
    RMT_NOTUSED(ncontinuum);
    RMT_NOTUSED(hash);

    ASSERT(continuums != NULL);
    ASSERT(ncontinuum != 0);

    begin = left = 0;
    end = right = ncontinuum;

    while (left < right) {
        middle = left + (right - left) / 2;
        continuum_m = array_get(continuums, middle);
        if (continuum_m->value < hash) {
          left = middle + 1;
        } else {
          right = middle;
        }
    }

    if (right == end) {
        right = begin;
    }

    return right;
}

static uint32_t
redis_twem_modula_dispatch(struct array *continuums, uint32_t ncontinuum, uint32_t hash)
{    
    RMT_NOTUSED(continuums);
    RMT_NOTUSED(ncontinuum);
    RMT_NOTUSED(hash);

    ASSERT(continuums != NULL);
    ASSERT(ncontinuum != 0);

    return hash % ncontinuum;
}

static uint32_t
redis_twem_random_dispatch(struct array *continuums, uint32_t ncontinuum, uint32_t hash)
{
    RMT_NOTUSED(continuums);
    RMT_NOTUSED(ncontinuum);
    RMT_NOTUSED(hash);

    ASSERT(continuums != NULL);
    ASSERT(ncontinuum != 0);

    return (uint32_t)(random() % ncontinuum);
}

uint32_t 
redis_twem_backend_idx(redis_group *rgroup, uint8_t *key, uint32_t keylen)
{
    uint32_t idx = 0, hash;
    int distribution = rgroup->distribution;//DIST_KETAMA;
    struct continuum *continuum;
    
    RMT_NOTUSED(rgroup);
    RMT_NOTUSED(key);
    RMT_NOTUSED(keylen);

    hash = rgroup->key_hash((char *)key, keylen);
    
    switch(distribution){
    case DIST_KETAMA:
        idx = redis_twem_ketama_dispatch(rgroup->route, rgroup->ncontinuum, hash);
        break;
    case DIST_MODULA:
        idx = redis_twem_modula_dispatch(rgroup->route, rgroup->ncontinuum, hash);
        break;
    case DIST_RANDOM:
        idx = redis_twem_random_dispatch(rgroup->route, rgroup->ncontinuum, hash);
        break;
    default:
        log_error("ERROR: Unknow distribution");
        NOT_REACHED();
        break;
    }

    continuum = array_get(rgroup->route, idx);
    
    return continuum->index;
}

redis_node *
redis_twem_backend_node(redis_group *rgroup, uint8_t *key, uint32_t keylen)
{
    uint32_t idx = 0, hash;
    int distribution = rgroup->distribution;//DIST_KETAMA;
    struct continuum *continuum;
    
    RMT_NOTUSED(rgroup);
    RMT_NOTUSED(key);
    RMT_NOTUSED(keylen);

    hash = rgroup->key_hash((char *)key, keylen);
    log_debug(LOG_DEBUG, "key %s hash : %u", key, hash);
    switch(distribution){
    case DIST_KETAMA:
        idx = redis_twem_ketama_dispatch(rgroup->route, rgroup->ncontinuum, hash);
        break;
    case DIST_MODULA:
        idx = redis_twem_modula_dispatch(rgroup->route, rgroup->ncontinuum, hash);
        break;
    case DIST_RANDOM:
        idx = redis_twem_random_dispatch(rgroup->route, rgroup->ncontinuum, hash);
        break;
    default:
        log_error("ERROR: Unknow distribution");
        NOT_REACHED();
        break;
    }

    log_debug(LOG_DEBUG, "key %s idx : %d", key, idx);
    
    continuum = array_get(rgroup->route, idx);

    return continuum->node;
}

/* ======================== Redis Twemproxy END ========================== */

/* ======================== Redis Rdb file ========================== */

int redis_rdb_file_init_from_conf(redis_group *rgroup, conf_pool *cp)
{
    int ret;
    uint32_t i;
    sds *str;
    
    if(rgroup == NULL || cp == NULL || 
        cp->servers == NULL){
        return RMT_ERROR;
    }
    
    for(i = 0; i < array_n(cp->servers); i ++){
        str = array_get(cp->servers, i);
        if(redis_group_add_node(rgroup, *str, *str) == NULL)
        {
            log_error("ERROR: Redis group add node[%s] failed", 
                *str);
            return RMT_ERROR;
        }
    }
    
    return RMT_OK;
}

/* ======================== Redis Rdb file END ========================== */

/* ======================== Redis Aof file ========================== */

int redis_aof_file_init_from_conf(redis_group *rgroup, conf_pool *cp)
{
    int ret;
    uint32_t i;
    sds *str;
    
    if(rgroup == NULL || cp == NULL || 
        cp->servers == NULL){
        return RMT_ERROR;
    }
    
    for(i = 0; i < array_n(cp->servers); i ++){
        str = array_get(cp->servers, i);
        if(redis_group_add_node(rgroup, *str, *str) == NULL)
        {
            log_error("ERROR: Redis group add node[%s] failed", 
                *str);
            return RMT_ERROR;
        }
    }
    
    return RMT_OK;
}

/* ======================== Redis Aof file END ========================== */

static int
get_char_from_mbuf_list(list *mbufs, listNode **node, uint8_t **pos, uint8_t *ch)
{
    struct mbuf *mbuf;
    
    if (mbufs == NULL || node == NULL || pos == NULL || ch == NULL) {
        return RMT_ERROR;
    }

    if (*node == NULL) {
        *node = listFirst(mbufs);
    }
    mbuf = listNodeValue(*node);

    if (*pos == NULL) {
        *pos = mbuf->start;
    }

    if (*pos < mbuf->start || *pos > mbuf->last) {
        log_debug(LOG_ERR, "ERROR: mbuf start: %p, mbuf last: %p, pos: %p", 
            mbuf->start, mbuf->last, *pos);
        return RMT_ERROR;
    }

    while (*pos == mbuf->last) {
        *node = (*node)->next;
        if (*node == NULL) {
            return RMT_ERROR;
        }

        mbuf = listNodeValue(*node);
        *pos = mbuf->start;
    }

    ch[0] = (*pos)[0];
    (*pos) ++;
    if (*pos > mbuf->last) {
        *node = (*node)->next;
        if (*node == NULL) {
            *pos = NULL;
            return RMT_OK;
        }

        mbuf = listNodeValue(*node);
        *pos = mbuf->start;
    }

    return RMT_OK;
}

static int
get_bulk_count_from_mbuf_list(list *mbufs, listNode **node, uint8_t **pos)
{
    struct mbuf *mbuf;
    uint8_t buf[1];
    int count = 0;
    
    if (mbufs == NULL || node == NULL || pos == NULL) {
        return -1;
    }

    if (*node == NULL) {
        *node = listFirst(mbufs);
    }
    mbuf = listNodeValue(*node);

    if (*pos == NULL) {
        *pos = mbuf->start;
    }

    if (*pos < mbuf->start || *pos > mbuf->last) {
        log_debug(LOG_ERR, "ERROR: mbuf start: %p, mbuf last: %p, pos: %p", 
            mbuf->start, mbuf->last, *pos);
        return -1;
    }

    if (get_char_from_mbuf_list(mbufs, node, pos, buf) != RMT_OK) {
        return -1;
    }
    if (buf[0] != '*') {
        return -1;
    }

    while (get_char_from_mbuf_list(mbufs, node, pos, buf) == RMT_OK) {
        if (buf[0] < '0' || buf[0] > '9') {
            break;
        }

        count = count*10 + (buf[0]-'0');
    }

    if (buf[0] != CR) {
        return -1;
    }

    if (get_char_from_mbuf_list(mbufs, node, pos, buf) != RMT_OK) {
        return -1;
    }
    if (buf[0] != LF) {
        return -1;
    }

    return count;
}

static int
get_bulk_len_from_mbuf_list(list *mbufs, listNode **node, uint8_t **pos)
{
    struct mbuf *mbuf;
    uint8_t buf[1];
    int len = 0;
    
    if (mbufs == NULL || node == NULL || pos == NULL) {
        return -1;
    }

    if (*node == NULL) {
        *node = listFirst(mbufs);
    }
    mbuf = listNodeValue(*node);

    if (*pos == NULL) {
        *pos = mbuf->start;
    }

    if (*pos < mbuf->start || *pos > mbuf->last) {
        log_debug(LOG_ERR, "ERROR: mbuf start: %p, mbuf last: %p, pos: %p", 
            mbuf->start, mbuf->last, *pos);
        return -1;
    }

    if (get_char_from_mbuf_list(mbufs, node, pos, buf) != RMT_OK) {
        return -1;
    }
    if (buf[0] != '$') {
        return -1;
    }

    while (get_char_from_mbuf_list(mbufs, node, pos, buf) == RMT_OK) {
        if (buf[0] < '0' || buf[0] > '9') {
            break;
        }

        len = len*10 + (buf[0]-'0');
    }

    if (buf[0] != CR) {
        return -1;
    }

    if (get_char_from_mbuf_list(mbufs, node, pos, buf) != RMT_OK) {
        return -1;
    }
    if (buf[0] != LF) {
        return -1;
    }

    return len;
}

static sds
get_bulk_from_mbuf_list(list *mbufs, listNode **node, uint8_t **pos, int bulk_len)
{
    sds str;
    struct mbuf *mbuf;
    int left_len, len;
    uint8_t buf[1];

    if (mbufs == NULL || node == NULL || pos == NULL || bulk_len < 0) {
        return NULL;
    }

    str = sdsempty();
    str = sdsMakeRoomFor(str, len);

    left_len = bulk_len;

    while (left_len > 0) {
        mbuf = listNodeValue(*node);
        if (*pos < mbuf->start || *pos > mbuf->last) {
            sdsfree(str);
            log_debug(LOG_ERR, "ERROR: mbuf start: %p, mbuf last: %p, pos: %p", 
                mbuf->start, mbuf->last, *pos);
            return NULL;
        }

        len = MIN(left_len, (mbuf->last - *pos));
        str = sdscatlen(str, *pos, len);
        (*pos) += len;
        left_len -= len;

        if ((*pos) >= mbuf->last) {
            *node = (*node)->next;
            if (*node != NULL) {
                mbuf = listNodeValue(*node);
                *pos = mbuf->start;
            }
        }

        if (*node == NULL && left_len > 0) {
            sdsfree(str);
            log_error("ERROR: node == NULL && left_len > 0");
            return NULL;
        }
    }

    if (get_char_from_mbuf_list(mbufs, node, pos, buf) != RMT_OK) {
        sdsfree(str);
        log_error("ERROR: read CR failed");
        return NULL;
    }
    if (buf[0] != CR) {
        sdsfree(str);
        log_error("ERROR: read CR failed");
        return NULL;
    }

    if (get_char_from_mbuf_list(mbufs, node, pos, buf) != RMT_OK) {
        sdsfree(str);
        log_error("ERROR: read LF failed");
        return NULL;
    }
    if (buf[0] != LF) {
        sdsfree(str);
        log_error("ERROR: read LF failed");
        return NULL;
    }

    return str;
}

struct array *
get_multi_bulk_array_from_mbuf_list(list *mbufs)
{
    struct array *bulks = NULL;
    sds *bulk;
    listNode *node;
    struct mbuf *mbuf;
    uint8_t *pos;
    int count, len;

    if (mbufs == NULL) {
        return NULL;
    }

    node = listFirst(mbufs);
    mbuf = listNodeValue(node);
    pos = mbuf->start;

    count = get_bulk_count_from_mbuf_list(mbufs, &node, &pos);
    if (count == -1) {
        log_error("ERROR: get bulk count failed");
        return NULL;
    }

    bulks = array_create(count<=0?1:count, sizeof(sds));
    if (bulks == NULL) {
        log_error("ERROR: out of memory");
        goto error;
    }

    while (count --) {
        mbuf = listNodeValue(node);
        len = get_bulk_len_from_mbuf_list(mbufs, &node, &pos);
        bulk = array_push(bulks);
        mbuf = listNodeValue(node);
        *bulk = get_bulk_from_mbuf_list(mbufs, &node, &pos, len);
        if (*bulk == NULL) {
            log_error("ERROR: read bulk failed");
            goto error;
        }
    }

    return bulks;

error:

    if (bulks != NULL) {
        while (array_n(bulks) > 0) {
            bulk = array_pop(bulks);
            sdsfree(*bulk);
        }
        array_destroy(bulks);
        bulks = NULL;
    }

    return NULL;
}
