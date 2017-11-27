#ifndef _RMT_REDIS_H_
#define _RMT_REDIS_H_

/* Object types */
#define REDIS_STRING    0
#define REDIS_LIST      1
#define REDIS_SET       2
#define REDIS_ZSET      3
#define REDIS_HASH      4

#define REDIS_REPLY_STATUS_OK     "+OK\r\n"
#define REDIS_REPLY_STATUS_PONG   "+PONG\r\n"
#define REDIS_REPLY_STATUS_NONE   "+none\r\n"
#define REDIS_REPLY_STATUS_STRING "+string\r\n"
#define REDIS_REPLY_STATUS_LIST   "+list\r\n"
#define REDIS_REPLY_STATUS_SET    "+set\r\n"
#define REDIS_REPLY_STATUS_ZSET   "+zset\r\n"
#define REDIS_REPLY_STATUS_HASH   "+hash\r\n"

#define REDIS_REPLY_BULK_NULL     "$-1\r\n"

#define REDIS_RDB_MBUF_BASE_SIZE        4096
#define REDIS_CMD_MBUF_BASE_SIZE        512
#define REDIS_RESPONSE_MBUF_BASE_SIZE   128

#define REDIS_RUN_ID_SIZE 40

#define REDIS_DATA_TYPE_UNKNOW      0
#define REDIS_DATA_TYPE_RDB         1
#define REDIS_DATA_TYPE_CMD         2

#define REDIS_RDB_TYPE_UNKNOW       0
#define REDIS_RDB_TYPE_FILE         1
#define REDIS_RDB_TYPE_MEM          2

/* Slave replication state. Used in rr.repl_state to remember
 * what to do next. */
#define REDIS_REPL_NONE 0 /* No active replication */
#define REDIS_REPL_CONNECT 1 /* Must connect to master */
#define REDIS_REPL_CONNECTING 2 /* Connecting to master */
/* --- Handshake states, must be ordered --- */
#define REDIS_REPL_RECEIVE_PONG 3 /* Wait for PING reply */
#define REDIS_REPL_SEND_AUTH 4 /* Send AUTH to master */
#define REDIS_REPL_RECEIVE_AUTH 5 /* Wait for AUTH reply */
#define REDIS_REPL_SEND_PORT 6 /* Send REPLCONF listening-port */
#define REDIS_REPL_RECEIVE_PORT 7 /* Wait for REPLCONF reply */
#define REDIS_REPL_SEND_CAPA 8 /* Send REPLCONF capa */
#define REDIS_REPL_RECEIVE_CAPA 9 /* Wait for REPLCONF reply */
#define REDIS_REPL_SEND_PSYNC 10 /* Send PSYNC */
#define REDIS_REPL_RECEIVE_PSYNC 11 /* Wait for PSYNC reply */
/* --- End of handshake states --- */
#define REDIS_REPL_TRANSFER 12 /* Receiving .rdb from master */
#define REDIS_REPL_CONNECTED 13 /* Connected to master */


/* Slave replication state - from the point of view of the master.
 * In SEND_BULK and ONLINE state the slave receives new updates
 * in its output queue. In the WAIT_BGSAVE state instead the server is waiting
 * to start the next background saving in order to send updates to it. */
#define REDIS_REPL_WAIT_BGSAVE_START 6 /* We need to produce a new RDB file. */
#define REDIS_REPL_WAIT_BGSAVE_END 7 /* Waiting RDB file creation to finish. */
#define REDIS_REPL_SEND_BULK 8 /* Sending RDB file to slave. */
#define REDIS_REPL_ONLINE 9 /* RDB file transmitted, sending just updates. */ 

struct redis_node;
struct redis_group;

typedef uint32_t (*backend_idx_t)(struct redis_group*, uint8_t *, uint32_t);
typedef struct redis_node*(*backend_node_t)(struct redis_group*, uint8_t *, uint32_t);

typedef uint32_t (*hash_t)(const char *, size_t);

struct rmtContext;
struct mbuf_base;

typedef struct redis_rdb{
    int type;       		/* rdb type: file or memory */
    int rdbver;             /* rdb version */
    
    struct mbuf_base *mb;   /* need to release */
    mttlist *data;     		/* type: mbuf */

    struct mbuf *mbuf;

    sds fname;    		    /* rdb file name */
    int fd;         		/* rdb file descriptor */

    FILE *fp;       		/* rdb file to read */
    uint64_t cksum; 		/* for rdb checksum */
    void (*update_cksum)(struct redis_rdb *, const void *, size_t);

    int state;

    uint8_t deleted:1;  		/* if the rdb file deleted after parse */
    uint8_t received:1;         /* if the rdb file had received */

    int (*handler)(struct redis_node *, sds, int, struct array *, int, long long, void *);
}redis_rdb;

/*redis replication*/
typedef struct redis_repl{
    /* Static vars used to hold the EOF mark, and the last bytes received
     * form the server: when they match, we reached the end of the transfer. */
    char eofmark[REDIS_RUN_ID_SIZE];
    char lastbytes[REDIS_RUN_ID_SIZE];
    int usemark;

    int flags;

    int repl_state;

    char replrunid[REDIS_RUN_ID_SIZE+1]; /* master run id if this is a master */
    long long reploff;  /* replication offset if this is our master */

    char repl_master_runid[REDIS_RUN_ID_SIZE+1];  /* Master run id for PSYNC. */
    long long repl_master_initial_offset;         /* Master PSYNC offset. */

    off_t repl_transfer_size;   /* Size of RDB to read from master during sync. */
    off_t repl_transfer_read;   /* Amount of RDB read from master during sync. */
    off_t repl_transfer_last_fsync_off; /* Offset when we fsync-ed last time. */
    long long repl_lastio;      /* Unix time of the latest read, for timeout. In milliseconds. */
}redis_repl;

typedef struct redis_group{
    struct rmtContext *ctx;
    dict *nodes;
    uint32_t node_id;
    int kind;            	/* twemproxy, redis cluster or ... */

    int source;          	/* source group? */
    sds password;      	    /* redis password */
    int timeout;            /* timeout in milliseconds */
    
    mbuf_base *mb;

    struct array *route; 	/* route table for redis group */
    backend_idx_t get_backend_idx;
    backend_node_t get_backend_node;

    hash_t key_hash;

    uint32_t ncontinuum;	/* # continuum points */

    dist_type_t distribution;
}redis_group;

typedef struct redis_node{
    uint32_t id;
    
    struct rmtContext *ctx;
    redis_group *owner;
    
    int state;
    char *addr;
    tcp_context *tc;

    struct thread_data *read_data;
    struct thread_data *write_data;

    redis_repl *rr;         	/* used to replication from source redis. */
    redis_rdb *rdb;         	/* used to cache rdb from the source redis. */
    struct mbuf *mbuf_in;   	/* used to read cmd data from source redis. */
    mttlist *cmd_data;      	/* used to cache cmd data from source redis. type: mbuf */

    list *piece_data;   	    /* used to cache the piece data for parse msg. type: mbuf */
    struct msg *msg;    	    /* used to parse msg */

    list *send_data;        	/* used to cache the msg that will be sent. type: msg */
    list *sent_data;        	/* used to cache the msg that have be sent. type: msg */
    struct msg *msg_rcv;    	/* used to recieve response msg from the target redis. */

    int sockpairfds[2];         /* sorcketpair used to notice between read and write thread. 
                                                         *  sockpairfds[0]: read thread,  sockpairfds[1]: write thread
                                                         */

    long long timestamp;

    int sk_event;				/* used to run some task */

    struct redis_node *next;	/* next redis_node to begin replication */
}redis_node;

int redis_replication_init(redis_repl *rr);
void redis_replication_deinit(redis_repl *rr);
int redis_node_init(redis_node *rnode, const char *addr, redis_group *rgroup);
void redis_node_deinit(redis_node *rnode);
int redis_group_init(struct rmtContext *ctx, redis_group *rgroup, conf_pool *cp, int source);
void redis_group_deinit(redis_group *rgroup);

int redis_rdb_init(redis_rdb *rdb, const char *addr, int type);
void redis_rdb_deinit(redis_rdb *rdb);

char *rmt_send_sync_cmd_read_line(int fd, ...);

int rmtConnectRedisMaster(redis_node *srnode);

void rmtRedisSlaveOffline(redis_node *srnode);
void rmtReceiveRdbAbort(redis_node *srnode);

void redisSlaveReplCorn(redis_node *srnode);

void redis_parse_req_rdb(struct msg *r);

void redis_parse_req(struct msg *r);
void redis_parse_rsp(struct msg *r);

void redis_pre_coalesce(struct msg *r);
void redis_post_coalesce(struct msg *r);
int redis_reply(struct msg *r);

int redis_fragment(struct redis_group *rgroup, 
    struct msg *r, uint32_t ncontinuum, list *frag_msgl);

int redis_response_check(redis_node *rnode, struct msg *r);

void redis_rdb_update_checksum(redis_rdb *rdb, const void *buf, size_t len);

void redis_delete_rdb_file(redis_rdb *rdb, int always);

int redis_parse_rdb_file(redis_node *srnode, int mbuf_count_one_time);
int redis_parse_rdb_time(aeEventLoop *el, long long id, void *privdata);
void redis_parse_rdb(aeEventLoop *el, int fd, void *privdata, int mask);

int redis_load_aof_file(redis_node *srnode, char *aof_file);

int redis_cluster_init_from_addrs(redis_group *rgroup, const char *addrs);

int redis_cluster_init_from_conf(redis_group *rgroup, conf_pool *cp);
int redis_single_init_from_conf(redis_group *rgroup, conf_pool *cp);
int redis_twem_init_from_conf(redis_group *rgroup, conf_pool *cp);
int redis_rdb_file_init_from_conf(redis_group *rgroup, conf_pool *cp);
int redis_aof_file_init_from_conf(redis_group *rgroup, conf_pool *cp);

redis_node *redis_group_add_node(redis_group *rgroup, const char *name, const char *addr);

uint32_t redis_cluster_backend_idx(redis_group *rgroup, uint8_t *key, uint32_t keylen);
uint32_t redis_twem_backend_idx(redis_group *rgroup, uint8_t *key, uint32_t keylen);
uint32_t redis_single_backend_idx(redis_group *rgroup, uint8_t *key, uint32_t keylen);

redis_node *redis_cluster_backend_node(redis_group *rgroup, uint8_t *key, uint32_t keylen);
redis_node *redis_twem_backend_node(redis_group *rgroup, uint8_t *key, uint32_t keylen);
redis_node *redis_single_backend_node(redis_group *rgroup, uint8_t *key, uint32_t keylen);

sds redis_msg_response_get_bulk_string(struct msg *msg);
int redis_append_bulk(struct msg *r, uint8_t *str, uint32_t str_len);
int redis_msg_append_multi_bulk_len_full(struct msg *msg, uint32_t integer);
int redis_msg_append_bulk_full(struct msg *msg, const char *str, uint32_t len);
int redis_msg_append_command_full(struct msg * msg, ...);
int redis_msg_append_command_full_safe(struct msg * msg, struct array *args);
struct msg *redis_generate_msg_with_key_value(struct rmtContext *ctx, mbuf_base *mb, int data_type, sds key, struct array *value, int expiretime_type, sds expiretime);
struct msg *redis_generate_msg_with_key_expire(struct rmtContext *ctx, mbuf_base *mb, sds key, int expiretime_type, sds expiretime);
int redis_key_value_send(redis_node *srnode, sds key, int data_type, struct array *value, int expiretime_type, long long expiretime, void *data);

struct array *redis_value_create(uint32_t nelem);
void redis_value_destroy(struct array *value);

char *get_redis_type_string(int type);

struct array *get_multi_bulk_array_from_mbuf_list(list *mbufs);

#endif

