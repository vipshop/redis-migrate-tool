#ifndef _RMT_CORE_H_
#define _RMT_CORE_H_

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <rmt_config.h>

#ifdef HAVE_DEBUG_LOG
# define RMT_DEBUG_LOG 1
#endif

#ifdef HAVE_ASSERT_PANIC
# define RMT_ASSERT_PANIC 1
#endif

#ifdef HAVE_ASSERT_LOG
# define RMT_ASSERT_LOG 1
#endif

#ifdef HAVE_MEMORY_TEST
# define RMT_MEMORY_TEST 1
#endif

#ifdef HAVE_JEMALLOC
# define RMT_JEMALLOC 1
#endif

#ifdef HAVE_BACKTRACE
# define RMT_HAVE_BACKTRACE 1
#endif

#ifdef HAVE_EPOLL
# define RMT_HAVE_EPOLL 1
#elif HAVE_KQUEUE
# define RMT_HAVE_KQUEUE 1
#elif HAVE_EVENT_PORTS
# define RMT_HAVE_EVENT_PORTS 1
#else
# error missing scalable I/O event notification mechanism
#endif

#ifndef __need_IOV_MAX
#define __need_IOV_MAX
#endif

#ifndef IOV_MAX
#if defined(__FreeBSD__) || defined(__APPLE__)
#define IOV_MAX 1024
#endif
#endif

#define RMT_AGAIN     1
#define RMT_OK        0
#define RMT_ERROR    -1
#define RMT_EAGAIN   -2
#define RMT_ENOMEM   -3

/* reserved fds for std streams, log etc. */
#define RESERVED_FDS 32

typedef int r_status; /* return type */
typedef int err_t;     /* error type */

#define RMT_REDIS_ROLE_NULL     0
#define RMT_REDIS_ROLE_ALL      1
#define RMT_REDIS_ROLE_MASTER   2
#define RMT_REDIS_ROLE_SLAVE    3

#define RMT_REDIS_ROLE_NAME_NODE    "node"
#define RMT_REDIS_ROLE_NAME_MASTER  "master"
#define RMT_REDIS_ROLE_NAME_SLAVE   "slave"

#define IP_PORT_SEPARATOR ":"
#define ADDRESS_SEPARATOR ","
#define SPACE_SEPARATOR   " "

#include <stdio.h>
#include <stdlib.h> 
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <pthread.h>
#include <limits.h>
#include <fcntl.h>
#include <math.h>

#include <rmt_sds.h>
#include <rmt_util.h>
#include <rmt_array.h>
#include <rmt_dict.h>
#include <rmt_list.h>
#include <rmt_net.h>
#include <rmt_hash.h>
#include <rmt_option.h>
#include <rmt_log.h>
#include <rmt_conf.h>
#include <rmt_command.h>
#include <rmt_mttlist.h>
#include <rmt_locklist.h>
#include <rmt_unlocklist.h>
#include <rmt_mbuf.h>
#include <rmt_message.h>

#include <ae/ae.h>
#include <lzf/lzfP.h>
#include <zipmap/zipmap.h>
#include <ziplist/ziplist.h>
#include <intset/intset.h>

#include <rmt_connect.h>
#include <rmt_redis.h>

struct redis_group;

#if (IOV_MAX > 128)
#define RMT_IOV_MAX 128
#else
#define RMT_IOV_MAX IOV_MAX
#endif

/* Anti-warning macro... */
#define RMT_NOTUSED(V) ((void) V)

#define RMT_NOTICE_FLAG_NULL        0
#define RMT_NOTICE_FLAG_SHUTDOWN    (1<<0)

#define run_with_period(_ms_, _cronloops, _hz) if ((_ms_ <= 1000/_hz) || !(_cronloops%((_ms_)/(1000/_hz))))

struct instance {
    int             log_level;                   /* log level */
    char            *log_filename;               /* log filename */
    char            *conf_filename;              /* configuration filename */
    
    char            *source_addr;                /* source redis address */
    char            *target_addr;                /* target redis address */
    group_type_t    source_type;                 /* target redis type */
    group_type_t    target_type;                 /* target redis type */

    pid_t           pid;                         /* process id */
    char            *pid_filename;               /* pid filename */
    unsigned        pidfile:1;                   /* pid file created? */

    size_t          mbuf_size;
    
    int             show_help;
    int             show_version;
    int             show_information;
    int             daemonize;
    
    char            *command;
    int             noreply;
    int             thread_count;
    uint64_t        buffer_size;

    int             step;
    int             source_safe;

    char            *listen;
    int             max_clients;
};

typedef struct rmtContext {
    dict *commands;                     /* Command table */
    rmt_conf *cf;
    char            *source_addr;       /* source redis address */
    char            *target_addr;       /* target redis address */
    group_type_t    source_type;        /* target redis type */
    group_type_t    target_type;        /* target redis type */

    int hz;     /* cron() calls frequency in hertz */
    
    sds cmd;    /* command string */

    int             thread_count;
    uint64_t        buffer_size;
    struct array args;  //type: sds

    int noreply;
    int rdb_diskless;

    size_t          mbuf_size;

    int step;
    int source_safe;

    sds dir;
    sds rdb_prefix;

    struct redis_group *srgroup;

    struct array *rdatas;   /* read thread_data */
    struct array *wdatas;   /* write thread_data */

    /* The fllow region used for client connect to migrate tool */
    aeEventLoop *loop;
    long long starttime; /* server start time in milliseconds */
    rmt_connect *proxy;
    struct rmt_listen lt;
    uint32_t max_ncconn;  /* max # client connections */
    uint64_t ntotal_cconn;
    uint32_t ncurr_cconn;
    list clients;
    mbuf_base *mb;

    sds filter;

    pthread_rwlock_t rwl_notice;        /* read write lock */
    int              flags_notice;      /* used to notice the threads */
    int              finish_count_after_notice; /* finished thread count after the main thread noticed */
}rmtContext;

typedef struct thread_data{
    int id;
    pthread_t thread_id;
    aeEventLoop *loop;
    long long unixtime;     /* Unix time sampled every cron cycle. In milliseconds. */

    rmtContext  *ctx;
    redis_group *srgroup;   /* source group */
    redis_group *trgroup;   /* target group */

    list *nodes;            /* type : source redis_node. */
    int nodes_count;        /* Count of the nodes that this loop thread is responsible for. */

    /* The fllow region used for command 'redis_check' */
    long long keys_count;   /* keys count to check for this thread */
    long long sent_keys_count;
    long long finished_keys_count;
    long long correct_keys_count;

    int cronloops;          /* Number of times the cron function run */
    
    void *data;             /* data for this thread */

    volatile uint64_t stat_total_msgs_recv;         /* total msg received for this thread */
    volatile uint64_t stat_total_msgs_sent;         /* total msg received for this thread */
    volatile uint64_t stat_total_net_input_bytes;   /* total bytes received from source group for this read thread */
    volatile uint64_t stat_total_net_output_bytes;  /* total bytes sent to target group for this write thread */
    volatile int      stat_rdb_received_count;      /* the rdb received count for this read thread */
    volatile int      stat_rdb_parsed_count;        /* the rdb parse finished count for this write thread */
    volatile int      stat_aof_loaded_count;        /* the aof file load finished count for this read thread */
    volatile uint64_t stat_mbufs_inqueue;           /* the count of mbufs that recived from source group */
    volatile uint64_t stat_msgs_outqueue;           /* the count of msgs that will be sent to target group and msgs had been sent to target but waiting for the response */
}thread_data;

rmtContext *init_context(struct instance *nci);
void destroy_context(rmtContext *rmt_ctx);

int thread_data_init(thread_data *tdata);
void thread_data_deinit(thread_data *tdata);

int get_notice_flag(rmtContext *ctx);
void set_notice_flag(rmtContext *ctx, int flags);
void reset_notice_flag(rmtContext *ctx);
int get_finish_count_after_notice(rmtContext *ctx);
void add_finish_count_after_notice(rmtContext *ctx);
void reset_finish_count_after_notice(rmtContext *ctx);


unsigned int dictSdsHash(const void *key);
int dictSdsKeyCompare(void *privdata, const void *key1, const void *key2);
void dictSdsDestructor(void *privdata, void *val);
void dictGroupNodeDestructor(void *privdata, void *val);

int core_core(rmtContext *ctx);

int prepare_send_msg(redis_node *srnode, struct msg *msg, redis_node *trnode);

void parse_prepare(aeEventLoop *el, int fd, void *privdata, int mask);
void parse_request(aeEventLoop *el, int fd, void *privdata, int mask);
int parse_response(redis_node *trnode);

int notice_write_thread(redis_node *srnode);

redis_group *source_group_create(rmtContext *ctx);
void source_group_destroy(redis_group *srgroup);
redis_group *target_group_create(rmtContext *ctx);
void target_group_destroy(redis_group *trgroup);

void redis_migrate(rmtContext *ctx, int type);
void redis_check_data(rmtContext *ctx, int type);
void redis_testinsert_data(rmtContext *ctx, int type);

#endif

