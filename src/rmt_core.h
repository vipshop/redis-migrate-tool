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

#include <rmt_util.h>
#include <rmt_array.h>
#include <rmt_sds.h>
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

#include <rmt_redis.h>

#if (IOV_MAX > 128)
#define RMT_IOV_MAX 128
#else
#define RMT_IOV_MAX IOV_MAX
#endif

/* Anti-warning macro... */
#define RMT_NOTUSED(V) ((void) V)

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
    int             daemonize;
    
    char            *command;
    int             noreply;
    int             thread_count;
    uint64_t        buffer_size;

    int step;
};

typedef struct rmtContext {
    dict *commands;                     /* Command table */
    rmt_conf *cf;
    char            *source_addr;       /* source redis address */
    char            *target_addr;       /* target redis address */
    group_type_t    source_type;        /* target redis type */
    group_type_t    target_type;        /* target redis type */
    
    sds cmd;

    int             thread_count;
    uint64_t        buffer_size;
    struct array args;  //type: sds

    int noreply;
    int rdb_diskless;

    size_t          mbuf_size;

    int step;
}rmtContext;

//for the read thread
typedef struct read_thread_data{
    pthread_t thread_id;
    aeEventLoop *loop;
    list *nodes_data;   //type : source redis_node.
    int nodes_count;    //this loop thread is responsible for.
    int finish_read_nodes;
}read_thread_data;

//for the write thread
typedef struct write_thread_data{
    pthread_t thread_id;
    aeEventLoop *loop;
    list *nodes;   //type : source redis_node.
    int nodes_count;    //this loop thread is responsible for.
    int finish_write_nodes;
    redis_group *trgroup;   //target group
    int notice_pipe[2];     //used to notice the read thread  to begin replication
}write_thread_data;

rmtContext *init_context(struct instance *nci);
void destroy_context(rmtContext *rmt_ctx);

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
void group_state(rmtContext *ctx, int type);

#endif

