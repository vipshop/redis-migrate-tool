#ifndef _RMT_CONF_H_
#define _RMT_CONF_H_

#define CONF_UNSET_NUM      -1
#define CONF_UNSET_PTR      NULL
#define CONF_UNSET_GROUP    (group_type_t) -1
#define CONF_UNSET_HASH     (hash_type_t) -1
#define CONF_UNSET_DIST     (dist_type_t) -1

typedef struct conf_option {
    char* name;
    int   (*set)(void *cf, struct conf_option *opt, void *data);
    int   offset;
}conf_option;

#define GROUP_CODEC(ACTION)                             \
    ACTION( GROUP_TYPE_UNKNOW,          unknow        ) \
    ACTION( GROUP_TYPE_SINGLE,          single        ) \
    ACTION( GROUP_TYPE_TWEM,            twemproxy     ) \
    ACTION( GROUP_TYPE_RCLUSTER,        redis cluster ) \
    ACTION( GROUP_TYPE_RDBFILE,         rdb file      ) \

#define DEFINE_ACTION(_group, _name) _group,
typedef enum group_type {
    GROUP_CODEC( DEFINE_ACTION )
    GROUP_SENTINEL
} group_type_t;
#undef DEFINE_ACTION

typedef struct conf_pool {
    group_type_t        type;
    struct array        *servers;   //type: sds
    
    hash_type_t         hash;
    dist_type_t         distribution;
    sds                 hash_tag;

    sds                 redis_auth;
    int                 redis_db;

    int                 timeout;
    int                 backlog;
} conf_pool;

typedef struct rmt_conf {
    char          *fname;           /* file name (ref in argv[]) */
    FILE          *fh;              /* file handle */

    dict          *organizations;    /* organizations */
    
    conf_pool     source_pool;
    conf_pool     target_pool;

    sds           listen;
    long long     maxmemory;
    int           threads;
    int           step;
    int           mbuf_size;
    int           noreply;
    int           rdb_diskless;
    int           source_safe;
}rmt_conf;

typedef struct conf_value{
    int     type;
    void    *value;
}conf_value;

conf_value *conf_value_create(int type);
void conf_value_destroy(conf_value *cv);

rmt_conf *conf_create(char *filename);
void conf_destroy(rmt_conf *cf);

int conf_pool_set_type(void *obj, conf_option *opt, void *data);
int conf_pool_set_hash(void *obj, conf_option *opt, void *data);
int conf_pool_set_hash_tag(void *obj, conf_option *opt, void *data);
int conf_pool_set_distribution(void *obj, conf_option *opt, void *data);
int conf_pool_set_servers(void *obj, conf_option *opt, void *data);

int conf_common_set_maxmemory(void *obj, conf_option *opt, void *data);

int conf_set_string(void *obj, conf_option *opt, void *data);
int conf_set_num(void *obj, conf_option *opt, void *data);
int conf_set_bool(void *obj, conf_option *opt, void *data);

#endif
