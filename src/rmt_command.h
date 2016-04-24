#ifndef _RMT_COMMAND_H_
#define _RMT_COMMAND_H_

#define RMT_CMD_REDIS_MIGRATE           "redis_migrate"
#define RMT_CMD_KEYS_NUM		        "keys_num"
#define RMT_CMD_REDIS_CHECK             "redis_check"
#define RMT_CMD_REDIS_TESTINSERT        "redis_testinsert"

#define CMD_FLAG_NEED_CONFIRM 			(1<<0)

struct rmtContext;

typedef enum redis_command_type{
	REDIS_COMMAND_FLUSHALL,
	REDIS_COMMAND_CONFIG_GET,
	REDIS_COMMAND_CONFIG_SET,
	REDIS_COMMAND_CONFIG_REWRITE,
	REDIS_COMMAND_GET,
	REDIS_COMMAND_SET
} redis_command_type_t;

typedef enum node_state_type{
	REDIS_KEY_NUM,
	REDIS_MEMORY,
	NODES_CLUSTER_STATE
} node_state_type_t;

typedef void RMTCommandProc(struct rmtContext *rmt, int type);

typedef struct RMTCommand {
	const char *name;
	const char *description;
	RMTCommandProc *proc;
	int type;
	int min_arg_count;
	int max_arg_count;
	int flag;
}RMTCommand;

void rmt_show_command_usage(void);

void populateCommandTable(dict *commands);

#endif
