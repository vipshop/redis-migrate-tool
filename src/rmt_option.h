#ifndef _RMT_OPTION_H_
#define _RMT_OPTION_H_

#define RMT_VERSION_STRING "0.1.0"

#define RMT_OPTION_REDIS_ROLE_ALL		"all"
#define RMT_OPTION_REDIS_ROLE_MASTER	RMT_REDIS_ROLE_NAME_MASTER
#define RMT_OPTION_REDIS_ROLE_SLAVE		RMT_REDIS_ROLE_NAME_SLAVE

#define RMT_OPTION_GROUP_TYPE_SINGLE    "single"
#define RMT_OPTION_GROUP_TYPE_TWEM	    "twemproxy"
#define RMT_OPTION_GROUP_TYPE_RCLUSTER  "redis_cluster"

struct instance;

void rmt_show_usage(void);
void rmt_set_default_options(struct instance *nci);
r_status rmt_get_options(int argc, char **argv, struct instance *nci);

#endif
