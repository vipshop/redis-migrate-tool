#include<unistd.h>

#include <rmt_core.h>

#define RMT_CONF_PATH        	"rmt.conf"

#define RMT_LOG_PATH         	NULL

#define RMT_SOURCE_ADDR         "127.0.0.1:6379"
#define RMT_TARGET_ADDR         "127.0.0.1:6380"
#define RMT_TARGET_TYPE         GROUP_TYPE_SINGLE

#define RMT_INTERVAL         	1000

#define RMT_PID_FILE         	NULL

#define RMT_COMMAND_DEFAULT	 	RMT_CMD_REDIS_MIGRATE

#define RMT_OPTION_REDIS_ROLE_DEFAULT	RMT_OPTION_REDIS_ROLE_ALL

#define RMT_OPTION_REDIS_TYPE_DEFAULT   RMT_OPTION_GROUP_TYPE_SINGLE

#define RMT_OPTION_THREAD_COUNT_DEFAULT	sysconf(_SC_NPROCESSORS_ONLN)

#define RMT_OPTION_BUFFER_DEFAULT		1024*1024

#define RMT_OPTION_MBUF_SIZE_DEFAULT    REDIS_CMD_MBUF_BASE_SIZE

#define RMT_OPTION_STEP_DEFAULT		    1
#define RMT_OPTION_SOURCE_SAFE_DEFAULT	1

#define RMT_OPTION_LISTEN_DEFAULT       "127.0.0.1:8888"
#define RMT_OPTION_MAX_CLIENTS_DEFAULT  100

#define RMT_OPTION_RATE_LIMITING_DEFAULT 0

static struct option long_options[] = {
    { "help",           no_argument,        NULL,   'h' },
    { "version",        no_argument,        NULL,   'V' },
    { "daemonize",      no_argument,        NULL,   'd' },
    { "noreply",        no_argument,        NULL,   'n' },
    { "information",    no_argument,        NULL,   'I' },
    { "output",         required_argument,  NULL,   'o' },
    { "verbose",        required_argument,  NULL,   'v' },
    { "conf-file",      required_argument,  NULL,   'c' },
    { "pid-file",       required_argument,  NULL,   'p' },
    { "mbuf-size",      required_argument,  NULL,   'm' },
    { "command",        required_argument,  NULL,   'C' },
    { "source-role",    required_argument,  NULL,   'r' },
    { "target-role",    required_argument,  NULL,   'R' },
    { "thread",        	required_argument,  NULL,   'T' },
    { "buffer",        	required_argument,  NULL,   'b' },
    { "step",        	required_argument,  NULL,   'S' },
    { "from",        	required_argument,  NULL,   'f' },
    { "to",        	    required_argument,  NULL,   't' },
    { "step",        	required_argument,  NULL,   's' },
    { "rate-limiting",  required_argument,  NULL,   'l' },
    { NULL,             0,                  NULL,    0  }
};

static char short_options[] = "hVdnIo:v:c:p:m:C:r:R:T:b:S:f:t:s:l:";

void
rmt_show_usage(void)
{
    log_stderr(
        "Usage: redis-migrate-tool [-?hVdIn] [-v verbosity level] [-o output file]" CRLF
        "                  [-c conf file] [-C command]" CRLF
        "                  [-f source address] [-t target address]" CRLF
        "                  [-p pid file] [-m mbuf size] [-r target role]" CRLF
        "                  [-T thread number] [-b buffer size]" CRLF
        "");
    log_stderr(
        "Options:" CRLF
        "  -h, --help             : this help" CRLF
        "  -V, --version          : show version and exit" CRLF
        "  -d, --daemonize        : run as a daemon" CRLF
        "  -I, --information      : print some useful information" CRLF
        "  -n, --noreply          : don't receive the target redis reply");
    log_stderr(
        "  -v, --verbosity=N      : set logging level (default: %d, min: %d, max: %d)" CRLF
        "  -o, --output=S         : set logging file (default: %s)" CRLF
        "  -c, --conf-file=S      : set configuration file (default: %s)" CRLF
        "  -p, --pid-file=S       : set pid file (default: %s)" CRLF
        "  -m, --mbuf-size=N      : set mbuf size (default: %d)" CRLF
        "  -C, --command=S        : set command to execute (default: %s)" CRLF
        "  -r, --source-role=S    : set the source role (default: %s, you can input: %s, %s or %s)" CRLF
        "  -R, --target-role=S    : set the target role (default: %s, you can input: %s, %s or %s)" CRLF
        "  -T, --thread=N         : set how many threads to run the job(default: %d)" CRLF
        "  -b, --buffer=S         : set buffer size to run the job (default: %lld byte, unit:G/M/K)" CRLF
        "  -f, --from=S           : set source redis address (default: %s)" CRLF
        "  -t, --to=S             : set target redis group address (default: %s)" CRLF
        "  -s, --step=N           : set step (default: %d)" CRLF
        "  -l, --rate-limiting    : rate limit of payload to backend server (default %d)" CRLF
        "",
        RMT_LOG_DEFAULT, RMT_LOG_MIN, RMT_LOG_MAX,
        RMT_LOG_PATH != NULL ? RMT_LOG_PATH : "stderr",
        RMT_CONF_PATH, 
        RMT_PID_FILE != NULL ? RMT_PID_FILE : "off",
        RMT_OPTION_MBUF_SIZE_DEFAULT,
        RMT_COMMAND_DEFAULT,
        RMT_OPTION_REDIS_TYPE_DEFAULT, RMT_OPTION_GROUP_TYPE_SINGLE, RMT_OPTION_GROUP_TYPE_TWEM, RMT_OPTION_GROUP_TYPE_RCLUSTER,
        RMT_OPTION_REDIS_TYPE_DEFAULT, RMT_OPTION_GROUP_TYPE_SINGLE, RMT_OPTION_GROUP_TYPE_TWEM, RMT_OPTION_GROUP_TYPE_RCLUSTER,
        RMT_OPTION_THREAD_COUNT_DEFAULT,
        RMT_OPTION_BUFFER_DEFAULT,
        RMT_SOURCE_ADDR,
        RMT_TARGET_ADDR,
        RMT_OPTION_STEP_DEFAULT,
        RMT_OPTION_RATE_LIMITING_DEFAULT);

	rmt_show_command_usage();
}

void
rmt_set_default_options(struct instance *nci)
{
	nci->show_version = 0;
	nci->show_help = 0;
    nci->show_information = 0;
	nci->daemonize = 0;
    nci->noreply = 0;
	
    nci->log_level = RMT_LOG_DEFAULT;
    nci->log_filename = RMT_LOG_PATH;

    nci->conf_filename = (char *)RMT_CONF_PATH;

    nci->source_addr = (char *)RMT_SOURCE_ADDR;
    nci->target_addr = (char *)RMT_TARGET_ADDR;
    nci->target_type = RMT_TARGET_TYPE;

    nci->pid = (pid_t)-1;
    nci->pid_filename = NULL;
    nci->pidfile = 0;

    nci->mbuf_size = RMT_OPTION_MBUF_SIZE_DEFAULT;
    
    nci->command = (char *)RMT_COMMAND_DEFAULT;
    nci->thread_count = (int)RMT_OPTION_THREAD_COUNT_DEFAULT;
    nci->buffer_size = RMT_OPTION_BUFFER_DEFAULT;

    nci->step = RMT_OPTION_STEP_DEFAULT;
    nci->source_safe = RMT_OPTION_SOURCE_SAFE_DEFAULT;

    nci->listen = RMT_OPTION_LISTEN_DEFAULT;
    nci->max_clients = RMT_OPTION_MAX_CLIENTS_DEFAULT;
    nci->rate_limiting = RMT_OPTION_RATE_LIMITING_DEFAULT;
}

r_status
rmt_get_options(int argc, char **argv, struct instance *nci)
{
    int c, value;
    uint64_t big_value;

	if(argc <= 1)
	{
		log_stderr("redis-migrate-tool needs some options.\n");
		return RMT_ERROR;
	}

    opterr = 0;

    for (;;) {
        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            /* no more options */
            break;
        }

        switch (c) {
        case 'h':
            nci->show_version = 1;
            nci->show_help = 1;
            break;

        case 'V':
            nci->show_version = 1;
            break;

        case 'd':
            nci->daemonize = 1;
            break;

        case 'n':
            nci->noreply = 1;
            break;

        case 'I':
            nci->show_information = 1;
            break;

        case 'v':
            value = rmt_atoi(optarg, rmt_strlen(optarg));
            if (value < 0) {
                log_stderr("redis-migrate-tool: option -v requires a number");
                return RMT_ERROR;
            }
            nci->log_level = value;
            break;

        case 'o':
            nci->log_filename = optarg;
            break;

        case 'c':
            nci->conf_filename = optarg;
            break;

        case 'p':
            nci->pid_filename = optarg;
            break;

        case 'm':
            value = rmt_atoi(optarg, rmt_strlen(optarg));
            if (value < 0) {
                log_stderr("redis-migrate-tool: option -m requires a number");
                return RMT_ERROR;
            }
            
            nci->mbuf_size = (size_t)value;
            break;
            
		case 'C':
            nci->command = optarg;
            break;
			
		case 'r':
            
            if(strcmp(optarg, RMT_OPTION_GROUP_TYPE_SINGLE) == 0)
            {
                nci->source_type = GROUP_TYPE_SINGLE;
            }
            else if(strcmp(optarg, RMT_OPTION_GROUP_TYPE_TWEM) == 0)
            {
                nci->source_type = GROUP_TYPE_TWEM;
            }
            else if(strcmp(optarg, RMT_OPTION_GROUP_TYPE_RCLUSTER) == 0)
            {
                nci->source_type = GROUP_TYPE_RCLUSTER;
            }
            else
            {
                log_stderr("redis-migrate-tool: option -r must be %s, %s or %s",
					RMT_OPTION_GROUP_TYPE_SINGLE,
					RMT_OPTION_GROUP_TYPE_TWEM,
					RMT_OPTION_GROUP_TYPE_RCLUSTER);
                return RMT_ERROR;
            }
            
            break;
            
        case 'R':
            
            if(strcmp(optarg, RMT_OPTION_GROUP_TYPE_SINGLE) == 0)
            {
                nci->target_type = GROUP_TYPE_SINGLE;
            }
            else if(strcmp(optarg, RMT_OPTION_GROUP_TYPE_TWEM) == 0)
            {
                nci->target_type = GROUP_TYPE_TWEM;
            }
            else if(strcmp(optarg, RMT_OPTION_GROUP_TYPE_RCLUSTER) == 0)
            {
                nci->target_type = GROUP_TYPE_RCLUSTER;
            }
            else
            {
                log_stderr("redis-migrate-tool: option -R must be %s, %s or %s",
					RMT_OPTION_GROUP_TYPE_SINGLE,
					RMT_OPTION_GROUP_TYPE_TWEM,
					RMT_OPTION_GROUP_TYPE_RCLUSTER);
                return RMT_ERROR;
            }
            
            break;
			
        case 'T':
            value = rmt_atoi(optarg, rmt_strlen(optarg));
            if (value < 0) {
                log_stderr("redis-migrate-tool: option -t requires a number");
                return RMT_ERROR;
            }
            
            nci->thread_count = value;
            break;
            
        case 'b':
            big_value = size_string_to_integer_byte(optarg, (int)strlen(optarg));
            if(big_value == 0)
            {
                log_stderr("redis-migrate-tool: option -b requires a memory size");
                return RMT_ERROR;
            }

            nci->buffer_size = big_value;
            break;

        case 'f':
            nci->source_addr = optarg;
            break;

        case 't':
            nci->target_addr = optarg;
            break;
            
        case 's':
            value = rmt_atoi(optarg, rmt_strlen(optarg));
            if (value < 0) {
                log_stderr("redis-migrate-tool: option -s requires a number");
                return RMT_ERROR;
            }
            
            nci->step = value;
            break;
        case 'l':
            value = rmt_atoi(optarg, rmt_strlen(optarg));
            if (value < 0) {
                log_stderr("redis-migrate-tool: option -s requires a number >=0");
                return RMT_ERROR;
            }
            nci->rate_limiting = value;
            break;
        case '?':
            switch (optopt) {
            case 'o':
            case 'c':
            case 'p':
                log_stderr("redis-migrate-tool: option -%c requires a file name",
                           optopt);
                break;

            case 'v':
            case 'i':
			case 't':
            case 'm':
            case 's':
                log_stderr("redis-migrate-tool: option -%c requires a number", optopt);
                break;

            case 'a':
			case 'C':
			case 'r':
            case 'R':
			case 'b':
                log_stderr("redis-migrate-tool: option -%c requires a string", optopt);
                break;

            default:
                log_stderr("redis-migrate-tool: invalid option -- '%c'", optopt);
                break;
            }
            return RMT_ERROR;

        default:
            log_stderr("redis-migrate-tool: invalid option -- '%c'", optopt);
            return RMT_ERROR;

        }
    }

    return RMT_OK;
}
