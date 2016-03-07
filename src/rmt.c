
#include <rmt_core.h>
#include <signal.h>

dictType commandTableDictType = {
    dictSdsHash,                /* hash function */
    NULL,                       /* key dup */
    NULL,                       /* val dup */
    dictSdsKeyCompare,          /* key compare */
    dictSdsDestructor,          /* key destructor */
    NULL                        /* val destructor */
};

rmtContext *
init_context(struct instance *rmti)
{
    int ret;
    int j;
    rmtContext *rmt_ctx;
    dict *commands;
    sds *cmd_parts = NULL;
    int cmd_parts_count = 0;
    sds *arg_addr;
    rmt_conf *cf;

    if(rmti == NULL)
    {
        return NULL;
    }

    rmt_ctx = rmt_alloc(sizeof(rmtContext));
    if(rmt_ctx == NULL)
    {
        return NULL;
    }

    rmt_ctx->commands = NULL;
    rmt_ctx->cf = NULL;
    rmt_ctx->source_addr = NULL;
    rmt_ctx->target_addr = NULL;
    rmt_ctx->source_type = 0;
    rmt_ctx->target_type = 0;
    
    rmt_ctx->cmd = NULL;
    rmt_ctx->thread_count = 0;
    rmt_ctx->buffer_size = 0;
    array_null(&rmt_ctx->args);
    rmt_ctx->noreply = 0;
    rmt_ctx->rdb_diskless = 0;

    rmt_ctx->mbuf_size = 0;

    rmt_ctx->step = 0;
    rmt_ctx->source_safe = 0;
    rmt_ctx->dir = NULL;

    commands = dictCreate(&commandTableDictType,NULL);
    if(commands == NULL)
    {
        rmt_free(rmt_ctx);
        return NULL;
    }

    populateCommandTable(commands);
    rmt_ctx->commands = commands;

    cmd_parts = sdssplitlen(rmti->command, (int)rmt_strlen(rmti->command), " ", 1, &cmd_parts_count);
    if(cmd_parts == NULL || cmd_parts_count <= 0)
    {
        rmt_free(rmt_ctx);
        dictRelease(commands);
        return NULL;
    }
    
    rmt_ctx->cmd = cmd_parts[0];

    ret = array_init(&rmt_ctx->args, 1, sizeof(sds));
    if(ret != RMT_OK)
    {
        sdsfreesplitres(cmd_parts, cmd_parts_count);
        rmt_free(rmt_ctx);
        dictRelease(commands);
        return NULL;
    }
    
    for(j = 1; j < cmd_parts_count; j++)
    {
        arg_addr = array_push(&rmt_ctx->args);
        *arg_addr = cmd_parts[j];
    }

    rmt_free(cmd_parts);

    rmt_ctx->buffer_size = rmti->buffer_size;
    rmt_ctx->thread_count = rmti->thread_count;

    rmt_ctx->source_addr = rmti->source_addr;
    rmt_ctx->target_addr = rmti->target_addr;
    rmt_ctx->source_type = rmti->source_type;
    rmt_ctx->target_type = rmti->target_type;

    rmt_ctx->noreply = rmti->noreply;

    rmt_ctx->mbuf_size = rmti->mbuf_size;

    rmt_ctx->step = rmti->step;
    rmt_ctx->source_safe = rmti->source_safe;

    cf = conf_create(rmti->conf_filename);
    if(cf == NULL){
        log_error("ERROR: Conf create from conf file %s failed", 
            rmti->conf_filename);
        destroy_context(rmt_ctx);
        return NULL;
    }

    rmt_ctx->cf = cf;

    if(cf->maxmemory != CONF_UNSET_NUM){
        rmt_ctx->buffer_size = (uint64_t)cf->maxmemory;
    }

    if(cf->threads != CONF_UNSET_NUM){
        rmt_ctx->thread_count = cf->threads;
    }

    if(cf->step != CONF_UNSET_NUM){
        rmt_ctx->step = cf->step;
    }

    if(cf->mbuf_size != CONF_UNSET_NUM){
        rmt_ctx->mbuf_size = cf->mbuf_size;
    }
    
    if(cf->noreply != CONF_UNSET_NUM){
        rmt_ctx->noreply = cf->noreply;
    }

    if(cf->rdb_diskless != CONF_UNSET_NUM){
        rmt_ctx->rdb_diskless = cf->rdb_diskless;
    }

    if(cf->source_safe != CONF_UNSET_NUM){
        rmt_ctx->source_safe = cf->source_safe;
    }

    if (cf->dir != CONF_UNSET_PTR) {
        rmt_ctx->dir = sdsdup(cf->dir);
    }
    
    return rmt_ctx;
}

void destroy_context(rmtContext *rmt_ctx)
{
    if(rmt_ctx == NULL){
        return;
    }
    
    while(array_n(&rmt_ctx->args) > 0)
    {
        sds *arg = array_pop(&rmt_ctx->args);
        sdsfree(*arg);
    }

    array_deinit(&rmt_ctx->args);
    
    if(rmt_ctx->cmd != NULL){
        sdsfree(rmt_ctx->cmd);
    }

    if(rmt_ctx->commands != NULL){
        dictRelease(rmt_ctx->commands);
    }

    if(rmt_ctx->cf != NULL){
        conf_destroy(rmt_ctx->cf);
    }

    if (rmt_ctx->dir != NULL) {
        sdsfree(rmt_ctx->dir);
    }

    rmt_free(rmt_ctx);
}

static int
rmt_daemonize(int dump_core)
{
    int status;
    pid_t pid, sid;
    int fd;

    pid = fork();
    switch (pid) {
    case -1:
        log_error("ERROR: fork() failed: %s", strerror(errno));
        return RMT_ERROR;

    case 0:
        break;

    default:
        /* parent terminates */
        log_info("parent terminates");
        _exit(0);
    }

    /* 1st child continues and becomes the session leader */

    sid = setsid();
    if (sid < 0) {
        log_error("ERROR: setsid() failed: %s", strerror(errno));
        return RMT_ERROR;
    }

    if (signal(SIGHUP, SIG_IGN) == SIG_ERR) {
        log_error("ERROR: signal(SIGHUP, SIG_IGN) failed: %s", strerror(errno));
        return RMT_ERROR;
    }

    pid = fork();
    switch (pid) {
    case -1:
        log_error("ERROR: fork() failed: %s", strerror(errno));
        return RMT_ERROR;

    case 0:
        break;

    default:
        /* 1st child terminates */
        log_info("1st child terminates");
        _exit(0);
    }

    /* 2nd child continues */

    /* change working directory */
    if (dump_core == 0) {
        status = chdir("/");
        if (status < 0) {
            log_error("ERROR: chdir(\"/\") failed: %s", strerror(errno));
            return RMT_ERROR;
        }
    }

    /* clear file mode creation mask */
    umask(0);

    /* redirect stdin, stdout and stderr to "/dev/null" */

    fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        log_error("ERROR: open(\"/dev/null\") failed: %s", strerror(errno));
        return RMT_ERROR;
    }

    status = dup2(fd, STDIN_FILENO);
    if (status < 0) {
        log_error("ERROR: dup2(%d, STDIN) failed: %s", fd, strerror(errno));
        close(fd);
        return RMT_ERROR;
    }

    status = dup2(fd, STDOUT_FILENO);
    if (status < 0) {
        log_error("ERROR: dup2(%d, STDOUT) failed: %s", fd, strerror(errno));
        close(fd);
        return RMT_ERROR;
    }

    status = dup2(fd, STDERR_FILENO);
    if (status < 0) {
        log_error("ERROR: dup2(%d, STDERR) failed: %s", fd, strerror(errno));
        close(fd);
        return RMT_ERROR;
    }

    if (fd > STDERR_FILENO) {
        status = close(fd);
        if (status < 0) {
            log_error("ERROR: close(%d) failed: %s", fd, strerror(errno));
            return RMT_ERROR;
        }
    }

    return RMT_OK;
}

static int
rmt_create_pidfile(struct instance *rmti)
{
    char pid[RMT_UINTMAX_MAXLEN];
    int fd, pid_len;
    ssize_t n;

    fd = open(rmti->pid_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        log_error("ERROR: opening pid file '%s' failed: %s", rmti->pid_filename,
                  strerror(errno));
        return RMT_ERROR;
    }
    rmti->pidfile = 1;

    pid_len = rmt_snprintf(pid, RMT_UINTMAX_MAXLEN, "%d", rmti->pid);

    n = rmt_write(fd, pid, pid_len);
    if (n < 0) {
        log_error("ERROR: write to pid file '%s' failed: %s", rmti->pid_filename,
                  strerror(errno));
        return RMT_ERROR;
    }

    close(fd);

    return RMT_OK;
}

int main(int argc,char *argv[])
{
    r_status status;
    struct instance rmti;
    rmtContext *rmt_ctx;

    rmt_set_default_options(&rmti);
    
    status = rmt_get_options(argc, argv, &rmti);
    if (status != RMT_OK) {
        rmt_show_usage();
        exit(0);
    }
    
    if (rmti.show_version) {
        log_stderr("This is redis-migrate-tool-%s" CRLF, RMT_VERSION_STRING);
        if (rmti.show_help) {
            rmt_show_usage();
        }

        exit(0);
    }

    status = log_init(rmti.log_level, rmti.log_filename);
    if (status != RMT_OK) {
        return status;
    }

    log_debug(LOG_DEBUG, "log enabled");

    if (rmti.daemonize) {
        status = rmt_daemonize(1);
        if (status != RMT_OK) {
            log_error("ERROR: Daemonize failed.");
            return status;
        }
    }
    
    rmti.pid = getpid();
    if (rmti.pid_filename) {
        status = rmt_create_pidfile(&rmti);
        if (status != RMT_OK) {
            log_error("ERROR: Create pidfile failed.");
            return status;
        }        
    }

    rmt_ctx = init_context(&rmti);
    if(rmt_ctx == NULL)
    {
        return RMT_ERROR;
    }
    
    core_core(rmt_ctx);

    destroy_context(rmt_ctx);

    return RMT_OK;
}

