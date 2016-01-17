#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <rmt_core.h>

int         LOG_RORATE                      = 0;
ssize_t     LOG_FIEL_MAX_SIZE_FOR_ROTATING  = 1048576;  /* 1MB */
int         LOG_FILE_COUNT_TO_STAY          = 2;

static struct logger logger;

int
log_init(int level, char *name)
{
    struct logger *l = &logger;

    l->level = MAX(LOG_EMERG, MIN(level, LOG_PVERB));
    l->name = name;
    if (name == NULL || !strlen(name)) {
        l->fd = STDERR_FILENO;
    } else {
        l->fd = open(name, O_WRONLY | O_APPEND | O_CREAT, 0644);
        if (l->fd < 0) {
            log_stderr("opening log file '%s' failed: %s", name,
                       strerror(errno));
            return -1;
        }

        log_debug(LOG_DEBUG, "LOG_RORATE %d", LOG_RORATE);
        log_debug(LOG_DEBUG, "LOG_FIEL_MAX_SIZE_FOR_ROTATING %ld", LOG_FIEL_MAX_SIZE_FOR_ROTATING);
        log_debug(LOG_DEBUG, "LOG_FILE_COUNT_TO_STAY %d", LOG_FILE_COUNT_TO_STAY);
        if(log_rotate_init(l) < 0)
        {
            return -1;
        }
        if(log_files_circular_init(l) < 0)
        {
            return -1;
        }

    }

    return 0;
}

void
log_deinit(void)
{
    struct logger *l = &logger;

    if (l->fd < 0 || l->fd == STDERR_FILENO) {
        return;
    }

    close(l->fd);

    _log_rotate_deinit(l);
    _log_files_circular_deinit(l);

}

void
log_reopen(void)
{
    struct logger *l = &logger;

    if (l->fd != STDERR_FILENO) {
        close(l->fd);
        l->fd = open(l->name, O_WRONLY | O_APPEND | O_CREAT, 0644);
        if (l->fd < 0) {
            log_stderr_safe("reopening log file '%s' failed, ignored: %s", l->name,
                       strerror(errno));
            return;
        }

        _log_files_circular_deinit(l);
        _log_rotate_deinit(l);
        log_rotate_init(l);
        log_files_circular_init(l);
    }
}

void
log_level_up(void)
{
    struct logger *l = &logger;

    if (l->level < LOG_PVERB) {
        l->level++;
        log_safe("up log level to %d", l->level);
    }
}

void
log_level_down(void)
{
    struct logger *l = &logger;

    if (l->level > LOG_EMERG) {
        l->level--;
        log_safe("down log level to %d", l->level);
    }
}

void
log_level_set(int level)
{
    struct logger *l = &logger;

    l->level = MAX(LOG_EMERG, MIN(level, LOG_PVERB));
    loga("set log level to %d", l->level);
}

void
log_stacktrace(void)
{
    struct logger *l = &logger;

    if (l->fd < 0) {
        return;
    }
    rmt_stacktrace_fd(l->fd);
}

int
log_loggable(int level)
{
    struct logger *l = &logger;

    if (level > l->level) {
        return 0;
    }

    return 1;
}

void
_log(const char *file, int line, int panic, const char *fmt, ...)
{
    struct logger *l = &logger;
    int len, size, errno_save;
    char buf[LOG_MAX_LEN];
    va_list args;
    ssize_t n;
    struct timeval tv;

    if (l->fd < 0) {
        return;
    }

    errno_save = errno;
    len = 0;            /* length of output buffer */
    size = LOG_MAX_LEN; /* size of output buffer */

    gettimeofday(&tv, NULL);
    buf[len++] = '[';
    len += rmt_strftime(buf + len, size - len, "%Y-%m-%d %H:%M:%S.", localtime(&tv.tv_sec));
    len += rmt_scnprintf(buf + len, size - len, "%03ld", tv.tv_usec/1000);
    len += rmt_scnprintf(buf + len, size - len, "] %s:%d ", file, line);

    va_start(args, fmt);
    len += rmt_vscnprintf(buf + len, size - len, fmt, args);
    va_end(args);

    buf[len++] = '\n';

    n = rmt_write(l->fd, buf, len);
    if (n < 0) {
        l->nerror++;
    }
    else
    {
        _log_rotating(n, l);
    }

    errno = errno_save;

    if (panic) {
        abort();
    }
}

void
_log_stderr(const char *fmt, ...)
{
    struct logger *l = &logger;
    int len, size, errno_save;
    char buf[4 * LOG_MAX_LEN];
    va_list args;
    ssize_t n;

    errno_save = errno;
    len = 0;                /* length of output buffer */
    size = 4 * LOG_MAX_LEN; /* size of output buffer */

    va_start(args, fmt);
    len += rmt_vscnprintf(buf, size, fmt, args);
    va_end(args);

    buf[len++] = '\n';

    n = rmt_write(STDERR_FILENO, buf, len);
    if (n < 0) {
        l->nerror++;
    }

    errno = errno_save;
}

void
_log_stdout(const char *fmt, ...)
{
    struct logger *l = &logger;
    int len, size, errno_save;
    char buf[4 * LOG_MAX_LEN];
    va_list args;
    ssize_t n;

    errno_save = errno;
    len = 0;                /* length of output buffer */
    size = 4 * LOG_MAX_LEN; /* size of output buffer */

    va_start(args, fmt);
    len += rmt_vscnprintf(buf, size, fmt, args);
    va_end(args);

    buf[len++] = '\n';

    n = rmt_write(STDOUT_FILENO, buf, len);
    if (n < 0) {
        l->nerror++;
    }

    errno = errno_save;
}

/*
 * Hexadecimal dump in the canonical hex + ascii display
 * See -C option in man hexdump
 */
void
_log_hexdump(const char *file, int line, char *data, int datalen,
             const char *fmt, ...)
{
    struct logger *l = &logger;
    char buf[8 * LOG_MAX_LEN];
    int i, off, len, size, errno_save;
    ssize_t n;

    RMT_NOTUSED(file);
    RMT_NOTUSED(line);
    RMT_NOTUSED(fmt);

    if (l->fd < 0) {
        return;
    }

    /* log hexdump */
    errno_save = errno;
    off = 0;                  /* data offset */
    len = 0;                  /* length of output buffer */
    size = 8 * LOG_MAX_LEN;   /* size of output buffer */

    while (datalen != 0 && (len < size - 1)) {
        char *save;
        const char *str;
        unsigned char c;
        int savelen;

        len += rmt_scnprintf(buf + len, size - len, "%08x  ", off);

        save = data;
        savelen = datalen;

        for (i = 0; datalen != 0 && i < 16; data++, datalen--, i++) {
            c = (unsigned char)(*data);
            str = (i == 7) ? "  " : " ";
            len += rmt_scnprintf(buf + len, size - len, "%02x%s", c, str);
        }
        for ( ; i < 16; i++) {
            str = (i == 7) ? "  " : " ";
            len += rmt_scnprintf(buf + len, size - len, "  %s", str);
        }

        data = save;
        datalen = savelen;

        len += rmt_scnprintf(buf + len, size - len, "  |");

        for (i = 0; datalen != 0 && i < 16; data++, datalen--, i++) {
            c = (unsigned char)(isprint(*data) ? *data : '.');
            len += rmt_scnprintf(buf + len, size - len, "%c", c);
        }
        len += rmt_scnprintf(buf + len, size - len, "|\n");

        off += 16;
    }

    n = rmt_write(l->fd, buf, len);
    if (n < 0) {
        l->nerror++;
    }
    else
    {
        _log_rotating(n, l);
    }

    if (len >= size - 1) {
        n = rmt_write(l->fd, "\n", 1);
        if (n < 0) {
            l->nerror++;
        }
        else
        {
            _log_rotating(n, l);
        }
    }

    errno = errno_save;
}

void
_log_safe(const char *fmt, ...)
{
    struct logger *l = &logger;
    int len, size, errno_save;
    char buf[LOG_MAX_LEN];
    va_list args;
    ssize_t n;

    if (l->fd < 0) {
        return;
    }

    errno_save = errno;
    len = 0;            /* length of output buffer */
    size = LOG_MAX_LEN; /* size of output buffer */

    len += rmt_safe_snprintf(buf + len, size - len, "[.......................] ");

    va_start(args, fmt);
    len += rmt_safe_vsnprintf(buf + len, size - len, fmt, args);
    va_end(args);

    buf[len++] = '\n';

    n = rmt_write(l->fd, buf, len);
    if (n < 0) {
        l->nerror++;
    }
    else
    {
        _log_rotating(n, l);
    }

    errno = errno_save;
}

void
_log_stderr_safe(const char *fmt, ...)
{
    struct logger *l = &logger;
    int len, size, errno_save;
    char buf[LOG_MAX_LEN];
    va_list args;
    ssize_t n;

    errno_save = errno;
    len = 0;            /* length of output buffer */
    size = LOG_MAX_LEN; /* size of output buffer */

    len += rmt_safe_snprintf(buf + len, size - len, "[.......................] ");

    va_start(args, fmt);
    len += rmt_safe_vsnprintf(buf + len, size - len, fmt, args);
    va_end(args);

    buf[len++] = '\n';

    n = rmt_write(STDERR_FILENO, buf, len);
    if (n < 0) {
        l->nerror++;
    }
    
    errno = errno_save;
}

int log_rotate_init(struct logger *l)
{
    r_status status = 0;
    if(LOG_RORATE == 0)
    {
        return status;
    }
    //struct logger *l = &logger;
    struct stat statbuff;
    if(stat(l->name, &statbuff) < 0)
    {
        log_stderr("stat log file '%s' failed: %s", l->name,
                   strerror(errno));
        status = -1;
        return status;
    }
    l->current_log_size = statbuff.st_size;
    
    return status;
}

int _log_rotate_deinit(struct logger *l)
{
    r_status status = 0;
    if(LOG_RORATE == 0)
    {
        return status;
    }
    //struct logger *l = &logger;
    l->current_log_size = 0;
    return status;
}

int _log_rotating(ssize_t write_bytes, struct logger *l)
{
    r_status status = 0;
    if(LOG_RORATE == 0)
    {
        return status;
    }
    //struct logger *l = &logger;
    if(write_bytes <= 0)
    {
        return -1;
    }
    l->current_log_size += write_bytes;

    if(l->current_log_size >= LOG_FIEL_MAX_SIZE_FOR_ROTATING)
    {
        if (l->fd < 0 || l->fd == STDERR_FILENO) 
        {
            return -1;
        }
        close(l->fd);
        size_t len = 0;
        char str_time[30];

        struct timeval tv;
        gettimeofday(&tv, NULL);
        len += (size_t)rmt_strftime(str_time, 30 - len, "_%Y-%m-%d_%H.%M.%S.", localtime(&tv.tv_sec));
        len += (size_t)rmt_scnprintf(str_time + len, 30 - len, "%03ld", tv.tv_usec/1000);

        size_t i;
        size_t log_filename_len = strlen(l->name);
    
        size_t filename_bak_len = log_filename_len + len + 1;
        
        char filename_bak[filename_bak_len];
        
        for(i = 0; i < log_filename_len; i ++)
        {
            filename_bak[i] = (l->name)[i];
        }
        for(i = log_filename_len; i < filename_bak_len - 1; i ++)
        {
            filename_bak[i] = str_time[i - log_filename_len];
        }
        filename_bak[filename_bak_len - 1] = '\0';

        //log_debug(LOG_DEBUG, "filename_bak is %s", filename_bak);

        
        if(rename(l->name, filename_bak) < 0)
        {
            log_stderr("rename log file '%s' to '%s' failed: %s", l->name, filename_bak,
                       strerror(errno));
            status |= -1;
        }

        l->fd = open(l->name, O_WRONLY | O_APPEND | O_CREAT, 0644);
        if (l->fd < 0) {
            log_stderr("opening log file '%s' failed: %s", l->name,
                       strerror(errno));
            return -1;
        }
        l->current_log_size = 0;
        status |= _log_files_circular_maintain(filename_bak, l);
    }
    return status;
}

/**
@function name : log_files_circular_maintain
@parameter
file: the newest log bak file(must include the file path and file name).
@return

*/
r_status _log_files_circular_maintain(const char * file, struct logger *l)
{
    r_status status = 0;

    if(LOG_FILE_COUNT_TO_STAY == 0)
    {
        if(unlink(file) < 0)
        {
            log_debug(LOG_WARN, "warning: delete log %s failed : %s", file, strerror(errno));
        }
        else
        {
            log_debug(LOG_DEBUG, "delete log : %s", file);
        }
        return status;
    }
    else if(LOG_FILE_COUNT_TO_STAY < 0)
    {
        return status;
    }
    
    int i = 0;
    //struct logger *l = &logger;
    log_debug(LOG_DEBUG, "file: %s", file);
    char * directory_end_pos = NULL;
    directory_end_pos = strrchr(file, '/');
    const char * filename;
    size_t log_bak_max_len = strlen(file) + 1;
    char log_bak[log_bak_max_len];
    if(NULL == directory_end_pos)
    {
        
        log_bak[1] = '\0';
        filename = file;
    }
    else
    {
        for(i = 0; i < directory_end_pos - file; i++)
        {
            log_bak[i] = (file)[i];
        }
        log_bak[i++] = '/';
        log_bak[i] = '\0';
        filename = directory_end_pos + 1;
    }
    log_debug(LOG_DEBUG,"log_bak : %s", log_bak);
    log_debug(LOG_DEBUG,"filename : %s", filename);
    
    const int max_array_id = LOG_FILE_COUNT_TO_STAY - 1;

    ASSERT(l->circular_cur_pos <= max_array_id);
    
    if(l->circular_full)
    {
        strcat(log_bak, l->log_files_circular[l->circular_cur_pos]);
        log_debug(LOG_DEBUG,"log_bak : %s", log_bak);
        if(unlink(log_bak) < 0)
        {
            log_debug(LOG_WARN, "warning: delete log %s failed : %s", log_bak, strerror(errno));
        }
        else
        {
            log_debug(LOG_DEBUG, "delete log : %s", log_bak);
        }
        strcpy(l->log_files_circular[l->circular_cur_pos], filename);
        l->circular_cur_pos --;
        if(l->circular_cur_pos < 0)
        {
            l->circular_cur_pos = max_array_id;
        }
    }
    else
    {
        status |= _log_files_circular_insert(filename, l);
    }
    _log_files_circular_info(l);
    return status;
}


/**
@function name : is_log_bak_file
@parameter
logname: original log file name.
filename: the filename to be check.
@return 
0: the filename is log bak file.
1: the filename is not log bak file.
-1: error.
*/
int _is_log_bak_file(const char * logname, const char * filename)
{
    if(logname == NULL)
    {
        log_debug(LOG_ERR,"error: logname is NULL!");
        return -1;
    }
    size_t logname_len = strlen(logname);
    size_t filename_len = strlen(filename);
    if((logname_len + 24) != filename_len)
    {
        return 1;
    }
    if(0 != strncmp(logname, filename, logname_len))
    {
        return 1;
    }
    
    int i = 0;
    for(i = 0; i < 24; i ++)
    {
        if(i == 0 || i == 11)
        {
            if(*(filename + logname_len + i) != '_')
            {   
                return 1;
            }
        }
        else if(i == 5 || i == 8)
        {
            if(*(filename + logname_len + i) != '-')
            {
                return 1;
            }
        }
        else if(i == 14 || i == 17 || i == 20)
        {
            if(*(filename + logname_len + i) != '.')
            {
                return 1;
            }
        }
        else
        {
            if(*(filename + logname_len + i) > '9' || *(filename + logname_len + i) < '0')
            {
                return 1;
            }
        }
    }
    return 0;
}

r_status _log_files_circular_insert(const char * filename, struct logger *l)
{
    r_status status = 0;

    if(LOG_FILE_COUNT_TO_STAY <= 0)
    {
        return status;
    }
    
    //struct logger *l = &logger;
    const int max_array_id = LOG_FILE_COUNT_TO_STAY - 1;
    int i = 0;
    int j = 0;
    if(l->circular_cur_pos < 0)
    {
        l->circular_cur_pos = 0;
        l->log_files_circular[l->circular_cur_pos] = rmt_zalloc(strlen(filename) + 1);
        strcpy(l->log_files_circular[l->circular_cur_pos], filename);
    }
    else if(l->circular_cur_pos == max_array_id)
    {
        for(i = max_array_id; i >=0; i --)
        {
            int cmpresult = strcmp(l->log_files_circular[i], filename);
            if(cmpresult < 0 && i > 0)
            {
                continue;   
            }
            else if(cmpresult < 0 && i == 0)
            {
                for(j = max_array_id; j >= i; j --)
                {   
                    l->log_files_circular[j + 1] = l->log_files_circular[j];
                }
                l->log_files_circular[i] = rmt_zalloc(strlen(filename) + 1);
                strcpy(l->log_files_circular[i], filename);
                break;
            }
            else if(cmpresult == 0)
            {
                status = -1;
                return status;
            }
            else if(i == max_array_id)
            {
                break;
            }
            else if(i < max_array_id)
            {
                for(j = max_array_id; j > i; j --)
                {
                    l->log_files_circular[j + 1] = l->log_files_circular[j];
                }
                l->log_files_circular[i + 1] = rmt_zalloc(strlen(filename) + 1);
                strcpy(l->log_files_circular[i + 1], filename);
                break;
            }
        }
        if(l->log_files_circular[max_array_id+1] != NULL)
        {
            rmt_free(l->log_files_circular[max_array_id+1]);
            l->log_files_circular[max_array_id+1] = NULL;
        }
    }
    else if(l->circular_cur_pos < max_array_id)
    {
        for(i = l->circular_cur_pos; i >=0; i --)
        {   
            int cmpresult = strcmp(l->log_files_circular[i], filename);
            if(cmpresult < 0 && i > 0)
            {   
                continue;
            }
            else if(cmpresult < 0 && i == 0)
            {
                for(j = l->circular_cur_pos; j >= i; j --)
                {
                    l->log_files_circular[j + 1] = l->log_files_circular[j];
                }
                l->log_files_circular[i] = rmt_zalloc(strlen(filename) + 1);
                strcpy(l->log_files_circular[i], filename);
                break;
            }
            else if(cmpresult == 0)
            {   
                log_debug(LOG_ERR,"error: find same filename!");
                status = -1;
                return status;
            }
            else
            {   
                for(j = l->circular_cur_pos; j > i; j --)
                {   
                    l->log_files_circular[j + 1] = l->log_files_circular[j];
                }
                l->log_files_circular[i + 1] = rmt_zalloc(strlen(filename) + 1);
                strcpy(l->log_files_circular[i + 1], filename);
                break;
            }
        }
        
        l->circular_cur_pos ++;
    }
    else
    {
        log_debug(LOG_ERR, "error: circular_cur_pos > LOG_FILE_COUNT_TO_STAY");
        status = -1;
        return status;
    }
    if(l->circular_cur_pos == max_array_id)
    {
        l->circular_full = true;
    }
    return status;
}

r_status log_files_circular_init(struct logger *l)
{
    r_status status = 0;
    if(LOG_RORATE == 0)
    {
        return status;
    }
    if(LOG_FILE_COUNT_TO_STAY <= 0)
    {
        log_debug(LOG_INFO, "LOG_FILE_COUNT_TO_STAY <= 0!");
        return status;
    }
    if(LOG_FILE_COUNT_TO_STAY > LOG_FILES_CIRCULAR_MAX_LEN)
    {
        log_debug(LOG_ERR,"error: LOG_FILE_COUNT_TO_STAY must be less then %d!", LOG_FILES_CIRCULAR_MAX_LEN);
        status = -1;
        return status;
    }
    //struct logger *l = &logger;
    int i = 0;
    for(i = 0; i < LOG_FILES_CIRCULAR_MAX_LEN; i ++)    
    {       
        l->log_files_circular[i] = NULL;    
    }   
    l->circular_cur_pos = -1;
    l->circular_full = false;
    //l->log_files_circular
    //char * pos = NULL;
    char * directory_end_pos = NULL;
    directory_end_pos = strrchr(l->name, '/');
    const char * logname;
    size_t directory_max_len = strlen(l->name) + 1;
    //ssize_t filename_max_len = strlen(l->name) + 30;
    char directory[directory_max_len];
    //char filename[filename_max_len];
    if(NULL == directory_end_pos)
    {
        directory[0] = '.';
        directory[1] = '\0';
        logname = l->name;
    }
    else
    {
        for(i = 0; i < directory_end_pos - l->name; i++)
        {
            directory[i] = (l->name)[i];
        }
        directory[i] = '\0';
        logname = directory_end_pos + 1;
    }
    log_debug(LOG_DEBUG, "directory : %s", directory);
    log_debug(LOG_DEBUG, "logname : %s", logname);
    struct stat statbuff;
    if(stat(directory, &statbuff) < 0)
    {
        log_debug(LOG_ERR,"error: stat return negative");
        status = -1;
        return status;
    }
    if(!S_ISDIR(statbuff.st_mode))
    {
        log_debug(LOG_ERR,"error: directory is not a directory!");
        status = -1;
        return status;
    }
    
    DIR *pDir = NULL;
    struct dirent *ent = NULL;
    if((pDir=opendir(directory)) == NULL)
    {
        log_debug(LOG_ERR,"error: can not open directory!");
        status = -1;
        return status;
    }

    while((ent=readdir(pDir))!=NULL)  
    {
        if(ent->d_type & DT_DIR)
        {
            if(strcmp(ent->d_name,".")==0 || strcmp(ent->d_name,"..")==0)  
            { 
                continue;
            }
            log_debug(LOG_DEBUG, "child path : %s", ent->d_name);
         }
        else
        {
            log_debug(LOG_DEBUG, "file name : %s", ent->d_name);
            //log_stderr("%d\n", is_log_bak_file(logname, ent->d_name));
            if(0 == _is_log_bak_file(logname, ent->d_name))
            {
                _log_files_circular_insert(ent->d_name, l);
            }
            else if(0 == strcmp(logname, ent->d_name))
            {
                
            }
            else
            {
                continue;
            }
        }
    }
    
    //l->log_files_circular[l->circular_cur_pos + 1] = rmt_zalloc(strlen(logname) + 1);
    //strcpy(l->log_files_circular[l->circular_cur_pos + 1], logname);
    //l->circular_cur_pos ++;
    _log_files_circular_info(l);
    closedir(pDir);
    return status;
}

r_status _log_files_circular_deinit(struct logger *l)
{
    r_status status = 0;
    if(LOG_RORATE == 0)
    {
        return status;
    }
    //struct logger *l = &logger;
    int i = 0;
    for(i = 0; i < LOG_FILES_CIRCULAR_MAX_LEN; i ++)
    {
        if(l->log_files_circular[i] != NULL)
        {
            rmt_free(l->log_files_circular[i]);
        }
    }
    l->circular_full = false;
    l->circular_cur_pos = -1;
    
    return status;
}

void _log_files_circular_info(struct logger *l)
{
    //struct logger *l = &logger;
    log_debug(LOG_DEBUG, "log files circular info:");
    log_debug(LOG_DEBUG, "l->circular_full : %d", l->circular_full);
    log_debug(LOG_DEBUG, "l->circular_cur_pos : %d", l->circular_cur_pos);
    int i = 0;
    for(i = 0; i < LOG_FILES_CIRCULAR_MAX_LEN; i ++)
    {
        if(l->log_files_circular[i] != NULL)
        {
            log_debug(LOG_DEBUG, "l->log_files_circular[%d] : %s", i, l->log_files_circular[i]);
        }
    }
}

char *
set_log_file_max_size(char *arg)
{
    char ch;
    ssize_t num;
    char *pos;
    char *result = rmt_zalloc(120*sizeof(char));
    char *value;
    size_t value_len;
    size_t i;
    ssize_t multiple_for_unit = 1;
    bool first_nonzero_flag = false;
    
    value = arg;
    value_len = strlen(arg);
    num = 0;
    if(value_len > 2)
    {
        pos = value + value_len - 2;
        if((*pos == 'G' || *pos == 'g') && (*(pos+1) == 'B' || *(pos+1) == 'b'))
        {
            multiple_for_unit = 1073741824;
            value_len -= 2;
        }
        else if((*pos == 'M' || *pos == 'm') && (*(pos+1) == 'B' || *(pos+1) == 'b'))
        {
            multiple_for_unit = 1048576;
            value_len -= 2;
        }
        else if(*(pos+1) == 'G' || *(pos+1) == 'g')
        {
            multiple_for_unit = 1000000000;
            value_len -= 1;
        }
        else if(*(pos+1) == 'M' || *(pos+1) == 'm')
        {
            multiple_for_unit = 1000000;
            value_len -= 1;
        }
        else if(*(pos+1) == 'B' || *(pos+1) == 'b')
        {
            value_len -= 1;
        }
    }
    else if(value_len > 1)
    {
        pos = value + value_len - 1;
        if(*pos == 'G' || *pos == 'g')
        {   
            multiple_for_unit = 1000000000;
            value_len -= 1;
        }
        else if(*pos == 'M' || *pos == 'm')
        {   
            multiple_for_unit = 1000000;
            value_len -= 1;
        }
        else if(*pos == 'B' || *pos == 'b')
        {
            value_len -= 1;
        }
    }
    else if(value_len == 0)
    {
        sprintf(result, "log-file-max-size is null");
        return result;
    }

    for(i = 0; i < value_len; i ++)
    {
        ch = *(value + i);
        if(ch < '0' || ch > '9')
        {
            sprintf(result, "log-file-max-size is not a number");
            return result;
        }
        else if(!first_nonzero_flag && ch != '0')
        {
            first_nonzero_flag = true;
        }
        
        if(first_nonzero_flag)
        {
            num = 10*num + (ch - 48);
        }
    }
    num *= multiple_for_unit;

    if(first_nonzero_flag == false)
    {
        sprintf(result, "log-file-max-size can not be 0");
        return result;
    }

    if(num < LOG_FILE_MAX_SIZE_MIN || num > LOG_FILE_MAX_SIZE_MAX)
    {
        sprintf(result, "log-file-max-size must be between %d and %ld bytes", 
            LOG_FILE_MAX_SIZE_MIN, LOG_FILE_MAX_SIZE_MAX);
        return result;
    }

    LOG_FIEL_MAX_SIZE_FOR_ROTATING = num;
    return NULL;
}

char *
set_log_file_count(char *arg)
{
    int num;
    char *result = rmt_zalloc(120*sizeof(char));
    if(arg == NULL || strlen(arg) == 0)
    {
        sprintf(result, "log-file-count is null");
        return result;
    }

    if(*arg == '-')
    {
        if(strlen(arg) == 2 && *(arg + 1) == '1')
        {
            LOG_FILE_COUNT_TO_STAY = -1;
            return NULL;
        }
        else
        {
            sprintf(result, "log-file-count must be a integer between %d and %d", 
                LOG_FILE_COUNT_MIN, LOG_FILE_COUNT_MAX);
            return result;
        }
    }
    
    num = rmt_atoi(arg, rmt_strlen(arg));
    if(num < 0) {
        sprintf(result, "log-file-count is not a number");
        return result;
    }
    if(num < LOG_FILE_COUNT_MIN || num > LOG_FILE_COUNT_MAX)
    {
        sprintf(result, "log-file-count must be between %d and %d", 
                LOG_FILE_COUNT_MIN, LOG_FILE_COUNT_MAX);
        return result;
    }

    LOG_FILE_COUNT_TO_STAY = num;
    return NULL;
}

void
log_all(const char *file, int line, size_t data_len, uint8_t *data, const char *fmt, ...)
{
    struct logger *l = &logger;
    int len, size, errno_save;
    char buf[50];
    va_list args;
    ssize_t n;
    struct timeval tv;

    if (l->fd < 0) {
        return;
    }

    errno_save = errno;
    len = 0;            /* length of output buffer */
    size = LOG_MAX_LEN; /* size of output buffer */

    gettimeofday(&tv, NULL);
    buf[len++] = '[';
    len += rmt_strftime(buf + len, size - len, "%Y-%m-%d %H:%M:%S.", localtime(&tv.tv_sec));
    len += rmt_scnprintf(buf + len, size - len, "%03ld", tv.tv_usec/1000);
    len += rmt_scnprintf(buf + len, size - len, "] %s:%d ", file, line);

    va_start(args, fmt);
    len += rmt_vscnprintf(buf + len, size - len, fmt, args);
    va_end(args);
    n = rmt_write(l->fd, buf, len);
    if (n < 0) {
        l->nerror++;
    }
    else
    {
        _log_rotating(n, l);
    }

    n = rmt_write(l->fd, data, data_len);
    if (n < 0) {
        l->nerror++;
    }
    else
    {
        _log_rotating(n, l);
    }

    n = rmt_write(l->fd, "\n", 1);
    if (n < 0) {
        l->nerror++;
    }
    else
    {
        _log_rotating(n, l);
    }

    errno = errno_save;
}

