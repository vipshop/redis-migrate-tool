
#include <rmt_core.h>

#define COMMAND_NAME_MAX_LENGTH 21

struct RMTCommand rmtCommandTable[] = {
    {RMT_CMD_REDIS_MIGRATE, "Migrate data from source group to target group.", 
        redis_migrate, -1, 0, 0, 0},
    {RMT_CMD_REDIS_CHECK, "Compare data between source group and target group. Default compare 1000 keys. You can set a key count behind.", 
        redis_check_data, -1, 0, 1, 0},
    {RMT_CMD_REDIS_TESTINSERT, "Just for test! Insert some string, list, set, zset and hash keys into the source redis group. Default 1000 keys. You can set key type and key count behind.", 
        redis_testinsert_data, -1, 0, 2, 0}
};

void
rmt_show_command_usage(void)
{
    int j;
    int numcommands;
    RMTCommand *c;
    int command_name_len;
    char command_name_with_space[COMMAND_NAME_MAX_LENGTH + 1];

    numcommands = sizeof(rmtCommandTable)/sizeof(RMTCommand);

    log_stdout("Commands:");

    for (j = 0; j < numcommands; j++) {
        c = rmtCommandTable+j;

        command_name_len = (int)strlen(c->name);
        if(command_name_len > COMMAND_NAME_MAX_LENGTH)
        {
            return;
        }

        memset(command_name_with_space, ' ', COMMAND_NAME_MAX_LENGTH);
        command_name_with_space[COMMAND_NAME_MAX_LENGTH] = '\0';
        memcpy(command_name_with_space, c->name, (size_t)command_name_len);
        log_stdout("    %s: %s", command_name_with_space, c->description);       
    }
}


/* Populates the Redis Command Table starting from the hard coded list
 * we have in the rmt_command.h file. */
void populateCommandTable(dict *commands) {
    
    int ret;
    int j;
    int numcommands;

    if(commands == NULL)
    {
        return;
    }

    numcommands = sizeof(rmtCommandTable)/sizeof(RMTCommand);

    for (j = 0; j < numcommands; j++) {
        RMTCommand *c = rmtCommandTable+j;

        ret = dictAdd(commands, sdsnew(c->name), c);
    }
}


