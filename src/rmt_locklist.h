#ifndef _RMT_LOCKLIST_H_
#define _RMT_LOCKLIST_H_

typedef struct locklist{
    list *l;
    pthread_mutex_t lmutex;
}locklist;

locklist *locklist_create(void);
int locklist_push(void *l, void *value);
void *locklist_pop(void *l);
void locklist_free(void *l);
long long locklist_length(void *l);

#endif
