#ifndef _RMT_MTTLIST_H_
#define _RMT_MTTLIST_H_

//multi-thread safe list
typedef struct mttlist{
    void *l;
    int (*lock_push)(void *l, void *value);
    void *(*lock_pop)(void *l);
    void (*free)(void *l);
    long long (*length)(void *l);
}mttlist;

typedef int (*mttlist_init)(mttlist *);

/******** multi-thread safe list interface ********/

mttlist *mttlist_create(void);
void mttlist_destroy(mttlist *l);
int mttlist_push(mttlist *l, void *value);
void *mttlist_pop(mttlist *l);
int mttlist_empty(mttlist *l);
long long mttlist_length(mttlist *l);

/******** multi-thread safe list implement ********/

int mttlist_init_with_locklist(mttlist *l);

int mttlist_init_with_unlocklist(mttlist *l);

#endif
