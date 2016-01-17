
#include <rmt_core.h>

/******** multi-thread safe list interface ********/
mttlist *mttlist_create(void)
{
    mttlist *l;

    l = rmt_alloc(sizeof(*l));
    if(l == NULL)
    {
        return NULL;
    }

    l->l = NULL;
    l->lock_push = NULL;
    l->lock_pop = NULL;
    l->free = NULL;
    l->length = NULL;
    
    return l;
}

void mttlist_destroy(mttlist *l)
{
    if(l == NULL)
    {
        return;
    }

    if(l->free)
    {
        l->free(l->l);
    }

    rmt_free(l);
}

int mttlist_push(mttlist *l, void *value)
{
    if(l == NULL || l->l == NULL
        || l->lock_push == NULL)
    {
        return RMT_ERROR;
    }

    return l->lock_push(l->l, value);
}

void *mttlist_pop(mttlist *l)
{
    if(l == NULL || l->l == NULL
        || l->lock_pop == NULL)
    {
        return NULL;
    }
    
    return l->lock_pop(l->l);
}

int mttlist_empty(mttlist *l)
{
    if(l == NULL || l->l == NULL
        || l->length == NULL)
    {
        return RMT_ERROR;
    }

    if(l->length(l->l) > 0)
    {
        return 0;
    }

    return 1;
}

long long mttlist_length(mttlist *l)
{
    if(l == NULL || l->l == NULL
        || l->length == NULL)
    {
        return -1;
    }

    return l->length(l->l);
}

/******** multi-thread safe list implement ********/

/**
* This is multi-thread safe list.
* This lock list's performance is not good, but it is safe.
*/
int mttlist_init_with_locklist(mttlist *l)
{
    if(l == NULL)
    {
        return RMT_ERROR;
    }

    l->l = locklist_create();
    if(l->l == NULL)
    {
        return RMT_ERROR;
    }
    
    l->lock_push = locklist_push;
    l->lock_pop = locklist_pop;
    l->free = locklist_free;
    l->length = locklist_length;

    return RMT_OK;
}

/**
* This is multi-thread unsafe list.
* You can only use it in one thread.
*/
int mttlist_init_with_unlocklist(mttlist *l)
{
    if(l == NULL)
    {
        return RMT_ERROR;
    }

    l->l = unlocklist_create();
    if(l->l == NULL)
    {
        return RMT_ERROR;
    }
    
    l->lock_push = unlocklist_push;
    l->lock_pop = unlocklist_pop;
    l->free = unlocklist_free;
    l->length = unlocklist_length;

    return RMT_OK;
}

