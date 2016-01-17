
#include <rmt_core.h>

locklist *locklist_create(void)
{
    locklist *llist;

    llist = rmt_alloc(sizeof(*llist));
    if(llist == NULL)
    {
        return NULL;
    }

    pthread_mutex_init(&llist->lmutex,NULL);
    
    llist->l = listCreate();
    if(llist->l == NULL)
    {
        locklist_free(llist);
        return NULL;
    }

    return llist;
}

int locklist_push(void *l, void *value)
{
    locklist *llist = l;
    if(llist == NULL || llist->l == NULL)
    {
        return RMT_ERROR;
    }
    
    pthread_mutex_lock(&llist->lmutex);    
    listAddNodeTail(llist->l, value);
    pthread_mutex_unlock(&llist->lmutex);

    return RMT_OK;
}

void *locklist_pop(void *l)
{
    locklist *llist = l;
    listNode *node;
    void *value;
        
    if(llist == NULL || llist->l == NULL)
    {
        return NULL;
    }
    
    pthread_mutex_lock(&llist->lmutex);
    
    node = listFirst(llist->l);
    if(node == NULL)
    {
        pthread_mutex_unlock(&llist->lmutex);
        return NULL;
    }

    value = listNodeValue(node);

    listDelNode(llist->l, node);

    pthread_mutex_unlock(&llist->lmutex);

    return  value;
}

void locklist_free(void *l)
{
    locklist *llist = l;
    if(llist == NULL)
    {
        return;
    }

    if(llist->l != NULL)
    {
        listRelease(llist->l);
    }

    pthread_mutex_destroy(&llist->lmutex);

    rmt_free(llist);
}

long long locklist_length(void *l)
{
    locklist *llist = l;
    long long length;
    
    if(llist == NULL || llist->l == NULL)
    {
        return -1;
    }

    pthread_mutex_lock(&llist->lmutex);
    length = listLength(llist->l);
    pthread_mutex_unlock(&llist->lmutex);
    
    return length;
}

