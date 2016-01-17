
#include <rmt_core.h>

unlocklist *unlocklist_create(void)
{
    unlocklist *unllist;

    unllist = rmt_alloc(sizeof(*unllist));
    if(unllist == NULL)
    {
        return NULL;
    }
    
    unllist->l = listCreate();
    if(unllist->l == NULL)
    {
        locklist_free(unllist);
        return NULL;
    }

    return unllist;
}

int unlocklist_push(void *l, void *value)
{
    unlocklist *unllist = l;
    if(unllist == NULL || unllist->l == NULL)
    {
        return RMT_ERROR;
    }

    listAddNodeTail(unllist->l, value);
    
    return RMT_OK;
}

void *unlocklist_pop(void *l)
{
    unlocklist *unllist = l;
    listNode *node;
    void *value;
        
    if(unllist == NULL || unllist->l == NULL)
    {
        return NULL;
    }
    
    node = listFirst(unllist->l);
    if(node == NULL)
    {
        return NULL;
    }

    value = listNodeValue(node);

    listDelNode(unllist->l, node);

    return  value;
}

void unlocklist_free(void *l)
{
    unlocklist *unllist = l;
    if(unllist == NULL)
    {
        return;
    }

    if(unllist->l != NULL)
    {
        listRelease(unllist->l);
    }

    rmt_free(unllist);
}

long long unlocklist_length(void *l)
{
    unlocklist *unllist = l;
    long long length;
    
    if(unllist == NULL || unllist->l == NULL)
    {
        return -1;
    }
    
    length = (long long)listLength(unllist->l);
    
    return length;
}

