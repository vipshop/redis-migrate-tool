#ifndef _RMT_UNLOCKLIST_H_
#define _RMT_UNLOCKLIST_H_

typedef struct unlocklist{
    list *l;
}unlocklist;

unlocklist *unlocklist_create(void);
int unlocklist_push(void *l, void *value);
void *unlocklist_pop(void *l);
void unlocklist_free(void *l);
long long unlocklist_length(void *l);

#endif
