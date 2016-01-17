
#ifndef _RMT_ARRAY_H_
#define _RMT_ARRAY_H_

typedef int (*array_compare_t)(const void *, const void *);
typedef int (*array_each_t)(void *, void *);

struct array {
    uint32_t nelem;  /* # element */
    void     *elem;  /* element */
    size_t   size;   /* element size */
    uint32_t nalloc; /* # allocated element */
};

#define null_array { 0, NULL, 0, 0 }

static inline void
array_null(struct array *a)
{
    a->nelem = 0;
    a->elem = NULL;
    a->size = 0;
    a->nalloc = 0;
}

static inline void
array_set(struct array *a, void *elem, size_t size, uint32_t nalloc)
{
    a->nelem = 0;
    a->elem = elem;
    a->size = size;
    a->nalloc = nalloc;
}

static inline uint32_t
array_n(const struct array *a)
{
    return a->nelem;
}

struct array *array_create(uint32_t n, size_t size);
void array_destroy(struct array *a);
int array_init(struct array *a, uint32_t n, size_t size);
void array_deinit(struct array *a);

uint32_t array_idx(struct array *a, void *elem);
void *array_push(struct array *a);
void *array_pop(struct array *a);
void *array_get(struct array *a, uint32_t idx);
void *array_top(struct array *a);
void array_swap(struct array *a, struct array *b);
void array_sort(struct array *a, array_compare_t compare);
int array_each(struct array *a, array_each_t func, void *data);

#endif
