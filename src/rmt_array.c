
#include <stdlib.h>

#include <rmt_core.h>

struct array *
array_create(uint32_t n, size_t size)
{
    struct array *a;

    ASSERT(n != 0 && size != 0);

    a = rmt_alloc(sizeof(*a));
    if (a == NULL) {
        return NULL;
    }

    a->elem = rmt_alloc(n * size);
    if (a->elem == NULL) {
        rmt_free(a);
        return NULL;
    }

    a->nelem = 0;
    a->size = size;
    a->nalloc = n;

    return a;
}

void
array_destroy(struct array *a)
{
    array_deinit(a);
    rmt_free(a);
}

int
array_init(struct array *a, uint32_t n, size_t size)
{
    ASSERT(n != 0 && size != 0);

    a->elem = rmt_alloc(n * size);
    if (a->elem == NULL) {
        return RMT_ENOMEM;
    }

    a->nelem = 0;
    a->size = size;
    a->nalloc = n;

    return RMT_OK;
}

void
array_deinit(struct array *a)
{
    ASSERT(a->nelem == 0);

    if (a->elem != NULL) {
        rmt_free(a->elem);
        a->elem = NULL;
    }
}

uint32_t
array_idx(struct array *a, void *elem)
{
    uint8_t *p, *q;
    uint32_t off, idx;

    ASSERT(elem >= a->elem);

    p = a->elem;
    q = elem;
    off = (uint32_t)(q - p);

    ASSERT(off % (uint32_t)a->size == 0);

    idx = off / (uint32_t)a->size;

    return idx;
}

void *
array_push(struct array *a)
{
    void *elem, *new;
    size_t size;

    if (a->nelem == a->nalloc) {

        /* the array is full; allocate new array */
        size = a->size * a->nalloc;
        new = rmt_realloc(a->elem, 2 * size);
        if (new == NULL) {
            return NULL;
        }

        a->elem = new;
        a->nalloc *= 2;
    }

    elem = (uint8_t *)a->elem + a->size * a->nelem;
    a->nelem++;

    return elem;
}

void *
array_pop(struct array *a)
{
    void *elem;

    ASSERT(a->nelem != 0);

    a->nelem--;
    elem = (uint8_t *)a->elem + a->size * a->nelem;

    return elem;
}

void *
array_get(struct array *a, uint32_t idx)
{
    void *elem;

    ASSERT(a->nelem != 0);
    ASSERT(idx < a->nelem);

    elem = (uint8_t *)a->elem + (a->size * idx);

    return elem;
}

void *
array_top(struct array *a)
{
    ASSERT(a->nelem != 0);

    return array_get(a, a->nelem - 1);
}

void
array_swap(struct array *a, struct array *b)
{
    struct array tmp;

    tmp = *a;
    *a = *b;
    *b = tmp;
}

/*
 * Sort nelem elements of the array in ascending order based on the
 * compare comparator.
 */
void
array_sort(struct array *a, array_compare_t compare)
{
    ASSERT(a->nelem != 0);

    qsort(a->elem, a->nelem, a->size, compare);
}

/*
 * Calls the func once for each element in the array as long as func returns
 * success. On failure short-circuits and returns the error status.
 */
int
array_each(struct array *a, array_each_t func, void *data)
{
    uint32_t i, nelem;

    ASSERT(array_n(a) != 0);
    ASSERT(func != NULL);

    for (i = 0, nelem = array_n(a); i < nelem; i++) {
        void *elem = array_get(a, i);
        int status;

        status = func(elem, data);
        if (status != RMT_OK) {
            return status;
        }
    }

    return RMT_OK;
}
