
#ifndef _RMT_MBUF_H_
#define _RMT_MBUF_H_

typedef struct mbuf_base{
    size_t mbuf_chunk_size; /* mbuf chunk size - header + data (const) */
    size_t mbuf_offset;     /* mbuf offset in chunk (const) */

    uint64_t ntotal_mbuf;   /* total mbuf count */
    mttlist  *free_mbufs;   /* free mbuf list */
}mbuf_base;

struct mbuf {
    mbuf_base          *mb;
    uint32_t           magic;   /* mbuf magic (const) */
    uint8_t            *pos;    /* read marker */
    uint8_t            *last;   /* write marker */
    uint8_t            *start;  /* start of buffer (const) */
    uint8_t            *end;    /* end of buffer (const) */
};

typedef void (*mbuf_copy_t)(struct mbuf *, void *);

#define MBUF_MAGIC      0xdeadbeef
#define MBUF_HSIZE      sizeof(struct mbuf) //48
#define MBUF_MIN_SIZE   128
#define MBUF_MAX_SIZE   16777216
#define MBUF_SIZE       16384

static inline int
mbuf_empty(struct mbuf *mbuf)
{
    return mbuf->pos == mbuf->last ? 1 : 0;
}

static inline int
mbuf_full(struct mbuf *mbuf)
{
    return mbuf->last == mbuf->end ? 1 : 0;
}

mbuf_base *mbuf_base_create(size_t mbuf_chunk_size, mttlist_init fn);
void mbuf_base_destroy(mbuf_base *mb);

struct mbuf *mbuf_get(mbuf_base *mb);
int mbuf_put(struct mbuf *mbuf);
void mbuf_rewind(struct mbuf *mbuf);
uint32_t mbuf_storage_length(struct mbuf *mbuf);
uint32_t mbuf_length(struct mbuf *mbuf);
uint32_t mbuf_size(struct mbuf *mbuf);
size_t mbuf_data_size(mbuf_base *mb);
void mbuf_copy(struct mbuf *mbuf, const uint8_t *pos, size_t n);
struct mbuf *mbuf_split(struct mbuf *mbuf, uint8_t *pos);
int mbuf_move(struct mbuf *mbuf_f, struct mbuf *mbuf_t, uint32_t n);

int mbuf_list_push_head(list *l, struct mbuf *mbuf);
int mbuf_list_push(list *l, struct mbuf *mbuf);
struct mbuf *mbuf_list_pop(list *l);
void mbuf_list_dump(list *mbufs, int level);

#ifdef RMT_MEMORY_TEST
int mbuf_used_init(void);
void mbuf_used_deinit(void);
long long mbuf_used_count(void);
int mbuf_used_up(void);
int mbuf_used_down(void);
#endif


#endif
