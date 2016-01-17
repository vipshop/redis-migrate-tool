#include <rmt_core.h>

#ifdef RMT_MEMORY_TEST
static volatile long long mbuf_used;
static pthread_mutex_t mbuf_mutex;
#endif

static struct mbuf *
_mbuf_get(mbuf_base *mb)
{
    struct mbuf *mbuf;
    uint8_t *buf;

    if(mb == NULL)
    {
        return NULL;
    }

    if(mb->free_mbufs)
    {
        mbuf = mttlist_pop(mb->free_mbufs);
        if(mbuf != NULL)
        {
            return mbuf;
        }
    }

    buf = rmt_alloc(mb->mbuf_chunk_size);
    if (buf == NULL) {
        return NULL;
    }

#ifdef RMT_MEMORY_TEST
    mbuf_used_up();
#endif

	mb->ntotal_mbuf ++;

    /*
     * mbuf header is at the tail end of the mbuf. This enables us to catch
     * buffer overrun early by asserting on the magic value during get or
     * put operations
     *
     *   <------------- mbuf_chunk_size ------------->
     *   +-------------------------------------------+
     *   |       mbuf data          |  mbuf header   |
     *   |     (mbuf_offset)       | (struct mbuf)   |
     *   +-------------------------------------------+
     *   ^          ^        ^        ^
     *   |           |        |         |
     *   |           |        |         |
     * start      pos     last      end 
     *
     * mbuf->end (one byte past valid bound)
     * mbuf->last (one byte past valid byte)
     */
    mbuf = (struct mbuf *)(buf + mb->mbuf_offset);
    mbuf->mb = mb;
    mbuf->magic = MBUF_MAGIC;
    
    return mbuf;
}

struct mbuf *
mbuf_get(mbuf_base *mb)
{
    struct mbuf *mbuf;
    uint8_t *buf;

    mbuf = _mbuf_get(mb);
    if (mbuf == NULL) {
        return NULL;
    }

    buf = (uint8_t *)mbuf - mb->mbuf_offset;
    mbuf->start = buf;
    mbuf->end = buf + mb->mbuf_offset;

    ASSERT(mbuf->end - mbuf->start == (int)mb->mbuf_offset);
    ASSERT(mbuf->start < mbuf->end);

    mbuf->pos = mbuf->start;
    mbuf->last = mbuf->start;

    log_debug(LOG_VVERB, "get mbuf %p", mbuf);

    return mbuf;
}

static void
mbuf_free(struct mbuf *mbuf)
{
    mbuf_base *mb = mbuf->mb;
    uint8_t *buf;

    log_debug(LOG_VVERB, "put mbuf %p len %d", mbuf, mbuf->last - mbuf->pos);

    ASSERT(mbuf->magic == MBUF_MAGIC);

    buf = (uint8_t *)mbuf - mb->mbuf_offset;
    rmt_free(buf);

#ifdef RMT_MEMORY_TEST
    mbuf_used_down();
#endif

}

int
mbuf_put(struct mbuf *mbuf)
{
    mbuf_base *mb = mbuf->mb;

    log_debug(LOG_VVERB, "put mbuf %p len %d", mbuf, mbuf->last - mbuf->pos);

    ASSERT(mbuf->magic == MBUF_MAGIC);

    if(mb == NULL || mbuf == NULL)
    {
        return RMT_ERROR;
    }

    if(mb->free_mbufs == NULL)
    {
        mbuf_free(mbuf);
        return RMT_OK;
    }

    return mttlist_push(mb->free_mbufs, mbuf);
}

/*
 * Rewind the mbuf by discarding any of the read or unread data that it
 * might hold.
 */
void
mbuf_rewind(struct mbuf *mbuf)
{
    mbuf->pos = mbuf->start;
    mbuf->last = mbuf->start;
}

/*
 * Return the length of data storage in mbuf. Mbuf cannot contain more than
 * 2^32 bytes (4G).
 */
uint32_t
mbuf_storage_length(struct mbuf *mbuf)
{
    ASSERT(mbuf->last >= mbuf->pos);

    return (uint32_t)(mbuf->last - mbuf->start);
}

/*
 * Return the length of data in mbuf. Mbuf cannot contain more than
 * 2^32 bytes (4G).
 */
uint32_t
mbuf_length(struct mbuf *mbuf)
{
    ASSERT(mbuf->last >= mbuf->pos);

    return (uint32_t)(mbuf->last - mbuf->pos);
}

/*
 * Return the remaining space size for any new data in mbuf. Mbuf cannot
 * contain more than 2^32 bytes (4G).
 */
uint32_t
mbuf_size(struct mbuf *mbuf)
{
    ASSERT(mbuf->end >= mbuf->last);

    return (uint32_t)(mbuf->end - mbuf->last);
}

/*
 * Return the maximum available space size for data in any mbuf. Mbuf cannot
 * contain more than 2^32 bytes (4G).
 */
size_t
mbuf_data_size(mbuf_base *mb)
{
    return mb->mbuf_offset;
}

/*
 * Copy n bytes from memory area pos to mbuf.
 *
 * The memory areas should not overlap and the mbuf should have
 * enough space for n bytes.
 */
void
mbuf_copy(struct mbuf *mbuf, const uint8_t *pos, size_t n)
{
    if (n == 0) {
        return;
    }

    /* mbuf has space for n bytes */
    ASSERT(!mbuf_full(mbuf) && n <= mbuf_size(mbuf));

    /* no overlapping copy */
    ASSERT(pos < mbuf->start || pos >= mbuf->end);

    rmt_memcpy(mbuf->last, pos, n);
    mbuf->last += n;
}

/*
 * Split mbuf h into h and t by copying data from h to t. Before
 * the copy, we invoke a precopy handler cb that will copy a predefined
 * string to the head of t.
 *
 * Return new mbuf t, if the split was successful.
 */
struct mbuf *
mbuf_split(struct mbuf *mbuf, uint8_t *pos)
{
    mbuf_base *mb = mbuf->mb;
    struct mbuf *nbuf;
    size_t size;

    if(mb == NULL || mbuf == NULL 
        || pos == NULL)
    {
        return NULL;
    }

    ASSERT(pos >= mbuf->pos && pos <= mbuf->last);

    nbuf = mbuf_get(mb);
    if (nbuf == NULL) {
        return NULL;
    }

	/* copy data from mbuf to nbuf */
    size = (size_t)(mbuf->last - pos);
    mbuf_copy(nbuf, pos, size);

    /* adjust mbuf */
    mbuf->last = pos;

    log_debug(LOG_VVERB, "split into mbuf %p len %"PRIu32" and nbuf %p len "
              "%"PRIu32" copied %zu bytes", mbuf, mbuf_length(mbuf), nbuf,
              mbuf_length(nbuf), size);

    return nbuf;
}

int 
mbuf_move(struct mbuf *mbuf_f, struct mbuf *mbuf_t, uint32_t n)
{
    uint32_t left;
    
    if(mbuf_f == NULL || mbuf_t == NULL)
    {
        log_debug(LOG_DEBUG, "mbuf_f is %s, mbuf_t is %s",
            mbuf_f == NULL?"NULL":"NOT NULL",
            mbuf_t == NULL?"NULL":"NOT NULL");
        return RMT_ERROR;
    }

    if(n > mbuf_length(mbuf_f))
    {
        log_debug(LOG_DEBUG, "n %d > mbuf_f length %d", 
            n, mbuf_length(mbuf_f));
        return RMT_ERROR;
    }

    if(n > mbuf_size(mbuf_t))
    {
        log_debug(LOG_DEBUG, "n %d > mbuf_t size %d", 
            n, mbuf_size(mbuf_t));
        return RMT_ERROR;
    }

    mbuf_copy(mbuf_t, mbuf_f->pos, n);
    log_debug(LOG_DEBUG, "mbuf_f(len %d) move data(%d) to mbuf_t(size %d) success",
        mbuf_length(mbuf_f), n, mbuf_size(mbuf_t));

    left = mbuf_length(mbuf_f) - n;
    log_debug(LOG_DEBUG, "mbuf_f left: %d", left);
    if(left > 0)
    {
        rmt_memcpy(mbuf_f->pos, mbuf_f->pos + n, left);
        mbuf_f->last -= n;
    }
    else
    {
        mbuf_f->last = mbuf_f->pos;
    }    

    return RMT_OK;
}

mbuf_base *
mbuf_base_create(size_t mbuf_chunk_size, mttlist_init fn)
{
    mbuf_base *mb;

    if(mbuf_chunk_size < MBUF_MIN_SIZE || 
        mbuf_chunk_size > MBUF_MAX_SIZE)
    {
        log_error("Error: mbuf size must be between %d and %d", 
            MBUF_MIN_SIZE, MBUF_MAX_SIZE);
        return NULL;
    }

    mb = rmt_alloc(sizeof(*mb));
    if(mb == NULL)
    {
        return NULL;
    }

    mb->free_mbufs = NULL;
    if(fn != NULL)
    {
        mb->free_mbufs = mttlist_create();
        if(mb->free_mbufs == NULL)
        {
            rmt_free(mb);
            return NULL;
        }

        fn(mb->free_mbufs);
    }

    mb->mbuf_chunk_size = mbuf_chunk_size;
    mb->mbuf_offset = mbuf_chunk_size - MBUF_HSIZE;

    mb->ntotal_mbuf = 0;

    log_debug(LOG_DEBUG, "mbuf hsize %d chunk size %zu offset %zu length %zu",
              MBUF_HSIZE, mbuf_chunk_size, mb->mbuf_offset, mb->mbuf_offset);

    return mb;
}

void
mbuf_base_destroy(mbuf_base *mb)
{
    struct mbuf *mbuf;

    if(mb == NULL)
    {
        return;
    }

    if(mb->free_mbufs)
    {
        while((mbuf = mttlist_pop(mb->free_mbufs)) != NULL)
        {
            mbuf_free(mbuf);
        }
        
        mttlist_destroy(mb->free_mbufs);
    }

    rmt_free(mb);
}

int mbuf_list_push(list *l, struct mbuf *mbuf)
{
    if(l == NULL)
    {
        return RMT_ERROR;
    }

    if(listAddNodeTail(l, mbuf) == NULL)
    {
        return RMT_ENOMEM;
    }

    return RMT_OK;
}

int mbuf_list_push_head(list *l, struct mbuf *mbuf)
{
    if(l == NULL)
    {
        return RMT_ERROR;
    }

    if(listAddNodeHead(l, mbuf) == NULL)
    {
        return RMT_ENOMEM;
    }

    return RMT_OK;
}

struct mbuf *mbuf_list_pop(list *l)
{
    struct mbuf *mbuf;
    listNode *lnode;

    if(l == NULL || listLength(l) == 0)
    {
        return NULL;
    }

    lnode = listFirst(l);
    if(lnode == NULL)
    {
        return NULL;
    }

    mbuf = listNodeValue(lnode);
    listDelNode(l, lnode);

    return mbuf;
}

#ifdef RMT_DEBUG_LOG
void
mbuf_list_dump(list *mbufs, int level)
{
    struct mbuf *mbuf;
    listIter *iter;
    listNode *node;
    uint8_t *p, *q;
    long int len;

    if (log_loggable(level) == 0) {
        return;
    }

    if(mbufs == NULL)
    {
        return;
    }

    loga("mbuf list length : %d", listLength(mbufs));

    iter = listGetIterator(mbufs, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        mbuf = listNodeValue(node);
        
        p = mbuf->start;
        q = mbuf->last;
        len = q - p;

        loga_hexdump(p, len, "mbuf [%p] with %ld bytes of data", p, len);
    }

    listReleaseIterator(iter);
}
#else
void
mbuf_list_dump(list *mbufs, int level)
{
    RMT_NOTUSED(mbufs);
    RMT_NOTUSED(level);
}
#endif

#ifdef RMT_MEMORY_TEST
int mbuf_used_init(void)
{
    mbuf_used = 0;
    pthread_mutex_init(&mbuf_mutex,NULL);
    return RMT_OK;
}

void mbuf_used_deinit(void)
{
    mbuf_used = 0;
    pthread_mutex_destroy(&mbuf_mutex);
}

long long mbuf_used_count(void)
{
    return mbuf_used;
}

int mbuf_used_up(void)
{
    pthread_mutex_lock(&mbuf_mutex);    
    mbuf_used ++;
    pthread_mutex_unlock(&mbuf_mutex);
    return RMT_OK;
}

int mbuf_used_down(void)
{
    pthread_mutex_lock(&mbuf_mutex);    
    mbuf_used --;
    pthread_mutex_unlock(&mbuf_mutex);
    return RMT_OK;
}
#endif
