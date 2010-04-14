/*
 * mblock.c
 *
 * memory block allocation/free stuff; it can be deployed on shared files.
 *
 *
 *
 */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <time.h>

#include "memcached/engine.h"

#define MBLOCK_MIN_BITS		7		/* 128byte */
#define MBLOCK_MAX_BITS		23		/* 8MB */
#define MBLOCK_MIN_SIZE		(1<<MBLOCK_MIN_BITS)
#define MBLOCK_MAX_SIZE		(1<<MBLOCK_MAX_BITS)
#define MBLOCK_HEAD_MAGIC	0x20100414

#define offset_to_addr(mhead,offset)			\
	((void *)(((char *)(mhead)) + (offset)))
#define addr_to_offset(mhead,addr)				\
	((uint64_t)(((char *)(addr)) - ((char *)(mhead))))
#define offset_of(type, member)					\
	((unsigned long) &((type *)0)->member)
#define container_of(ptr, type, member)			\
	(type *)(((char *)ptr) - offset_of(type, member))

typedef struct {
	uint64_t	next;
	uint64_t	prev;
} mblock_list;

typedef struct {
	uint32_t	magic;
	uint32_t	flags;
	uint64_t	total_size;

	mblock_list	active_list[MBLOCK_MAX_BITS + 1];
	mblock_list	free_list[MBLOCK_MAX_BITS + 1];

	/* statical information */
	uint32_t	num_active[MBLOCK_MAX_BITS + 1];
	uint32_t	num_free[MBLOCK_MAX_BITS + 1];

	pthread_mutex_t	lock;
} mblock_head;

typedef struct {
	mblock_list	list;
	uint16_t	flags;
	uint8_t		data[0];
} mblock_chunk;

#define MCHUNK_INDEX_MASK		0x003f
#define MCHUNK_FLAGS_ACTIVE		0x0040

#define mchunk_next(mc)		(mc)->list.next
#define mchunk_prev(mc)		(mc)->list.prev
#define mchunk_index(mc)	((mc)->flags & MCHUNK_INDEX_MASK)
#define mchunk_active(mc)	((mc)->flags & MCHUNK_FLAGS_ACTIVE)

static inline bool
mblock_list_is_empty(mblock_head *mhead, mblock_list *list)
{
	return offset_to_addr(mhead, list->next) == list;
}

static inline void
mblock_list_init(mblock_head *mhead, mblock_list *list)
{
	list->next = list->prev = addr_to_offset(mhead, list);
}

static inline void
mblock_list_add(mblock_head *mhead, mblock_list *base, mblock_list *list)
{
	mblock_list	   *plist = offset_to_addr(mhead, base->prev);
	mblock_list	   *nlist = offset_to_addr(mhead, base->next);

	plist->next = addr_to_offset(mhead, list);
	list->prev = addr_to_offset(mhead, plist);
	list->next = addr_to_offset(mhead, nlist);
	nlist->prev = addr_to_offset(mhead, list);
}

static inline void
mblock_list_del(mblock_head *mhead, mblock_list *list)
{
	mblock_list	   *plist = offset_to_addr(mhead, list->prev);
	mblock_list    *nlist = offset_to_addr(mhead, list->next);

	plist->next = addr_to_offset(mhead, nlist);
	nlist->prev = addr_to_offset(mhead, plist);
	list->next = list->prev = addr_to_offset(mhead, list);
}

static bool
mblock_divide_chunk(mblock_head *mhead, int index)
{
	mblock_chunk   *mchunk1;
	mblock_chunk   *mchunk2;
	uint64_t		offset;

	assert(index != MBLOCK_MIN_BITS);

	if (mblock_list_is_empty(mhead, &mhead->free_list[index]))
	{
		if (index == MBLOCK_MAX_BITS)
			return false;
		else
			if (!mblock_divide_chunk(mhead, index + 1))
				return false;
	}

	mchunk1 = offset_to_addr(mhead, mhead->free_list[index].next);
	assert(mchunk_index(mchunk1) == index);

	/* detach from free list */
	mblock_list_del(mhead, &mchunk1->list);
	mhead->num_free[index]--;

	offset = addr_to_offset(mhead, mchunk1);
	index--;

	mchunk2 = offset_to_addr(mhead, offset + (1 << index));

	/* set up smaller chunks */
	mchunk1->flags = index;
	mchunk2->flags = index;

	mblock_list_add(mhead, &mhead->free_list[index], &mchunk1->list);
	mhead->num_free[index]++;

	mblock_list_add(mhead, &mhead->free_list[index], &mchunk2->list);
	mhead->num_free[index]++;

	return true;
}

void *
mblock_alloc(void *handle, size_t size)
{
	mblock_head	   *mhead = handle;
	mblock_chunk   *mchunk;
	int				index;

	if (size > MBLOCK_MAX_SIZE)
		return NULL;

	for (index = MBLOCK_MIN_BITS; index <= MBLOCK_MAX_BITS; index++)
	{
		if ((1 << index) >= size)
			break;
	}

	pthread_mutex_lock(&mhead->lock);

	/*
	 * If freelist is empty, divide a larger chunk into two.
	 * If unavailable anymore, we cannot allocate new chunks.
	 */
	if (mblock_list_is_empty(mhead, &mhead->free_list[index]) &&
		!mblock_divide_chunk(mhead, index + 1))
	{
		pthread_mutex_unlock(&mhead->lock);

		return NULL;
	}
	assert(!mblock_list_is_empty(mhead, &mhead->free_list[index]));

	mchunk = offset_to_addr(mhead, mhead->free_list[index].next);
	assert(mchunk_index(mchunk) == index);

	mblock_list_del(mhead, &mchunk->list);
	mhead->num_free[index]--;

	mblock_list_add(mhead, &mhead->active_list[index], &mchunk->list);
	mhead->num_active[index]++;

	mchunk->flags |= MCHUNK_FLAGS_ACTIVE;

	pthread_mutex_unlock(&mhead->lock);

	return mchunk->data;
}

void
mblock_free(void *handle, void *ptr)
{
	mblock_head	   *mhead = handle;
	mblock_chunk   *mchunk = container_of(ptr, mblock_chunk, data);
	mblock_chunk   *buddy;
	uint64_t		offset = addr_to_offset(mhead, mchunk);
	int				index = mchunk_index(mchunk);

	assert(mchunk_active(mchunk));

	pthread_mutex_lock(&mhead->lock);

	/* Detach from the active list */
	mblock_list_del(mhead, &mchunk->list);
	mhead->num_active[index]--;

	while (index < MBLOCK_MAX_BITS)
	{
		/* Is the buddy chunk also free? */
		if (offset & (1 << index))
		    buddy= offset_to_addr(mhead, offset & ~(1 << index));
		else
			buddy = offset_to_addr(mhead, offset | (1 << index));

		/* Is it available to compound the two into one? */
		if (mchunk_active(buddy) || mchunk_index(buddy) != index)
			break;

		/* If compoundable, also detach it from free list */
		mblock_list_del(mhead, &buddy->list);
		mhead->num_free[index]--;

		/* Compound two chunks into one */
		index++;
		offset &= ~((1 << index) - 1);
		mchunk = offset_to_addr(mhead, offset);

		mchunk->flags = index;
	}

	/* Add mchunk into free list */
	mblock_list_add(mhead, &mhead->free_list[index], &mchunk->list);
	mhead->num_free[index]++;

	pthread_mutex_unlock(&mhead->lock);
}

void
mblock_reset(void *handle)
{}

void
mblock_stat(void *handle, char *buffer, size_t buflen)
{
	mblock_head	   *mhead = handle;
	uint64_t		total_active = 0;
	uint64_t		total_free = 0;
	int				i, ofs = 0;

	ofs += snprintf(buffer, buflen, "total_size: %" PRIu64 "\n",
					mhead->total_size);
	for (i = MBLOCK_MIN_BITS; i <= MBLOCK_MAX_BITS; i++)
	{
		ofs += snprintf(buffer + ofs, buflen - ofs,
						"class %02d: %lu of used, %lu of free\n",
						mhead->num_active[i], mhead->num_free[i]);
		total_active += mhead->num_active[i] * (1 << i);
		total_free += mhead->num_free[i] * (1 << i);
	}

	ofs += snprintf(buffer + ofs, buflen - ofs,
					"total_active: %" PRIu64 "\n", total_active);
	ofs += snprintf(buffer + ofs, buflen - ofs,
					"total_free: %" PRIu64 "\n", total_free);
	ofs += snprintf(buffer + ofs, buflen - ofs,
					"total: %" PRIu64 "\n", total_active + total_free);
}

void *
mblock_init(int fdesc, size_t total_size,
			bool (*callback_mchunk)(void *data))
{
	mblock_head	   *mhead;
	mblock_chunk   *mchunk;
	uint64_t		offset;
	int				index;
	int				count;

	mhead = (mblock_head *) mmap(NULL, total_size,
								 PROT_READ | PROT_WRITE,
								 fdesc < 0 ? MAP_ANONYMOUS : MAP_SHARED,
								 fdesc, 0);
	if (mhead == MAP_FAILED)
		return NULL;

	if (mhead->magic != MBLOCK_HEAD_MAGIC)
	{
		/* construct memory block */
		mhead->magic = MBLOCK_HEAD_MAGIC;
		mhead->flags = 0;

		pthread_mutex_init(&mhead->lock, NULL);

		for (index = 0; index < MBLOCK_MAX_BITS + 1; index++)
		{
			mblock_list_init(mhead, &mhead->free_list[index]);
			mblock_list_init(mhead, &mhead->active_list[index]);
			mhead->num_free[index] = 0;
			mhead->num_active[index] = 0;
		}

		/* adjust initial position */
		for (offset = MBLOCK_MIN_SIZE;
			 offset < sizeof(mblock_head);
			 offset <<= 1);

		while (total_size - offset >= MBLOCK_MIN_SIZE)
		{
			/* choose an appropriate chunk class */
			index = ffsll(offset) - 1;
			assert(index < MBLOCK_MIN_BITS);

			/* truncate to maximum size */
			if (index > MBLOCK_MAX_BITS)
				index = MBLOCK_MAX_BITS;

			/* if (offset + chunk_size) over the tail, truncate it */
			while (total_size > offset + (1 << index))
				index--;

			if (index < MBLOCK_MIN_BITS)
				break;

			/* chain a memory chunk to free list */
			mchunk = offset_to_addr(mhead, offset);
			mchunk->flags = index;

			mblock_list_add(mhead, &mhead->free_list[index], &mchunk->list);
			mhead->num_free[index]++;

			offset += (1 << index);
		}
		mhead->total_size = offset;
	}
	else
	{
		/* sanity checks */
		struct timespec		timeout = { .tv_sec = 5, .tv_nsec = 0 };
		uint32_t	num_free[MBLOCK_MAX_BITS + 1];
		uint32_t	num_active[MBLOCK_MAX_BITS + 1];
		uint64_t	total_free;
		uint64_t	total_active;

		/* try to lock this mapped file */
		if (pthread_mutex_timedlock(&mhead->lock, &timeout) != 0)
			goto error;

		memset(num_free, 0, sizeof(num_free));
		memset(num_active, 0, sizeof(num_active));

		for (index = 0; index <= MBLOCK_MAX_BITS; index++)
		{
			offset = mhead->free_list[index].next;
			while (offset_to_addr(mhead, offset) != &mhead->free_list[index])
			{
				mchunk = container_of(offset_to_addr(mhead, offset),
									  mblock_chunk, list);
				if (mchunk_index(mchunk) != index)
					goto error;
				if (mchunk_active(mchunk))
					goto error;

				total_free += (1 << index);
				num_free[index]++;

				offset = mchunk_next(mchunk);
			}

			offset = mhead->active_list[index].next;
			while (offset_to_addr(mhead, offset) != &mhead->active_list[index])
			{
				mchunk = container_of(offset_to_addr(mhead, offset),
									  mblock_chunk, list);
				if (mchunk_index(mchunk) != index)
					goto error;
				if (!mchunk_active(mchunk))
					goto error;

				total_active += (1 << index);
				num_active[index]++;

				offset = mchunk_next(mchunk);
			}

			if (mhead->num_free[index] != num_free[index] ||
				mhead->num_active[index] != num_active[index] ||
				mhead->total_size != (total_free + total_active))
				goto error;
		}
		
		/* unlock mapped file */
		pthread_mutex_unlock(&mhead->lock);
	}
	return (void *)mhead;

error:
	munmap(mhead, total_size);
	return NULL;
}

int main(int argc, const char *argv[])
{

	return 0;
}
