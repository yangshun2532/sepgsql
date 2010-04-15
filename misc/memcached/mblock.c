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
	uint64_t	segment_size;	/* segment size of the block */

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
	mblock_list	   *nlist = offset_to_addr(mhead, base->next);

	base->next = addr_to_offset(mhead, list);
	list->prev = addr_to_offset(mhead, base);
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
	mchunk->flags &= ~MCHUNK_FLAGS_ACTIVE;
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
{
	mblock_head	   *mhead = handle;
	mblock_chunk   *mchunk;
	uint64_t		offset;
	int				index;

	pthread_mutex_lock(&mhead->lock);

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

	while (mhead->segment_size - offset >= MBLOCK_MIN_SIZE)
	{
		/* choose an appropriate chunk class */
		index = ffsll(offset) - 1;
		assert(index >= MBLOCK_MIN_BITS);

		/* truncate to maximum size */
		if (index > MBLOCK_MAX_BITS)
			index = MBLOCK_MAX_BITS;

		/* if (offset + chunk_size) over the tail, truncate it */
		while (mhead->segment_size < offset + (1 << index))
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
	pthread_mutex_unlock(&mhead->lock);
}

void
mblock_stat(void *handle, char *buffer, size_t buflen)
{
	mblock_head	   *mhead = handle;
	uint64_t		total_active = 0;
	uint64_t		total_free = 0;
	int				index, ofs = 0;

	ofs += snprintf(buffer, buflen, "segment_size: %" PRIu64 "\n",
					mhead->segment_size);
	for (index = MBLOCK_MIN_BITS; index <= MBLOCK_MAX_BITS; index++)
	{
		if ((1<<index) < 1024)
			ofs += snprintf(buffer + ofs, buflen - ofs,
							"% 4ubyte: ", (1<<index));
		else if ((1<<index) < 1024 * 1024)
			ofs += snprintf(buffer + ofs, buflen - ofs,
							"% 6uKB: ", (1<<(index - 10)));
		else
			ofs += snprintf(buffer + ofs, buflen - ofs,
							"% 6uMB: ", (1<<(index - 20)));
		ofs += snprintf(buffer + ofs, buflen - ofs,
						"%lu of used, %lu of free\n",
						mhead->num_active[index],
						mhead->num_free[index]);

		total_active += mhead->num_active[index] * (1 << index);
		total_free += mhead->num_free[index] * (1 << index);
	}

	ofs += snprintf(buffer + ofs, buflen - ofs,
					"total_active: %" PRIu64 "\n", total_active);
	ofs += snprintf(buffer + ofs, buflen - ofs,
					"total_free: %" PRIu64 "\n", total_free);
	ofs += snprintf(buffer + ofs, buflen - ofs,
					"total: %" PRIu64 "\n", total_active + total_free);
}

void *
mblock_init(int fdesc, size_t segment_size,
			bool (*callback_mchunk)(void *data, size_t size))
{
	mblock_head	   *mhead;
	mblock_chunk   *mchunk;
	uint64_t		offset;
	int				index;
	int				count;

	mhead = (mblock_head *) mmap(NULL, segment_size,
								 PROT_READ | PROT_WRITE,
								 fdesc < 0 ? MAP_ANONYMOUS | MAP_PRIVATE : MAP_SHARED,
								 fdesc, 0);
	if (mhead == MAP_FAILED)
		return NULL;

	if (mhead->magic != MBLOCK_HEAD_MAGIC)
	{
		/* construct memory block */
		mhead->magic = MBLOCK_HEAD_MAGIC;
		mhead->flags = 0;
		mhead->segment_size = segment_size;

		pthread_mutex_init(&mhead->lock, NULL);

		mblock_reset(mhead);
	}
	else
	{
		/* sanity checks */
		struct timespec		timeout = { .tv_sec = 5, .tv_nsec = 0 };
		uint32_t	num_free[MBLOCK_MAX_BITS + 1];
		uint32_t	num_active[MBLOCK_MAX_BITS + 1];
		uint64_t	total_free = 0;
		uint64_t	total_active = 0;

		/*
		 * XXX - we need check to prevent concurrent file using
		 */
		pthread_mutex_init(&mhead->lock, NULL);

		if (mhead->segment_size != segment_size)
			goto error;

		memset(num_free, 0, sizeof(num_free));
		memset(num_active, 0, sizeof(num_active));

		for (index = 0; index <= MBLOCK_MAX_BITS; index++)
		{
			size_t	size = (1 << index) - offset_of(mblock_chunk, data);

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

				if (callback_mchunk && !callback_mchunk(mchunk->data, size))
					goto error;

				total_active += (1 << index);
				num_active[index]++;

				offset = mchunk_next(mchunk);
			}
			if (mhead->num_free[index] != num_free[index] ||
				mhead->num_active[index] != num_active[index])
				goto error;
		}
	}
	return (void *)mhead;

error:
	munmap(mhead, segment_size);
	return NULL;
}

#if 1
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static int my_index = 0;
static void *my_ptr[1024];

static bool
my_callback(void *data, size_t size)
{
	printf("%s called on %p (size=%d)\n", __FUNCTION__, data, size);

	my_ptr[my_index++] = data;

	return true;
}

int main(int argc, const char *argv[])
{
	int		i, fd = -1;
	size_t	length = 1024 * 1024;
	void   *handle;
	char	buffer[1024];
	void   *a, *b, *c;

	if (argc > 2)
	{
		length = atol(argv[2]);
		if (length < 1024 * 1024)
		{
			fprintf(stderr, "file length too short %u\n", length);
			return 1;
		}
	}

	if (argc > 1)
	{
		fd = open(argv[1], O_RDWR | O_CREAT);
		if (fd < 0)
		{
			fprintf(stderr, "failed to open %s\n", argv[1]);
			return 1;
		}
	}

	handle = mblock_init(fd, length, my_callback);
	if (!handle)
	{
		fprintf(stderr, "failed to init mblock\n");
		return 1;
	}

	mblock_stat(handle, buffer, sizeof(buffer));
	puts(buffer);

	a = mblock_alloc(handle, 1);

	mblock_stat(handle, buffer, sizeof(buffer));
	puts(buffer);

	b = mblock_alloc(handle, 385);

	mblock_stat(handle, buffer, sizeof(buffer));
	puts(buffer);

	c = mblock_alloc(handle, 3);

	mblock_stat(handle, buffer, sizeof(buffer));
	puts(buffer);

	mblock_free(handle, a);
	mblock_free(handle, b);
	mblock_free(handle, c);

	printf("mokeke\n");

	while (my_index > 0)
		mblock_free(handle, my_ptr[--my_index]);

	mblock_stat(handle, buffer, sizeof(buffer));
	puts(buffer);

	return 0;
}
#endif
