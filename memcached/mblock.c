/*
 * mblock.c
 *
 * Copyright (C) 2010, NEC Corporation
 *
 * Authors: KaiGai Kohei <kaigai@ak.jp.nec.com> 
 *
 * This program is distributed under the modified BSD license.
 * See the LICENSE file for full text.
 */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "selinux_engine.h"

pthread_mutex_t	mblock_lock = PTHREAD_MUTEX_INITIALIZER;

static bool
mlist_empty(mhead_t *mhead, mlist_t *list)
{
	return offset_to_addr(mhead, list->next) == list;
}

static void
mlist_init(mhead_t *mhead, mlist_t *list)
{
	list->next = list->prev = addr_to_offset(mhead, list);
}

static void
mlist_add(mhead_t *mhead, mlist_t *plist, mlist_t *list)
{
	mlist_t	   *nlist = offset_to_addr(mhead, plist->next);

	plist->next = addr_to_offset(mhead, list);
	list->prev = addr_to_offset(mhead, plist);
	list->next = addr_to_offset(mhead, nlist);
	nlist->prev = addr_to_offset(mhead, list);
}

static void
mlist_del(mhead_t *mhead, mlist_t *list)
{
	mlist_t	   *plist = offset_to_addr(mhead, list->prev);
	mlist_t	   *nlist = offset_to_addr(mhead, list->next);

	plist->next = addr_to_offset(mhead, nlist);
	nlist->prev = addr_to_offset(mhead, plist);

	list->prev = list->next = addr_to_offset(mhead, list);
}

/*
 * ffs64 - returns first (smallest) bit of the value
 */
static int
ffs64(uint64_t value)
{
	int		ret = 1;

	if (!value)
		return 0;
	if (!(value & 0xffffffff))
	{
		value >>= 32;
		ret += 32;
	}
	if (!(value & 0x0000ffff))
	{
		value >>= 16;
		ret += 16;
	}
	if (!(value & 0x000000ff))
	{
		value >>= 8;
		ret += 8;
	}
	if (!(value & 0x0000000f))
	{
		value >>= 4;
		ret += 4;
	}
	if (!(value & 0x00000003))
	{
		value >>= 2;
		ret += 2;
	}
	if (!(value & 0x00000001))
	{
		value >>= 1;
		ret += 1;
	}
	return ret;
}

/*
 * fls64 - returns last (biggest) bit of the value
 */
static int
fls64(uint64_t value)
{
	int		ret = 1;

	if (!value)
		return 0;
	if (value & 0xffffffff00000000)
	{
		value >>= 32;
		ret += 32;
	}
	if (value & 0xffff0000)
	{
		value >>= 16;
		ret += 16;
	}
	if (value & 0xff00)
	{
		value >>= 8;
		ret += 8;
	}
	if (value & 0xf0)
	{
		value >>= 4;
		ret += 4;
	}
	if (value & 0xc)
	{
		value >>= 2;
		ret += 2;
	}
	if (value & 0x2)
	{
		value >>= 1;
		ret += 1;
	}
	return ret;
}

static bool
mblock_split_chunk(mhead_t *mhead, int mclass)
{
	mchunk_t   *mchunk1;
	mchunk_t   *mchunk2;
	mlist_t	   *list;
	uint64_t	offset;

	assert(mclass > MBLOCK_MIN_BITS && mclass <= MBLOCK_MAX_BITS);

	if (mlist_empty(mhead, &mhead->free_list[mclass]))
	{
		if (mclass == MBLOCK_MAX_BITS)
			return false;
		else if (!mblock_split_chunk(mhead, mclass + 1))
			return false;
	}
	list = offset_to_addr(mhead, mhead->free_list[mclass].next);
	mchunk1 = container_of(list, mchunk_t, free.list);
	assert(mchunk1->mclass == mclass);

	mlist_del(mhead, &mchunk1->free.list);
	mhead->num_free[mclass]--;

	offset = addr_to_offset(mhead, mchunk1);
	mclass--;
	mchunk2 = offset_to_addr(mhead, offset + (1<<mclass));

	mchunk1->tag = mchunk2->tag = MCHUNK_TAG_FREE;
	mchunk1->mclass = mchunk2->mclass = mclass;
	mchunk1->magic = mchunk_magic(mhead,mchunk1);
	mchunk2->magic = mchunk_magic(mhead,mchunk2);

	mlist_add(mhead, &mhead->free_list[mclass], &mchunk1->free.list);
	mhead->num_free[mclass]++;
	mlist_add(mhead, &mhead->free_list[mclass], &mchunk2->free.list);
	mhead->num_free[mclass]++;

	return true;
}

mchunk_t *
mblock_alloc(mhead_t *mhead, uint8_t tag, size_t size)
{
	mchunk_t   *mchunk;
	mlist_t    *list;
	int			mclass;

	mclass = fls64(size);
	if (mclass > MBLOCK_MAX_BITS)
		return NULL;
	if (mclass < MBLOCK_MIN_BITS)
		mclass = MBLOCK_MIN_BITS;

	pthread_mutex_lock(&mblock_lock);

	/*
	 * when free_list of the mclass is not available, it tries to split
	 * a larger free chunk into two. If unavailable anymore, we cannot
	 * allocate a new free chunk.
	 */
	if (mlist_empty(mhead, &mhead->free_list[mclass]))
	{
		if (!mblock_split_chunk(mhead, mclass + 1))
		{
			pthread_mutex_unlock(&mblock_lock);
			return NULL;
		}
	}
	assert(!mlist_empty(mhead, &mhead->free_list[mclass]));

	list = offset_to_addr(mhead, mhead->free_list[mclass].next);
	mchunk = container_of(list, mchunk_t, free.list);
	assert(mchunk->mclass == mclass);

	mlist_del(mhead, &mchunk->free.list);
	mhead->num_free[mclass]--;
	mhead->num_active[mclass]++;

	mchunk->mclass = mclass;
	mchunk->tag = tag;
	mchunk->magic = mchunk_magic(mhead,mchunk);

	pthread_mutex_unlock(&mblock_lock);

	return mchunk;
}

void
mblock_free(mhead_t *mhead, mchunk_t *mchunk)
{
	mchunk_t   *buddy;
	uint64_t	offset;
	uint64_t	offset_buddy;
	int			mclass = mchunk->mclass;

	assert(mchunk->tag != MCHUNK_TAG_FREE);

	pthread_mutex_lock(&mblock_lock);

	mchunk->tag = MCHUNK_TAG_FREE;
	mhead->num_active[mclass]--;

	/*
	 * If its buddy is also free, we consolidate them into one.
	 */
	offset = addr_to_offset(mhead, mchunk);
	while (mclass < MBLOCK_MAX_BITS)
	{
		if (offset & (1 << mclass))
			offset_buddy = offset & ~(1 << mclass);
		else
			offset_buddy = offset | (1 << mclass);

		/* offset should not be on the mhead structure */
		if (offset_buddy < sizeof(mhead_t) + mhead->super_size)
			break;
		buddy = offset_to_addr(mhead, offset_buddy);

		/*
		 * If buddy is also free and same size, we consolidate them
		 */
		if (buddy->tag != MCHUNK_TAG_FREE || buddy->mclass != mclass)
			break;

		mlist_del(mhead, &buddy->free.list);
		mhead->num_free[mclass]--;

		mclass++;
		offset &= ~((1 << mclass) - 1);
		mchunk = offset_to_addr(mhead, offset);

		mchunk->tag = MCHUNK_TAG_FREE;
		mchunk->mclass = mclass;
		mchunk->magic = mchunk_magic(mhead,mchunk);
	}
	/*
	 * Attach this mchunk on the freelist[mclass]
	 */
	mlist_add(mhead, &mhead->free_list[mclass], &mchunk->free.list);
	mhead->num_free[mclass]++;

	pthread_mutex_unlock(&mblock_lock);
}

void
mblock_reset(mhead_t *mhead)
{
	mchunk_t   *mchunk;
	uint64_t	offset;
	int			mclass;

	pthread_mutex_lock(&mblock_lock);

	for (mclass = 0; mclass <= MBLOCK_MAX_BITS; mclass++)
	{
		mlist_init(mhead, &mhead->free_list[mclass]);
		mhead->num_free[mclass] = 0;
		mhead->num_active[mclass] = 0;
	}

	offset = (1 << (fls64(sizeof(mhead_t) + mhead->super_size) + 1));
	while (mhead->block_size - offset >= MBLOCK_MIN_SIZE)
	{
		/* choose an appropriate chunk class */
		mclass = ffs64(offset) - 1;
		if (mclass > MBLOCK_MAX_BITS)
			mclass = MBLOCK_MAX_BITS;
		assert(mclass >= MBLOCK_MIN_BITS);

		/* if (offset + chunk_size) over the tail, truncate it */
		while (mhead->block_size < offset + (1 << mclass))
			mclass--;

		if (mclass < MBLOCK_MIN_BITS)
			break;

		/* chain this free-chunk to the free_list */
		mchunk = offset_to_addr(mhead, offset);
		mchunk->mclass = mclass;
		mchunk->tag = MCHUNK_TAG_FREE;
		mchunk->magic = mchunk_magic(mhead,mchunk);

		mlist_add(mhead, &mhead->free_list[mclass], &mchunk->free.list);

		mhead->num_free[mclass]++;

		offset += (1 << mclass);
	}
	pthread_mutex_unlock(&mblock_lock);
}

void
mblock_dump(mhead_t *mhead)
{
	uint64_t	total_active = 0;
	uint64_t	total_free = 0;
	int			mclass;

	pthread_mutex_lock(&mblock_lock);

	printf("block_size: %" PRIu64 "\n", mhead->block_size);
	for (mclass = MBLOCK_MIN_BITS; mclass <= MBLOCK_MAX_BITS; mclass++)
	{
		if ((1<<mclass) < 1024)
			printf("%4ubyte: ", (1<<mclass));
		else if ((1<<mclass) < 1024 * 1024)
			printf("%6uKB: ", (1<<(mclass - 10)));
		else
			printf("%6uMB: ", (1<<(mclass - 20)));

		printf("%u of used, %u of free\n",
			   mhead->num_active[mclass],
			   mhead->num_free[mclass]);

		total_active += mhead->num_active[mclass] * (1 << mclass);
		total_free += mhead->num_free[mclass] * (1 << mclass);
	}

	printf("total_active: %" PRIu64 "\n", total_active);
	printf("total_free: %" PRIu64 "\n", total_free);
	printf("total: %" PRIu64 "\n", total_active + total_free);

	pthread_mutex_unlock(&mblock_lock);
}

mhead_t *
mblock_map(int fdesc, size_t block_size, size_t super_size)
{
	mhead_t	   *mhead;

	mhead = (mhead_t *)mmap(NULL, block_size,
							PROT_READ | PROT_WRITE,
							fdesc < 0 ? MAP_ANONYMOUS | MAP_PRIVATE : MAP_SHARED,
							fdesc, 0);
	if (mhead == MAP_FAILED)
		return NULL;

	if (strncmp(mhead->magic, MBLOCK_MAGIC_STRING, sizeof(mhead->magic)) != 0)
	{
		strcpy(mhead->magic, MBLOCK_MAGIC_STRING);
		mhead->block_size = block_size;
		mhead->super_size = super_size;

		mblock_reset(mhead);
	}
	else if (mhead->super_size < super_size)
	{
		fprintf(stderr, "lack of available superblock\n");
		goto error;
	}
	else if (mhead->block_size < block_size)
	{
		fprintf(stderr, "lack of available block size\n");
		goto error;
	}
	return mhead;

error:
	munmap(mhead, block_size);
	return NULL;
}

void
mblock_unmap(mhead_t *mhead)
{
	munmap(mhead, mhead->block_size);
}

#if 0
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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
			fprintf(stderr, "file length too short %lu\n", length);
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

	handle = mblock_map(fd, length, 2048);
	if (!handle)
	{
		fprintf(stderr, "failed to init mblock\n");
		return 1;
	}
	a = mblock_alloc(handle, MCHUNK_TAG_ITEM, 1);
	b = mblock_alloc(handle, MCHUNK_TAG_ITEM, 256);
	c = mblock_alloc(handle, MCHUNK_TAG_ITEM, 257);

	mblock_dump(handle);

	mblock_alloc(handle, MCHUNK_TAG_BTREE, 1);

	mblock_dump(handle);

	mblock_free(handle, a);
	mblock_free(handle, b);
	mblock_free(handle, c);

	mblock_dump(handle);

	printf("offset = %d\n", offset_of(mchunk_t, item.data));

	return 0;
}
#endif
