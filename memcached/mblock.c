/*
 * mblock.c
 *
 * buddy based memory block management routines
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "memcached/engine.h"
#include "memcached_selinux.h"

/*
 * mbhead_t
 *
 * header structure of the memory block
 */
#define MBLOCK_MAGIC_STRING		"@MBLOCK_20100702"
#define MBLOCK_MIN_BITS			7	/* 128byte */
#define MBLOCK_MAX_BITS			25	/* 32MB */
#define MBLOCK_MIN_SIZE			(1<<MBLOCK_MIN_BITS)
#define MBLOCK_MAX_SIZE			(1<<MBLOCK_MAX_BITS)

typedef struct {
	char		magic[16];
	uint64_t	block_size;
	uint64_t	super_size;
	mlist_t		free_list[MBLOCK_MAX_BITS];
	uint8_t		super_block[0];
} mhead_t;

#define offset_to_addr(mhead,offset)				\
	((void *)((unsigned long)(mhead) + (offset)))
#define addr_to_offset(mhead,addr)					\
	((uint64_t)((unsigned long)(addr) - (unsigned long)(mhead)))
#define offset_of(type, member)						\
	((unsigned long) &((type *)0)->member)
#define container_of(ptr, type, member)				\
	(type *)(((char *)ptr) - offset_of(type, member))

static uint16_t
mchunk_magic(mhead_t *mhead, mchunk_t *mchunk)
{
	uint64_t	magic = addr_to_offset(mhead,mchunk) >> MBLOCK_MIN_BITS;

	magic ^= (magic >> 16);
	magic ^= (mchunk->mclass << 4);
	magic ^= (mchunk->tag) | (mchunk->tag << 8);

	return (magic ^ 0xa55a) & 0xffff;
}

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

	offset = addr_to_offset(mhead, mchunk1);
	mclass--;
	mchunk2 = offset_to_addr(mhead, offset + (1<<mclass));

	mchunk1->tag = mchunk2->tag = MCHUNK_TAG_FREE;
	mchunk1->mclass = mchunk2->mclass = mclass;
	mchunk1->magic = mchunk_magic(mhead,mchunk1);
	mchunk2->magic = mchunk_magic(mhead,mchunk2);

	mlist_add(mhead, &mhead->free_list[mclass], &mchunk1->free.list);
	mlist_add(mhead, &mhead->free_list[mclass], &mchunk2->free.list);

	return true;
}

mchunk_t *
mblock_alloc(void *handle, uint8_t tag, size_t size)
{
	mhead_t	   *mhead = container_of(handle, mhead_t, super_block[0]);
	mchunk_t   *mchunk;
	mlist_t    *list;
	uint64_t	offset;
	int			mclass;

	mclass = fls64(size);
	if (mclass > MBLOCK_MAX_BITS)
		return NULL;
	if (mclass < MBLOCK_MIN_BITS)
		mclass = MBLOCK_MIN_BITS;

	/*
	 * when free_list of the mclass is not available, it tries to split
	 * a larger free chunk into two. If unavailable anymore, we cannot
	 * allocate a new free chunk.
	 */
	if (mlist_empty(mhead, &mhead->free_list[mclass]))
	{
		if (!mblock_split_chunk(mhead, mclass + 1))
			return NULL;
	}
	assert(!mlist_empty(mhead, &mhead->free_list[mclass]));

	list = offset_to_addr(mhead, mhead->free_list[mclass].next);
	mchunk = container_of(list, mchunk_t, free.list);
	assert(mchunk->mclass == mclass);

	mlist_del(mhead, &mchunk->free.list);

	mchunk->mclass = mclass;
	mchunk->tag = tag;
	mchunk->magic = mchunk_magic(mhead,mchunk);

	return mchunk;
}

void
mblock_free(void *handle, mchunk_t *mchunk)
{
	mhead_t	   *mhead = container_of(handle, mhead_t, super_block[0]);
	mchunk_t   *buddy;
	uint64_t	offset;
	int			mclass = mchunk->mclass;

	assert(mchunk->tag != MCHUNK_TAG_FREE);

	/*
	 * If its buddy is also free, we consolidate them into one.
	 */
	offset = addr_to_offset(mhead, mchunk);
	while (mclass < MBLOCK_MAX_BITS)
	{
		if (offset & (1 << mclass))
			buddy = offset_to_addr(mhead, offset & ~(1 << mclass));
		else
			buddy = offset_to_addr(mhead, offset | (1 << mclass));

		/*
		 * If buddy is also free, we consolidate them
		 */
		if (buddy->tag != MCHUNK_TAG_FREE)
			break;

		mlist_del(mhead, &buddy->free.list);

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
}

void
mblock_reset(void *handle)
{
	mhead_t	   *mhead = container_of(handle, mhead_t, super_block[0]);
	mchunk_t   *mchunk;
	uint64_t	offset;
	int			mclass;

	for (mclass = 0; mclass <= MBLOCK_MAX_BITS; mclass++)
	{
		mlist_init(mhead, &mhead->free_list[mclass]);
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

		offset += (1 << mclass);
	}
}

void *
mblock_map(int fdesc, size_t block_size, size_t super_size)
{
	mhead_t	   *mhead =
		(mhead_t *)mmap(NULL, block_size,
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
	return (void *) mhead->super_block;

error:
	munmap(mhead, block_size);
	return NULL;
}

void
mblock_unmap(void *handle)
{
	mhead_t	   *mhead = container_of(handle, mhead_t, super_block[0]);

	munmap(mhead, mhead->block_size);
}
