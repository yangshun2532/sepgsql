/*
 * mblock.c
 *
 * memory block allocation/free stuff; it can be deployed on shared files.
 *
 *
 *
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <time.h>

#include "memcached/engine.h"
#include "memcached_selinux.h"

#define MBLOCK_MIN_BITS		6		/* 64byte */
#define MBLOCK_MAX_BITS		25		/* 32MB */
#define MBLOCK_MIN_SIZE		(1<<MBLOCK_MIN_BITS)
#define MBLOCK_MAX_SIZE		(1<<MBLOCK_MAX_BITS)

#define offset_to_addr(mhead,offset)			\
	((void *)((unsigned long)(mhead) + (offset)))
#define addr_to_offset(mhead,addr)				\
	((uint64_t)((unsigned long)(addr) - (unsigned long)(mhead)))
#define offset_of(type, member)					\
	((unsigned long) &((type *)0)->member)
#define container_of(ptr, type, member)			\
	(type *)(((char *)ptr) - offset_of(type, member))

/*
 * Dual-linked list structure
 */
typedef struct {
	uint64_t	prev;
	uint64_t	next;
} mblock_list;

/*
 * mblock_head
 *
 * Header structure of the memory block
 */
#define MBLOCK_HEAD_MAGIC	"MBLOCK_20100629"
typedef struct {
	char		magic[16];
	uint64_t	block_size;		/* total size of the block */
	uint64_t	super_size;		/* size of the super block */

	mblock_list	free_list[MBLOCK_MAX_BITS + 1];

	/* statical information */
	uint32_t	num_active[MBLOCK_MAX_BITS + 1];
	uint32_t	num_free[MBLOCK_MAX_BITS + 1];

	/* super block */
	uint8_t		super_block[0];
} mblock_head;

/*
 * mblock_chunk
 *
 * chunk structure of the memory block
 */
typedef struct {
	uint64_t		flags;

	union {
		uint8_t		data[1];	/* only available when active chunk */
		mblock_list	list;		/* only available when free chunk */
	};
} mblock_chunk;

#define MCHUNK_IS_ACTIVE		0x8000
#define MCHUNK_CLASS_MASK		0x7fff

#define mchunk_is_active(mc)	((mc)->flags & MCHUNK_IS_ACTIVE ? true : false)
#define mchunk_get_class(mc)	((mc)->flags & MCHUNK_CLASS_MASK)
#define mchunk_get_size(mc)		((1<<mchunk_get_class(mc)) - offset_of(mblock_chunk, data))
#define mchunk_get_data(mc)		((mc)->data)
#define mchunk_get_next(mc)		((mc)->list.next)
#define mchunk_get_prev(mc)		((mc)->list.prev)

/*
 * mblock_list operations
 *
 *
 *
 *
 */
static inline bool
mblist_is_empty(mblock_head *mhead, mblock_list *list)
{
	return offset_to_addr(mhead, list->next) == list;
}

static inline void
mblist_init(mblock_head *mhead, mblock_list *list)
{
	list->next = list->prev = addr_to_offset(mhead, list);
}

static inline void
mblist_add(mblock_head *mhead, mblock_list *base, mblock_list *list)
{
	mblock_list	   *nlist = offset_to_addr(mhead, base->next);

	base->next = addr_to_offset(mhead, list);
	list->prev = addr_to_offset(mhead, base);
	list->next = addr_to_offset(mhead, nlist);
	nlist->prev = addr_to_offset(mhead, list);
}

static inline void
mblist_del(mblock_head *mhead, mblock_list *list)
{
	mblock_list	   *plist = offset_to_addr(mhead, list->prev);
	mblock_list    *nlist = offset_to_addr(mhead, list->next);

	plist->next = addr_to_offset(mhead, nlist);
	nlist->prev = addr_to_offset(mhead, plist);
	list->next = list->prev = addr_to_offset(mhead, list);
}

/*
 * ffs_uint64
 *
 * It returns least bit of the given value.
 */
static inline int
ffs_uint64(uint64_t value)
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
 * fls_uint64
 *
 * It returns highest bit number of the given value.
 */
static inline int
fls_uint64(uint64_t value)
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

/*
 * mblock_divide_chunk
 *
 * It tries to divide a free memory chunk in the given class.
 * If no available free chunk is in this class, it recursively
 * tries to divide upper class.
 * Then, it returns true, if successfully divided.
 */
static bool
mblock_divide_chunk(mblock_head *mhead, int mclass)
{
	mblock_chunk   *mchunk1;
	mblock_chunk   *mchunk2;
	mblock_list	   *list;
	uint64_t		offset;

	assert(mclass > MBLOCK_MIN_BITS && mclass <= MBLOCK_MAX_BITS);

	if (mblist_is_empty(mhead, &mhead->free_list[mclass]))
	{
		if (mclass == MBLOCK_MAX_BITS)
			return false;
		else
			if (!mblock_divide_chunk(mhead, mclass + 1))
				return false;
	}
	list = offset_to_addr(mhead, mhead->free_list[mclass].next);
	mchunk1 = container_of(list, mblock_chunk, list);
	assert(mchunk_get_class(mchunk1) == mclass);

	/* detach from free list */
	mblist_del(mhead, &mchunk1->list);
	mhead->num_free[mclass]--;

	offset = addr_to_offset(mhead, mchunk1);
	mclass--;
	mchunk2 = offset_to_addr(mhead, offset + (1 << mclass));

	/* set up smaller chunks */
	mchunk1->flags = mclass;
	mchunk2->flags = mclass;

	mblist_add(mhead, &mhead->free_list[mclass], &mchunk1->list);
	mhead->num_free[mclass]++;

	mblist_add(mhead, &mhead->free_list[mclass], &mchunk2->list);
	mhead->num_free[mclass]++;

	return true;
}

/*
 * mblock_alloc
 *
 * It allocate a memory chunk with the required size, and returns
 * pointer of the user data. It shall be freeed using mblock_free().
 * If no available chunk, it returns NULL.
 */
void *
mblock_alloc(void *handle, size_t size)
{
	mblock_head	   *mhead = container_of(handle, mblock_head, super_block[0]);
	mblock_chunk   *mchunk;
	mblock_list	   *list;
	int				mclass;

	mclass = fls_uint64(size + offset_of(mblock_chunk, data)- 1);
	if (mclass > MBLOCK_MAX_BITS)
		return NULL;
	if (mclass < MBLOCK_MIN_BITS)
		mclass = MBLOCK_MIN_BITS;

	/*
	 * When freelist of mclass is empty, divide a larger chunk into
	 * two. If unavailable anymore, we cannot allocate a new chunk.
	 */
	if (mblist_is_empty(mhead, &mhead->free_list[mclass]))
	{
		if (!mblock_divide_chunk(mhead, mclass + 1))
			return NULL;
	}
	assert(!mblist_is_empty(mhead, &mhead->free_list[mclass]));

	list = offset_to_addr(mhead, mhead->free_list[mclass].next);
	mchunk = container_of(list, mblock_chunk, list);
	assert(mchunk_get_class(mchunk) == mclass);

	mblist_del(mhead, &mchunk->list);
	mhead->num_free[mclass]--;
	mhead->num_active[mclass]++;

	mchunk->flags |= MCHUNK_IS_ACTIVE;

	return mchunk_get_data(mchunk);
}

/*
 * mblock_free
 *
 * It release the given memory chunk, and chains to the free list.
 * If we can consolidate two buddy chunks into one, it do that.
 */
void mblock_free(void *handle, void *ptr)
{
	mblock_head	   *mhead = container_of(handle, mblock_head, super_block[0]);
	mblock_chunk   *mchunk = container_of(ptr, mblock_chunk, data);
	mblock_chunk   *buddy;
	uint64_t		offset = addr_to_offset(mhead, mchunk);
	int				mclass = mchunk_get_class(mchunk);

	assert(offset > 0);
	assert(mchunk_is_active(mchunk));

	/* Mark it as a free mchunk */
	mchunk->flags &= ~MCHUNK_IS_ACTIVE;
	mhead->num_active[mclass]--;

	/*
	 * If its buddy is also free, we consolidate them into one chunk.
	 */
	while (mclass < MBLOCK_MAX_BITS)
	{
		if (offset & (1 << mclass))
			buddy = offset_to_addr(mhead, offset & ~(1 << mclass));
		else
			buddy = offset_to_addr(mhead, offset | (1 << mclass));

		/* Is it available to consolidate the two chunks? */
		if (mchunk_is_active(buddy) || mchunk_get_class(buddy) != mclass)
			break;

		/* If the buddy is also free, it is detached from the freelist */
		mblist_del(mhead, &buddy->list);
		mhead->num_free[mclass]--;

		/* Do consolidation */
		mclass++;
		offset &= ~((1 << mclass) - 1);
		mchunk = offset_to_addr(mhead, offset);

		mchunk->flags = mclass;
	}

	/* Attach the mchunk into freelist */
	mblist_add(mhead, &mhead->free_list[mclass], &mchunk->list);
	mhead->num_free[mclass]++;
}

/*
 * mblock_reset
 *
 * It initialize the given memory block. All the chunks are released, and
 * chained to free list for the upcoming future request.
 */
void
mblock_reset(void *handle)
{
	mblock_head	   *mhead = container_of(handle, mblock_head, super_block[0]);
	mblock_chunk   *mchunk;
	uint64_t		offset;
	int				mclass;

	for (mclass = 0; mclass <= MBLOCK_MAX_BITS; mclass++)
	{
		mblist_init(mhead, &mhead->free_list[mclass]);
		mhead->num_free[mclass] = 0;
		mhead->num_active[mclass] = 0;
	}

	/* adjust initial position */
	for (offset = MBLOCK_MIN_SIZE;
		 offset < sizeof(mblock_head);
		 offset <<= 1);
	offset = (1 << (fls_uint64(sizeof(mblock_head)) + 1));

	while (mhead->block_size - offset >= MBLOCK_MIN_SIZE)
	{
		/* choose an appropriate chunk class */
		mclass = ffs_uint64(offset) - 1;
		assert(mclass >= MBLOCK_MIN_BITS);

		/* truncate to maximum size */
		if (mclass > MBLOCK_MAX_BITS)
			mclass = MBLOCK_MAX_BITS;

		/* if (offset + chunk_size) over the tail, truncate it */
		while (mhead->block_size < offset + (1 << mclass))
			mclass--;

		if (mclass < MBLOCK_MIN_BITS)
			break;

		/* chain a memory chunk to free list */
		mchunk = offset_to_addr(mhead, offset);
		mchunk->flags = mclass;

		mblist_add(mhead, &mhead->free_list[mclass], &mchunk->list);
		mhead->num_free[mclass]++;

		offset += (1 << mclass);
	}
}

/*
 * mblock_dump
 *
 * It prints out current status of the memory block
 */
void mblock_dump(void *handle)
{
	mblock_head	   *mhead = container_of(handle, mblock_head, super_block[0]);
	uint64_t		total_active = 0;
	uint64_t		total_free = 0;
	int				mclass;

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
}

/*
 * mblock_addr_to_offset
 *
 * It translate a pointer of object on the memory block into offset value.
 */
uint64_t
mblock_addr_to_offset(void *handle, void *addr)
{
	mblock_head	   *mhead = container_of(handle, mblock_head, super_block[0]);

	return addr_to_offset(mhead, addr);
}

/*
 * mblock_offset_to_addr
 *
 * It translate a offset value into a pointer of obejct on the memory block.
 */
void *
mblock_offset_to_addr(void *handle, uint64_t offset)
{
	mblock_head	   *mhead = container_of(handle, mblock_head, super_block[0]);

	return offset_to_addr(mhead, offset);
}

/*
 * mblock_init
 *
 * It tries to acquire a memory block, and returns its handle.
 * If @fdesc shows a valid file descriptor, it tries to map existing file.
 * Elsewhere, it tries to map private memory and initialize it.
 */
void *
mblock_init(int fdesc, size_t block_size, size_t super_size)
{
	mblock_head	   *mhead
		= (mblock_head *) mmap(NULL, block_size,
							   PROT_READ | PROT_WRITE,
							   fdesc < 0 ? MAP_ANONYMOUS | MAP_PRIVATE : MAP_SHARED,
							   fdesc, 0);
	if (mhead == MAP_FAILED)
		return NULL;

	/*
	 * If the given memory block is already initialized,
	 * we run sanity check on the segment.
	 */
	if (strncmp(mhead->magic, MBLOCK_HEAD_MAGIC, 16) == 0)
	{
		if (mhead->block_size != block_size)
		{
			fprintf(stderr,
					"Block size was mismatch (%" PRIu64 ", %" PRIu64 ")\n",
					block_size, mhead->block_size);
			goto error;
		}
		if (mhead->super_size < super_size)
		{
			fprintf(stderr,
					"No available superblock (%" PRIu64 ", %" PRIu64 ")\n",
					super_size, mhead->super_size);
			goto error;
		}
	}
	else
	{
		strcpy(mhead->magic, MBLOCK_HEAD_MAGIC);
		mhead->block_size = block_size;
		mhead->super_size = super_size;

		mblock_reset((void *)mhead->super_block);
	}
	return (void *)mhead->super_block;

error:
	munmap(mhead, block_size);
	return NULL;
}

/*
 * mblock_unmap
 *
 */
void
mblock_unmap(void *handle)
{
	mblock_head	   *mhead = container_of(handle, mblock_head, super_block[0]);

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

	handle = mblock_init(fd, length, 2048);
	if (!handle)
	{
		fprintf(stderr, "failed to init mblock\n");
		return 1;
	}

	mblock_dump(handle);

	a = mblock_alloc(handle, 255);
	b = mblock_alloc(handle, 256);
	c = mblock_alloc(handle, 257);

	mblock_dump(handle);

	mblock_alloc(handle, 1);

	mblock_dump(handle);

	mblock_free(handle, a);
	mblock_free(handle, b);
	mblock_free(handle, c);

	mblock_dump(handle);

	printf("offset = %d\n", offset_of(mblock_chunk, data));

	return 0;
}
#endif
