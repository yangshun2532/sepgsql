/*
 * mhash.c
 *
 * Hash logic on mmap() based memory block.
 *
 *
 *
 */
#include <assert.h>
#include <string.h>

#include "memcached/engine.h"
#include "selinux_engine.h"

#define MHASH_INIT_SIZE		31

typedef struct {
	uint64_t		hash_slot;
	uint32_t		hash_size;
	/* only available under rebuilding */
	uint64_t		hash_new_slot;
	uint32_t		hash_new_size;

	/* statical informations */
	uint32_t		num_items;
} mhash_super;

typedef struct {
	uint64_t	next;
	uint32_t	key;
	uint64_t	item;
} mhash_entry;

bool
mhash_lookup(void *handle, uint32_t key, mhash_scan *scan)
{
	mhash_super	   *mhsup = handle;
	mhash_entry	   *mentry;
	uint64_t		offset;

	if (scan->entry != 0)
	{
		mentry = mblock_offset_to_addr(mhsup, scan->entry);

		offset = mentry->next;
	}
	else
	{
		uint64_t   *hash_slot = mblock_offset_to_addr(mhsup, mhsup->hash_slot);

		offset = hash_slot[key % mhsup->hash_size];
	}

	while (offset != 0)
	{
		mentry = mblock_offset_to_addr(mhsup, offset);

		if (key == mentry->key)
		{
			scan->entry = offset;
			scan->key = key;
			scan->item = mentry->item;
			return true;
		}
		offset = mentry->next;
	}
	return false;
}

void
mhash_dump(void *handle)
{
	mhash_super	   *mhsup = handle;
	mhash_entry	   *mentry;
	uint64_t	   *hash_slot;
	uint64_t		offset;
	int				index;

	hash_slot = mblock_offset_to_addr(mhsup, mhsup->hash_slot);

	printf("hash dump\n");
	printf("--------------------------------\n");
	for (index = 0; index < mhsup->hash_size; index++)
	{
		printf("slot% 4d: ", index);

		offset = hash_slot[index];
		while (offset != 0)
		{
			mentry = mblock_offset_to_addr(mhsup, offset);

			printf(" -> {%" PRIu32 ", %" PRIu64 "}", mentry->key, mentry->item);

			offset = mentry->next;
		}
		putchar('\n');
	}
	putchar('\n');
	printf("num of items: %" PRIu32 "\n", mhsup->num_items);
}

bool
mhash_insert(void *handle, uint32_t key, uint64_t item)
{
	mhash_super	   *mhsup = handle;
	mhash_entry	   *mentry;
	uint64_t	   *hash_slot;
	uint64_t		offset;

	hash_slot = mblock_offset_to_addr(mhsup, mhsup->hash_slot);
	offset = hash_slot[key % mhsup->hash_size];

	/* check duplication */
	while (offset != 0)
	{
		mentry = mblock_offset_to_addr(mhsup, offset);
		if (mentry->key == key && mentry->item == item)
			return false;
		offset = mentry->next;
	}

	/* insert it */
	mentry = mblock_alloc(mhsup, sizeof(mhash_entry));
	if (mentry)
	{
		mentry->next = hash_slot[key % mhsup->hash_size];
		hash_slot[key % mhsup->hash_size]
			= mblock_addr_to_offset(mhsup, mentry);
		mentry->key = key;
		mentry->item = item;

		mhsup->num_items++;

		/* TODO: adjust hash table size here */

		return true;
	}
	return false;
}

bool
mhash_delete(void *handle, uint32_t key, uint64_t item)
{
	mhash_super	   *mhsup = handle;
	mhash_entry	   *mentry, *pentry;
	uint64_t	   *hash_slot;
	uint64_t		offset, prev = 0;
	int				index;

	hash_slot = mblock_offset_to_addr(mhsup, mhsup->hash_slot);
	index = key % mhsup->hash_size;
	offset = hash_slot[index];

	while (offset != 0)
	{
		mentry = mblock_offset_to_addr(mhsup, offset);
		if (mentry->key == key && mentry->item == item)
		{
			if (prev == 0)
				hash_slot[index] = mentry->next;
			else
			{
				pentry = mblock_offset_to_addr(mhsup, prev);
				pentry->next = mentry->next;
			}
			mblock_free(mhsup, mentry);

			mhsup->num_items--;

			/* TODO: adjust hash table size here */

			return true;
		}
		prev = offset;
		offset = mentry->next;
	}
	return false;
}

/*
 *
 *
 *
 */
void *
mhash_init(int fdesc, size_t block_size)
{
	mhash_super	   *mhsup;
	uint64_t	   *hash_slot;

	mhsup = mblock_init(fdesc, block_size, sizeof(mhash_super));
	if (!mhsup)
		return NULL;

	if (mhsup->hash_slot == 0)
	{
		mhsup->hash_size = MHASH_INIT_SIZE;
		hash_slot = mblock_alloc(mhsup, mhsup->hash_size * sizeof(uint64_t));
		if (!hash_slot)
			goto error;
		memset(hash_slot, 0, mhsup->hash_size * sizeof(uint64_t));
		mhsup->hash_slot = mblock_addr_to_offset(mhsup, hash_slot);
	}

	/*
	 * If backend was crashed under rebuilding the new hash,
	 * we release preallocated region.
	 */
	if (mhsup->hash_new_slot != 0)
	{
		hash_slot = mblock_offset_to_addr(mhsup, mhsup->hash_new_slot);
		mblock_free(mhsup, hash_slot);

		mhsup->hash_new_slot = 0;
		mhsup->hash_new_size = 0;
	}
	return mhsup;

error:
	mblock_unmap(mhsup);
	return NULL;
}

#if 1
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, const char *argv[])
{
	uint32_t	key;
	uint64_t	item;
	void	   *handle;
	int			fd;
	struct stat	stbuf;

	if (argc < 2)
		goto usage;

	fd = open(argv[1], O_RDWR);
	if (fd < 0)
	{
		printf("failed to open '%s'\n", argv[1]);
		return 1;
	}
	if (fstat(fd, &stbuf) != 0)
	{
		printf("failed to stat '%s'\n", argv[1]);
		return 1;
	}

	handle = mhash_init(fd, stbuf.st_size);
	if (!handle)
	{
		printf("failed to init mblock\n");
		return 1;
	}

	if (argc == 4 && strcmp(argv[2], "get") == 0)
	{
		mhash_scan	scan;
		uint32_t	key;

		key = atol(argv[3]);
		memset(&scan, 0, sizeof(scan));
		while (mhash_lookup(handle, key, &scan))
        {
            printf("==> GET key=%" PRIu32 " value=%" PRIu64 "\n",
                   scan.key, scan.item);
        }
        mhash_dump(handle);
        return 0;
	}
	else if (argc == 5 && strcmp(argv[2], "ins") == 0)
	{
		key = atol(argv[3]);
		item = atoll(argv[4]);

		printf("==> INSERT (key=%" PRIu32 ", value=%" PRIu64 ")\n", key, item);
		if (!mhash_insert(handle, key, item))
		{
			printf("failed to mhash_insert\n");
			return 1;
		}
		mhash_dump(handle);
		mblock_dump(handle);
		return 0;
	}
	else if (argc == 5 && strcmp(argv[2], "del") == 0)
	{
		key = atol(argv[3]);
		item = atoll(argv[4]);

		printf("==> DELETE (key=%" PRIu32 ", value=%" PRIu64 ")\n", key, item);
		if (!mhash_delete(handle, key, item))
		{
			printf("failed to mhash_delete\n");
			return 1;
		}
		mhash_dump(handle);
		mblock_dump(handle);
		return 0;
	}

usage:
	printf("usage: %s <filename> get <key>\n", argv[0]);
	printf("       %s <filename> ins <key> <value>\n", argv[0]);
	printf("       %s <filename> del <key> <value>\n", argv[0]);

	return 1;
}
#endif
