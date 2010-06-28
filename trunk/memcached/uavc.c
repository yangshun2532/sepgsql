/*
 * uavc.c
 *
 * userspace access vector optimized to memcached
 *
 *
 */
#include "memcached/engine.h"
#include "selinux_engine.h"


typedef struct
{
	uint16_t	tag;
	uint32_t	refcnt;
	char		label[1];
} uavc_label;

typedef struct
{
	void   *prev;
	void   *next;
} uavc_list;

typedef struct
{
	
	
} uavc_node;

#define UAVC_HASH_SIZE	(1<<7)
#define UAVC_HASH_MASK	(UAVC_HASH_SIZE - 1)
typedef strucy
{
	pthread_rwlock_t	lock;
	void			   *handle;
	void			   *label_index;
	int					lru_hint;
	uavc_list			slot[UAVC_HASH_SIZE];
} uavc_page;




uint64_t
uavc_sidget(void *uavc_page, const char *label)
{
	uavc_page  *page = uavc_page;
	uavc_label *ulabel = NULL;
	mbtree_scan	scan;
	uint32_t	key;
	uint64_t	item;

	pthread_rwlock_wrlock(&page->lock);

	key = hash(label);

	item = mbtree_lookup(page->handle, page->label_index, key, &scan);
	while (item != 0)
	{
		ulabel = offset_to_addr(page->handle, item);

		assert(ulabel->tag == TAG_SELINUX_LABEL);

		if (strcmp(label, ulabel->label) == 0)
		{
			ulabel->refcnt++;
			break;
		}
		item = mbtree_next(page->handle, &scan);
	}

	if (item == 0)
	{
		int		length = strlen(context);

		ulabel = mblock_alloc(page->handle, sizeof(uavc_label) + length);
		if (ulabel != NULL)
		{
			ulabel->tag = TAG_SELINUX_LABEL;
			ulabel->refcnt = 1;
			strcpy(ulabel->label, label);

			item = addr_to_offset(page->handle, ulabel);

			if (!mbtree_insert(page->handle, page->label_index, key, item))
			{
				mblock_free(page->handle, page->label_index);
				item = 0;
			}
		}
	}
	pthread_rwlock_unlock(&page->lock);

	return item;
}

void
uavc_sidput(void *page, uint64_t secid)
{
	uavc_page  *page = uavc_page;
	uavc_label *ulabel;
	mbtree_scan	scan;
	uint32_t	key;
	uint64_t	item;

	pthread_rwlock_wrlock(&page->lock);

	ulabel = offset_to_addr(page->handle, secid);
	assert(ulabel->tag == TAG_SELINUX_LABEL);

	if (--ulabel->refcnt == 0)
	{
		key = hash(ulabel->label);

		mbtree_delete(page->handle, page->label_index, key, secid);

		mblock_free(page->handle, ulabel);
	}
	pthread_rwlock_unlock(&page->lock);
}




bool
uavc_has_perms(void *handle,
			   uint32_t ssid,
			   uint32_t tsid,
			   uint16_t tclass,
			   uint32_t required,
			   const char *auname)
{}

uint32_t
uavc_compute_create(uint32_t ssid,
					uint32_t tsid,
					uint16_t tclass)
{}

bool
uavc_init(void *handle, void *sidtab_index)
{}



