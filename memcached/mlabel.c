/*
 * mlabel.c
 *
 *
 */
#include <assert.h>
#include <string.h>
#include "selinux_engine.h"

mchunk_t *
mlabel_lookup_secid(selinux_engine_t *se, uint32_t secid)
{
	mbtree_scan	scan;
	mchunk_t   *mchunk;

	memset(&scan, 0, sizeof(scan));
	scan.key = secid;
	while (mbtree_lookup(se->mhead, &scan))
	{
		if (scan.key != secid)
			break;

		mchunk = offset_to_addr(se->mhead, scan.item);
		if (mchunk_is_label(mchunk) &&
			mchunk->label.secid == secid)
			return mchunk;
	}
	return NULL;
}

mchunk_t *
mlabel_lookup_label(selinux_engine_t *se, const char *label)
{
	mbtree_scan	scan;
	mchunk_t   *mchunk;
	uint32_t	hkey;

	hkey = se->server.core->hash(label, strlen(label), 0);

	memset(&scan, 0, sizeof(scan));
	scan.key = hkey;
	while (mbtree_lookup(se->mhead, &scan))
	{
		if (scan.key != hkey)
			break;

		mchunk = offset_to_addr(se->mhead, scan.item);
		if (mchunk_is_label(mchunk) &&
			strcmp(mchunk->label.value, label) == 0)
			return mchunk;
	}
	return NULL;
}

static uint32_t
get_new_secid(selinux_engine_t *se)
{
	mbtree_scan		scan;
	mchunk_t	   *mchunk;
	uint32_t		secid;

	secid = se->mhead->last_secid + 1;

	memset(&scan, 0, sizeof(scan));
	scan.key = secid;
	while (mbtree_lookup(se->mhead, &scan))
	{
		if (scan.key != secid)
			break;

		mchunk = offset_to_addr(se->mhead, scan.item);
		if (!mchunk_is_label(mchunk))
			break;

		scan.key = ++secid;
	}
	se->mhead->last_secid = secid;

	return secid;
}

/*
 * mlabel_install
 *
 * NOTE: caller shall hold write-lock
 */
uint32_t
mlabel_install(selinux_engine_t *se, const char *label)
{
	mchunk_t   *mchunk;
	uint32_t	hkey;
	uint64_t	hitem;
	size_t		length;

	mchunk = mlabel_lookup_label(se, label);
	if (mchunk)
	{
		mchunk->label.refcount++;

		return mchunk->label.secid;
	}

	length = offset_of(mchunk_t, item.data[0]) + strlen(label) + 1;
retry:
	mchunk = mblock_alloc(se->mhead, MCHUNK_TAG_LABEL, length);
	if (!mchunk)
	{
		if (se->config.reclaim)
		{
			mitem_reclaim(se, length);
			goto retry;
		}
		return 0;
	}
	mchunk->label.secid = get_new_secid(se);
	mchunk->label.refcount = 1;
	strcpy(mchunk->label.value, label);

	hkey = se->server.core->hash(label, strlen(label), 0);
	hitem = addr_to_offset(se->mhead, mchunk);

	/* insert into index */
	if (!mbtree_insert(se->mhead, hkey, hitem))
	{
		mblock_free(se->mhead, mchunk);
		return 0;
	}
	if (!mbtree_insert(se->mhead, mchunk->label.secid, hitem))
	{
		mbtree_delete(se->mhead, hkey, hitem);
		mblock_free(se->mhead, mchunk);
		return 0;
	}
	return mchunk->label.secid;
}

/*
 * mlabel_uninstall
 *
 * NOTE: caller shall hold write-lock
 */
bool
mlabel_uninstall(selinux_engine_t *se, uint32_t secid)
{
	mchunk_t   *mchunk;
	uint32_t	hkey;
	uint64_t	hitem;
	bool		rc;

	mchunk = mlabel_lookup_secid(se, secid);
	if (!mchunk)
	{
		if (se->config.debug)
			fprintf(stderr, "%s:%d no label entry for secid=%" PRIu32 "\n",
					__FUNCTION__, __LINE__, secid);
		return false;
	}

	if (--mchunk->label.refcount == 0)
	{
		hkey = se->server.core->hash(mchunk->label.value,
									 strlen(mchunk->label.value), 0);
		hitem = addr_to_offset(se->mhead, mchunk);

		/* remove from index */
		rc = mbtree_delete(se->mhead, secid, hitem);
		assert(rc == true);

		rc = mbtree_delete(se->mhead, hkey,  hitem);
		assert(rc == true);

		/* free the block */
		mblock_free(se->mhead, mchunk);
	}
	return true;
}

/*
 * mlabel_duplicate
 *
 * NOTE: caller must hold write-lock
 */
bool
mlabel_duplicate(selinux_engine_t *se, uint32_t secid)
{
	mchunk_t   *mchunk;

	mchunk = mlabel_lookup_secid(se, secid);
	if (!mchunk)
		return false;

	mchunk->label.refcount++;

	return true;
}
