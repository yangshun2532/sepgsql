/*
 * mlabel.c
 *
 *
 */




mchunk_t *
mlabel_lookup_secid(selinux_engine *se, uint32_t secid)
{}

mchunk_t *
mlabel_lookup_label(selinux_engine *se, const char *label)
{}

static uint32_t
get_new_secid(selinux_engine_t *se)
{
	mbtree_scan	scan;

	memset(&scan, 0, sizeof(scan));
	scan.key = ++se->mhead.last_secid;
	if (scan.key < 0x1000)
		scan.key = 0x1000;


}

uint32_t
mlabel_install(selinux_engine_t *se, const char *label)
{
	mchunk_t	*mchunk;
	size_t		length;
	uint32_t	hkey;
	uint64_t	hitem;

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
		return NULL;
	}
	mchunk->label.secid = get_new_secid(se);
	mchunk->label.refcnt = 1;
	strcpy(mchunk->label.label, label);

	hkey = se->server.core->hash(label, strlen(label), 0);
	hitem = addr_to_offset(se->mhead, mchunk);

	/* Insert into index */
	if (!mbtree_insert(se->mhead, hkey, hitem))
	{
		mblock_free(mhead, mchunk);
		return 0;
	}
	if (!mbtree_insert(se->mhead, secid, hitem))
	{
		mbtree_delete(se->mhead, hkey, hitem);
		mblock_free(mhead, mchunk);
		return 0;
	}
	return secid;
}

bool
mlabel_uninstall(selinux_engine_t *se, uint32_t secid)
{}

mchunk_t *
mlabel_get(selinux_engine_t *se, uint32_t secid)
{}

bool
mlabel_put(selinux_engine_t *se, mlabel_t *)
{}
