/*
 * row-level access control implementation
 *
 *
 */

bool rowaclIsEnabled(void)
{
	/* TODO: to control it via postgres.conf */
	return true;
}

/*
 * special handling for PK/FK constraints
 */
static bool abort_on_violated_tuple = false;

void rowaclBeginPerformCheckFK(Relation rel, bool primary, Datum *priv)
{
	if (primary)
		return;

	*priv = BoolGetDatum(abort_on_violated_tuple);
	abort_on_violated_tuple = true;
}

void rowaclEndPerformCheckFK(Relation rel, bool primary, Datum priv)
{
	if (primary)
		return;
	
	abort_on_violated_tuple = DatumGetBool(priv);
}

/*
 * row-level access controls
 */
bool rowaclExecScan(Scan *scan, Relation rel, TupleTableSlot *slot)
{}

bool rowaclCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple)
{}

/*
 * hooks for INSERT/UPDATE/DELETE
 */
staic HeapTuple
getHeapTupleFromItemPointer(Relation rel, ItemPointer tid)
{
	/*
	 * obtain an old tuple
	 */
	Buffer          buffer;
	PageHeader      dp;
	ItemId          lp;
	HeapTupleData tuple;
	HeapTuple       oldtup;

	buffer = ReadBuffer(rel, ItemPointerGetBlockNumber(tid));
	LockBuffer(buffer, BUFFER_LOCK_SHARE);

	dp = (PageHeader) BufferGetPage(buffer);
	lp = PageGetItemId(dp, ItemPointerGetOffsetNumber(tid));

	Assert(ItemIdIsNormal(lp));

	tuple.t_data = (HeapTupleHeader) PageGetItem((Page) dp, lp);
	tuple.t_len = ItemIdGetLength(lp);
	tuple.t_self = *tid;
	tuple.t_tableOid = RelationGetRelid(rel);
	oldtup = heap_copytuple(&tuple);

	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
	ReleaseBuffer(buffer);

	return oldtup;
}

bool rowaclHeapTupleInsert(Relation rel, HeapTuple tuple,
						   bool is_internal, bool with_returning)
{
	/* TODO: set default acl from pg_class */
	HeapTupleSetSecurity(tuple, InvalidOid);

	return true;
}

bool rowaclHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup,
						   bool is_internal, bool with_returning)
{
	HeapTuple oldtup = getHeapTupleFromItemPointer(rel, otid);

	return true;
}

bool rowaclHeapTupleDelete(Relation rel, ItemPointer otid,
						   bool is_internal, bool with_returning)
{
	HeapTuple oldtup = getHeapTupleFromItemPointer(rel, otid);

	return true;
}

/*
 * row-level acl handling
 */
char *rowaclValidateSecurityLabel(char *seclabel)
{
	return seclabel;
}

/*
 * SQL functions
 */
Datum row_acl_grant(PG_FUNCTION_ARGS)
{}

Datum row_acl_revoke(PG_FUNCTION_ARGS)
{}

#endif
