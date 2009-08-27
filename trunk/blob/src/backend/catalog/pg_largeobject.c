/*-------------------------------------------------------------------------
 *
 * pg_largeobject.c
 *	  routines to support manipulation of the pg_largeobject relation
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  $PostgreSQL: pgsql/src/backend/catalog/pg_largeobject.c,v 1.33 2009/08/04 16:08:36 tgl Exp $
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "catalog/indexing.h"
#include "catalog/pg_largeobject.h"
#include "catalog/toasting.h"
#include "miscadmin.h"
#include "utils/bytea.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "utils/tqual.h"


/*
 * Create a large object having the given LO identifier.
 *
 * We do this by inserting an empty first page, so that the object will
 * appear to exist with size 0.  Note that the unique index will reject
 * an attempt to create a duplicate page.
 */
Oid
LargeObjectCreate(Oid loid)
{
	Relation	pg_largeobject;
	HeapTuple	ntup;
	Datum		values[Natts_pg_largeobject];
	bool		nulls[Natts_pg_largeobject];
	Oid			loid_new;

	pg_largeobject = heap_open(LargeObjectRelationId, RowExclusiveLock);

	/*
	 * Form new tuple
	 */
	memset(values, 0, sizeof(values));
	memset(nulls, false, sizeof(nulls));

	values[Anum_pg_largeobject_loowner - 1]
		= ObjectIdGetDatum(GetUserId());
	values[Anum_pg_largeobject_lochunk - 1]
		= ObjectIdGetDatum(InvalidOid);		/* empty largeobject */
	nulls[Anum_pg_largeobject_loacl - 1] = true;

	ntup = heap_form_tuple(RelationGetDescr(pg_largeobject),
						   values, nulls);
	if (OidIsValid(loid))
		HeapTupleSetOid(ntup, loid);

	/*
	 * Insert it
	 */
	loid_new = simple_heap_insert(pg_largeobject, ntup);
	Assert(!OidIsValid(loid) || loid == loid_new);

	/* Update indexes */
	CatalogUpdateIndexes(pg_largeobject, ntup);

	heap_close(pg_largeobject, RowExclusiveLock);

	heap_freetuple(ntup);

	return loid_new;
}

void
LargeObjectDrop(Oid loid)
{
	Relation	pg_largeobject;
	Relation	pg_toast;
	ScanKeyData skey[1];
	SysScanDesc sd;
	Oid			chunk_id;
	HeapTuple	tuple;

	pg_largeobject = heap_open(LargeObjectRelationId, RowExclusiveLock);

	pg_toast = heap_open(PgLargeObjectToastTable, RowExclusiveLock);

	tuple = SearchSysCache(LARGEOBJECTOID,
						   ObjectIdGetDatum(loid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("large object %u does not exist", loid)));

	chunk_id = ((Form_pg_largeobject) GETSTRUCT(tuple))->lochunk;

	simple_heap_delete(pg_largeobject, &tuple->t_self);

	ReleaseSysCache(tuple);

	if (OidIsValid(chunk_id))
	{
		ScanKeyInit(&skey[0],
					Anum_pg_toast_chunk_id,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(chunk_id));

		sd = systable_beginscan(pg_toast, PgLargeObjectToastIndex,
								true, SnapshotNow, 1, skey);
		while (HeapTupleIsValid(tuple = systable_getnext(sd)))
		{
			simple_heap_delete(pg_toast, &tuple->t_self);
		}
		systable_endscan(sd);
	}
	heap_close(pg_toast, RowExclusiveLock);

	heap_close(pg_largeobject, RowExclusiveLock);
}
