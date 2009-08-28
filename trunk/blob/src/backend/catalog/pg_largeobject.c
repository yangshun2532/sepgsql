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
#include "catalog/catalog.h"
#include "catalog/dependency.h"
#include "catalog/indexing.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_largeobject.h"
#include "catalog/toasting.h"
#include "miscadmin.h"
#include "utils/acl.h"
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
	Relation	pg_toast;
	HeapTuple	ntup;
	Datum		values[Natts_pg_largeobject];
	bool		nulls[Natts_pg_largeobject];
	Oid			chunk_id;
	Oid			loid_new;

	pg_largeobject = heap_open(LargeObjectRelationId, RowExclusiveLock);

	pg_toast = heap_open(PgLargeObjectToastTable, RowExclusiveLock);

	/*
	 * Insert an empty chunk
	 */
	chunk_id = GetNewOidWithIndex(pg_toast, PgLargeObjectToastIndex,
								  Anum_pg_toast_chunk_id);

	memset(values, 0, sizeof(values));
	memset(nulls, false, sizeof(nulls));

	values[Anum_pg_toast_chunk_id - 1] = ObjectIdGetDatum(chunk_id);
	values[Anum_pg_toast_chunk_seq - 1] = Int32GetDatum(0);
	values[Anum_pg_toast_chunk_data - 1]
		= DirectFunctionCall1(byteain, CStringGetDatum(""));

	ntup = heap_form_tuple(RelationGetDescr(pg_toast),
						   values, nulls);

	simple_heap_insert(pg_toast, ntup);

	CatalogUpdateIndexes(pg_toast, ntup);

	heap_freetuple(ntup);

	/*
	 * Insert pg_largeobject itself
	 */
	memset(values, 0, sizeof(values));
	memset(nulls, false, sizeof(nulls));

	values[Anum_pg_largeobject_loowner - 1]
		= ObjectIdGetDatum(GetUserId());
	values[Anum_pg_largeobject_lochunk - 1]
		= ObjectIdGetDatum(chunk_id);
	nulls[Anum_pg_largeobject_loacl - 1] = true;

	ntup = heap_form_tuple(RelationGetDescr(pg_largeobject),
						   values, nulls);
	if (OidIsValid(loid))
		HeapTupleSetOid(ntup, loid);

	loid_new = simple_heap_insert(pg_largeobject, ntup);
	Assert(!OidIsValid(loid) || loid == loid_new);

	CatalogUpdateIndexes(pg_largeobject, ntup);

	heap_freetuple(ntup);

	heap_close(pg_toast, RowExclusiveLock);

	heap_close(pg_largeobject, RowExclusiveLock);

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

static void
ac_largeobject_alter(Oid lobjId, Oid newOwner)
{
	/* must be owner of largeobject */
	if (!pg_largeobject_ownercheck(lobjId, GetUserId()))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be owner of largeobject %u", lobjId)));

	/* Superusers can always do it */
	if (OidIsValid(newOwner) && !superuser())
	{
		HeapTuple	auTup;

		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have privilege to create largeobject */
		auTup = SearchSysCache(AUTHOID,
							   ObjectIdGetDatum(newOwner),
							   0, 0, 0);
		if (!HeapTupleIsValid(auTup))
			elog(ERROR, "cache lookup failed for role: %u", newOwner);

		if (!((Form_pg_authid) GETSTRUCT(auTup))->rollargeobject)
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("permission denied to create largeobject")));

		ReleaseSysCache(auTup);
	}
}

void
LargeObjectAlterOwner(Oid loid, Oid newOwnerId)
{
	Form_pg_largeobject	loForm;
	Relation	loRel;
	HeapTuple	oldtup, newtup;

	loRel = heap_open(LargeObjectRelationId, RowExclusiveLock);

	oldtup = SearchSysCache(LARGEOBJECTOID,
							ObjectIdGetDatum(loid),
							0, 0, 0);
	if (!HeapTupleIsValid(oldtup))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("large object %u does not exist", loid)));

	loForm = (Form_pg_largeobject) GETSTRUCT(oldtup);
	if (loForm->loowner != newOwnerId)
	{
		Datum		values[Natts_pg_largeobject];
		bool		nulls[Natts_pg_largeobject];
		bool		replaces[Natts_pg_largeobject];
		Acl		   *newAcl;
		Datum		aclDatum;
		bool		isnull;

		/* Permission checks */
		ac_largeobject_alter(loid, newOwnerId);

		memset(values, 0, sizeof(values));
		memset(nulls, false, sizeof(nulls));
		memset(replaces, false, sizeof(nulls));

		values[Anum_pg_largeobject_loowner - 1]
			= ObjectIdGetDatum(newOwnerId);
		replaces[Anum_pg_largeobject_loowner - 1] = true;

		/*
		 * Determine the modified ACL for the new owner.
		 * This is only necessary when the ACL is non-null.
		 */
		aclDatum = SysCacheGetAttr(LARGEOBJECTOID, oldtup,
								   Anum_pg_largeobject_loacl,
								   &isnull);
		if (!isnull)
		{
			newAcl = aclnewowner(DatumGetAclP(aclDatum),
								 loForm->loowner, newOwnerId);
			values[Anum_pg_largeobject_loacl - 1]
				= PointerGetDatum(newAcl);
			replaces[Anum_pg_largeobject_loacl - 1] = true;
		}

		newtup = heap_modify_tuple(oldtup, RelationGetDescr(loRel),
								   values, nulls, replaces);

		simple_heap_update(loRel, &newtup->t_self, newtup);
		CatalogUpdateIndexes(loRel, newtup);

		heap_freetuple(newtup);

		/* Update owner dependency reference */
		changeDependencyOnOwner(LargeObjectRelationId,
								loid, newOwnerId);
	}
	ReleaseSysCache(oldtup);

	heap_close(loRel, RowExclusiveLock);
}
