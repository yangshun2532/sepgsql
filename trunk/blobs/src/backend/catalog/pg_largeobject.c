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
 *	  $PostgreSQL: pgsql/src/backend/catalog/pg_largeobject.c,v 1.32 2009/01/01 17:23:37 momjian Exp $
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "catalog/dependency.h"
#include "catalog/indexing.h"
#include "catalog/namespace.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_largeobject_data.h"
#include "miscadmin.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

/*
 * Create a large object having the given LO identifier.
 *
 * We do this by inserting an empty first page, so that the object will
 * appear to exist with size 0.  Note that the unique index will reject
 * an attempt to create a duplicate page.
 */
void
LargeObjectCreate(Oid loid, Oid lonsp, Oid loowner, Name loname)
{
	Relation	pg_largeobject;
	HeapTuple	ntup;
	Datum		values[Natts_pg_largeobject];
	bool		nulls[Natts_pg_largeobject];
	ObjectAddress	myself, referenced;

	pg_largeobject = heap_open(LargeObjectRelationId, RowExclusiveLock);

	/*
	 * Form new tuple
	 */
	memset(nulls, false, sizeof(nulls));
	values[Anum_pg_largeobject_loname - 1] = NameGetDatum(loname);
	values[Anum_pg_largeobject_lonsp - 1] = ObjectIdGetDatum(lonsp);
	values[Anum_pg_largeobject_loowner - 1] = ObjectIdGetDatum(loowner);
	nulls[Anum_pg_largeobject_loacl - 1] = true;

	ntup = heap_form_tuple(RelationGetDescr(pg_largeobject),
						   values, nulls);
	HeapTupleSetOid(ntup, loid);

	/*
	 * Insert it
	 */
	simple_heap_insert(pg_largeobject, ntup);

	/* Update indexes */
	CatalogUpdateIndexes(pg_largeobject, ntup);

	heap_close(pg_largeobject, RowExclusiveLock);

	heap_freetuple(ntup);

	/*
	 * Add dependency on namespace/authid
	 */
	myself.classId = LargeObjectRelationId;
	myself.objectId = loid;
	myself.objectSubId = 0;

	referenced.classId = NamespaceRelationId;
	referenced.objectId = lonsp;
	referenced.objectSubId = 0;

	recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);

	recordDependencyOnOwner(LargeObjectRelationId, loid, loowner);
}

void
LargeObjectDrop(Oid loid)
{
	Relation	pg_largeobject;
	ScanKeyData skey[1];
	SysScanDesc sd;
	HeapTuple	tuple;

	/*
	 * delete meta data
	 */
	pg_largeobject = heap_open(LargeObjectRelationId, RowExclusiveLock);

	tuple = SearchSysCache(LARGEOBJECTOID,
						   ObjectIdGetDatum(loid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for largeobejct: %u", loid);

	simple_heap_delete(pg_largeobject, &tuple->t_self);

	ReleaseSysCache(tuple);

	heap_close(pg_largeobject, RowExclusiveLock);
	
	/*
	 * delate contents data
	 */
	pg_largeobject = heap_open(LargeObjectDataRelationId, RowExclusiveLock);

	ScanKeyInit(&skey[0],
				Anum_pg_largeobject_data_loid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(loid));

	sd = systable_beginscan(pg_largeobject,
							LargeObjectDataLOidPNIndexId, true,
							SnapshotNow, 1, skey);

	while (HeapTupleIsValid(tuple = systable_getnext(sd)))
		simple_heap_delete(pg_largeobject, &tuple->t_self);

	systable_endscan(sd);

	heap_close(pg_largeobject, RowExclusiveLock);
}

bool
LargeObjectExists(Oid loid)
{
	return SearchSysCacheExists(LARGEOBJECTOID,
								ObjectIdGetDatum(loid),
								0, 0, 0);
}

void
LargeObjectAlterNamespace(List *loid_list, const char *newschema)
{
	Oid			loid = intVal(linitial(loid_list));
	Oid			lonsp;
	Oid			lonsp_old;
	Relation	rel;
	HeapTuple	tuple;
	Form_pg_largeobject	loform;

	/* check permissions on largeobject */
	if (!pg_largeobject_ownercheck(loid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_LARGEOBJECT,
					   get_largeobject_name(loid));

	/* get schema OID and check its permissions */
	lonsp = LookupCreationNamespace(newschema);

	/* Exec update */
	rel = heap_open(LargeObjectRelationId, RowExclusiveLock);

	tuple = SearchSysCacheCopy(LARGEOBJECTOID,
							   ObjectIdGetDatum(loid),
							   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for largeobject: %u", loid);
	loform = (Form_pg_largeobject) GETSTRUCT(tuple);
	lonsp_old = loform->lonsp;

	/* check correctness of the operating */
	if (lonsp == lonsp_old)
		ereport(ERROR,
				(errcode(ERRCODE_DUPLICATE_FUNCTION),
				 errmsg("largeobject \"%u\" is already in schema \"%s\"",
						loid, newschema)));

	/* disallow renaming into or out of temp schemas */
	if (isAnyTempNamespace(lonsp) || isAnyTempNamespace(lonsp_old))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("cannot move objects into or out of temporary schemas")));

	/* same for TOAST schema */
	if (lonsp == PG_TOAST_NAMESPACE || lonsp_old == PG_TOAST_NAMESPACE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("cannot move objects into or out of TOAST schema")));

	/*
	 * TODO: we should put duplicate naming checks here,
	 * when 'named largeobject' feature got included.
	 */

	/* OK, modyfy the pg_largeobject row */
	loform->lonsp = lonsp;

	simple_heap_update(rel, &tuple->t_self, tuple);

	CatalogUpdateIndexes(rel, tuple);

	/* Update schema dependency */
	if (changeDependencyFor(LargeObjectRelationId, loid,
                            NamespaceRelationId, lonsp_old, lonsp) != 1)
		elog(ERROR,
			 "failed to change schema dependency for largeobject: %u", loid);

	heap_freetuple(tuple);

	heap_close(rel, RowExclusiveLock);
}

void
LargeObjectAlterOwner(List *loid_list, Oid newowner)
{
	Oid			loid = intVal(linitial(loid_list));
	Relation	rel;
	HeapTuple	tuple;
	Form_pg_largeobject	loform;

	rel = heap_open(LargeObjectRelationId, RowExclusiveLock);

	tuple = SearchSysCache(LARGEOBJECTOID,
						   ObjectIdGetDatum(loid),
						   0, 0, 0);
    if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_SCHEMA),
				 errmsg("largeobject %u does not exist", loid)));
	loform = (Form_pg_largeobject) GETSTRUCT(tuple);

	if (loform->loowner != newowner)
	{
		Datum		values[Natts_pg_largeobject];
		bool		nulls[Natts_pg_largeobject];
		bool		replaces[Natts_pg_largeobject];
		Acl		   *newAcl;
		Datum		aclDatum;
		bool		isnull;
		HeapTuple	newtup;
		AclResult	aclresult;

		/* Superusers can always do it */
		if (!superuser())
		{
			/* Otherwise, must be owner of the existing object */
			if (!pg_largeobject_ownercheck(loid, GetUserId()))
				aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_LARGEOBJECT,
							   get_largeobject_name(loid));

			/* Must be able to become new owner */
			check_is_member_of_role(GetUserId(), newowner);

			/* New owner must have CREATE privilege on namespace */
			aclresult = pg_namespace_aclcheck(loform->lonsp,
											  newowner, ACL_CREATE);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_LARGEOBJECT,
							   get_largeobject_name(loform->lonsp));
		}

		memset(values, 0, sizeof(values));
		memset(nulls, false, sizeof(nulls));
		memset(replaces, false, sizeof(replaces));

		values[Anum_pg_largeobject_loowner - 1] = ObjectIdGetDatum(newowner);
		replaces[Anum_pg_largeobject_loowner - 1] = true;

		/*
		 * Determine the modified ACL for the new owner.
		 * This is only necessary when the ACL is non-null.
		 */
		aclDatum = SysCacheGetAttr(PROCOID, tuple,
								   Anum_pg_largeobject_loacl,
								   &isnull);
		if (!isnull)
		{
			newAcl = aclnewowner(DatumGetAclP(aclDatum),
								 loform->loowner, newowner);
			replaces[Anum_pg_largeobject_loacl - 1] = true;
			replaces[Anum_pg_largeobject_loacl - 1] = PointerGetDatum(newAcl);
		}

		newtup = heap_modify_tuple(tuple, RelationGetDescr(rel),
								   values, nulls, replaces);

		simple_heap_update(rel, &newtup->t_self, newtup);
		CatalogUpdateIndexes(rel, newtup);

		heap_freetuple(newtup);

		/* Update owner dependency reference */
		changeDependencyOnOwner(LargeObjectRelationId, loid, newowner);
	}
	ReleaseSysCache(tuple);

	heap_close(rel, NoLock);
}
