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
#include "catalog/pg_largeobject_metadata.h"
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
CreateLargeObject(Oid loid)
{
	Relation	pg_lo_meta;
	HeapTuple	ntup;
	Oid			loid_new;
	Datum		values[Natts_pg_largeobject_metadata];
	bool		nulls[Natts_pg_largeobject_metadata];

	pg_lo_meta = heap_open(LargeObjectMetadataRelationId,
						   RowExclusiveLock);

	/*
	 * Insert metadata of the largeobject
	 */
	memset(values, 0, sizeof(values));
	memset(nulls, false, sizeof(nulls));

	values[Anum_pg_largeobject_metadata_lomowner - 1]
		= ObjectIdGetDatum(GetUserId());
	nulls[Anum_pg_largeobject_metadata_lomacl - 1] = true;

	ntup = heap_form_tuple(RelationGetDescr(pg_lo_meta),
						   values, nulls);
	if (OidIsValid(loid))
		HeapTupleSetOid(ntup, loid);

	loid_new = simple_heap_insert(pg_lo_meta, ntup);
	Assert(!OidIsValid(loid) || loid == loid_new);

	CatalogUpdateIndexes(pg_lo_meta, ntup);

	heap_freetuple(ntup);

	heap_close(pg_lo_meta, RowExclusiveLock);

	return loid_new;
}

void
DropLargeObject(Oid loid)
{
	Relation	pg_lo_meta;
	Relation	pg_largeobject;
	ScanKeyData skey[1];
	SysScanDesc sd;
	HeapTuple	tuple;

	pg_lo_meta = heap_open(LargeObjectMetadataRelationId,
						   RowExclusiveLock);

	pg_largeobject = heap_open(LargeObjectRelationId,
							   RowExclusiveLock);

	/*
	 * Delete an entry from pg_largeobject_metadata
	 */
	tuple = SearchSysCache(LARGEOBJECTOID,
						   ObjectIdGetDatum(loid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("large object %u does not exist", loid)));

	simple_heap_delete(pg_lo_meta, &tuple->t_self);

	ReleaseSysCache(tuple);

	/*
	 * Delete all the associated entries from pg_largeobject
	 */
	ScanKeyInit(&skey[0],
				Anum_pg_largeobject_loid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(loid));

	sd = systable_beginscan(pg_largeobject, LargeObjectLOidPNIndexId, true,
							SnapshotNow, 1, skey);
	while (HeapTupleIsValid(tuple = systable_getnext(sd)))
	{
		simple_heap_delete(pg_largeobject, &tuple->t_self);
	}

	systable_endscan(sd);

	heap_close(pg_largeobject, RowExclusiveLock);

	heap_close(pg_lo_meta, RowExclusiveLock);
}

void
AlterLargeObjectOwner(Oid loid, Oid newOwnerId)
{
	Form_pg_largeobject_metadata	lomForm;
	Relation	lomRel;
	HeapTuple	oldtup, newtup;

	lomRel = heap_open(LargeObjectMetadataRelationId,
					   RowExclusiveLock);

	oldtup = SearchSysCache(LARGEOBJECTOID,
							ObjectIdGetDatum(loid),
							0, 0, 0);
	if (!HeapTupleIsValid(oldtup))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("large object %u does not exist", loid)));

	lomForm = (Form_pg_largeobject_metadata) GETSTRUCT(oldtup);
	if (lomForm->lomowner != newOwnerId)
	{
		Datum		values[Natts_pg_largeobject_metadata];
		bool		nulls[Natts_pg_largeobject_metadata];
		bool		replaces[Natts_pg_largeobject_metadata];
		Acl		   *newAcl;
		Datum		aclDatum;
		bool		isnull;

		/* Permission checks */
		ac_largeobject_alter(loid, newOwnerId);

		memset(values, 0, sizeof(values));
		memset(nulls, false, sizeof(nulls));
		memset(replaces, false, sizeof(nulls));

		values[Anum_pg_largeobject_metadata_lomowner - 1]
			= ObjectIdGetDatum(newOwnerId);
		replaces[Anum_pg_largeobject_metadata_lomowner - 1] = true;

		/*
		 * Determine the modified ACL for the new owner.
		 * This is only necessary when the ACL is non-null.
		 */
		aclDatum = SysCacheGetAttr(LARGEOBJECTOID, oldtup,
								   Anum_pg_largeobject_metadata_lomacl,
								   &isnull);
		if (!isnull)
		{
			newAcl = aclnewowner(DatumGetAclP(aclDatum),
								 lomForm->lomowner, newOwnerId);
			values[Anum_pg_largeobject_metadata_lomacl - 1]
				= PointerGetDatum(newAcl);
			replaces[Anum_pg_largeobject_metadata_lomacl - 1] = true;
		}

		newtup = heap_modify_tuple(oldtup, RelationGetDescr(lomRel),
								   values, nulls, replaces);

		simple_heap_update(lomRel, &newtup->t_self, newtup);
		CatalogUpdateIndexes(lomRel, newtup);

		heap_freetuple(newtup);

		/* Update owner dependency reference */
		changeDependencyOnOwner(LargeObjectMetadataRelationId,
								loid, newOwnerId);
	}
	ReleaseSysCache(oldtup);

	heap_close(lomRel, RowExclusiveLock);
}

/*
 * security check functions (to be moved to
 * the backend/security/access_control.c)
 */

/*
 * ac_largeobject_compat_acl
 *
 * It enables to turn on/off ACL checks on largeobjects to keep
 * backward compatibility. The pgsql-8.4.x or prior didn't have
 * any access controls on largeobjects (except for supruser checks
 * on the server side import/export), so turning it off allows us
 * to use the largeobject stuff as if older version doing.
 */
bool ac_largeobject_compat_acl;

/*
 * ac_largeobject_create
 *
 * It checks permission to create a new largeobject.
 *
 * [Params]
 * loid : InvalidOid or OID of the new largeobject if given
 */
void ac_largeobject_create(Oid loid)
{
	/*
	 * MEMO: In this revision, PostgreSQL implicitly allows everyone
	 * to create new largeobject. It is backward compatible behavior,
	 * but may be changed at the future version.
	 */
}

/*
 * ac_largeobject_alter
 *
 * It checks permission to alter a certain largeobject.
 * (Now the only caller is ALTER LARGE OBJECT loid OWNER TO newowner)
 *
 * [Params]
 * loid     : OID of the largeobject to be altered
 * newOwner : OID of the new largeobject owner
 */
void
ac_largeobject_alter(Oid loid, Oid newOwner)
{
	/* must be owner of largeobject */
	if (!pg_largeobject_ownercheck(loid, GetUserId()))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be owner of largeobject %u", loid)));

	/* Superusers can always do it */
	if (OidIsValid(newOwner) && !superuser())
	{
		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/*
		 * MEMO: The new owner must have privilege to create
		 * a new largeobject, and to be checked here.
		 * But it is implicitly allowed to everyone, so we
		 * don't put any checks in this revision.
		 */
	}
}

/*
 * ac_largeobject_drop
 *
 * It checks permission to drop a certain largeobejct
 *
 * [Params]
 * loid    : OID of the largeobject to be altered
 * dacSkip : True, if dac permission checks should be bypassed
 */
void ac_largeobject_drop(Oid loid, bool dacSkip)
{
	/* Must be owner of the largeobject */
	if (!dacSkip &&
		!pg_largeobject_ownercheck(loid, GetUserId()))
		ereport(!ac_largeobject_compat_acl ? ERROR : NOTICE,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be owner of largeobject %u", loid)));
}

/*
 * ac_largeobject_comment
 *
 * It checks permission to comment on a certain largeobject
 *
 * [Params]
 * loid : OID of the largeobject to be commented on
 */
void ac_largeobject_comment(Oid loid)
{
	if (!pg_largeobject_ownercheck(loid, GetUserId()))
		ereport(!ac_largeobject_compat_acl ? ERROR : NOTICE,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be owner of largeobject %u", loid)));
}

/*
 * ac_largeobject_read
 *
 * It checks permission to read data chunks from a certain largeobject
 *
 * [Params]
 * loid : OID of the largeobject to be read from
 */
void ac_largeobject_read(Oid loid)
{
	AclResult	aclresult;

	aclresult = pg_largeobject_aclcheck(loid, GetUserId(), ACL_SELECT);
	if (aclresult != ACLCHECK_OK)
		ereport(!ac_largeobject_compat_acl ? ERROR : NOTICE,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied for largeobject %u", loid)));
}

/*
 * ac_largeobject_write
 *
 * It checks permission to write data chunkd to a certain largeobject
 *
 * [Params]
 * loid : OID of the largeobject to be written to
 */
void ac_largeobject_write(Oid loid)
{
	AclResult	aclresult;

	aclresult = pg_largeobject_aclcheck(loid, GetUserId(), ACL_UPDATE);
	if (aclresult != ACLCHECK_OK)
		ereport(!ac_largeobject_compat_acl ? ERROR : NOTICE,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied for largeobject %u", loid)));
}

/*
 * ac_largeobject_export
 *
 * It checks permission to export a certain largeobject to a server-side file.
 *
 * [Params]
 * loid     : OID of the largeobject to be exported
 * filename : The target filename to be exported to
 */
void ac_largeobject_export(Oid loid, const char *filename)
{
#ifndef ALLOW_DANGEROUS_LO_FUNCTIONS
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to use server-side lo_export()"),
				 errhint("Anyone can use the client-side lo_export() provided by libpq.")));
#endif
}

/*
 * ac_largeobject_import
 *
 * It checks permission to import contents from a server-side file.
 *
 * [Params]
 * loid     : InvalidOid or OID of the largeobject, if given
 * filename : The target filename to be imported from
 */
void ac_largeobject_import(Oid loid, const char *filename)
{
#ifndef ALLOW_DANGEROUS_LO_FUNCTIONS
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to use server-side lo_import()"),
				 errhint("Anyone can use the client-side lo_import() provided by libpq.")));
#endif
}
