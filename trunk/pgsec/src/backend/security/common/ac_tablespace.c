/*
 * src/backend/security/common/ac_tablespace.c
 *   common access control abstration corresponding to tablespaces
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/sysattr.h"
#include "catalog/pg_tablespace.h"
#include "commands/tablespace.h"
#include "miscadmin.h"
#include "security/common.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/tqual.h"

/*
 * ac_tablespace_create
 *
 * It checks privileges to create a new tablespace
 *
 * [Params]
 *  tblspcName : Name of the new tablespace
 */
void
ac_tablespace_create(const char *tblspcName)
{
	/* Must be super user */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to create tablespace \"%s\"",
						tblspcName),
				 errhint("Must be superuser to create a tablespace.")));
}

/*
 * ac_tablespace_alter
 *
 * It checks privileges to alter a certain tablespace
 *
 * [Params]
 *  tblspcOid : OID of the tablespace to be altered
 *  newName   : New name of the tablespace, if exist
 *  newOwner  : OID of the new tablespace owner, if exist
 *  newAcl    : Pointer to set a new acl datum, when newOwner is valid
 */
void
ac_tablespace_alter(Oid tblspcOid, const char *newName,
					Oid newOwner, Datum *newAcl)
{
	/* Must be owner for all the ALTER TABLESPACE options */
	if (!pg_tablespace_ownercheck(tblspcOid, GetUserId()))
		aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_TABLESPACE,
					   get_tablespace_name(tblspcOid));

	if (OidIsValid(newOwner))
	{
		Form_pg_tablespace	spcForm;
		Relation		rel;
		ScanKeyData		key[1];
		HeapScanDesc	scan;
		HeapTuple		spctup;
		Datum			datum;
		bool			isnull;
		Acl			   *acl = NULL;

		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/* system cache does not support tablespace */
		rel = heap_open(TableSpaceRelationId, AccessShareLock);

		ScanKeyInit(&key[0],
					ObjectIdAttributeNumber,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(tblspcOid));

		scan = heap_beginscan(rel, SnapshotNow, 1, key);

		spctup = heap_getnext(scan, ForwardScanDirection);
		if (!HeapTupleIsValid(spctup))
			elog(ERROR, "tablespace with OID %u does not exist", tblspcOid);
		spcForm = (Form_pg_tablespace) GETSTRUCT(spctup);

		datum = heap_getattr(spctup,
							 Anum_pg_tablespace_spcacl,
							 RelationGetDescr(rel),
							 &isnull);
		if (!isnull)
			acl = aclnewowner(DatumGetAclP(datum),
							  spcForm->spcowner, newOwner);
		*newAcl = PointerGetDatum(acl);

		heap_endscan(scan);
		heap_close(rel, AccessShareLock);
	}
}

/*
 * ac_tablespace_drop
 *
 * It checks privileges to drop a certain tablespace
 *
 * [Params]
 *  tblspcOid : OID of the tablespace to be dropped
 *  cascade   : True, if cascaded deletion
 */
void
ac_tablespace_drop(Oid tblspcOid, bool cascade)
{
	/* Must be tablespace owner */
	if (!cascade &&
		!pg_tablespace_ownercheck(tblspcOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TABLESPACE,
					   get_tablespace_name(tblspcOid));
}

/*
 * ac_tablespace_grant
 *
 * It checks privileges to grant/revoke permissions on a certain tablespace
 *
 * [Params]
 *  tblspcOid  : OID of the target tablespace for GRANT/REVOKE
 *  isGrant    : True, if the statement is GRANT
 *  privileges : AclMask being tries to be granted
 *  grantor    : OID of the gractor database role
 *  goptions   : Available AclMask to grant others
 */
void
ac_tablespace_grant(Oid tblspcOid, bool isGrant, AclMode privileges,
					Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		AclMode		whole_mask = ACL_ALL_RIGHTS_TABLESPACE;

		if (pg_tablespace_aclmask(tblspcOid, grantor,
								  whole_mask | ACL_GRANT_OPTION_FOR(whole_mask),
								  ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_TABLESPACE,
						   get_tablespace_name(tblspcOid));
	}
}

/*
 * ac_tablespace_calculate_size
 *
 * It checks privileges to calculate size of a certain tablespace
 *
 * [Params]
 *   tblspcOid : OID of the target tablespace
 */
void
ac_tablespace_calculate_size(Oid tblspcOid)
{
	AclResult	aclresult;

	/*
	 * User must have CREATE privilege for target tablespace, either
	 * explicitly granted or implicitly because it is default for current
	 * database.
	 */
	if (tblspcOid != MyDatabaseTableSpace)
	{
		aclresult = pg_tablespace_aclcheck(tblspcOid, GetUserId(),
										   ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE,
						   get_tablespace_name(tblspcOid));
	}
}

/*
 * ac_tablespace_for_temporary
 *
 * It checks privileges to list up a certain tablespace (except for
 * the default tablespace of the current database) as a candidate of
 * temporary database objects.
 *
 * [Params]
 *   tblspcOid : OID of the target tablespace
 *   abort     : True, if caller want to raise an error, if violated
 */
bool
ac_tablespace_for_temporary(Oid tblspcOid, bool abort)
{
	AclResult	aclresult;

	aclresult = pg_tablespace_aclcheck(tblspcOid, GetUserId(),
									   ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		return false;

	return true;
}

/*
 * ac_tablespace_comment
 *
 * It checks privileges to comment on a certain tablespace
 *
 * [Params]
 *   tblspcOid : OID of the tablespace to be commented on
 */
void
ac_tablespace_comment(Oid tblspcOid)
{
	if (!pg_tablespace_ownercheck(tblspcOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TABLESPACE,
					   get_tablespace_name(tblspcOid));
}
