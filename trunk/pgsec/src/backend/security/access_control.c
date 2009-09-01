/*
 * src/backend/security/access_control.c
 *
 * Routines for common access control facilities. 
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/sysattr.h"
#include "catalog/indexing.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_cast.h"
#include "catalog/pg_class.h"
#include "catalog/pg_constraint.h"
#include "catalog/pg_conversion.h"
#include "catalog/pg_database.h"
#include "catalog/pg_foreign_data_wrapper.h"
#include "catalog/pg_foreign_server.h"
#include "catalog/pg_language.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_opfamily.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_rewrite.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_ts_config.h"
#include "catalog/pg_ts_dict.h"
#include "catalog/pg_ts_parser.h"
#include "catalog/pg_ts_template.h"
#include "catalog/pg_type.h"
#include "catalog/pg_user_mapping.h"
#include "commands/dbcommands.h"
#include "commands/tablespace.h"
#include "miscadmin.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/security.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

/* ************************************************************
 *
 * Pg_attribute system catalog related access control stuffs
 *
 * ************************************************************/

/*
 * ac_attribute_create
 *
 * It checks privilege to create a new column using ALTER TABLE
 * statement.
 * Note that this check is not called on CREARE TABLE, so use
 * the ac_class_create() instead, if necessary.
 *
 * [Params]
 * relOid : OID of the relation to be altered
 * colDef : Definition of the new column
 */
void
ac_attribute_create(Oid relOid, ColumnDef *colDef)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_attribute_alter
 *
 * It checks privilege to alter definition of a certain column
 * using ALTER TABLE statement.
 *
 * [Params]
 * relOid  : OID of the relation to be altered
 * attName : Name of the target attribute to be altered
 */
void
ac_attribute_alter(Oid relOid, const char *attName)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_attribute_drop
 *
 * It checks privilege to drop a certain column using ALTER TABLE
 * statement. Note that this check is not called on DROP TABLE, so
 * use the ac_class_drop() instead, if necessary.
 *
 * [Params]
 * relOid  : OID of the relation to be altered
 * attName : Name of the target attribute to be dropped
 * dacSkip : True, if dac permission check should be bypassed
 */
void
ac_attribute_drop(Oid relOid, const char *attName, bool dacSkip)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_attribute_grant
 *
 * It checks privileges to grant/revoke permissions on a certain attribute
 *
 * [Params]
 * relOid   : OID of the target relation for GRANT/REVOKE
 * attnum   : Attribute number of the target column for GRANT/REVOKE
 * grantor  : OID of the gractor role
 * goptions : Available AclMask available to grant others
 */
void
ac_attribute_grant(Oid relOid, AttrNumber attnum,
				   Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		AclMode		whole_mask = ACL_ALL_RIGHTS_COLUMN;

		if (pg_class_aclmask(relOid, grantor,
							 whole_mask | ACL_GRANT_OPTION_FOR(whole_mask),
							 ACLMASK_ANY) == ACL_NO_RIGHTS ||
			pg_attribute_aclmask(relOid, attnum, grantor,
								 whole_mask | ACL_GRANT_OPTION_FOR(whole_mask),
								 ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error_col(ACLCHECK_NO_PRIV, ACL_KIND_COLUMN,
							   get_rel_name(relOid),
							   get_attname(relOid, attnum));
	}
}

/*
 * ac_attribute_comment
 *
 * It checks privilege to comment on a certain attribute
 *
 * [Params]
 * relOid  : OID of the relation which contains the target
 * attName : Name of the target attribute
 */
void
ac_attribute_comment(Oid relOid, const char *attName)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/* ************************************************************
 *
 * Pg_authid system catalog related access control stuffs
 *
 * ************************************************************/

/* Helper functions */
static bool
have_createrole_privilege(void)
{
	bool        result = false;
	HeapTuple   utup;

	/* Superusers can always do everything */
	if (superuser())
		return true;

	utup = SearchSysCache(AUTHOID,
						  ObjectIdGetDatum(GetUserId()),
						  0, 0, 0);
	if (HeapTupleIsValid(utup))
	{
		result = ((Form_pg_authid) GETSTRUCT(utup))->rolcreaterole;
		ReleaseSysCache(utup);
	}
	return result;
}

/*
 * ac_role_create
 *
 * It checks privilege to create a new database role.
 *
 * [Params]
 * rolName  : Name of the new database role
 * rolSuper : True, if the new role is set up as a superuser
 */
void
ac_role_create(const char *rolName, bool rolSuper)
{
	if (rolSuper)
	{
		if (!superuser())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("must be superuser to create superusers")));
	}
	else
	{
		if (!have_createrole_privilege())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("permission denied to create role")));
	}
}

/*
 * ac_role_alter
 *
 * It checks privilege to alter a certain database role.
 *
 * [Params]
 * roleId     : OID of the database role
 * newSuper   : Zero or positive value, if user gives new SUPERUSER state.
 *              If it is negative, it keeps the value as is.
 * onlyPasswd : True, if user only changes his password.
 * setRoleGuc : True, if user changes per role Guc setting.
 */
void
ac_role_alter(Oid roleId, int newSuper, bool onlyPassword, bool setRoleGuc)
{
	Form_pg_authid	rolForm;
	HeapTuple		rolTup;

	rolTup = SearchSysCache(AUTHOID,
							ObjectIdGetDatum(roleId),
							0, 0, 0);
	if (!HeapTupleIsValid(rolTup))
		elog(ERROR, "cache lookup failed for role %u", roleId);

	/*
	 * If user tries to change any attribute on superuser or
	 * SUPERUSER attribute of any database roles, he also needs
	 * to be superuser.
	 * Otherwise, user needs to have CREATEROLE privilege to
	 * alter any attributes of database roles, except for the
	 * password and local Guc setting of himself.
	 */
	rolForm = (Form_pg_authid) GETSTRUCT(rolTup);
	if (rolForm->rolsuper || newSuper >= 0)
	{
		if (!superuser())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("must be superuser to alter superusers")));
	}
	else if (!have_createrole_privilege())
	{
		/*
		 * When we alter the password or user local Guc setting,
		 * it is not necessary to have CREATEROLE privilege, as
		 * long as the target database role is himself.
		 */
		if ((!onlyPassword && !setRoleGuc) || roleId != GetUserId())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("permission denied")));
	}
	ReleaseSysCache(rolTup);
}

/*
 * ac_role_drop
 *
 * It checks privilege to drop a certain database role.
 *
 * [Params]
 * roleId  : OID of the database role to be dropped
 * dacSkip : True, if dac permission check should be bypassed
 */
void
ac_role_drop(Oid roleId, bool dacSkip)
{
	if (!dacSkip)
	{
		HeapTuple	rolTup;

		if (!have_createrole_privilege())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("permission denied to drop role")));

		/*
		 * For safety's sake, we allow createrole holders to drop ordinary
		 * roles but not superuser roles.  This is mainly to avoid the
		 * scenario where you accidentally drop the last superuser.
		 */
		rolTup = SearchSysCache(AUTHOID,
								ObjectIdGetDatum(roleId),
								0, 0, 0);
		if (!HeapTupleIsValid(rolTup))
			elog(ERROR, "cache lookup failed for role %u", roleId);

		if (((Form_pg_authid) GETSTRUCT(rolTup))->rolsuper &&
			!superuser())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("must be superuser to drop superusers")));

		ReleaseSysCache(rolTup);
	}
}

/*
 * ac_role_comment
 *
 * It checks privilege to comment on a certain database role
 *
 * [Params]
 * roleId : OID of the target database role
 */
void
ac_role_comment(Oid roleId)
{
	if (!has_privs_of_role(GetUserId(), roleId))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be member of role \"%s\" to comment upon it",
						GetUserNameFromId(roleId))));
}

/*
 * ac_role_grant
 *
 * It checks privilege to add/delete membership of a certain role.
 *
 * [Params]
 * roleId   : OID of the database role to be modified
 * grantor  : OID of the grantor's role
 * is_grant : True, if caller tries to add membership.
 */
void
ac_role_grant(Oid roleId, Oid grantorId, bool is_grant)
{
	/*
	 * Check permissions: must have createrole or admin option on the role to
	 * be changed.	To mess with a superuser role, you gotta be superuser.
	 */
	if (superuser_arg(roleId))
	{
		if (!superuser())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("must be superuser to alter superusers")));
	}
	else
	{
		if (!have_createrole_privilege() &&
			!is_admin_of_role(grantorId, roleId))
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("must have admin option on role \"%s\"",
							GetUserNameFromId(roleId))));
	}

	/* XXX not sure about this check */
	if (grantorId != GetUserId() && !superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to set grantor")));
}

/* ************************************************************
 *
 * Pg_cast system catalog related access control stuffs
 *
 * ************************************************************/

/*
 * ac_cast_create
 *
 * It checks privilege to create a new cast
 *
 * [Params]
 * sourceTypOid  : OID of the source type
 * targetTypOid  : OID of the target type
 * castMethod    : One of the COERCION_METHOD_*
 * funcOid       : OID of the cast function
 */
void
ac_cast_create(Oid sourceTypOid, Oid targetTypOid,
			   char castMethod, Oid funcOid)
{
	/* Must be owner of either source or target type */
	if (!pg_type_ownercheck(sourceTypOid, GetUserId()) &&
		!pg_type_ownercheck(targetTypOid, GetUserId()))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be owner of type %s or type %s",
						format_type_be(sourceTypOid),
						format_type_be(targetTypOid))));
	/*
	 * Must be superuser to create binary-compatible casts,
	 * since erroneous casts can easily crash the backend.
	 */
	if (castMethod == COERCION_METHOD_BINARY)
	{
		if (!superuser())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("must be superuser to create "
							"a cast WITHOUT FUNCTION")));
	}
}

/*
 * ac_cast_drop
 *
 * It checks privilege to drop a certain cast
 *
 * [Params]
 * sourceTypOid : OID of the source type
 * targetTypOid : OID of the target type
 * dacSkip      : True, if dac permission check should be bypassed
 */
void
ac_cast_drop(Oid sourceTypOid, Oid targetTypOid, bool dacSkip)
{
	if (!dacSkip &&
		!pg_type_ownercheck(sourceTypOid, GetUserId()) &&
		!pg_type_ownercheck(targetTypOid, GetUserId()))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be owner of type %s or type %s",
						format_type_be(sourceTypOid),
						format_type_be(targetTypOid))));
}

/* Helper function to call ac_cast_drop() by oid */
static void
ac_cast_drop_by_oid(Oid castOid, bool dacSkip)
{
	Form_pg_cast	castForm;
	Relation		castRel;
	HeapTuple		castTup;
	ScanKeyData		skey;
	SysScanDesc		sscan;

	castRel = heap_open(CastRelationId, AccessShareLock);

	ScanKeyInit(&skey,
				ObjectIdAttributeNumber,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(castOid));
	sscan = systable_beginscan(castRel, CastOidIndexId, true,
							   SnapshotNow, 1, &skey);
	castTup = systable_getnext(sscan);
	if (!HeapTupleIsValid(castTup))
		elog(ERROR, "could not find tuple for cast %u", castOid);

	castForm = (Form_pg_cast) GETSTRUCT(castTup);
	ac_cast_drop(castForm->castsource, castForm->casttarget, dacSkip);

	systable_endscan(sscan);

	heap_close(castRel, AccessShareLock);
}

/*
 * ac_cast_comment
 *
 * It checks privilege to comment on a certain cast
 *
 * [Params]
 * sourceTypOid : OID of the source type
 * targetTypOid : OID of the target type
 */
void
ac_cast_comment(Oid sourceTypOid, Oid targetTypOid)
{
	if (!pg_type_ownercheck(sourceTypOid, GetUserId()) &&
		!pg_type_ownercheck(targetTypOid, GetUserId()))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be owner of type %s or type %s",
						format_type_be(sourceTypOid),
						format_type_be(targetTypOid))));
}

/* ************************************************************
 *
 * Pg_class system catalog related access control stuffs
 *
 * ************************************************************/

/*
 * ac_relation_perms
 *
 * It checks privilege to access a certain table and columns using
 * regular DML statements.
 *
 * [Params]
 * relOid   : OID of the relation to be checked
 * roleId   : OID of the database role to be checked
 * reqPerms : mask of permission bits
 * selCols  : bitmapset of referenced columns
 * modCols  : bitmapset of modified columns
 * abort    : True, if caller want to raise an error on access violation
 */
bool
ac_relation_perms(Oid relOid, Oid roleId, AclMode reqPerms,
				  Bitmapset *selCols, Bitmapset *modCols, bool abort)
{
	AclMode		relationPerms;
	AclMode		remainingPerms;
	Bitmapset  *tmpset;
	int			col;

	/*
	 * We must have *all* the requiredPerms bits, but some of the bits can be
	 * satisfied from column-level rather than relation-level permissions.
	 * First, remove any bits that are satisfied by relation permissions.
	 */
	relationPerms = pg_class_aclmask(relOid, roleId, reqPerms, ACLMASK_ALL);
	remainingPerms = reqPerms & ~relationPerms;
	if (remainingPerms != 0)
	{
		/*
		 * If we lack any permissions that exist only as relation permissions,
		 * we can fail straight away.
		 */
		if (remainingPerms & ~(ACL_SELECT | ACL_INSERT | ACL_UPDATE))
		{
			if (abort)
				aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
							   get_rel_name(relOid));
			return false;
		}

		/*
		 * Check to see if we have the needed privileges at column level.
		 *
		 * Note: failures just report a table-level error; it would be nicer
		 * to report a column-level error if we have some but not all of the
		 * column privileges.
		 */
		if (remainingPerms & ACL_SELECT)
		{
			/*
			 * When the query doesn't explicitly reference any columns (for
			 * example, SELECT COUNT(*) FROM table), allow the query if we
			 * have SELECT on any column of the rel, as per SQL spec.
			 */
			if (bms_is_empty(selCols))
			{
				if (pg_attribute_aclcheck_all(relOid, roleId, ACL_SELECT,
											  ACLMASK_ANY) != ACLCHECK_OK)
				{
					if (abort)
						aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
									   get_rel_name(relOid));
					return false;
				}
			}

			tmpset = bms_copy(selCols);
			while ((col = bms_first_member(tmpset)) >= 0)
			{
				/* remove the column number offset */
				col += FirstLowInvalidHeapAttributeNumber;
				if (col == InvalidAttrNumber)
				{
					/* Whole-row reference, must have priv on all cols */
					if (pg_attribute_aclcheck_all(relOid, roleId, ACL_SELECT,
												  ACLMASK_ALL) != ACLCHECK_OK)
					{
						if (abort)
							aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
										   get_rel_name(relOid));
						return false;
					}
				}
				else
				{
					if (pg_attribute_aclcheck(relOid, col, roleId,
											  ACL_SELECT) != ACLCHECK_OK)
					{
						if (abort)
							aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
										   get_rel_name(relOid));
					}
				}
			}
			bms_free(tmpset);
		}

		/*
		 * Basically the same for the mod columns, with either INSERT or
		 * UPDATE privilege as specified by remainingPerms.
		 */
		remainingPerms &= ~ACL_SELECT;
		if (remainingPerms != 0)
		{
			/*
			 * When the query doesn't explicitly change any columns, allow the
			 * query if we have permission on any column of the rel.  This is
			 * to handle SELECT FOR UPDATE as well as possible corner cases in
			 * INSERT and UPDATE.
			 */
			if (bms_is_empty(modCols))
			{
				if (pg_attribute_aclcheck_all(relOid, roleId, remainingPerms,
											  ACLMASK_ANY) != ACLCHECK_OK)
				{
					if (abort)
						aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
									   get_rel_name(relOid));
					return false;
				}
			}

			tmpset = bms_copy(modCols);
			while ((col = bms_first_member(tmpset)) >= 0)
			{
				/* remove the column number offset */
				col += FirstLowInvalidHeapAttributeNumber;
				if (col == InvalidAttrNumber)
				{
					/* whole-row reference can't happen here */
					elog(ERROR, "whole-row update is not implemented");
				}
				else
				{
					if (pg_attribute_aclcheck(relOid, col, roleId,
											  remainingPerms) != ACLCHECK_OK)
					{
						if (abort)
							aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
										   get_rel_name(relOid));
						return false;
					}
				}
			}
			bms_free(tmpset);
		}
	}

	return true;
}

/*
 * ac_relation_create
 *
 * It checks privilege to create a new relation (except for indexes;
 * use ac_index_create() instead).
 *
 * Note that this check is not currently called from bootparse.y
 * (Boot_CreateStmt), create_toast_table() and make_new_heap(),
 * because they are used to the initialization or internal stuffs,
 * so they don't need to check any permissions here.
 * But SE-PgSQL will require to return its default security context
 * to be assigned on the new relation, even if no permission checks.
 *
 * [Params]
 * relName   : Name of the new relation
 * relkind   : relkind of the new relation
 * tupDesc   : tupDesc of the new relation
 * relNsp    : OID of the namespace of the relation
 * relTblspc : OID of the tablespace of the relation, if exist
 * colList   : List of ColumnDef, if exist
 */
void
ac_relation_create(const char *relName, char relkind, TupleDesc tupDesc,
				   Oid relNsp, Oid relTblspc, List *colList)
{
	AclResult	aclresult;

	/* For indexes, use ac_index_create() instead */
	Assert(relkind != RELKIND_INDEX);

	if (!IsBootstrapProcessingMode())
	{
		/* Check permissions to create a relation on the namespace */
		aclresult = pg_namespace_aclcheck(relNsp, GetUserId(),
										  ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(relNsp));
	}

	/* Check permissions except when using database's default */
	if (OidIsValid(relTblspc) && relTblspc != MyDatabaseTableSpace)
	{
		aclresult = pg_tablespace_aclcheck(relTblspc, GetUserId(),
										   ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE,
						   get_tablespace_name(relTblspc));
	}
}

/*
 * ac_relation_alter
 *
 * It checks privilege to alter a certain relation
 *
 * [Params]
 * relOid    : OID of the relation to be altered
 * newName   : New name of the relation, if given
 * newNsp    : OID of the new namespace, if given
 * newTblspc : OID of the new tablespace, if given
 * newOwner  : OID of the new relation owner, if given
 */
void
ac_relation_alter(Oid relOid, const char *newName,
				  Oid newNsp, Oid newTblspc, Oid newOwner)
{
	AclResult	aclresult;
	Oid			relNsp;

	/* Must be owner for all the ALTER TABLE options */
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));

	if (newName)
	{
		relNsp = get_rel_namespace(relOid);
		aclresult = pg_namespace_aclcheck(relNsp, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(relNsp));
	}

	if (OidIsValid(newNsp))
	{
		aclresult = pg_namespace_aclcheck(newNsp, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(newNsp));
	}

	if (OidIsValid(newTblspc))
	{
		aclresult = pg_tablespace_aclcheck(newTblspc, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE,
						   get_tablespace_name(newTblspc));
	}

	/* Superusers can always do it */
	if (OidIsValid(newOwner) && !superuser())
	{
		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have CREATE privilege on namespace */
		relNsp = get_rel_namespace(relOid);
		aclresult = pg_namespace_aclcheck(relNsp, newOwner, ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(relNsp));
	}
}

/*
 * ac_relation_drop
 *
 * It checks privilege to drop a certain relation.
 * Note that the security feature also needs to check permissions to
 * drop columns within the relation to be removed here, if necessary.
 *
 * [Params]
 * relOid  : OID of the relation to be dropped
 * dacSkip : True, if dac permission checks should be bypassed
 */
void
ac_relation_drop(Oid relOid, bool dacSkip)
{
	Oid		relNspOid = get_rel_namespace(relOid);

	/* Allow DROP to either table owner or schema owner */
	if (!dacSkip &&
		!pg_class_ownercheck(relOid, GetUserId()) &&
		!pg_namespace_ownercheck(relNspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_relation_grant
 *
 * It checks privileges to grant/revoke permissions on a certain relation
 *
 * [Params]
 * relOid   : OID of the target relation for GRANT/REVOKE
 * grantor  : OID of the gractor role
 * goptions : Available AclMask available to grant others
 */
void
ac_relation_grant(Oid relOid, Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		char		relkind = get_rel_relkind(relOid);
		AclMode		whole_mask;

		whole_mask = (relkind == RELKIND_SEQUENCE
					  ? ACL_ALL_RIGHTS_SEQUENCE : ACL_ALL_RIGHTS_RELATION);
		if (pg_class_aclmask(relOid, grantor,
							 whole_mask | ACL_GRANT_OPTION_FOR(whole_mask),
							 ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error(ACLCHECK_NO_PRIV,
						   (relkind == RELKIND_SEQUENCE
							? ACL_KIND_SEQUENCE : ACL_KIND_CLASS),
						   get_rel_name(relOid));
	}
}

/*
 * ac_class_comment
 *
 * It checks privilges to comment on the relation
 *
 * [Params]
 * relOid : OID of the relation to be commented
 */
void
ac_relation_comment(Oid relOid)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_relation_get_transaction_id
 *
 * It checks privilege to execute currtid() function.
 *
 * [Params]
 * relOid : OID of the relation to be referenced
 */
void
ac_relation_get_transaction_id(Oid relOid)
{
	AclResult	aclresult;

	aclresult = pg_class_aclcheck(relOid, GetUserId(), ACL_SELECT);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_relation_copy_definition
 *
 * It checks privileges to define a new column which is copied from
 * another relation, using LIKE clause in CREATE TABLE
 *
 * [Params]
 * relOidSrc : OID of the relation to be copied its column's definition
 */
void
ac_relation_copy_definition(Oid relOidSrc)
{
	AclResult	aclresult;

	aclresult = pg_class_aclcheck(relOidSrc, GetUserId(), ACL_SELECT);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_CLASS, get_rel_name(relOidSrc));
}

/*
 * ac_relation_inheritance
 *
 * It checks privilege to set up an inheritance relationship between
 * a couple of two relations. 
 *
 * [Params]
 * parentOid : OID of the parant relation
 * childOid  : OID of the child relation
 *             It is available onlt when ALTER TABLE INHERIT case.
 */
void
ac_relation_inheritance(Oid parentOid, Oid childOid)
{
	Assert(get_rel_relkind(parentOid) == RELKIND_RELATION);

	/*
	 * We should have an UNDER permission flag for this, but for now,
	 * demand that creator of a child table own the parent.
	 */
	if (!pg_class_ownercheck(parentOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(parentOid));

	/*
	 * MEMO: CREATE TABLE (...) INHERITS(xxx); does not prevent to
	 * create a child table with system catalog, but ALTER TABLE
	 * INHERIT xxx prents this. Which is correct?
	 */
}

/*
 * ac_relation_cluster
 *
 * It checks privilege to cluster certain tables using CLUSTER
 * statement.
 *
 * [Params]
 * relOid : OID of the target relation
 * abort  : True, if caller want to raise an error on violation
 */
bool
ac_relation_cluster(Oid relOid, bool abort)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
	{
		if (abort)
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
						   get_rel_name(relOid));
		return false;
	}
	return true;
}

/*
 * ac_relation_truncate
 *
 * It checks privilege to truncate certain tables using TRUNCATE
 * statement.
 *
 * [Params]
 * rel : The Relation to be truncated.
 */
void
ac_relation_truncate(Relation rel)
{
	AclResult	aclresult;

	Assert(RelationGetForm(rel)->relkind == RELKIND_RELATION);

	aclresult = pg_class_aclcheck(RelationGetRelid(rel), GetUserId(),
								  ACL_TRUNCATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_CLASS,
					   RelationGetRelationName(rel));
}

/*
 * ac_relation_references
 *
 * It checks privilege to set up a FK constraint.
 * Note that this check is called twice for both of PK and FK tables.
 *
 * [Params]
 * rel     : The Relation to be constrained
 * attnums : An array of constrained attributes numbers
 * natts   : length of the attnums array
 */
void
ac_relation_references(Relation rel, int16 *attnums, int natts)
{
	AclResult	aclresult;
	int			i;

	Assert(RelationGetForm(rel)->relkind == RELKIND_RELATION);

	/* Okay if we have relation-level REFERENCES permission */
	aclresult = pg_class_aclcheck(RelationGetRelid(rel), GetUserId(),
								  ACL_REFERENCES);
	/* Else we must have REFERENCES on each column */
	if (aclresult != ACLCHECK_OK)
	{
		for (i = 0; i < natts; i++)
		{
			aclresult = pg_attribute_aclcheck(RelationGetRelid(rel),
											  attnums[i], GetUserId(),
											  ACL_REFERENCES);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_CLASS,
							   RelationGetRelationName(rel));
		}
	}
}

/*
 * ac_relation_lock
 *
 * It checks privilege to lock a certain relation using LOCK statement
 *
 * [Params]
 * relOid   : OID of the target relation
 * lockmode : The lock mode to be acquired
 */
void
ac_relation_lock(Oid relOid, LOCKMODE lockmode)
{
	AclResult	aclresult;

	Assert(get_rel_relkind(relOid) == RELKIND_RELATION);

	if (lockmode == AccessShareLock)
		aclresult = pg_class_aclcheck(relOid, GetUserId(),
									  ACL_SELECT);
	else
		aclresult = pg_class_aclcheck(relOid, GetUserId(),
						ACL_UPDATE | ACL_DELETE | ACL_TRUNCATE);

	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_relation_vacuum
 *
 * It checks privilege to vacuum a certain relation, and returns
 * false on privilege violation.
 *
 * [Params]
 * rel : The Relation to be vacuumed
 */
bool
ac_relation_vacuum(Relation rel)
{
	Assert(RelationGetForm(rel)->relkind == RELKIND_RELATION ||
		   RelationGetForm(rel)->relkind == RELKIND_TOASTVALUE);

	if (pg_class_ownercheck(RelationGetRelid(rel), GetUserId()) ||
		(pg_database_ownercheck(MyDatabaseId, GetUserId()) &&
		 !rel->rd_rel->relisshared))
		return true;

	return false;
}

/*
 * ac_relation_indexon
 *
 * It checks privilege to create a new index on a certain table.
 *
 * [Params]
 * relOid : OID of the relation to be rebuilt
 */
void
ac_relation_indexon(Oid relOid)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_relation_reindex
 *
 * It checks privilege to rebuild all the indexes defined on a certain
 * table using REINDEX statement.
 *
 * Note that this check is not called on REINDEX DATABSE or INDEX
 *
 * [Params]
 * relOid : OID of the index to be rebuilt
 */
void
ac_relation_reindex(Oid relOid)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_view_replace
 *
 * It checks privilege to replace a certain view using CREATE OR REPLACE
 * VIEW. Note that ac_class_create() is called if here is not previously
 * defined view.
 *
 * [Params]
 * viewOid : OID of the target view.
 */
void
ac_view_replace(Oid viewOid)
{
	if (!pg_class_ownercheck(viewOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(viewOid));
}

/*
 * ac_index_create
 *
 * It checks privilege to create a new index.
 * Note that ac_relation_indexon() is also called on CREATE INDEX statement.
 * Note that create_toast_table() does not call the check.
 *
 * [Params]
 * indName      : Name of the new index
 * check_rights : True, if caller wait permission checks on namespace
 * indNsp       : OID of the namespace to be used
 * indTblSpc    : OID of the tablespace, if given
 */
void
ac_index_create(const char *indName, bool check_rights,
				Oid indNsp, Oid indTblSpc)
{
	AclResult	aclresult;

	if (check_rights)
	{
		aclresult = pg_namespace_aclcheck(indNsp, GetUserId(),
										  ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(indNsp));
	}

	if (OidIsValid(indTblSpc) && indTblSpc != MyDatabaseTableSpace)
	{
		aclresult = pg_tablespace_aclcheck(indTblSpc, GetUserId(),
										   ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE,
						   get_tablespace_name(indTblSpc));
	}
}

/*
 * ac_index_reindex
 *
 * It checks privilege to rebuild a certain index using REINDEX statement.
 * Note that this check is not called on REINDEX DATABASE or TABLE.
 *
 * [Params]
 * indOid : OID of the target index
 */
void
ac_index_reindex(Oid indOid)
{
	Assert(get_rel_relkind(indOid) == RELKIND_INDEX);

	if (!pg_class_ownercheck(indOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(indOid));
}

/*
 * ac_sequence_get_value
 *
 * It checks privilege to refer a certain sequence object without any
 * modifications. In other words, getval() and lastval() invoke this
 * check.
 *
 * [Params]
 * seqOid : OID of the sequence to be referenced
 */
void
ac_sequence_get_value(Oid seqOid)
{
	Assert(get_rel_relkind(seqOid) == RELKIND_SEQUENCE);

	if (pg_class_aclcheck(seqOid, GetUserId(), ACL_SELECT) != ACLCHECK_OK &&
		pg_class_aclcheck(seqOid, GetUserId(), ACL_USAGE) != ACLCHECK_OK)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied for sequence %s",
						get_rel_name(seqOid))));
}

/*
 * ac_sequence_next_value
 *
 * It checks privilege to increment and fetch a value from a certain sequence
 * object. In other words, nextval() invokes this check.
 *
 * [Params]
 * seqOid : OID of the sequence to be fetched
 */
void
ac_sequence_next_value(Oid seqOid)
{
	Assert(get_rel_relkind(seqOid) == RELKIND_SEQUENCE);

	if (pg_class_aclcheck(seqOid, GetUserId(), ACL_USAGE) != ACLCHECK_OK &&
		pg_class_aclcheck(seqOid, GetUserId(), ACL_UPDATE) != ACLCHECK_OK)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied for sequence %s",
						get_rel_name(seqOid))));
}

/*
 * ac_sequence_set_value
 *
 * It checks privilege to set a discretionary value on a certain sequence
 * object. In other words, setval() invokes this check.
 *
 * [Params]
 * seqOid : OID of the sequence to be rewritten
 */
void
ac_sequence_set_value(Oid seqOid)
{
	Assert(get_rel_relkind(seqOid) == RELKIND_SEQUENCE);

	if (pg_class_aclcheck(seqOid, GetUserId(), ACL_UPDATE) != ACLCHECK_OK)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied for sequence %s",
						get_rel_name(seqOid))));
}

/* ************************************************************
 *
 * Pg_constraint system catalog related access control stuffs
 *
 * ************************************************************/

/*
 * ac_constraint_comment
 *
 * It checks privilege to comment on a certain constraint
 *
 * [Params]
 * conOid : OID of the constraint to be commented on
 */
void
ac_constraint_comment(Oid conOid)
{
	Form_pg_constraint	conForm;
	HeapTuple	conTup;

	conTup = SearchSysCache(CONSTROID,
							ObjectIdGetDatum(conOid),
							0, 0, 0);
	if (!HeapTupleIsValid(conTup))
		elog(ERROR, "cache lookup failed for constraint %u", conOid);

	conForm = (Form_pg_constraint) GETSTRUCT(conTup);
	if (!pg_class_ownercheck(conForm->conrelid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(conForm->conrelid));

	ReleaseSysCache(conTup);
}

/* ************************************************************
 *
 * Pg_conversion system catalog related access control stuffs
 *
 * ************************************************************/

/* Helper function */
static char *
get_conversion_name(Oid convOid)
{
	Form_pg_conversion	convForm;
	HeapTuple	convTup;
	char	   *convName = NULL;

	convTup = SearchSysCache(CONVOID,
							 ObjectIdGetDatum(convOid),
							 0, 0, 0);
	if (HeapTupleIsValid(convTup))
	{
		convForm = (Form_pg_conversion) GETSTRUCT(convTup);
		convName = pstrdup(NameStr(convForm->conname));

		ReleaseSysCache(convTup);
	}
	return convName;
}

static Oid
get_conversion_namespace(Oid convOid)
{
	HeapTuple	convTup;
	Oid			convNsp = InvalidOid;

	convTup = SearchSysCache(CONVOID,
							 ObjectIdGetDatum(convOid),
							 0, 0, 0);
	if (HeapTupleIsValid(convTup))
	{
		convNsp = ((Form_pg_conversion) GETSTRUCT(convTup))->connamespace;

		ReleaseSysCache(convTup);
	}
	return convNsp;
}

/*
 * ac_conversion_create
 *
 * It checks privilege to create a new conversion
 *
 * [Params]
 * convName : Name of the new conversion
 * convNsp  : OID of the namespace to be created on
 * funcOid  : OID of the conversion function
 */
void
ac_conversion_create(const char *convName, Oid convNsp, Oid funcOid)
{
	AclResult	aclresult;

	aclresult = pg_namespace_aclcheck(convNsp, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(convNsp));

	aclresult = pg_proc_aclcheck(funcOid, GetUserId(), ACL_EXECUTE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_PROC,
					   get_func_name(funcOid));
}

/*
 * ac_conversion_alter
 *
 * It checks privilege to alter a certain conversion
 *
 * [Params]
 * convOid  : OID of the conversion to be altered
 * newName  : New name of the conversion, if exist
 * newOwner : OID of the new conversion owner, if exist
 */
void
ac_conversion_alter(Oid convOid, const char *newName, Oid newOwner)
{
	Oid			convNsp = get_conversion_namespace(convOid);
	AclResult	aclresult;

	/* Must be owner for all the ALTER CONVERSION options */
	if (!pg_conversion_ownercheck(convOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CONVERSION,
					   get_conversion_name(convOid));

	/* Must have CREATE privilege on namespace on renaming */
	if (newName)
	{
		aclresult = pg_namespace_aclcheck(convNsp, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(convNsp));
	}

	/* Superusers can always do it */
	if (OidIsValid(newOwner) && !superuser())
	{
		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have CREATE privilege on namespace */
		aclresult = pg_namespace_aclcheck(convNsp, newOwner, ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(convNsp));
	}
}

/*
 * ac_conversion_drop
 *
 * It checks privilege to drop a certain conversion
 *
 * [Params]
 * convOid : OID of the target conversion
 * dacSkip:  True, if dac permission check should be bypassed
 */
void
ac_conversion_drop(Oid convOid, bool dacSkip)
{
	Oid		convNsp = get_conversion_namespace(convOid);

	if (!dacSkip &&
		!pg_conversion_ownercheck(convOid, GetUserId()) &&
		!pg_namespace_ownercheck(convNsp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CONVERSION,
					   get_conversion_name(convOid));
}

/*
 * ac_conversion_comment
 *
 * It checks privilege to comment on a certain conversion
 *
 * [Params]
 * convOid : OID of the conversion to be commented on
 */
void
ac_conversion_comment(Oid convOid)
{
	if (!pg_conversion_ownercheck(convOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CONVERSION,
					   get_conversion_name(convOid));
}

/* ************************************************************
 *
 * Pg_database system catalog related access control stuffs
 *
 * ************************************************************/

/* Helper function */
static bool
have_createdb_privilege(void)
{
	bool		result = false;
	HeapTuple	utup;

	/* Superusers can always do everything */
	if (superuser())
		return true;

	utup = SearchSysCache(AUTHOID,
						  ObjectIdGetDatum(GetUserId()),
						  0, 0, 0);
	if (HeapTupleIsValid(utup))
	{
		result = ((Form_pg_authid) GETSTRUCT(utup))->rolcreatedb;
		ReleaseSysCache(utup);
	}
	return result;
}

/*
 * ac_database_create
 *
 * It checks privileges to create a new database.
 *
 * [Params]
 * datName   : Name of the new database 
 * srcDatOid : OID of the source database
 * srcIsTemp : True, if the source database is template
 * datOwner  : OID of the new database owner
 * datTblspc : OID of the new default tablespace, if given
 */
void
ac_database_create(const char *datName, Oid srcDatOid, bool srcIsTemp,
				   Oid datOwner, Oid datTblspc)
{
	AclResult	aclresult;

	/*
	 * To create a database, must have createdb privilege and must be able to
	 * become the target role (this does not imply that the target role itself
	 * must have createdb privilege).  The latter provision guards against
	 * "giveaway" attacks.	Note that a superuser will always have both of
	 * these privileges a fortiori.
	 */
	if (!have_createdb_privilege())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to create database")));

	check_is_member_of_role(GetUserId(), datOwner);


	/*
	 * Permission check: to copy a DB that's not marked datistemplate, you
	 * must be superuser or the owner thereof.
	 */
	if (!srcIsTemp)
	{
		if (!pg_database_ownercheck(srcDatOid, GetUserId()))
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("permission denied to copy database \"%s\"",
							get_database_name(srcDatOid))));
	}

	/*
	 * Check permissions to use a certain tablespace as a default one
	 * on the new database
	 */
	if (OidIsValid(datTblspc))
	{
		aclresult = pg_tablespace_aclcheck(datTblspc, GetUserId(),
										   ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE,
						   get_tablespace_name(datTblspc));
	}
}

/*
 * ac_database_alter
 *
 * It checks privileges to alter a certain database.
 *
 * [Params]
 * datOid    : OID of the database to be altered
 * newName   : New name of the database, if exist
 * newTblspc : OID of the new default tablespace, if exist
 * newOwner  : OID of the new owner, if exist
 */
void
ac_database_alter(Oid datOid, const char *newName,
				  Oid newTblspc, Oid newOwner)
{
	AclResult	aclresult;

	/* Must be owner for all the ALTER DATABASE options */
	if (!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));

	/* Must have createdb right for renaming */
	if (newName)
	{
		if (!have_createdb_privilege())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("permission denied to rename database")));
	}

	/* Must have ACL_CREATE for the new default tablespace */
	if (OidIsValid(newTblspc))
	{
		aclresult = pg_tablespace_aclcheck(newTblspc, GetUserId(),
										   ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE,
						   get_tablespace_name(newTblspc));
	}

	if (OidIsValid(newOwner))
	{
		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/*
		 * must have createdb rights
		 *
		 * NOTE: This is different from other alter-owner checks in that the
		 * current user is checked for createdb privileges instead of the
		 * destination owner.  This is consistent with the CREATE case for
		 * databases.  Because superusers will always have this right, we need
		 * no special case for them.
		 */
		if (!have_createdb_privilege())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("permission denied to change owner of database")));
	}
}

/*
 * ac_database_drop
 *
 * It checks privileges to drop a certain database
 *
 * [Params]
 * datOid  : OID of the database to be dropped
 * dacSkip : True, if dac permission checks should be bypassed
 */
void
ac_database_drop(Oid datOid, bool dacSkip)
{
	if (!dacSkip &&
		!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));
}

/*
 * ac_database_grant
 *
 * It checks privileges to grant/revoke permissions on a certain database.
 *
 * [Params]
 * datOid   : OID of the target database for GRANT/REVOKE
 * grantor  : OID of the gractor role
 * goptions : Available AclMask available to grant others
 */
void
ac_database_grant(Oid datOid, Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		AclMode		whole_mask = ACL_ALL_RIGHTS_DATABASE;

		if (pg_database_aclmask(datOid, grantor,
								whole_mask | ACL_GRANT_OPTION_FOR(whole_mask),
								ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_DATABASE,
						   get_database_name(datOid));
	}
}

/*
 * ac_database_connect
 *
 * It checks privileges to connect on the database
 * If violated, it raises a FATAL error to disconnect soon.
 *
 * [Params]
 * datOid : OID of the database to be connected
 */
void
ac_database_connect(Oid datOid)
{
	if (pg_database_aclcheck(MyDatabaseId, GetUserId(),
							 ACL_CONNECT) != ACLCHECK_OK)
		ereport(FATAL,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied for database \"%s\"",
						get_database_name(datOid)),
				 errdetail("User does not have CONNECT privilege.")));
}

/*
 * ac_database_calculate_size
 *
 * It checks privileges to calculate size of a certain database
 *
 * [Params]
 * datOid : OID of the target database
 */
void
ac_database_calculate_size(Oid datOid)
{
	AclResult	aclresult;

	/* User must have connect privilege for target database */
	aclresult = pg_database_aclcheck(datOid, GetUserId(),
									 ACL_CONNECT);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_DATABASE,
					   get_database_name(datOid));
}

/*
 * ac_database_reindex
 *
 * It checks privileges to reindex tables within the database
 *
 * [Params]
 * datOid : OID of the database to be commented on
 */
void
ac_database_reindex(Oid datOid)
{
	if (!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));
}

/*
 * ac_database_comment
 *
 * It checks privilges to comment on the database
 *
 * [Params]
 * datOid : OID of the database to be commented
 */
void
ac_database_comment(Oid datOid)
{
	if (!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));
}

/* ************************************************************
 *
 * Pg_foreign_data_wrapper system catalog related access control stuffs
 *
 * ************************************************************/

/* Helper functions */
static char *
get_foreign_data_wrapper_name(Oid fdwOid)
{
	Form_pg_foreign_data_wrapper	fdwForm;
	HeapTuple	fdwTup;
	char	   *fdwName = NULL;

	fdwTup = SearchSysCache(FOREIGNDATAWRAPPEROID,
							ObjectIdGetDatum(fdwOid),
							0, 0, 0);
	if (HeapTupleIsValid(fdwTup))
	{
		fdwForm = (Form_pg_foreign_data_wrapper) GETSTRUCT(fdwTup);
		fdwName = pstrdup(NameStr(fdwForm->fdwname));

		ReleaseSysCache(fdwTup);
	}
	return fdwName;
}

/*
 * ac_foreign_data_wrapper_create
 *
 * It checks privilege to create a new foreign data wrapper
 *
 * [Params]
 * fdwName      : Name of the new foreign data wrapper
 * fdwValidator : OID of the validator function, if exist
 */
void
ac_foreign_data_wrapper_create(const char *fdwName, Oid fdwValidator)
{
	/* Must be super user */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
		errmsg("permission denied to create foreign-data wrapper \"%s\"",
			   fdwName),
		errhint("Must be superuser to create a foreign-data wrapper.")));
}

/*
 * ac_foreign_data_wrapper_alter
 *
 * It checks privilege to alter a certain foreign data wrapper
 *
 * [Params]
 * fdwOid       : OID of the target foreign data wrapper
 * newValidator : OID of the new validator function, if exist
 * newOwner     : OID of the new owner, if exist
 */
void
ac_foreign_data_wrapper_alter(Oid fdwOid, Oid newValidator, Oid newOwner)
{
	/* Must be super user */
	if (!superuser())
	{
		const char *actmsg
			= (OidIsValid(newOwner) ? "change owner of" : "alter");

		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to %s foreign-data wrapper \"%s\"",
						actmsg, get_foreign_data_wrapper_name(fdwOid)),
				 errhint("Must be superuser to %s a foreign-data wrapper.",
						 actmsg)));
	}

	if (OidIsValid(newOwner) && !superuser_arg(newOwner))
	{
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to change owner of foreign-data wrapper \"%s\"",
						get_foreign_data_wrapper_name(fdwOid)),
				 errhint("The owner of a foreign-data wrapper must be a superuser.")));
	}
}

/*
 * ac_foreign_data_wrapper_drop
 *
 * It checks privilege to drop a certain foreign data wrapper
 *
 * [Params]
 * fdwOid  : OID of the target foreign data wrapper
 * dacSkip : True, if dac permission check should be bypassed
 */
void
ac_foreign_data_wrapper_drop(Oid fdwOid, bool dacSkip)
{
	if (!dacSkip &&
		!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to drop foreign-data wrapper \"%s\"",
						get_foreign_data_wrapper_name(fdwOid)),
				 errhint("Must be superuser to drop a foreign-data wrapper.")));
}

/*
 * ac_foreign_data_wrapper_grant
 *
 * It checks privilege to grant/revoke permissions on a certain foreign
 * data wrapper
 *
 * [Params]
 * fdwOid   : OID of the target foreign data wrapper
 * grantor  : OID of the gractor database role
 * goptions : Available AclMask to grant others
 */
void
ac_foreign_data_wrapper_grant(Oid fdwOid, Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		AclMode		whole_mask = ACL_ALL_RIGHTS_FDW;

		whole_mask |= ACL_GRANT_OPTION_FOR(whole_mask);
		if (pg_foreign_data_wrapper_aclmask(fdwOid, grantor, whole_mask,
											ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_FDW,
						   get_foreign_data_wrapper_name(fdwOid));
	}
}

/* ************************************************************
 *
 * Pg_foreign_server system catalog related access control stuffs
 *
 * ************************************************************/

/* Helper functions */
static char *
get_foreign_server_name(Oid fsrvOid)
{
	Form_pg_foreign_server	fsrvForm;
	HeapTuple	fsrvTup;
	char	   *fsrvName = NULL;

	fsrvTup = SearchSysCache(FOREIGNSERVEROID,
							 ObjectIdGetDatum(fsrvOid),
							 0, 0, 0);
	if (HeapTupleIsValid(fsrvTup))
	{
		fsrvForm = (Form_pg_foreign_server) GETSTRUCT(fsrvTup);
		fsrvName = pstrdup(NameStr(fsrvForm->srvname));

		ReleaseSysCache(fsrvTup);
	}
	return fsrvName;
}

/*
 * ac_foreign_server_create
 *
 * It checks privilege to create a new foreign server
 *
 * [Params]
 * fsrvName  : Name of the new foreign server
 * fsrvOwner : OID of the foreign server owner
 * fdwOid    : OID of the foreign data wrapper used in the server
 */
void
ac_foreign_server_create(const char *fsrvName, Oid fsrvOwner, Oid fdwOid)
{
	AclResult	aclresult;

	aclresult = pg_foreign_data_wrapper_aclcheck(fdwOid, fsrvOwner, ACL_USAGE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_FDW,
					   get_foreign_data_wrapper_name(fdwOid));
}

/*
 * ac_foreign_server_alter
 *
 * It checks privilege to alter a certain foreign server
 *
 * [Params]
 * fsrvOid  : OID of the target foreign server
 * newOwner : OID of the new foreign server owner, if exist
 */
void
ac_foreign_server_alter(Oid fsrvOid, Oid newOwner)
{
	if (!pg_foreign_server_ownercheck(fsrvOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_FOREIGN_SERVER,
					   get_foreign_server_name(fsrvOid));

	/* Additional checks for change owner
	 * (superuser bypasses all the checks) */
	if (OidIsValid(newOwner) && !superuser())
	{
		Form_pg_foreign_server	fsrvForm;
		HeapTuple		fsrvTup;
		AclResult		aclresult;

		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have USAGE privilege on foreign-data wrapper */
		fsrvTup = SearchSysCacheCopy(FOREIGNSERVEROID,
									 ObjectIdGetDatum(fsrvOid),
									 0, 0, 0);
		if (!HeapTupleIsValid(fsrvTup))
			elog(ERROR, "cache lookup failed for foreign server: %u", fsrvOid);

		fsrvForm = (Form_pg_foreign_server) GETSTRUCT(fsrvTup);

		aclresult = pg_foreign_data_wrapper_aclcheck(fsrvForm->srvfdw,
													 newOwner, ACL_USAGE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_FDW,
						   get_foreign_data_wrapper_name(fsrvForm->srvfdw));
	}
}

/*
 * ac_foreign_server_drop
 *
 * It checks privilege to drop a certain foreign server.
 *
 * [Params]
 * fsrvOid : OID of the target foreign server
 * dacSkip : True, if dac permission check should be bypassed
 */
void
ac_foreign_server_drop(Oid fsrvOid, bool dacSkip)
{
	/* Only allow DROP if the server is owned by the user. */
	if (!dacSkip &&
		!pg_foreign_server_ownercheck(fsrvOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_FOREIGN_SERVER,
					   get_foreign_server_name(fsrvOid));
}

/*
 * ac_foreign_server_grant
 *
 * It checks privilege to grant/revoke permissions on a certain
 * foreign server
 *
 * [Params]
 * fsrvOid  : OID of the target foreign server
 * grantor  : OID of the gractor database role
 * goptions : Available AclMask to grant others
 */
void
ac_foreign_server_grant(Oid fsrvOid, Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		AclMode		whole_mask = ACL_ALL_RIGHTS_FOREIGN_SERVER;

		whole_mask |= ACL_GRANT_OPTION_FOR(whole_mask);
		if (pg_foreign_server_aclmask(fsrvOid, grantor, whole_mask,
									  ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_FOREIGN_SERVER,
						   get_foreign_server_name(fsrvOid));
	}
}

/* ************************************************************
 *
 * Pg_language system catalog related access control stuffs
 *
 * ************************************************************/

/* Helper functions */
static char *
get_lang_name(Oid langOid)
{
	Form_pg_language	langForm;
	HeapTuple	langTup;
	char	   *langName = NULL;

	langTup = SearchSysCache(LANGOID,
							 ObjectIdGetDatum(langOid),
							 0, 0, 0);
	if (HeapTupleIsValid(langTup))
	{
		langForm = (Form_pg_language) GETSTRUCT(langTup);
		langName = pstrdup(NameStr(langForm->lanname));

		ReleaseSysCache(langTup);
	}
	return langName;
}

/*
 * ac_language_create
 *
 * It checks privilege to create a new procedural language.
 *
 * [Params]
 * langName     : Name of the new procedural language
 * IsTemplate   : True, if the procedural language is based on a template
 * plTrusted    : A copy from PLTemplate->tmpltrusted, if exist
 * plDbaCreate  : A copy from PLTemplate->tmpldbacreate, if exist
 * handlerOid   : OID of the handler function
 * validatorOid : OID of the validator function
 */
void
ac_language_create(const char *langName, bool IsTemplate,
				   bool plTrusted, bool plDbaCreate,
				   Oid handlerOid, Oid validatorOid)
{
	if (!superuser())
	{
		if (!IsTemplate)
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("must be superuser to create "
							"custom procedural language")));

		if (!plDbaCreate)
			ereport(ERROR,
                    (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                     errmsg("must be superuser to create "
							"procedural language \"%s\"", langName)));

		if (!pg_database_ownercheck(MyDatabaseId, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
						   get_database_name(MyDatabaseId));
	}
}

/*
 * ac_language_alter
 *
 * It checks privilege to alter a certain procedural language
 *
 * [Params]
 * langOid  : OID of the procedural language to be altered
 * newName  : New name of the procedural language, if exist
 * newOwner : New owner of the procedural language, if exist
 */
void
ac_language_alter(Oid langOid, const char *newName, Oid newOwner)
{
	/* must be owner of PL */
	if (!pg_language_ownercheck(langOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_LANGUAGE,
					   get_lang_name(langOid));

	/* Must be able to become new owner, when owner changes  */
	if (OidIsValid(newOwner))
		check_is_member_of_role(GetUserId(), newOwner);
}

/*
 * ac_langugae_drop
 *
 * It checks privilege to drop a certain procedural language
 *
 * [Params]
 * langOid : OID of the procedural language to be dropped
 * dacSkip : True, if dac permission check should be bypassed
 */
void
ac_language_drop(Oid langOid, bool dacSkip)
{
	if (!dacSkip &&
		!pg_language_ownercheck(langOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_LANGUAGE,
					   get_lang_name(langOid));
}

/*
 * ac_language_grant
 *
 * It checks privilege to grant/revoke permissions on procedural language
 *
 * [Params]
 * langOid  : OID of the target procedural language
 * grantor  : OID of the gractor database role
 * goptions : Available AclMask to grant others
 */
void
ac_language_grant(Oid langOid, Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		AclMode		whole_mask = ACL_ALL_RIGHTS_LANGUAGE;

		if (pg_language_aclmask(langOid, grantor,
								whole_mask | ACL_GRANT_OPTION_FOR(whole_mask),
								ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_LANGUAGE,
						   get_lang_name(langOid));
	}
}

/*
 * ac_language_comment
 *
 * It checks privilege to comment on a certain procedural language
 *
 * [Params]
 * langOid : OID of the procedural language
 */
void
ac_language_comment(Oid langOid)
{
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to comment on procedural language")));
}

/* ************************************************************
 *
 * Pg_namespace system catalog related access control stuffs
 *
 * ************************************************************/

/*
 * ac_schema_create
 *
 * It checks privileges to create a new schema object
 *
 * [Params]
 * nspName  : Name of the new schema object
 * nspOwner : OID of the new schema owner
 * isTemp   : True, if the schema is temporay
 */
void
ac_schema_create(const char *nspName, Oid nspOwner, bool isTemp)
{
	AclResult	aclresult;

	/*
	 * To create a schema, must have (temporary) schema-create privilege
	 * on the current database and must be able to become the target role
	 * (this does not imply that the target role itself must have create-schema
	 * privilege), if not temporary schema.
	 * The latter provision guards against "giveaway" attacks.  Note that a
	 * superuser will always have both of these privileges a fortiori.
	 */
	aclresult = pg_database_aclcheck(MyDatabaseId, GetUserId(),
									 isTemp ? ACL_CREATE_TEMP : ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_DATABASE,
					   get_database_name(MyDatabaseId));

	if (!isTemp)
		check_is_member_of_role(GetUserId(), nspOwner);
}

/*
 * ac_schema_alter
 *
 * It checks privileges to alter a certain schema object
 *
 * [Params]
 * nspOid   : OID of the namespace to be altered
 * newName  : New name of the namespace, if exist
 * newOwner : OID of the new namespace owner, if exist
 */
void
ac_schema_alter(Oid nspOid, const char *newName, Oid newOwner)
{
	AclResult	aclresult;

	/* must be owner for all the ALTER SCHEMA options */
	if (!pg_namespace_ownercheck(nspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));

	/* must have CREATE privilege on database to rename */
	if (newName)
	{
		aclresult = pg_database_aclcheck(MyDatabaseId, GetUserId(),
										 ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_DATABASE,
						   get_database_name(MyDatabaseId));
	}

	if (OidIsValid(newOwner))
	{
		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);
	}
}

/*
 * ac_schema_drop
 *
 * It checks privileges to drop a certain schema object
 *
 * [Params]
 * nspOid  : OID of the namespace to be dropped
 * dacSkip : True, if dac permission checks should be bypassed
 */
void
ac_schema_drop(Oid nspOid, bool dacSkip)
{
	if (!dacSkip &&
		!pg_namespace_ownercheck(nspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));
}

/*
 * ac_schema_grant
 *
 * It checks privileges to grant/revoke permissions on a certain namespace
 *
 * [Params]
 * nspOid   : OID of the target schema for GRANT/REVOKE
 * grantor  : OID of the gractor role
 * goptions : Available AclMask available to grant others
 */
void
ac_schema_grant(Oid nspOid, Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		AclMode		whole_mask = ACL_ALL_RIGHTS_NAMESPACE;

		if (pg_namespace_aclmask(nspOid, grantor, 
								 whole_mask | ACL_GRANT_OPTION_FOR(whole_mask),
								 ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_DATABASE,
						   get_namespace_name(nspOid));
	}
}

/*
 * ac_schema_search
 *
 * It checks privileges to search a certain schema
 *
 * [Params]
 * nspOid : OID of the target schema
 * abort  : True, if caller want to raise an error, if violated
 */
bool
ac_schema_search(Oid nspOid, bool abort)
{
	AclResult	aclresult;

	aclresult = pg_namespace_aclcheck(nspOid, GetUserId(),
									  ACL_USAGE);
	if (aclresult != ACLCHECK_OK)
	{
		if (abort)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(nspOid));
		return false;
	}

	return true;
}

/*
 * ac_schema_comment
 *
 * It checks privileges to comment on a certain schema
 *
 * [Params]
 * nspOid : OID of the schema to be commented on
 */
void
ac_schema_comment(Oid nspOid)
{
	if (!pg_namespace_ownercheck(nspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));
}

/* ************************************************************
 *
 * Pg_opclass system catalog related access control stuffs
 *
 * ************************************************************/

/* Helper functions */
static char *
get_opclass_name(Oid opcOid)
{
	Form_pg_opclass		opcForm;
	HeapTuple	opcTup;
	char	   *opcName = NULL;

	opcTup = SearchSysCache(CLAOID,
							ObjectIdGetDatum(opcOid),
							0, 0, 0);
	if (HeapTupleIsValid(opcTup))
	{
		opcForm = (Form_pg_opclass) GETSTRUCT(opcTup);
		opcName = pstrdup(NameStr(opcForm->opcname));

		ReleaseSysCache(opcTup);
	}
	return opcName;
}

static Oid
get_opclass_namespace(Oid opcOid)
{
	HeapTuple	opcTup;
	Oid			opcNsp;

	opcTup = SearchSysCache(CLAOID,
							ObjectIdGetDatum(opcOid),
							0, 0, 0);
	if (!HeapTupleIsValid(opcTup))
		elog(ERROR, "cache lookup failed for opclass %u", opcOid);

	opcNsp = ((Form_pg_opclass) GETSTRUCT(opcTup))->opcnamespace;

	ReleaseSysCache(opcTup);

	return opcNsp;
}

/*
 * ac_opclass_create
 *
 * It checks privilege to create a new operator class
 *
 * [Params]
 * opcName  : Name of the new operator class
 * opcNsp   : OID of the namespace to be used
 * typOid   : OID of the type to be set up
 * opfOid   : OID of the corresponding operator family, 
 * operList : List of operator OID
 * procList : List of procedure OID
 * stgOid   : OID of the type stored used as a storage
 */
void
ac_opclass_create(const char *opcName,
				  Oid opcNsp, Oid typOid, Oid opfOid,
				  List *operList, List *procList, Oid stgOid)
{
	AclResult	aclresult;
#ifdef NOT_USED
	ListCell   *l;
#endif

	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(opcNsp, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(opcNsp));

	/* XXX Should we make any privilege check against the AM? */

	/*
	 * The question of appropriate permissions for CREATE OPERATOR CLASS is
	 * interesting.  Creating an opclass is tantamount to granting public
	 * execute access on the functions involved, since the index machinery
	 * generally does not check access permission before using the functions.
	 * A minimum expectation therefore is that the caller have execute
	 * privilege with grant option.  Since we don't have a way to make the
	 * opclass go away if the grant option is revoked, we choose instead to
	 * require ownership of the functions.  It's also not entirely clear what
	 * permissions should be required on the datatype, but ownership seems
	 * like a safe choice.
	 *
	 * Currently, we require superuser privileges to create an opclass. This
	 * seems necessary because we have no way to validate that the offered set
	 * of operators and functions are consistent with the AM's expectations.
	 * It would be nice to provide such a check someday, if it can be done
	 * without solving the halting problem :-(
	 *
	 * XXX re-enable NOT_USED code sections below if you remove this test.
	 */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to create an operator class")));

#ifdef NOT_USED
	/*
	 * XXX this is unnecessary given the superuser check above
	 * Check we have ownership of the datatype
	 */
	if (!pg_type_ownercheck(typOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TYPE,
					   format_type_be(typeoid));

	/*
	 * XXX given the superuser check above, there's no need
	 * for an ownership check to operator family here
	 */
	if (!pg_opfamily_ownercheck(opfOid, GetUserId())
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPFAMILY,
					   get_opfamily_name(opfOid));
#endif

#ifdef NOT_USED
	/* XXX this is unnecessary given the superuser check above */
	foreach(l, operList)
	{
		Oid		operOid = lfirst_oid(l);
		Oid		funcOid

		/* Caller must own operator and its underlying function */
		if (!pg_oper_ownercheck(operOid, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
						   get_opname(operOid));
		funcOid = get_opcode(operOid);
		if (!pg_proc_ownercheck(funcOid, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
						   get_func_name(funcOid));
	}
#endif

#ifdef NOT_USED
	/* XXX this is unnecessary given the superuser check above */
	foreach(l, procList)
	{
		Oid		funcOid = lfirst_oid(l);

		/* Caller must own function */
		if (!pg_proc_ownercheck(funcOid, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
						   get_func_name(funcOid));
	}
#endif

#ifdef NOT_USED
	/* XXX this is unnecessary given the superuser check above */
	if (OidIsValid(stgOid))
	{
		/* Check we have ownership of the datatype */
		if (!pg_type_ownercheck(stgOid, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TYPE,
						   format_type_be(stgOid));
	}
#endif
}

/*
 * ac_opclass_alter
 *
 * It checks privilege to alter a certain operator class
 *
 * [Params]
 * opcOid   : OID of the operator class to be altered
 * newName  : New name of the operator class, if exist
 * newOwner : OID of new owner of the operator class, if exist
 */
void
ac_opclass_alter(Oid opcOid, const char *newName, Oid newOwner)
{
	Oid			opcNsp = get_opclass_namespace(opcOid);
	AclResult	aclresult;

	/* Must be owner for all the ALTER OPERATOR CLASS option */
	if (!pg_opclass_ownercheck(opcOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPCLASS,
					   get_opclass_name(opcOid));

	if (newName)
	{
		/* must have CREATE privilege on namespace */
		aclresult = pg_namespace_aclcheck(opcNsp, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(opcNsp));
	}

	if (OidIsValid(newOwner) && !superuser())
	{
		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have CREATE privilege on namespace */
		aclresult = pg_namespace_aclcheck(opcNsp, newOwner, ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(opcNsp));
	}
}

/*
 * ac_opclass_drop
 *
 * It checks privilege to drop a certain operator class
 *
 * [Params]
 * opcOid  : OID of the operator class to be dropped
 * dacSkip : True, if dac permission check should be bypassed
 */
void
ac_opclass_drop(Oid opcOid, bool dacSkip)
{
	Oid		opcNsp = get_opclass_namespace(opcOid);

	if (!dacSkip &&
		!pg_opclass_ownercheck(opcOid, GetUserId()) &&
		!pg_namespace_ownercheck(opcNsp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPCLASS,
					   get_opclass_name(opcOid));
}

/*
 * ac_opclass_comment
 *
 * It checks privilege to comment on a certain operator class
 *
 * [Params]
 * opcOid  : OID of the operator class to be commented on
 */
void
ac_opclass_comment(Oid opcOid)
{
	if (!pg_opclass_ownercheck(opcOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPCLASS,
					   get_opclass_name(opcOid));
}

/* ************************************************************
 *
 * Pg_operator system catalog related access control stuffs
 *
 * ************************************************************/

/* Helper function */
static Oid
get_operator_namespace(Oid operOid)
{
	Form_pg_operator	operForm;
	HeapTuple	operTup;
	Oid			operNsp;

	operTup = SearchSysCache(OPEROID,
							 ObjectIdGetDatum(operOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(operTup))
		elog(ERROR, "cache lookup failed for operator %u", operOid);

	operForm = (Form_pg_operator) GETSTRUCT(operTup);
	operNsp = operForm->oprnamespace;

	ReleaseSysCache(operTup);

	return operNsp;
}

/*
 * ac_operator_create
 *
 * It checks privilege to create a new operator
 *
 * [Params]
 * oprName : Name of the new operator
 * oprNsp  : OID of the namespace to be used for the operator
 * operOid : OID of the shell operator to be replaced, if exist
 * commOp  : OID of the commutator operator, if exist 
 * negaOp  : OID of the nagator operator, if exist
 * codeFn  : OID of the function to implement the operator, if exist
 * restFn  : OID of the restriction estimator function, if exist
 * joinFn  : OID of the join estimator function, if exist
 */
void
ac_operator_create(const char *oprName,
				   Oid oprNsp, Oid operOid,
				   Oid commOp, Oid negaOp,
				   Oid codeFn, Oid restFn, Oid joinFn)
{
	AclResult	aclresult;

	/* ACL_CREATE on the namespace is always required */
	aclresult = pg_namespace_aclcheck(oprNsp, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(oprNsp));

	/*
	 * When we try to replace an existing operator, it is
	 * necessary to own the operator to be replaced.
	 */
	if (OidIsValid(operOid) &&
		!pg_oper_ownercheck(operOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
					   get_opname(operOid));

	if (OidIsValid(commOp) &&
		!pg_oper_ownercheck(commOp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
					   get_opname(commOp));

	if (OidIsValid(negaOp) &&
		!pg_oper_ownercheck(negaOp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
					   get_opname(negaOp));

	if (OidIsValid(codeFn))
	{
		/*
		 * We require EXECUTE rights for the function.	This isn't strictly
		 * necessary, since EXECUTE will be checked at any attempted use of
		 * the operator, but it seems like a good idea anyway.
		 */
		aclresult = pg_proc_aclcheck(codeFn, GetUserId(), ACL_EXECUTE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(codeFn));
	}

	if (OidIsValid(restFn))
	{
		/* Require EXECUTE rights for the estimator */
		aclresult = pg_proc_aclcheck(restFn, GetUserId(), ACL_EXECUTE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(restFn));
	}

	if (OidIsValid(joinFn))
	{
		/* Require EXECUTE rights for the estimator */
		aclresult = pg_proc_aclcheck(joinFn, GetUserId(), ACL_EXECUTE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(joinFn));
	}
}

/*
 * ac_operator_alter
 *
 * It checks privilege to alter a certain operator.
 *
 * [Params]
 * operOid  : OID of the operator to be altered
 * newOwner : OID of the new operator owner, if exist
 */
void
ac_operator_alter(Oid operOid, Oid newOwner)
{
	AclResult	aclresult;

	/* Must be owner of the operator */
	if (!pg_oper_ownercheck(operOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
					   get_opname(operOid));

	if (OidIsValid(newOwner) && !superuser())
	{
		Oid		operNsp = get_operator_namespace(operOid);

		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have CREATE privilege on the namespace */
		aclresult = pg_namespace_aclcheck(operNsp, newOwner, ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(operNsp));
	}
}

/*
 * ac_operator_drop
 *
 * It checks privilege to drop a certain operator
 *
 * [Params]
 * operOid : OID of the operator to be dropped
 * dacSkip : True, if dac permission check should be bypassed
 */
void
ac_operator_drop(Oid operOid, bool dacSkip)
{
	Oid			operNsp = get_operator_namespace(operOid);

	/* Must be owner of the operator or its namespace */
	if (!dacSkip &&
		!pg_oper_ownercheck(operOid, GetUserId()) &&
		!pg_namespace_ownercheck(operNsp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
					   get_opname(operOid));
}

/*
 * ac_operator_comment
 *
 * It checks privilege to comment on 
 *
 * [Params]
 * operOid: OID of the operator to be commented on
 */
void
ac_operator_comment(Oid operOid)
{
	if (!pg_oper_ownercheck(operOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
					   get_opname(operOid));
}

/* ************************************************************
 *
 * Pg_opfamily system catalog related access control stuffs
 *
 * ************************************************************/

/* Helper function */
static char *
get_opfamily_name(Oid opfOid)
{
	Form_pg_opfamily	opfForm;
	HeapTuple	opfTup;
	char	   *opfName = NULL;

	opfTup = SearchSysCache(OPFAMILYOID,
							ObjectIdGetDatum(opfOid),
							0, 0, 0);
	if (HeapTupleIsValid(opfTup))
	{
		opfForm = (Form_pg_opfamily) GETSTRUCT(opfTup);
		opfName = pstrdup(NameStr(opfForm->opfname));

		ReleaseSysCache(opfTup);
	}
	return opfName;
}

static Oid
get_opfamily_namespace(Oid opfOid)
{
	HeapTuple	opfTup;
	Oid			opfNsp;

	opfTup = SearchSysCache(OPFAMILYOID,
							ObjectIdGetDatum(opfOid),
							0, 0, 0);
	if (!HeapTupleIsValid(opfTup))
		elog(ERROR, "cache lookup failed for opfamily %u", opfOid);

	opfNsp = ((Form_pg_opfamily) GETSTRUCT(opfTup))->opfnamespace;

	ReleaseSysCache(opfTup);

	return opfNsp;
}

/*
 * ac_opfamily_create
 *
 * It checks privilege to create a new operator family
 *
 * [Params]
 * opfName : New name of the operator family
 * opfNsp  : OID of the namespace to be used
 */
void
ac_opfamily_create(const char *opfName, Oid opfNsp, Oid amOid)
{
	AclResult	aclresult;

	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(opfNsp, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(opfNsp));

	/* XXX Should we make any privilege check against the AM? */

	/*
	 * Currently, we require superuser privileges to create an opfamily. See
	 * comments in DefineOpClass.
	 *
	 * XXX re-enable NOT_USED code sections below if you remove this test.
	 */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to create an operator family")));
}

/*
 * ac_opfamily_alter
 *
 * It checks privilege to alter a certain operator family
 *
 * [Params]
 * opfOid   : OID of the operator family 
 * newName  : New name of the operator family, if exist
 * newOwner : New owner of the operator family, if exist
 */
void
ac_opfamily_alter(Oid opfOid, const char *newName, Oid newOwner)
{
	if (!newName && !OidIsValid(newOwner))
	{
		/*
		 * Currently, we require superuser privileges to alter an opfamily.
		 *
		 * XXX re-enable NOT_USED code sections below if you remove this test.
		 */
		if (!superuser())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("must be superuser to alter an operator family")));
	}
	else
	{
		Oid			opfNsp = get_opfamily_namespace(opfOid);
		AclResult	aclresult;

		/* Must be owner for RENAME and OWNER TO */
		if (!pg_opfamily_ownercheck(opfOid, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPFAMILY,
						   get_opfamily_name(opfOid));

		if (newName)
		{
			/* must have CREATE privilege on namespace */
			aclresult = pg_namespace_aclcheck(opfNsp, GetUserId(), ACL_CREATE);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
							   get_namespace_name(opfNsp));
		}

		if (OidIsValid(newOwner) && !superuser())
		{
			/* Must be able to become new owner */
			check_is_member_of_role(GetUserId(), newOwner);

			/* New owner must have CREATE privilege on namespace */
			aclresult = pg_namespace_aclcheck(opfNsp, newOwner, ACL_CREATE);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
							   get_namespace_name(opfNsp));
		}
	}
}

/*
 * ac_opfamily_drop
 *
 * It checks privilege to drop a certain operator family
 *
 * [Params]
 * opfOid  : OID of the operator family to be dropped
 * dacSkip : True, if dac permission check should by bypassed
 */
void
ac_opfamily_drop(Oid opfOid, bool dacSkip)
{
	Oid		opfNsp = get_opfamily_namespace(opfOid);

	/* Must be owner of opfamily or its namespace */
	if (!pg_opfamily_ownercheck(opfOid, GetUserId()) &&
		!pg_namespace_ownercheck(opfNsp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPFAMILY,
					   get_opfamily_name(opfOid));
}

/*
 * ac_opfamily_comment
 *
 * It checks privilege to comment on a certain operator family
 *
 * [Params]
 * opfOid : OID of the operator family to be commented
 */
void
ac_opfamily_comment(Oid opfOid)
{
	if (!pg_opfamily_ownercheck(opfOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPFAMILY,
					   get_opfamily_name(opfOid));
}

/*
 * ac_opfamily_add_oper
 *
 * It checks privilege to add a certain operator to the given
 * operator family.
 *
 * [Params]
 * opfOid  : OID of the target operator family
 * operOid : OID of the given operator
 */
void
ac_opfamily_add_oper(Oid opfOid, Oid operOid)
{
#ifdef NOT_USED
	Oid		funcOid;

	/* XXX this is unnecessary given the superuser check above */
	/* Caller must own operator and its underlying function */
	if (!pg_oper_ownercheck(itemOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
					   get_opname(itemOid));

	funcOid = get_opcode(itemOid);
	if (!pg_proc_ownercheck(funcOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(funcOid));
#endif
}

/*
 * ac_opfamily_add_proc
 *
 * It checks privilege to add a certain procedure to the given
 * operator family.
 *
 * [Params]
 * opfOid  : OID of the target operator family
 * procOid : OID of the given procedure
 */
void
ac_opfamily_add_proc(Oid opfOid, Oid procOid)
{
#ifdef NOT_USED
	/* XXX this is unnecessary given the superuser check above */
	/* Caller must own function */
	if (!pg_proc_ownercheck(itemOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(itemOid));
#endif
}

/* ************************************************************
 *
 * Pg_proc system catalog related access control stuffs
 *
 * ************************************************************/

/*
 * ac_proc_create
 *
 * It checks privilege to create a new function
 *
 * [Params]
 * proName : Name of the new function
 * proOid  : OID of the procedure to be replaced, if exist
 * proNsp  : OID of the namespace for the new function
 * langOid : OID of the procedural language for the new function
 */
void
ac_proc_create(const char *proName, Oid proOid, Oid proNsp, Oid langOid)
{
	AclResult			aclresult;
	Form_pg_language	langForm;
	HeapTuple			langTup;
	bool				langTrusted;

	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(proNsp, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(proNsp));

	/* Check permission to use language */
	langTup = SearchSysCache(LANGOID,
							 ObjectIdGetDatum(langOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(langTup))
		elog(ERROR, "cache lookup failed for language %u", langOid);

	langForm = (Form_pg_language) GETSTRUCT(langTup);
	langTrusted = langForm->lanpltrusted;

	if (langTrusted)
	{
		/* if trusted language, need USAGE privilege */
		aclresult = pg_language_aclcheck(langOid, GetUserId(), ACL_USAGE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_LANGUAGE,
						   NameStr(langForm->lanname));
	}
	else
	{
		/* if untrusted language, must be superuser */
		if (!superuser())
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_LANGUAGE,
						   NameStr(langForm->lanname));
	}
	ReleaseSysCache(langTup);

	/* Need ownership to replace an existing function */
	if (OidIsValid(proOid) &&
		!pg_proc_ownercheck(proOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(proOid));
}

/*
 * ac_aggregate_create
 *
 * It checks privilege to create a new aggregate function
 *
 * [Params]
 * aggName : Name of the new aggregate function
 * proNsp  : OID of the namespace for the new aggregate function
 * transfn : OID of the trans function for the aggregate
 * finalfn : OID of the final function for the aggregate, if exist
 */
void
ac_aggregate_create(const char *aggName, Oid proNsp,
					Oid transfn, Oid finalfn)
{
	AclResult	aclresult;

	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(proNsp, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(proNsp));

	/* Check aggregate creator has permission to call the trans function */
	Assert(OidIsValid(transfn));
	aclresult = pg_proc_aclcheck(transfn, GetUserId(), ACL_EXECUTE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(transfn));

	/* Check aggregate creator has permission to call the final function */
	if (OidIsValid(finalfn))
	{
		aclresult = pg_proc_aclcheck(finalfn, GetUserId(), ACL_EXECUTE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(finalfn));
	}
}

/*
 * ac_proc_alter
 *
 * It checks privilege to alter a certain function
 *
 * [Params]
 * proOid    : OID of the function to be altered
 * newName   : New name of the function, if given
 * newNspOid : OID of the new namespace, if given
 * newOwner  : OID of the new function owner, if given
 */
void
ac_proc_alter(Oid proOid, const char *newName, Oid newNspOid, Oid newOwner)
{
	AclResult	aclresult;
	Oid			curNspOid;

	/* Must be owner for all the ALTER FUNCTION options */
	if (!pg_proc_ownercheck(proOid, GetUserId()))
        aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(proOid));

	/* must have CREATE privilege on namespace, to rename it */
	if (newName)
	{
		curNspOid = get_func_namespace(proOid);

		aclresult = pg_namespace_aclcheck(curNspOid, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(curNspOid));
	}

	/* must have CREATE privilege on the new namespace, to change it */
	if (OidIsValid(newNspOid))
	{
		aclresult = pg_namespace_aclcheck(newNspOid, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(newNspOid));
	}

	/*
	 * Must be able to become new owner, and he must have CREATE privilege
	 * on the namespace
	 */
	if (OidIsValid(newOwner))
	{
		/* Must be owner of the existing object */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have CREATE privilege on namespace */
		curNspOid = get_func_namespace(proOid);

		aclresult = pg_namespace_aclcheck(curNspOid, newOwner, ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(curNspOid));
	}
}

/*
 * ac_proc_drop
 *
 * It checks privilege to drop a certain function.
 *
 * [Params]
 * proOid  : OID of the function to be dropped
 * dacSkip : True, if dac permission check should be bypassed
 */
void
ac_proc_drop(Oid proOid, bool cascade)
{
	Oid		proNsp = get_func_namespace(proOid);

	if (!cascade &&
		!pg_proc_ownercheck(proOid, GetUserId()) &&
		!pg_namespace_ownercheck(proNsp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(proOid));
}

/*
 * ac_proc_grant
 *
 * It checks privileges to grant/revoke permissions on a certain function
 *
 * [Params]
 * proOid   : OID of the target function for GRANT/REVOKE
 * grantor  : OID of the gractor role
 * goptions : Available AclMask available to grant others
 */
void
ac_proc_grant(Oid proOid, Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		AclMode		whole_mask = ACL_ALL_RIGHTS_FUNCTION;

		if (pg_proc_aclmask(proOid, grantor,
							whole_mask | ACL_GRANT_OPTION_FOR(whole_mask),
							ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_DATABASE,
						   get_func_name(proOid));
	}
}

/*
 * ac_proc_comment
 *
 * It checks privilege to comment on the function
 *
 * [Params]
 * proOid : OID of the function to be commented
 */
void
ac_proc_comment(Oid proOid)
{
	if (!pg_proc_ownercheck(proOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(proOid));
}

/*
 * ac_proc_execute
 *
 * It checks privilege to execute a certain function.
 *
 * Note that it should be checked on the function runtime.
 * Some of DDL statements requires ACL_EXECUTE on creation time, such as
 * CreateConversionCommand(), however, these are individually checked on
 * the ac_xxx_create() hook.
 *
 * [Params]
 * proOID  : OID of the function to be executed
 * roleOid : OID of the database role to be evaluated
 */
void
ac_proc_execute(Oid proOid, Oid roleOid)
{
	AclResult	aclresult;

	aclresult = pg_proc_aclcheck(proOid, roleOid, ACL_EXECUTE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(proOid));
}

/*
 * ac_proc_hint_inlined
 *
 * It provides a hint for the optimizer whether the given SQL function
 * can be inlined from the viewpoint of access controls.
 * Because we have no chance to apply execution permission checks on
 * the inlined functions, the function must be executable.
 *
 * [Params]
 * proOid : OID of the function tried to be inlined
 */
bool
ac_proc_hint_inline(Oid proOid)
{
	if (pg_proc_aclcheck(proOid, GetUserId(), ACL_EXECUTE) != ACLCHECK_OK)
		return false;

	return true;
}

/* ************************************************************
 *
 * Pg_rewrite system catalog related access control stuffs
 *
 * ************************************************************/

/*
 * ac_rule_create
 *
 * It checks privilege to create a new query rewrite rule.
 *
 * [Params]
 * relOid   : OID of the relation to be applied on
 * ruleName : Name of the query rewrite rule
 */
void
ac_rule_create(Oid relOid, const char *ruleName)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_rule_drop
 *
 * It checks privilege to drop a certain query rewrite rule
 *
 * [Params]
 * relOid   : OID of the relation to be applied on
 * ruleName : Name of the query rewrite rule
 * dacSkip  : True, if dac permission checks should be bypassed
 */
void
ac_rule_drop(Oid relOid, const char *ruleName, bool dacSkip)
{
	if (!dacSkip &&
		!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/* Helper function to call ac_rule_drop */
static void
ac_rule_drop_by_oid(Oid ruleOid, bool dacSkip)
{
	Form_pg_rewrite	ruleForm;
	Relation		ruleRel;
	ScanKeyData		skey;
	SysScanDesc		sscan;
	HeapTuple		ruleTup;

	ruleRel = heap_open(RewriteRelationId, AccessShareLock);

	ScanKeyInit(&skey,
				ObjectIdAttributeNumber,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(ruleOid));
	sscan = systable_beginscan(ruleRel, RewriteOidIndexId, true,
							   SnapshotNow, 1, &skey);
	ruleTup = systable_getnext(sscan);
	if (!HeapTupleIsValid(ruleTup))
		elog(ERROR, "could not find tuple for rule %u", ruleOid);

	ruleForm = (Form_pg_rewrite) GETSTRUCT(ruleTup);

	ac_rule_drop(ruleForm->ev_class, NameStr(ruleForm->rulename), dacSkip);

	systable_endscan(sscan);

	heap_close(ruleRel, AccessShareLock);
}

/*
 * ac_rule_comment
 *
 * It checks privilege to comment on a certain query rewrite rule
 *
 * [Params]
 * relOid   : OID of the relation to be applied on
 * ruleName : Name of the query rewrite rule
 */
void
ac_rule_comment(Oid relOid, const char *ruleName)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_rule_toggle
 *
 * It checks privilege to enable/disable a certain query rewrite rule
 *
 * [Params]
 * relOid    : OID of the relation to be applied on
 * ruleName  : Name of the query rewrite rule
 * fire_when : One of the RULE_FIRES_* or RULE_DISABLED
 */
void
ac_rule_toggle(Oid relOid, const char *ruleName, char fire_when)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/* ************************************************************
 *
 * Pg_tablespace system catalog related access control stuffs
 *
 * ************************************************************/

/*
 * ac_tablespace_create
 *
 * It checks privileges to create a new tablespace
 *
 * [Params]
 * tblspcName : Name of the new tablespace
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
 * tblspcOid : OID of the tablespace to be altered
 * newName   : New name of the tablespace, if exist
 * newOwner  : OID of the new tablespace owner, if exist
 */
void
ac_tablespace_alter(Oid tblspcOid, const char *newName, Oid newOwner)
{
	/* Must be owner for all the ALTER TABLESPACE options */
	if (!pg_tablespace_ownercheck(tblspcOid, GetUserId()))
		aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_TABLESPACE,
					   get_tablespace_name(tblspcOid));

	if (OidIsValid(newOwner))
	{
		/* Must be able to become new owner */
        check_is_member_of_role(GetUserId(), newOwner);
	}
}

/*
 * ac_tablespace_drop
 *
 * It checks privileges to drop a certain tablespace
 *
 * [Params]
 * tblspcOid : OID of the tablespace to be dropped
 * dacSkip   : True, if dac permission check should be bypassed
 */
void
ac_tablespace_drop(Oid tblspcOid, bool dacSkip)
{
	/* Must be tablespace owner */
	if (!dacSkip &&
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
 * tblspcOid  : OID of the target tablespace for GRANT/REVOKE
 * grantor    : OID of the gractor database role
 * goptions   : Available AclMask to grant others
 */
void
ac_tablespace_grant(Oid tblspcOid, Oid grantor, AclMode goptions)
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
 * tblspcOid : OID of the target tablespace
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
 * tblspcOid : OID of the target tablespace
 * abort     : True, if caller want to raise an error, if violated
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
 * tblspcOid : OID of the tablespace to be commented on
 */
void
ac_tablespace_comment(Oid tblspcOid)
{
	if (!pg_tablespace_ownercheck(tblspcOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TABLESPACE,
					   get_tablespace_name(tblspcOid));
}

/* ************************************************************
 *
 * Pg_trigger system catalog related access control stuffs
 *
 * ************************************************************/

/*
 * ac_trigger_create
 *
 * It checks privilege to create a new trigger on a certain table.
 *
 * [Params]
 * relOid    : OID of the relation on which the trigger is set up
 * trigName  : Name of the new trigger
 * conRelOid : OID of the constrained relation, if exist
 * funcOid   : OID of the trigger function
 */
void
ac_trigger_create(Oid relOid, const char *trigName, Oid conRelOid, Oid funcOid)
{
	AclResult	aclresult;

	aclresult = pg_class_aclcheck(relOid, GetUserId(), ACL_TRIGGER);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_CLASS, get_rel_name(relOid));

	if (OidIsValid(conRelOid))
	{
		aclresult = pg_class_aclcheck(conRelOid, GetUserId(), ACL_TRIGGER);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_CLASS, get_rel_name(conRelOid));
	}
}

/*
 * ac_trigger_alter
 *
 * It checks privilege to alter definition of a certain trigger.
 * Currently, only an operation to rename is defined on triggers.
 *
 * [Params]
 * relOid   : OID of the ralation on which the trigger is set up
 * trigName : Name of the trigger to be altered
 * newName  : New name of the trigger, if exist
 */
void
ac_trigger_alter(Oid relOid, const char *trigName, const char *newName)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_trigger_drop
 *
 * It checks privilege to drop a certain trigger
 *
 * [Params]
 * relOid   : OID of the ralation on which the trigger is set up
 * trigName : Name of the trigger to be dropped
 * dacSkip  : True, if dac permission check should be bypassed
 */
void
ac_trigger_drop(Oid relOid, const char *trigName, bool dacSkip)
{
	if (!dacSkip &&
		!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/* Helper function to call ac_trigger_drop() */
static void
ac_trigger_drop_by_oid(Oid trigOid, bool dacSkip)
{
	Form_pg_trigger	tgForm;
	Relation	tgRel;
	HeapTuple	tgTup;
	SysScanDesc sscan;
    ScanKeyData skey;

	tgRel = heap_open(TriggerRelationId, AccessShareLock);

	ScanKeyInit(&skey,
				ObjectIdAttributeNumber,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(trigOid));

	sscan = systable_beginscan(tgRel, TriggerOidIndexId, true,
							   SnapshotNow, 1, &skey);

	tgTup = systable_getnext(sscan);
	if (!HeapTupleIsValid(tgTup))
		elog(ERROR, "could not find tuple for trigger %u", trigOid);

	tgForm = (Form_pg_trigger) GETSTRUCT(tgTup);
	ac_trigger_drop(tgForm->tgrelid, NameStr(tgForm->tgname), dacSkip);

	systable_endscan(sscan);

    heap_close(tgRel, AccessShareLock);
}

/*
 * ac_trigger_comment
 *
 * It checks privilege to comment on a certain trigger
 *
 * [Params]
 * relOid   : OID of the ralation on which the trigger is set up
 * trigName : Name of the trigger to be commented on
 */
void
ac_trigger_comment(Oid relOid, const char *trigName)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/* ************************************************************
 *
 * Pg_ts_config system catalog related access control stuffs
 *
 * ************************************************************/

static char *
get_ts_config_name(Oid cfgOid)
{
	Form_pg_ts_config	cfgForm;
	HeapTuple	cfgTup;
	char	   *cfgName = NULL;

	cfgTup =  SearchSysCache(TSCONFIGOID,
							 ObjectIdGetDatum(cfgOid),
							 0, 0, 0);
	if (HeapTupleIsValid(cfgTup))
	{
		cfgForm = ((Form_pg_ts_config) GETSTRUCT(cfgTup));
		cfgName = pstrdup(NameStr(cfgForm->cfgname));

		ReleaseSysCache(cfgTup);
	}
	return cfgName;
}

static Oid
get_ts_config_namespace(Oid cfgOid)
{
	HeapTuple	cfgTup;
	Oid			cfgNsp;

	cfgTup =  SearchSysCache(TSCONFIGOID,
							 ObjectIdGetDatum(cfgOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(cfgTup))
		elog(ERROR, "cache lookup failed for text search configuration %u", cfgOid);

	cfgNsp = ((Form_pg_ts_config) GETSTRUCT(cfgTup))->cfgnamespace;

	ReleaseSysCache(cfgTup);

	return cfgNsp;
}

/*
 * ac_ts_config_create
 *
 * It checks privilege to create a new text search config
 *
 * [Params]
 * cfgName : Name of the new text search config
 * cfgNsp  : OID of the namespace to be used
 */
void
ac_ts_config_create(const char *cfgName, Oid cfgNsp)
{
	AclResult	aclresult;

	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(cfgNsp, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(cfgNsp));
}

/*
 * ac_ts_config_alter
 *
 * It checks privilege to alter a certain text search config
 *
 * [Params]
 * cfgOid   : OID of the text search config to be dropped
 * newName  : New name of the text search config, if exist
 * newOwner : New owner of the text search config, if exist
 */
void
ac_ts_config_alter(Oid cfgOid, const char *newName, Oid newOwner)
{
	Oid			cfgNsp = get_ts_config_namespace(cfgOid);
	AclResult	aclresult;

	/* Must be owner for all the ALTER TEXT SEARCH CONFIG options */
	if (!pg_ts_config_ownercheck(cfgOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TSCONFIGURATION,
					   get_ts_config_name(cfgOid));

	/* Must have CREATE privilege on namespace when renaming */
	if (newName)
	{
		aclresult = pg_namespace_aclcheck(cfgNsp, GetUserId(), ACL_CREATE);
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(cfgNsp));
	}

	/* Superusers can always do it */
	if (OidIsValid(newOwner) && !superuser())
	{
		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have CREATE privilege on namespace */
		aclresult = pg_namespace_aclcheck(cfgNsp, newOwner, ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(cfgNsp));
	}
}

/*
 * ac_ts_config_drop
 *
 * It checks privilege to drop a certain text search config
 *
 * [Params]
 * cfgOid  : OID of the text search config to be dropped
 * dacSkip : True, if dac permission checks should be bypassed
 */
void
ac_ts_config_drop(Oid cfgOid, bool dacSkip)
{
	Oid		cfgNsp = get_ts_config_namespace(cfgOid);

	if (!dacSkip &&
		!pg_ts_config_ownercheck(cfgOid, GetUserId()) &&
		!pg_namespace_ownercheck(cfgNsp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TSCONFIGURATION,
					   get_ts_config_name(cfgOid));
}

/*
 * ac_ts_config_comment
 *
 * It checks privilege to comment on a certain text search config
 *
 * [Params]
 * cfgOid : OID of the text search config to be dropped
 */
void
ac_ts_config_comment(Oid cfgOid)
{
	if (!pg_ts_config_ownercheck(cfgOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TSCONFIGURATION,
					   get_ts_config_name(cfgOid));
}

/* ************************************************************
 *
 * Pg_ts_dict system catalog related access control stuffs
 *
 * ************************************************************/

static char *
get_ts_dict_name(Oid dictOid)
{
	Form_pg_ts_dict	dictForm;
	HeapTuple	dictTup;
	char	   *dictName = NULL;

	dictTup = SearchSysCache(TSDICTOID,
							 ObjectIdGetDatum(dictOid),
							 0, 0, 0);
	if (HeapTupleIsValid(dictTup))
	{
		dictForm = (Form_pg_ts_dict) GETSTRUCT(dictTup);
		dictName = pstrdup(NameStr(dictForm->dictname));

		ReleaseSysCache(dictTup);
	}
	return dictName;
}

static Oid
get_ts_dict_namespace(Oid dictOid)
{
	HeapTuple	dictTup;
	Oid			dictNsp;

	dictTup = SearchSysCache(TSDICTOID,
							 ObjectIdGetDatum(dictOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(dictTup))
		elog(ERROR, "cache lookup failed for text search dictionary %u", dictOid);

	dictNsp = ((Form_pg_ts_dict) GETSTRUCT(dictTup))->dictnamespace;

	ReleaseSysCache(dictTup);

	return dictNsp;
}

/*
 * ac_ts_dict_create
 *
 * It checks privilege to create a new text search dictionary
 *
 * [Params]
 * dictName : Name of the new text search dictionary
 * dictNsp  : OID of the namespace to be used
 */
void
ac_ts_dict_create(const char *dictName, Oid dictNsp)
{
	AclResult	aclresult;

	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(dictNsp, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(dictNsp));
}

/*
 * ac_ts_dict_alter
 *
 * It checks privilege to alter a certain text search dictionary
 *
 * [Params]
 * dictOid  : OID of the text search dictionary to be altered
 * newName  : New name of the text search dictionary, if exist
 * newOwner : New OID of the text search dictionary owner, if exist
 */
void
ac_ts_dict_alter(Oid dictOid, const char *newName, Oid newOwner)
{
	Oid			dictNsp = get_ts_dict_namespace(dictOid);
	AclResult	aclresult;

	/* Must be owner for all the ALTER TEXT SEARCH DICTIONARY options */
	if (!pg_ts_dict_ownercheck(dictOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TSDICTIONARY,
					   get_ts_dict_name(dictOid));

	/* must have CREATE privilege on namespace, if renaming */
	if (newName)
	{
		aclresult = pg_namespace_aclcheck(dictNsp, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(dictNsp));
	}

	/* Superusers can always do it */
	if (OidIsValid(newOwner) && !superuser())
	{
		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have CREATE privilege on namespace */
		aclresult = pg_namespace_aclcheck(dictNsp, newOwner, ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(dictNsp));
	}
}

/*
 * ac_ts_dict_drop
 *
 * It checks privilege to drop a certain text search dictionary
 *
 * [Params]
 * dictOid : OID of the text search dictionary to be dropped
 * dacSkip : True, if dac permission checks should be bypassed
 */
void
ac_ts_dict_drop(Oid dictOid, bool dacSkip)
{
	Oid		dictNsp = get_ts_dict_namespace(dictOid);

	/* Must be owner of the dictionary or its namespace */
	if (!dacSkip &&
		!pg_ts_dict_ownercheck(dictOid, GetUserId()) &&
		!pg_namespace_ownercheck(dictNsp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TSDICTIONARY,
					   get_ts_dict_name(dictOid));
}

/*
 * ac_ts_dict_comment
 *
 * It checks privilege to comment on a certain text search dictionary
 *
 * [Params]
 * dictOid : OID of the text search dictionary to be commented
 */
void
ac_ts_dict_comment(Oid dictOid)
{
   	if (!pg_ts_dict_ownercheck(dictOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TSDICTIONARY,
					   get_ts_dict_name(dictOid));
}

/* ************************************************************
 *
 * Pg_ts_parser system catalog related access control stuffs
 *
 * ************************************************************/

/*
 * ac_ts_parser_create
 *
 * It checks privilege to create a new text search parser
 *
 * [Params]
 * prsName    : Name of the new text search parser
 * prsNsp     : OID of the namespace to be used
 * startFn    : OID of the start function
 * tokenFn    : OID of the token function
 * sendFn     : OID of the send function
 * headlineFn : OID of the headline function, if exist
 * lextypeFn  : OID of the lextype function
 */
void
ac_ts_parser_create(const char *prsName, Oid prsNsp,
					Oid startFn, Oid tokenFn, Oid sendFn,
					Oid headlineFn, Oid lextypeFn)
{
	/*
	 * Note that it checks superuser privilege here, so it implicitly 
	 * allows the caller to create a new object within the namespace
	 * and grant public to execute the given functions.
	 * These permissions should be checked, if we don't omit obvious
	 * checks.
	 */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to create text search parsers")));
}

/*
 * ac_ts_parser_alter
 *
 * It checks privilege to alter a certain text search parser
 *
 * [Params]
 * prsOid  : OID of the text search parser
 * newName : New name of the text search parser, if exist
 */
void
ac_ts_parser_alter(Oid prsOid, const char *newName)
{
	/*
	 * Note that it checks superuser privilege here, so it implicitly
	 * allows caller CREATE privilege on the current namespace.
	 */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to rename text search parsers")));
}

/*
 * ac_ts_parser_drop
 *
 * It checks privilege to drop a certain text search parser
 *
 * [Params]
 * prsOid  : OID of the text search parser
 * dacSkip : True, if dac permission checks should be bypassed
 */
void
ac_ts_parser_drop(Oid prsOid, bool dacSkip)
{
	if (!dacSkip &&
		!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to drop text search parsers")));
}

/*
 * ac_ts_parser_comment
 *
 * It checks privilege to comment on a certain text search parser
 *
 * [Params]
 * prsOid  : OID of the text search parser
 */
void
ac_ts_parser_comment(Oid prsOid)
{
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to comment on text search parser")));
}

/* ************************************************************
 *
 * Pg_ts_template system catalog related access control stuffs
 *
 * ************************************************************/

/*
 * ac_ts_template_create
 *
 * It checks privilege to create a new text search templace
 *
 * [Params]
 * tmplName : Name of the new text search template
 * tmplNsp  : OID of the namespace to be used
 * initFn   : OID of the initialization function, if exist
 * lexizeFn : OID of the base function of dictionary
 */
void
ac_ts_template_create(const char *tmplName, Oid tmplNsp,
					  Oid initFn, Oid lexizeFn)
{
	/*
	 * Note that it checks superuser privilege here, so it implicitly 
	 * allows the caller to create a new object within the namespace
	 * and grant public to execute the given functions.
	 * These permissions should be checked, if we don't omit obvious
	 * checks.
	 */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to create text search templates")));
}

/*
 * ac_ts_template_alter
 *
 * It checks privilege to alter a certain text search templates
 *
 * [Params]
 * tmplOid : OID of the text search template to be altered
 * newName : New name of the text search template, if exist
 */
void
ac_ts_template_alter(Oid tmplOid, const char *newName)
{
	/*
	 * Note that it checks superuser privilege here, so it implicitly
	 * allows caller CREATE privilege on the current namespace.
	 */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to rename text search templates")));
}

/*
 * ac_ts_template_drop
 *
 * It checks privilege to drop a certain text search template
 *
 * [Params]
 * tmplOid : OID of the text search template to be dropped
 * dacSkip : True, if dac permission checks should be bypassed
 */
void
ac_ts_template_drop(Oid tmplOid, bool dacSkip)
{
	if (!dacSkip &&
		!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to drop text search templates")));
}

/*
 * ac_ts_template_comment
 *
 * It checks privilege to comment on a certain tect search template
 *
 * [Params]
 * tmplOid : OID of the text search template to be commented on
 */
void
ac_ts_template_comment(Oid tmplOid)
{
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to comment on text search template")));
}

/* ************************************************************
 *
 * Pg_type system catalog related access control stuffs
 *
 * ************************************************************/

static Oid
get_type_namespace(Oid typOid)
{
	HeapTuple	typTup;
	Oid			typNsp;

	typTup = SearchSysCache(TYPEOID,
							ObjectIdGetDatum(typOid),
							0, 0, 0);
	if (!HeapTupleIsValid(typTup))
		elog(ERROR, "cache lookup failed for type: %u", typOid);

	typNsp = ((Form_pg_type) GETSTRUCT(typTup))->typnamespace;

	ReleaseSysCache(typTup);

	return typNsp;
}

/*
 * ac_type_create
 *
 * It checks privilege to create a new type
 *
 * [Params]
 * typName    : Name of the new type
 * typNsp     : OID of the namespace to be used for the type
 * typOwner   : OID of the type owner
 * typReplOid : OID of the shell type to be replaced, if exist
 * typTypey   : TYPTYPE_* of the new type
 * typIsArray : True, if implicit array type
 * inputOid   : OID of the input function, if exist
 * outputOid  : OID of the output function, if exist
 * recvOid    : OID of the receive function, if exist
 * sendOid    : OID of the send function, if exist
 * modinOid   : OID of the typemodin function, if exist
 * modoutOid  : OID of the typemodout function, if exist
 * analyzeOid : OID of the analyze function, if exist
 */
void
ac_type_create(const char *typName, Oid typNsp, Oid typOwner,
			   Oid typReplOid, char typType, bool typIsArray,
			   Oid inputOid, Oid outputOid, Oid recvOid, Oid sendOid,
			   Oid modinOid, Oid modoutOid, Oid analyzeOid)
{
	AclResult	aclresult;

	switch (typType)
	{
		case TYPTYPE_BASE:
			/* No permission checks for implicit array type */
			if (typIsArray)
				break;

			/*
			 * As of Postgres 8.4, we require superuser privilege to create
			 * a base type.  This is simple paranoia: there are too many ways
			 * to mess up the system with an incorrect type definition (for
			 * instance, representation parameters that don't match what the
			 * C code expects).  In practice it takes superuser privilege to
			 * create the I/O functions, and so the former requirement that
			 * you own the I/O functions pretty much forced superuserness
			 * anyway.
			 * We're just making doubly sure here.
			 *
			 * XXX re-enable NOT_USED code sections below if you remove this test.
			 */
			if (!superuser())
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("must be superuser to create a base type")));
#ifdef NOT_USED
			/* XXX this is unnecessary given the superuser check above */
			/* Check we have creation rights in target namespace */
			aclresult = pg_namespace_aclcheck(typNsp, GetUserId(), ACL_CREATE);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
							   get_namespace_name(typNsp));

			/*
			 * Check permissions on functions.	We choose to require the
			 * creator/owner of a type to also own the underlying functions.
			 * Since creating a type is tantamount to granting public execute
			 * access on the functions, the minimum sane check would be for
			 * execute-with-grant-option.  But we don't have a way to make
			 * the type go away if the grant option is revoked, so ownership
			 * seems better.
			 */
			/* XXX this is unnecessary given the superuser check above */
			if (inputOid && !pg_proc_ownercheck(inputOid, GetUserId()))
				aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
							   format_type_be(inputOid));
			if (outputOid && !pg_proc_ownercheck(outputOid, GetUserId()))
				aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
							   format_type_be(outputOid));
			if (recvOid && !pg_proc_ownercheck(recvOid, GetUserId()))
				aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
							   format_type_be(recvOid));
			if (sendOid && !pg_proc_ownercheck(sendOid, GetUserId()))
				aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
							   format_type_be(sendOid));
			if (modinOid && !pg_proc_ownercheck(modinOid, GetUserId()))
				aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
							   format_type_be(modinOid));
			if (modoutOid && !pg_proc_ownercheck(modoutOid, GetUserId()))
				aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
							   format_type_be(modoutOid));
			if (analyzeOid && !pg_proc_ownercheck(analyzeOid, GetUserId()))
				aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
							   format_type_be(analyzeOid));
#endif
			break;

		case TYPTYPE_COMPOSITE:
			/* do nothing here */
			break;

		case TYPTYPE_DOMAIN:
		case TYPTYPE_ENUM:
		case TYPTYPE_PSEUDO:
			/*
			 * For DOMAIN, ENUM and shell-type, it requires ACL_CREATE
			 * on the namespace to be associated, instead of superuser
			 * privilege.
			 */
			aclresult = pg_namespace_aclcheck(typNsp, GetUserId(), ACL_CREATE);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
							   get_namespace_name(typNsp));
			break;

		default:
			elog(ERROR, "Unexpected typetype: %c", typType);
			break;
	}

	/*
	 * If the new type replaces an existing shell type,
	 * its ownership must be matched.
	 */
	if (OidIsValid(typReplOid))
	{
		HeapTuple	typTup;

		typTup = SearchSysCache(TYPEOID,
								ObjectIdGetDatum(typReplOid),
								0, 0, 0);
        if (!HeapTupleIsValid(typTup))
            elog(ERROR, "cache lookup failed for type %u", typReplOid);

		if (((Form_pg_type) GETSTRUCT(typTup))->typowner != typOwner)
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TYPE, typName);

		ReleaseSysCache(typTup);
	}
}

/*
 * ac_type_alter
 *
 * It checks privilege to alter a certain type
 *
 * [Params]
 * typOid    : OID of the type to be altered
 * newName   : New name of the type, if exist
 * newNspOid : OID of the new type namespace, if exist
 * newOwner  : OID of the new type owner, if exist
 */
void
ac_type_alter(Oid typOid, const char *newName,
			  Oid newNspOid, Oid newOwner)
{
	AclResult	aclresult;

	if (!pg_type_ownercheck(typOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TYPE,
					   format_type_be(typOid));

	if (newName)
	{
		/*
		 * MEMO: Why ACL_CREATE on the namespace is not checked
		 * on renaming the type? Other database objects also checks
		 * it on renaming.
		 */
	}

	if (OidIsValid(newNspOid))
	{
		aclresult = pg_namespace_aclcheck(newNspOid, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(newNspOid));
	}

	if (OidIsValid(newOwner))
	{
		if (!superuser())
		{
			Oid		typNsp = get_type_namespace(typOid);

			/* Must be able to become new owner */
			check_is_member_of_role(GetUserId(), newOwner);

			/* New owner must have CREATE privilege on namespace */
			aclresult = pg_namespace_aclcheck(typNsp, newOwner, ACL_CREATE);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
							   get_namespace_name(typNsp));
		}
	}
}

/*
 * ac_type_drop
 *
 * It checks privileges to drop a certain type
 *
 * [Params]
 * typOid  : OID of the type to be dropped
 * dacSkip : True, if dac permission check should be bypassed
 */
void
ac_type_drop(Oid typOid, bool dacSkip)
{
	Oid		typNsp = get_type_namespace(typOid);

	/* Permission check: must own type or its namespace */
	if (!dacSkip &&
		!pg_type_ownercheck(typOid, GetUserId()) &&
		!pg_namespace_ownercheck(typNsp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TYPE,
					   format_type_be(typOid));
}

/*
 * ac_type_comment
 *
 * It checks privilege to comment on a certain type
 *
 * [Params]
 * typOid : OID of the type to be commented on
 */
void
ac_type_comment(Oid typOid)
{
	if (!pg_type_ownercheck(typOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TYPE,
					   format_type_be(typOid));
}

/* ************************************************************
 *
 * Pg_user_mapping system catalog related access control stuffs
 *
 * ************************************************************/

/* Helper functions */

/*
 * Common routine to check permission for user-mapping-related DDL
 * commands.  We allow server owners to operate on any mapping, and
 * users to operate on their own mapping.
 */
static void
user_mapping_ddl_aclcheck(Oid umuserid, Oid serverid)
{
	Oid		curuserid = GetUserId();

	if (!pg_foreign_server_ownercheck(serverid, curuserid))
	{
		if (umuserid == curuserid)
		{
			AclResult	aclresult;

			aclresult = pg_foreign_server_aclcheck(serverid, curuserid,
												   ACL_USAGE);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_FOREIGN_SERVER,
							   get_foreign_server_name(serverid));
		}
		else
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_FOREIGN_SERVER,
						   get_foreign_server_name(serverid));
    }
}

/*
 * ac_user_mapping_create
 *
 * It checks permission to create a new user mapping
 *
 * [Params]
 * userOid : OID of the mapped user id
 * fsrvOid : OID of the foreign server
 */
void
ac_user_mapping_create(Oid userOid, Oid fsrvOid)
{
	user_mapping_ddl_aclcheck(userOid, fsrvOid);
}

/*
 * ac_user_mapping_alter
 *
 * It checks permission to alter a certain user mapping
 *
 * [Params]
 * umOid : OID of the user mapping to be altered
 */
void
ac_user_mapping_alter(Oid umOid)
{
	Form_pg_user_mapping	umForm;
	HeapTuple		umTup;

	umTup = SearchSysCache(USERMAPPINGOID,
						   ObjectIdGetDatum(umOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(umTup))
		elog(ERROR, "cache lookup failed for user mapping %u", umOid);

	umForm = (Form_pg_user_mapping) GETSTRUCT(umTup);
	user_mapping_ddl_aclcheck(umForm->umuser, umForm->umserver);

	ReleaseSysCache(umTup);
}

/*
 * ac_user_mapping_drop
 *
 * It checks permission to drop a certain user mapping
 *
 * [Params]
 * umOid   : OID of the user mapping to be dropped
 * dacSkip : True, if dac permission check should be bypassed
 */
void
ac_user_mapping_drop(Oid umOid, bool dacSkip)
{
	Form_pg_user_mapping	umForm;
	HeapTuple		umTup;

	umTup = SearchSysCache(USERMAPPINGOID,
						   ObjectIdGetDatum(umOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(umTup))
		elog(ERROR, "cache lookup failed for user mapping %u", umOid);

	umForm = (Form_pg_user_mapping) GETSTRUCT(umTup);
	user_mapping_ddl_aclcheck(umForm->umuser, umForm->umserver);

	ReleaseSysCache(umTup);
}

/* ************************************************************
 *
 * Entrypoint to drop miscellaneous database objects
 *
 * ************************************************************/

/*
 * ac_object_drop
 *
 * It checks privilege to drop a certain miscellaneous database objects
 * during cascaded deletion and so on.
 *
 * [Params]
 * object  : a miscellaneous database object to be dropped
 * dacSkip : True, if dac permission check should be bypassed
 */
void
ac_object_drop(const ObjectAddress *object, bool dacSkip)
{
	switch (getObjectClass(object))
	{
	case OCLASS_CLASS:				/* pg_class */
		if (object->objectSubId != 0)
			ac_relation_drop(object->objectId, dacSkip);
		else
		{
			char *attName
				= get_relid_attribute_name(object->objectId,
										   object->objectSubId);
			ac_attribute_drop(object->objectId, attName, dacSkip);
		}
		break;
	case OCLASS_PROC:				/* pg_proc */
		ac_proc_drop(object->objectId, dacSkip);
		break;
	case OCLASS_TYPE:				/* pg_type */
		ac_type_drop(object->objectId, dacSkip);
		break;
	case OCLASS_CAST:				/* pg_cast */
		ac_cast_drop_by_oid(object->objectId, dacSkip);
		break;
	case OCLASS_CONSTRAINT:			/* pg_constraint */
		/* no need to do nothing in this version */
		break;
	case OCLASS_CONVERSION:			/* pg_conversion */
		ac_conversion_drop(object->objectId, dacSkip);
		break;
 	case OCLASS_LANGUAGE:			/* pg_language */
		ac_language_drop(object->objectId, dacSkip);
		break;
 	case OCLASS_OPERATOR:			/* pg_operator */
		ac_operator_drop(object->objectId, dacSkip);
		break;
	case OCLASS_OPCLASS:			/* pg_opclass */
		ac_opclass_drop(object->objectId, dacSkip);
		break;
	case OCLASS_OPFAMILY:			/* pg_opfamily */
		ac_opfamily_drop(object->objectId, dacSkip);
		break;
	case OCLASS_AMOP:				/* pg_amop */
	case OCLASS_AMPROC:				/* pg_amproc */
		/* no need to do nothing in this version */
		break;
	case OCLASS_REWRITE:			/* pg_rewrite */
		ac_rule_drop_by_oid(object->objectId, dacSkip);
		break;
	case OCLASS_TRIGGER:			/* pg_trigger */
		ac_trigger_drop_by_oid(object->objectId, dacSkip);
		break;
	case OCLASS_SCHEMA:				/* pg_namespace */
		ac_schema_drop(object->objectId, dacSkip);
		break;
	case OCLASS_TSPARSER:			/* pg_ts_parser */
		ac_ts_parser_drop(object->objectId, dacSkip);
		break;
	case OCLASS_TSDICT:				/* pg_ts_dict */
		ac_ts_dict_drop(object->objectId, dacSkip);
		break;
	case OCLASS_TSTEMPLATE:			/* pg_ts_template */
		ac_ts_template_drop(object->objectId, dacSkip);
		break;
	case OCLASS_TSCONFIG:			/* pg_ts_config */
		ac_ts_config_drop(object->objectId, dacSkip);
		break;
	case OCLASS_ROLE:
	case OCLASS_DATABASE:
	case OCLASS_TBLSPACE:
		/* should not be happen */
		break;
	case OCLASS_FDW:				/* pg_foreign_data_wrapper */
		ac_foreign_data_wrapper_drop(object->objectId, dacSkip);
		break;
	case OCLASS_FOREIGN_SERVER:		/* pg_foreign_server */
		ac_foreign_server_drop(object->objectId, dacSkip);
		break;
	case OCLASS_USER_MAPPING:		/* pg_user_mapping */
		ac_user_mapping_drop(object->objectId, dacSkip);
		break;
	default:
		/* do nothing */
		break;
	}
}
