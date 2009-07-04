/*
 * src/backend/security/sepgsql/checker.c
 *    walks on given Query tree and applies checks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/sysattr.h"
#include "catalog/pg_database.h"
#include "catalog/pg_language.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_rewrite.h"
#include "catalog/pg_security.h"
#include "catalog/pg_shsecurity.h"
#include "security/sepgsql.h"
#include "storage/bufmgr.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

/*
 * fixupWholeRowReference
 */
static Bitmapset *
fixupWholeRowReference(Oid relid, int nattrs, Bitmapset *columns)
{
	Bitmapset  *result;
	AttrNumber	attno;

	attno = InvalidAttrNumber - FirstLowInvalidHeapAttributeNumber;

	if (!bms_is_member(attno, columns))
		return columns;		/* no need to fixup */

	result = bms_copy(columns);
	result = bms_del_member(result, attno);

	for (attno=1; attno <= nattrs; attno++)
	{
		Form_pg_attribute	attform;
		HeapTuple			atttup;

		atttup = SearchSysCache(ATTNUM,
								ObjectIdGetDatum(relid),
								Int16GetDatum(attno),
								0, 0);
		if (!HeapTupleIsValid(atttup))
			continue;

		attform = (Form_pg_attribute) GETSTRUCT(atttup);
		if (!attform->attisdropped)
		{
			int		cindex = attno - FirstLowInvalidHeapAttributeNumber;
			result = bms_add_member(result, cindex);
		}
		ReleaseSysCache(atttup);
	}

	return result;
}

/*
 * checkTabelColumnPerms
 *   This functions applies table/column level permissions for
 *   all the appeared ones in user's query, and raises an error
 *   if violated.
 *   It also applies a few hardwired policy which prevent to
 *   modified some of system catalogs.
 */
static void
checkTabelColumnPerms(Oid relid, Bitmapset *selected, Bitmapset *modified,
					  access_vector_t required)
{
	Bitmapset		   *columns;
	Bitmapset		   *selected_ex;
	Bitmapset		   *modified_ex;
	HeapTuple			tuple;
	AttrNumber			attno;
	int					nattrs;
	security_class_t	tclass;

	/*
	 * NOTE: HARDWIRED POLICY IN SE-POSTGRESQL
	 * - User cannot access RELKIND_TOASTVALUE by hand, because
	 *   it is used to store variable length data within other
	 *   column and tuples, and it should be considered as a part
	 *   of content within them.
	 * - User cannot modify pg_rewrite.* by hand, because it holds
	 *   a parsed Query tree which includes requiredPerms and
	 *   RangeTblEntry with selectedCols/modifiedCols.
	 *   The correctness of access controls depends on these data
	 *   are protected from unexpected manipulation..
	 *
	 * - User cannot modify pg_security.* by hand, because it holds
	 *   all the pairs of security identifier and label, so the
	 *   correctness of access controls depends on these data are
	 *   protected from unexpected manipulation.
	 *
	 * SE-PostgreSQL always prevent user's query tries to modify
	 * these system catalogs by hand. Please use approariate
	 * interfaces.
	 */
	if (!sepgsqlGetExceptionMode())
	{
		switch (relid)
		{
		case RewriteRelationId:
		case SecurityRelationId:
		case SharedSecurityRelationId:
			if ((required & (SEPG_DB_TABLE__UPDATE |
							 SEPG_DB_TABLE__INSERT |
							 SEPG_DB_TABLE__DELETE)) != 0)
				ereport(ERROR,
						(errcode(ERRCODE_SELINUX_ERROR),
						 errmsg("SE-PostgreSQL prevent to modify \"%s\" "
								"by hand due to the hardwired policy",
								get_rel_name(relid))));
			break;

		default:
			if (get_rel_relkind(relid) == RELKIND_TOASTVALUE)
				ereport(ERROR,
						(errcode(ERRCODE_SELINUX_ERROR),
						 errmsg("SE-PostgreSQL prevent to accuees \"%s\" "
								"by hand due to the hardwired policy",
								get_rel_name(relid))));
			break;
		}
	}

	/*
	 * Check db_table:{...} or db_sequence permissions
	 */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation %u", relid);

	tclass = sepgsqlTupleObjectClass(RelationRelationId, tuple);

	if (tclass != SEPG_CLASS_DB_TABLE)
	{
		/* check db_sequence:{xxx} permission */
		if (tclass == SEPG_CLASS_DB_SEQUENCE)
		{
			if (required & SEPG_DB_TABLE__SELECT)
			{
				sepgsqlClientHasPermsTup(RelationRelationId, tuple,
										 SEPG_CLASS_DB_SEQUENCE,
										 SEPG_DB_SEQUENCE__GET_VALUE,
										 true);
			}
		}
		ReleaseSysCache(tuple);
		return;
	}

	sepgsqlClientHasPermsTup(RelationRelationId, tuple,
							 SEPG_CLASS_DB_TABLE,
							 required, true);

	nattrs = ((Form_pg_class) GETSTRUCT(tuple))->relnatts;

	ReleaseSysCache(tuple);

	/*
	 * Check db_column:{...} permissions
	 */
	selected_ex = fixupWholeRowReference(relid, nattrs, selected);
	modified_ex = fixupWholeRowReference(relid, nattrs, modified);
	columns = bms_union(selected_ex, modified_ex);

	while ((attno = bms_first_member(columns)) >= 0)
	{
		Form_pg_attribute	attForm;
		access_vector_t		attperms = 0;

		if (bms_is_member(attno, selected_ex))
			attperms |= SEPG_DB_COLUMN__SELECT;
		if (bms_is_member(attno, modified_ex))
		{
			if (required & SEPG_DB_TABLE__UPDATE)
				attperms |= SEPG_DB_COLUMN__UPDATE;
			if (required & SEPG_DB_TABLE__INSERT)
				attperms |= SEPG_DB_COLUMN__INSERT;
		}
		if (attperms == 0)
			continue;

		/* remove the attribute number offset */
		attno += FirstLowInvalidHeapAttributeNumber;
		tuple = SearchSysCache(ATTNUM,
							   ObjectIdGetDatum(relid),
							   Int16GetDatum(attno),
							   0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for attribute %d of relation %u",
				 attno, relid);

		attForm = (Form_pg_attribute) GETSTRUCT(tuple);
		if (attForm->attisdropped)
			elog(ERROR, "attribute %d of relation %u does not exist",
				 attno, relid);

		sepgsqlClientHasPermsTup(AttributeRelationId, tuple,
								 SEPG_CLASS_DB_COLUMN,
								 attperms, true);
		ReleaseSysCache(tuple);
	}

	if (selected_ex != selected)
		bms_free(selected_ex);

	if (modified_ex != modified)
		bms_free(modified_ex);

	bms_free(columns);
}

/*
 * sepgsqlCheckQueryPerms
 *   It checks permission for all the required tables/columns on
 *   generic user queries.
 */
void
sepgsqlCheckRTEPerms(RangeTblEntry *rte)
{
	access_vector_t		required = 0;

	if (!sepgsqlIsEnabled())
		return;

	if (rte->rtekind != RTE_RELATION)
		return;

	if (rte->requiredPerms & ACL_SELECT)
		required |= SEPG_DB_TABLE__SELECT;
	if (rte->requiredPerms & ACL_INSERT)
		required |= SEPG_DB_TABLE__INSERT;
	if (rte->requiredPerms & ACL_UPDATE)
	{
		/*
		 * ACL_SELECT_FOR_UPDATE is defined as an aliase of ACL_UPDATE,
		 * so we cannot determine whether the given relation is accessed
		 * with UPDATE statement or SELECT FOR SHARE/UPDATE immediately.
		 * UPDATE statements set a bit on rte->modifiedCols at least,
		 * so we use it as a watermark.
		 */
		if (!bms_is_empty(rte->modifiedCols))
			required |= SEPG_DB_TABLE__UPDATE;
		else
			required |= SEPG_DB_TABLE__LOCK;
	}
	if (rte->requiredPerms & ACL_DELETE)
		required |= SEPG_DB_TABLE__DELETE;

	if (required == 0)
		return;

	checkTabelColumnPerms(rte->relid,
						  rte->selectedCols,
						  rte->modifiedCols,
						  required);
}

/*
 * sepgsqlCheckCopyTable
 *   It checks permissions on COPY TO/FROM.
 */
void
sepgsqlCheckCopyTable(Relation rel, List *attnumlist, bool is_from)
{
	Bitmapset	   *selected = NULL;
	Bitmapset	   *modified = NULL;
	ListCell	   *l;

	if (!sepgsqlIsEnabled())
		return;

	/* all checkes are done in sepgsqlCheckRTEPerms */
	if (!rel)
		return;

	foreach (l, attnumlist)
	{
		AttrNumber	attno = lfirst_int(l);

		attno -= FirstLowInvalidHeapAttributeNumber;
		if (is_from)
			modified = bms_add_member(modified, attno);
		else
			selected = bms_add_member(selected, attno);
	}

	checkTabelColumnPerms(RelationGetRelid(rel),
						  selected, modified,
						  is_from ? SEPG_DB_TABLE__INSERT
								  : SEPG_DB_TABLE__SELECT);
}

/*
 * sepgsqlCheckSelectInto
 *   It checks db_table/db_column:{insert} on the table newly created
 */
void
sepgsqlCheckSelectInto(Oid relationId)
{
	Bitmapset	   *modified = NULL;

	if (!sepgsqlIsEnabled())
		return;

	modified = bms_add_member(modified, InvalidAttrNumber
					- FirstLowInvalidHeapAttributeNumber);

	checkTabelColumnPerms(relationId, NULL, modified,
						  SEPG_DB_TABLE__INSERT);
}

/*
 * fixupColumnAvPerms
 *   To change pg_attribute.attisdropped means dropping a column,
 *   although this operation done by update, so it need to change
 *   required permmision in this special case.
 */
static access_vector_t
fixupColumnAvPerms(HeapTuple oldtup, HeapTuple newtup)
{
	Form_pg_attribute	oldatt = (Form_pg_attribute) GETSTRUCT(oldtup);
	Form_pg_attribute	newatt = (Form_pg_attribute) GETSTRUCT(newtup);

	if (!oldatt->attisdropped && newatt->attisdropped)
		return SEPG_DB_COLUMN__DROP;
	if (oldatt->attisdropped && !newatt->attisdropped)
		return SEPG_DB_COLUMN__CREATE;

	return 0;
}

/*
 * sepgsqlExecScan
 *   makes a decision on the given tuple.
 */
bool
sepgsqlExecScan(Relation rel, HeapTuple tuple, uint32 required, bool abort)
{
	security_class_t	tclass;

	if (!sepgsqlIsEnabled() ||
		!required ||
		RelationGetForm(rel)->relkind != RELKIND_RELATION)
		return true;

	tclass = sepgsqlTupleObjectClass(RelationGetRelid(rel), tuple);
	return sepgsqlClientHasPermsTup(RelationGetRelid(rel), tuple,
									tclass, required, abort);
}

uint32
sepgsqlSetupTuplePerms(RangeTblEntry *rte)
{
	AclMode		perms = 0;

	if (!sepgsqlIsEnabled())
		return 0;

	if (rte->rtekind != RTE_RELATION)
		return 0;

	if (rte->requiredPerms & ACL_SELECT)
		perms |= SEPG_DB_TUPLE__SELECT;
	if (rte->requiredPerms & ACL_UPDATE && !bms_is_empty(rte->modifiedCols))
		perms |= SEPG_DB_TUPLE__UPDATE;
	if (rte->requiredPerms & ACL_DELETE)
		perms |= SEPG_DB_TUPLE__DELETE;

	return perms;
}

/*
 * checkTrustedAction
 *   It returns true, if we can ignore access controls for create/alter/drop
 *   on the given database objects.
 */
static bool
checkTrustedAction(Relation rel, bool internal)
{
	if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
		return true;

	if (internal &&
		(RelationGetRelid(rel) == SecurityRelationId ||
		 RelationGetRelid(rel) == SharedSecurityRelationId))
		return true;

	if (RelationGetRelid(rel) == DatabaseRelationId ||
		RelationGetRelid(rel) == NamespaceRelationId ||
		RelationGetRelid(rel) == RelationRelationId ||
		RelationGetRelid(rel) == AttributeRelationId ||
		RelationGetRelid(rel) == ProcedureRelationId)
		return false;

	return !sepostgresql_row_level;
}

/*
 * HeapTuple INSERT/UPDATE/DELETE
 */
bool
sepgsqlHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal)
{
	Oid					relid = RelationGetRelid(rel);
	security_class_t	tclass;

	if (!sepgsqlIsEnabled())
		return true;

	/* set a default security context */
	if (!OidIsValid(HeapTupleGetSecLabel(newtup)))
	{
		if (HeapTupleHasSecLabel(newtup))
			sepgsqlSetDefaultSecLabel(rel, newtup);
	}

	if (checkTrustedAction(rel, internal))
		return true;

	tclass = sepgsqlTupleObjectClass(relid, newtup);
	return sepgsqlClientHasPermsTup(relid, newtup, tclass,
									SEPG_DB_TUPLE__INSERT,
									internal);
}

bool
sepgsqlHeapTupleUpdate(Relation rel, HeapTuple oldtup,
					   HeapTuple newtup, bool internal)
{
	Oid					relid = RelationGetRelid(rel);
	access_vector_t		required = 0;
	security_class_t	newclass;
	security_class_t	oldclass;

	if (!sepgsqlIsEnabled())
		return true;

	/* preserve security label, if unchanged */
	if (!OidIsValid(HeapTupleGetSecLabel(newtup)))
	{
		if (HeapTupleHasSecLabel(newtup))
			HeapTupleSetSecLabel(newtup, HeapTupleGetSecLabel(oldtup));
	}

	if (checkTrustedAction(rel, internal))
		return true;

	newclass = sepgsqlTupleObjectClass(relid, newtup);
	oldclass = sepgsqlTupleObjectClass(relid, oldtup);

	/* already checked at ExecScan? */
	if (internal)
		required |= SEPG_DB_TUPLE__UPDATE;
	/* special case for pg_attribute */
	if (relid == AttributeRelationId)
		required |= fixupColumnAvPerms(oldtup, newtup);
	/* relabeled? */
	if (oldclass != newclass ||
		HeapTupleGetSecLabel(oldtup) != HeapTupleGetSecLabel(newtup))
		required |= SEPG_DB_TUPLE__RELABELFROM;

	if (required != 0)
	{
		if (!sepgsqlClientHasPermsTup(relid, oldtup, oldclass,
									  required, false))
			return false;
	}

	if ((required & SEPG_DB_TUPLE__RELABELFROM) != 0)
	{
		if (!sepgsqlClientHasPermsTup(relid, newtup, newclass,
									  SEPG_DB_TUPLE__RELABELTO,
									  internal))
			return false;
	}

	return true;
}

bool
sepgsqlHeapTupleDelete(Relation rel, HeapTuple oldtup, bool internal)
{
	Oid					relid = RelationGetRelid(rel);
	security_class_t	tclass;
	access_vector_t		required = 0;

	if (!sepgsqlIsEnabled())
		return true;

	if (checkTrustedAction(rel, internal))
		return true;

	/* already checked at ExecScan? */
	if (internal)
		required |= SEPG_DB_TUPLE__DELETE;

	if (required != 0)
	{

		tclass = sepgsqlTupleObjectClass(relid, oldtup);
		if (!sepgsqlClientHasPermsTup(relid, oldtup, tclass,
									  SEPG_DB_TUPLE__DELETE,
									  internal))
			return false;
	}

	return true;
}
