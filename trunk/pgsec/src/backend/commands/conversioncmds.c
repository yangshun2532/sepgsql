/*-------------------------------------------------------------------------
 *
 * conversioncmds.c
 *	  conversion creation command support code
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  $PostgreSQL: pgsql/src/backend/commands/conversioncmds.c,v 1.39 2009/06/11 14:48:55 momjian Exp $
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/heapam.h"
#include "catalog/dependency.h"
#include "catalog/indexing.h"
#include "catalog/pg_conversion.h"
#include "catalog/pg_conversion_fn.h"
#include "catalog/pg_type.h"
#include "commands/conversioncmds.h"
#include "mb/pg_wchar.h"
#include "miscadmin.h"
#include "parser/parse_func.h"
#include "security/common.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/syscache.h"

static void AlterConversionOwner_internal(Relation rel, Oid conversionOid,
							  Oid newOwnerId);

/*
 * CREATE CONVERSION
 */
void
CreateConversionCommand(CreateConversionStmt *stmt)
{
	Oid			namespaceId;
	char	   *conversion_name;
	int			from_encoding;
	int			to_encoding;
	Oid			funcoid;
	const char *from_encoding_name = stmt->for_encoding_name;
	const char *to_encoding_name = stmt->to_encoding_name;
	List	   *func_name = stmt->func_name;
	static Oid	funcargs[] = {INT4OID, INT4OID, CSTRINGOID, INTERNALOID, INT4OID};
	char		result[1];

	/* Convert list of names to a name and namespace */
	namespaceId = QualifiedNameGetCreationNamespace(stmt->conversion_name,
													&conversion_name);

	/* Check the encoding names */
	from_encoding = pg_char_to_encoding(from_encoding_name);
	if (from_encoding < 0)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("source encoding \"%s\" does not exist",
						from_encoding_name)));

	to_encoding = pg_char_to_encoding(to_encoding_name);
	if (to_encoding < 0)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("destination encoding \"%s\" does not exist",
						to_encoding_name)));

	/*
	 * Check the existence of the conversion function. Function name could be
	 * a qualified name.
	 */
	funcoid = LookupFuncName(func_name, sizeof(funcargs) / sizeof(Oid),
							 funcargs, false);

	/* Check it returns VOID, else it's probably the wrong function */
	if (get_func_rettype(funcoid) != VOIDOID)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_OBJECT_DEFINITION),
		  errmsg("encoding conversion function %s must return type \"void\"",
				 NameListToString(func_name))));

	/* Permission checks to create a new conversion */
	ac_conversion_create(conversion_name, namespaceId, funcoid);

	/*
	 * Check that the conversion function is suitable for the requested source
	 * and target encodings. We do that by calling the function with an empty
	 * string; the conversion function should throw an error if it can't
	 * perform the requested conversion.
	 */
	OidFunctionCall5(funcoid,
					 Int32GetDatum(from_encoding),
					 Int32GetDatum(to_encoding),
					 CStringGetDatum(""),
					 CStringGetDatum(result),
					 Int32GetDatum(0));

	/*
	 * All seem ok, go ahead (possible failure would be a duplicate conversion
	 * name)
	 */
	ConversionCreate(conversion_name, namespaceId, GetUserId(),
					 from_encoding, to_encoding, funcoid, stmt->def);
}

/*
 * DROP CONVERSION
 */
void
DropConversionsCommand(DropStmt *drop)
{
	ObjectAddresses *objects;
	ListCell   *cell;

	/*
	 * First we identify all the conversions, then we delete them in a single
	 * performMultipleDeletions() call.  This is to avoid unwanted DROP
	 * RESTRICT errors if one of the conversions depends on another. (Not that
	 * that is very likely, but we may as well do this consistently.)
	 */
	objects = new_object_addresses();

	foreach(cell, drop->objects)
	{
		List	   *name = (List *) lfirst(cell);
		Oid			conversionOid;
		HeapTuple	tuple;
		Form_pg_conversion con;
		ObjectAddress object;

		conversionOid = FindConversionByName(name);

		if (!OidIsValid(conversionOid))
		{
			if (!drop->missing_ok)
			{
				ereport(ERROR,
						(errcode(ERRCODE_UNDEFINED_OBJECT),
						 errmsg("conversion \"%s\" does not exist",
								NameListToString(name))));
			}
			else
			{
				ereport(NOTICE,
						(errmsg("conversion \"%s\" does not exist, skipping",
								NameListToString(name))));
			}
			continue;
		}

		/* Permission check */
		ac_conversion_drop(conversionOid, false);

		object.classId = ConversionRelationId;
		object.objectId = conversionOid;
		object.objectSubId = 0;

		add_exact_object_address(&object, objects);
	}

	performMultipleDeletions(objects, drop->behavior);

	free_object_addresses(objects);
}

/*
 * Rename conversion
 */
void
RenameConversion(List *name, const char *newname)
{
	Oid			conversionOid;
	Oid			namespaceOid;
	HeapTuple	tup;
	Relation	rel;

	rel = heap_open(ConversionRelationId, RowExclusiveLock);

	conversionOid = FindConversionByName(name);
	if (!OidIsValid(conversionOid))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("conversion \"%s\" does not exist",
						NameListToString(name))));

	tup = SearchSysCacheCopy(CONVOID,
							 ObjectIdGetDatum(conversionOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(tup)) /* should not happen */
		elog(ERROR, "cache lookup failed for conversion %u", conversionOid);

	namespaceOid = ((Form_pg_conversion) GETSTRUCT(tup))->connamespace;

	/* make sure the new name doesn't exist */
	if (SearchSysCacheExists(CONNAMENSP,
							 CStringGetDatum(newname),
							 ObjectIdGetDatum(namespaceOid),
							 0, 0))
		ereport(ERROR,
				(errcode(ERRCODE_DUPLICATE_OBJECT),
				 errmsg("conversion \"%s\" already exists in schema \"%s\"",
						newname, get_namespace_name(namespaceOid))));

	/* Permission check */
	ac_conversion_alter(conversionOid, newname, InvalidOid);

	/* rename */
	namestrcpy(&(((Form_pg_conversion) GETSTRUCT(tup))->conname), newname);
	simple_heap_update(rel, &tup->t_self, tup);
	CatalogUpdateIndexes(rel, tup);

	heap_close(rel, NoLock);
	heap_freetuple(tup);
}

/*
 * Change conversion owner, by name
 */
void
AlterConversionOwner(List *name, Oid newOwnerId)
{
	Oid			conversionOid;
	Relation	rel;

	rel = heap_open(ConversionRelationId, RowExclusiveLock);

	conversionOid = FindConversionByName(name);
	if (!OidIsValid(conversionOid))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("conversion \"%s\" does not exist",
						NameListToString(name))));

	AlterConversionOwner_internal(rel, conversionOid, newOwnerId);

	heap_close(rel, NoLock);
}

/*
 * Change conversion owner, by oid
 */
void
AlterConversionOwner_oid(Oid conversionOid, Oid newOwnerId)
{
	Relation	rel;

	rel = heap_open(ConversionRelationId, RowExclusiveLock);

	AlterConversionOwner_internal(rel, conversionOid, newOwnerId);

	heap_close(rel, NoLock);
}

/*
 * AlterConversionOwner_internal
 *
 * Internal routine for changing the owner.  rel must be pg_conversion, already
 * open and suitably locked; it will not be closed.
 */
static void
AlterConversionOwner_internal(Relation rel, Oid conversionOid, Oid newOwnerId)
{
	Form_pg_conversion convForm;
	HeapTuple	tup;

	Assert(RelationGetRelid(rel) == ConversionRelationId);

	tup = SearchSysCacheCopy(CONVOID,
							 ObjectIdGetDatum(conversionOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(tup)) /* should not happen */
		elog(ERROR, "cache lookup failed for conversion %u", conversionOid);

	convForm = (Form_pg_conversion) GETSTRUCT(tup);

	/*
	 * If the new owner is the same as the existing owner, consider the
	 * command to have succeeded.  This is for dump restoration purposes.
	 */
	if (convForm->conowner != newOwnerId)
	{
		/* Permission checks */
		ac_conversion_alter(HeapTupleGetOid(tup), NULL, newOwnerId);

		/*
		 * Modify the owner --- okay to scribble on tup because it's a copy
		 */
		convForm->conowner = newOwnerId;

		simple_heap_update(rel, &tup->t_self, tup);

		CatalogUpdateIndexes(rel, tup);

		/* Update owner dependency reference */
		changeDependencyOnOwner(ConversionRelationId, conversionOid,
								newOwnerId);
	}

	heap_freetuple(tup);
}
