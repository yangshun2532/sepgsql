/*
 * src/backend/security/sepgsqlCopy.c
 *   SE-PostgreSQL hooks related to COPY TP/COPY FROM statement
 *
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "security/sepgsql.h"

void sepgsqlDoCopy(Relation rel, List *attnumlist, bool is_from)
{
	HeapTuple tuple;
	uint32 perms;
	ListCell *l;

	/* on 'COPY FROM SELECT ...' cases, any checkings are done in select.c */
	if (rel == NULL)
		return;

	/* 1. check table:select/insert permission */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(RelationGetRelid(rel)),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for relation %u", RelationGetRelid(rel));

	perms = (is_from ? TABLE__INSERT : TABLE__SELECT);
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_TABLE,
						   perms,
						   HeapTupleGetRelationName(tuple));
	ReleaseSysCache(tuple);

	/* 2. check column:select/insert for each column */
	perms = (is_from ? COLUMN__INSERT : COLUMN__SELECT);
	foreach(l, attnumlist) {
		char objname[2 * NAMEDATALEN + 1];
		AttrNumber attno = lfirst_int(l);

		tuple = SearchSysCache(ATTNUM,
							   ObjectIdGetDatum(RelationGetRelid(rel)),
							   Int16GetDatum(attno),
							   0, 0);
		if (!HeapTupleIsValid(tuple))
			selerror("cache lookup failed for attribute %d, relation %u",
					 attno, RelationGetRelid(rel));

		snprintf(objname, sizeof(objname), "%s.%s",
				 RelationGetRelationName(rel),
				 HeapTupleGetAttributeName(tuple));

		perms = (is_from ? COLUMN__INSERT : COLUMN__SELECT);
		sepgsql_avc_permission(sepgsqlGetClientPsid(),
							   HeapTupleGetSecurity(tuple),
							   SECCLASS_COLUMN,
							   perms,
							   objname);
		ReleaseSysCache(tuple);
	}
}

bool sepgsqlCopyTo(Relation rel, HeapTuple tuple)
{
	Datum rc;

	rc = DirectFunctionCall3(sepgsql_tuple_perms,
							 ObjectIdGetDatum(RelationGetRelid(rel)),
							 PointerGetDatum(tuple->t_data),
							 Int32GetDatum(TUPLE__SELECT));
	return BoolGetDatum(rc);
}


