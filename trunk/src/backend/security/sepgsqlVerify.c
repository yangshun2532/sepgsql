/*
 * src/backend/security/sepgsqlVerify.c
 *   SE-PostgreSQL permission verifying functions according to SEvalItem
 *
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "optimizer/plancat.h"
#include "security/sepgsql.h"
#include "security/sepgsql_internal.h"
#include "utils/syscache.h"

static void verifyPgClassPermsInheritances(Oid relid, uint32 perms);

static void verifyPgClassPerms(Oid relid, bool inh, uint32 perms)
{
	Form_pg_class pgclass;
	HeapTuple tuple;

	/* check table:{required permissions} */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("RELOID cache lookup failed (relid=%u)", relid);
	pgclass = (Form_pg_class) GETSTRUCT(tuple);

	if (pgclass->relkind == RELKIND_RELATION) {
		sepgsql_avc_permission(sepgsqlGetClientPsid(),
							   HeapTupleGetSecurity(tuple),
							   SECCLASS_TABLE,
							   perms,
							   HeapTupleGetRelationName(tuple));
	} else {
		selnotice("%s is not a general relation", NameStr(pgclass->relname));
	}
	ReleaseSysCache(tuple);

	/* check child relations, if necessary */
	if (inh)
		verifyPgClassPermsInheritances(relid, perms);
}

static void verifyPgClassPermsInheritances(Oid relid, uint32 perms)
{
	List *chld_list;
	ListCell *l;

	chld_list = find_inheritance_children(relid);
	foreach (l, chld_list) {
		Oid chld_oid = lfirst_oid(l);

		verifyPgClassPerms(chld_oid, true, perms);
	}
}

static void verifyPgAttributePermsInheritances(Oid parent_relid, char *attname, uint32 perms);

static void verifyPgAttributePerms(Oid relid, bool inh, AttrNumber attno, uint32 perms)
{
	HeapTuple tuple;

	tuple = SearchSysCache(ATTNUM,
						   ObjectIdGetDatum(relid),
						   Int16GetDatum(attno),
						   0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("ATTNUM cache lookup failed (relid=%u, attno=%d)", relid, attno);

	/* check column:{required permissions} */
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_COLUMN,
						   perms,
						   HeapTupleGetAttributeName(tuple));

	/* check child relations, if necesasry */
	if (inh)
		verifyPgAttributePermsInheritances(relid, HeapTupleGetAttributeName(tuple), perms);

	ReleaseSysCache(tuple);
}

static void verifyPgAttributePermsInheritances(Oid parent_relid, char *attname, uint32 perms)
{
	List *chld_list;
	ListCell *l;

	chld_list = find_inheritance_children(parent_relid);
	foreach (l, chld_list) {
		Form_pg_attribute attr;
		HeapTuple tuple;
		Oid chld_oid;

		chld_oid = lfirst_oid(l);
		tuple = SearchSysCacheAttName(chld_oid, attname);
		if (!HeapTupleIsValid(tuple)) {
			selnotice("relation %u dose not have attribute '%s'", chld_oid, attname);
			continue;
		}
		attr = (Form_pg_attribute) GETSTRUCT(tuple);
		verifyPgAttributePerms(chld_oid, true, attr->attnum, perms);
		ReleaseSysCache(tuple);
	}
}

static void verifyPgProcPerms(Oid funcid, uint32 perms)
{
	HeapTuple tuple;
	psid newcon;

	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(funcid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for procedure %d", funcid);

	/* compute domain transition */
	newcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
								   HeapTupleGetSecurity(tuple),
								   SECCLASS_PROCESS);
	if (newcon != sepgsqlGetClientPsid())
		perms |= PROCEDURE__ENTRYPOINT;

	/* check procedure executiong permission */
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_PROCEDURE,
						   perms,
						   HeapTupleGetProcedureName(tuple));

	/* check domain transition, if necessary */
	if (newcon != sepgsqlGetClientPsid()) {
		sepgsql_avc_permission(sepgsqlGetClientPsid(),
							   newcon,
							   SECCLASS_PROCESS,
							   PROCESS__TRANSITION,
							   HeapTupleGetProcedureName(tuple));
	}

	ReleaseSysCache(tuple);
}

static void sepgsqlVerifyQuery(Query *query)
{
	ListCell *l;

	foreach (l, query->SEvalItemList) {
		SEvalItem *se = lfirst(l);

		switch (se->tclass) {
		case SECCLASS_TABLE:
			verifyPgClassPerms(se->c.relid, se->c.inh, se->perms);
			break;
		case SECCLASS_COLUMN:
			verifyPgAttributePerms(se->a.relid, se->a.inh, se->a.attno, se->perms);
			break;
		case SECCLASS_PROCEDURE:
			verifyPgProcPerms(se->p.funcid, se->perms);
			break;
		default:
			selerror("unknown SEvalItem (tclass=%u)", se->tclass);
			break;
		}
	}
}

void sepgsqlVerifyQueryList(List *queryList)
{
	ListCell *l;

	if (!sepgsqlIsEnabled())
		return;

	foreach (l, queryList) {
		Query *query = lfirst(l);

		sepgsqlVerifyQuery(query);
	}
}
