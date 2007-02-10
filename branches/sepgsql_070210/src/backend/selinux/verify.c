/*
 * src/backend/selinux/verify.c
 *
 *
 *
 */
#include "postgres.h"

#include "optimizer/plancat.h"
#include "sepgsql.h"
#include "utils/syscache.h"
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

static void verifyPgClassPermsInheritances(Oid relid, uint32 perms);

static void verifyPgClassPerms(Oid relid, bool inh, uint32 perms)
{
	Form_pg_class cls;
	HeapTuple tuple;
	char *audit;
	int rc;

	/* check table:{required permissions} */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("RELOID cache lookup failed (relid=%u)", relid);
	cls = (Form_pg_class) GETSTRUCT(tuple);

	if (cls->relkind == RELKIND_RELATION) {
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
									cls->relselcon,
									SECCLASS_TABLE,
									perms,
									&audit);
		sepgsql_audit(rc, audit, NameStr(cls->relname));
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
	Form_pg_attribute attr;
	HeapTuple tuple;
	char *audit;
	int rc;

	tuple = SearchSysCache(ATTNUM,
						   ObjectIdGetDatum(relid),
						   Int16GetDatum(attno),
						   0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("ATTNUM cache lookup failed (relid=%u, attno=%d)", relid, attno);
	attr = (Form_pg_attribute) GETSTRUCT(tuple);

	/* check column:{required permissions} */
	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								attr->attselcon,
								SECCLASS_COLUMN,
								perms,
								&audit);
	sepgsql_audit(rc, audit, NameStr(attr->attname));

	/* check child relations, if necesasry */
	if (inh)
		verifyPgAttributePermsInheritances(relid, NameStr(attr->attname), perms);

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
	Form_pg_proc proc;
	HeapTuple tuple;
	psid curcon, newcon;
	char *audit;
	int rc;

	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(funcid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("PROCID cache lookup failed (proid=%u)", funcid);
	proc = (Form_pg_proc) GETSTRUCT(tuple);
	
	/* compute domain transition */
	curcon = sepgsqlGetClientPsid();
	newcon = sepgsql_avc_createcon(curcon, proc->proselcon,
								   SECCLASS_PROCESS);
	if (curcon != newcon)
		perms |= PROCEDURE__ENTRYPOINT;

	/* check procedure executiong permission */
	rc = sepgsql_avc_permission(curcon, proc->proselcon,
								SECCLASS_PROCEDURE,
								perms, &audit);
	sepgsql_audit(rc, audit, NameStr(proc->proname));

	/* check domain transition, if necessary */
	if (curcon != newcon) {
		rc = sepgsql_avc_permission(curcon, newcon,
									SECCLASS_PROCESS,
									PROCESS__TRANSITION,
									&audit);
		sepgsql_audit(rc, audit, NULL);
	}

	ReleaseSysCache(tuple);
}

void sepgsqlVerifyQuery(Query *query)
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
