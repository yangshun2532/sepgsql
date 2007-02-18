/*
 * src/backend/security/sepgsqlDatabase.c
 *   SE-PostgreSQL hooks related to misc database object.
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "catalog/pg_authid.h"
#include "security/sepgsql.h"

/*
 * pg_database related hoosk
 */
void sepgsqlCreateDatabase(HeapTuple tuple)
{
	psid ncon;
	ncon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
								 sepgsqlGetServerPsid(),
								 SECCLASS_DATABASE);
	HeapTupleSetSecurity(tuple, ncon);
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DATABASE,
						   DATABASE__CREATE,
						   HeapTupleGetDatabaseName(tuple));
}

void sepgsqlAlterDatabase(HeapTuple tuple, char *dselcon)
{
	psid ocon, ncon = InvalidOid;
	uint32 perms;

	ocon = HeapTupleGetSecurity(tuple);
	perms = DATABASE__SETATTR;
	if (dselcon) {
		Datum _ncon = DirectFunctionCall1(psid_in, CStringGetDatum(dselcon));
		ncon = DatumGetObjectId(_ncon);
		if (ocon != ncon)
			perms |= DATABASE__RELABELFROM;
	}

	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   ocon,
						   SECCLASS_DATABASE,
						   perms,
						   HeapTupleGetDatabaseName(tuple));
	if (ocon != ncon) {
		sepgsql_avc_permission(sepgsqlGetClientPsid(),
							   ncon,
							   SECCLASS_DATABASE,
							   DATABASE__RELABELTO,
							   HeapTupleGetDatabaseName(tuple));
		HeapTupleSetSecurity(tuple, ncon);
	}
}

void sepgsqlDropDatabase(HeapTuple tuple)
{
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DATABASE,
						   DATABASE__DROP,
						   HeapTupleGetDatabaseName(tuple));
}

/*
 * pg_authid related hoohs
 */
void sepgsqlCreateRole(Relation rel, HeapTuple tuple)
{
	psid ncon;
	Assert(RelationGetRelid(rel) == AuthIdRelationId);

	ncon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
								 sepgsqlGetDatabasePsid(),
								 SECCLASS_DATABASE);
	HeapTupleSetSecurity(tuple, ncon);
	sepgsqlCheckTuplePerms(rel, tuple, TUPLE__INSERT);
}

void sepgsqlAlterRole(Relation rel, HeapTuple newtup, HeapTuple oldtup)
{
	/* now, we don't have ALTER ROLE ... CONTEXT = 'xxx' statement */
	psid ocon;
	Assert(RelationGetRelid(rel) == AuthIdRelationId);

	ocon = HeapTupleGetSecurity(oldtup);
	sepgsqlCheckTuplePerms(rel, oldtup, TUPLE__UPDATE);
	HeapTupleSetSecurity(newtup, ocon);
}

void sepgsqlDropRole(Relation rel, HeapTuple tuple)
{
	Assert(RelationGetRelid(rel) == AuthIdRelationId);

	sepgsqlCheckTuplePerms(rel, tuple, TUPLE__DELETE);
}
