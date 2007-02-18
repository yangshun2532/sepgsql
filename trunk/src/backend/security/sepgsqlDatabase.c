/*
 * src/backend/security/sepgsqlDatabase.c
 *   SE-PostgreSQL hooks related to misc database object.
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "security/sepgsql.h"

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

