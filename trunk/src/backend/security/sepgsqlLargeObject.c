/*
 * src/backend/security/sepgsqlLargeObject.c
 *   SE-PostgreSQL hooks related to binary large object
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "security/sepgsql.h"

void sepgsqlLargeObjectCreate(Relation rel, HeapTuple tuple)
{
	psid newcon;

	newcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
								   sepgsqlGetDatabasePsid(),
								   SECCLASS_BLOB);

	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   newcon,
						   SECCLASS_BLOB,
						   BLOB__CREATE,
						   NULL);
	HeapTupleSetSecurity(tuple, newcon);
}

void sepgsqlLargeObjectDrop(Relation rel, HeapTuple tuple)
{
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_BLOB,
						   BLOB__DROP,
						   NULL);
}

void sepgsqlLargeObjectGetattr(Relation rel, HeapTuple tuple)
{
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_BLOB,
						   BLOB__GETATTR,
						   NULL);
}

void sepgsqlLargeObjectSetattr(Relation rel, HeapTuple oldtup, HeapTuple newtup)
{
	if (HeapTupleGetSecurity(oldtup) == HeapTupleGetSecurity(newtup))
		return;
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(oldtup),
						   SECCLASS_BLOB,
						   BLOB__SETATTR | BLOB__RELABELFROM,
						   NULL);
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(newtup),
						   SECCLASS_BLOB,
						   BLOB__RELABELTO,
						   NULL);
}

void sepgsqlLargeObjectRead(Relation rel, HeapTuple tuple)
{
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_BLOB,
						   BLOB__READ,
						   NULL);
}

void sepgsqlLargeObjectWrite(Relation rel, HeapTuple tuple)
{
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
                           HeapTupleGetSecurity(tuple),
                           SECCLASS_BLOB,
                           BLOB__WRITE,
                           NULL);
}

void sepgsqlLargeObjectImport()
{
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   sepgsqlGetServerPsid(),
						   SECCLASS_BLOB,
						   BLOB__IMPORT,
						   NULL);
}

void sepgsqlLargeObjectExport()
{
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   sepgsqlGetServerPsid(),
						   SECCLASS_BLOB,
						   BLOB__EXPORT,
						   NULL);
}

