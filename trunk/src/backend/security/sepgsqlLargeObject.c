/*
 * src/backend/security/sepgsqlLargeObject.c
 *   SE-PostgreSQL hooks related to binary large object
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/skey.h"
#include "catalog/indexing.h"
#include "catalog/pg_largeobject.h"
#include "security/sepgsql.h"
#include "security/sepgsql_internal.h"
#include "utils/fmgroids.h"

psid sepgsqlLargeObjectGetattr(Oid loid)
{
	Relation rel;
	ScanKeyData skey;
	SysScanDesc sd;
	HeapTuple tuple;
	psid lo_security = InvalidOid;

	if (!sepgsqlIsEnabled())
		selerror("SE-PostgreSQL was disabled");

	ScanKeyInit(&skey,
				Anum_pg_largeobject_loid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(loid));

	rel = heap_open(LargeObjectRelationId, AccessShareLock);

	sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
							SnapshotNow, 1, &skey);

	while ((tuple = systable_getnext(sd)) != NULL) {
		sepgsqlCheckTuplePerms(rel, tuple, TUPLE__SELECT, NULL, 0, true);
		lo_security = HeapTupleGetSecurity(tuple);
		break;
	}
	systable_endscan(sd);

	heap_close(rel, NoLock);

	if (lo_security == InvalidOid)
		selerror("LargeObject %u did not found", loid);

	return lo_security;
}

void sepgsqlLargeObjectSetattr(Oid loid, psid lo_security)
{
	Relation rel;
	ScanKeyData skey;
	SysScanDesc sd;
	HeapTuple tuple, newtup;
	CatalogIndexState indstate;
	bool found = false;

	if (!sepgsqlIsEnabled())
		selerror("SE-PostgreSQL was disabled");

	ScanKeyInit(&skey,
				Anum_pg_largeobject_loid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(loid));

	rel = heap_open(LargeObjectRelationId, RowExclusiveLock);

	indstate = CatalogOpenIndexes(rel);

	sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
							SnapshotNow, 1, &skey);

	while ((tuple = systable_getnext(sd)) != NULL) {
		newtup = heap_copytuple(tuple);
		HeapTupleSetSecurity(newtup, lo_security);
		simple_heap_update(rel, &newtup->t_self, newtup);
		CatalogUpdateIndexes(rel, newtup);
		found = true;
	}
	systable_endscan(sd);
	CatalogCloseIndexes(indstate);
	heap_close(rel, RowExclusiveLock);

	CommandCounterIncrement();

	if (!found)
		selerror("LargeObject %u did not found", loid);
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
