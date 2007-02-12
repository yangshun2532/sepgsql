/*
 * src/backend/selinux/bootstrap.c
 *    SE-PgSQL bootstrap hook functions.
 *
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/htup.h"
#include "access/xact.h"
#include "bootstrap/bootstrap.h"
#include "catalog/indexing.h"
#include "catalog/pg_database.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_selinux.h"
#include "miscadmin.h"
#include "sepgsql.h"
#include "utils/builtins.h"
#include "utils/syscache.h"

#include <unistd.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>
#include <selinux/selinux.h>
#include <sys/file.h>


char *sepgsqlBootstrapPsidToContext(psid sid)
{
	char fname[MAXPGPATH], buffer[1024];
	FILE *filp;
	psid cursid;

	snprintf(fname, sizeof(fname), "%s/%s", DataDir, EARLY_PG_SELINUX);
	filp = fopen(fname, "rb");
	if (!filp)
		goto not_found;
	flock(fileno(filp), LOCK_SH);
	while (fscanf(filp, "%u %s", &cursid, buffer) == 2) {
		if (cursid == sid) {
			fclose(filp);
			return pstrdup(buffer);
		}
	}
	fclose(filp);

not_found:
	selerror("No string expression for psid=%u", sid);
	return NULL;
}

HeapTuple sepgsqlInsertOneTuple(HeapTuple tuple, Relation rel)
{
	TupleDesc tdesc;
	psid icon, econ, tcon;
	AttrNumber attno = 0;
	uint16 tclass;
	uint32 perms;
	bool isnull;
	char *audit;
	int rc;

	if (!rel)
		selerror("no open relation to assign a security context");

	tdesc = RelationGetDescr(rel);

	switch (RelationGetRelid(rel)) {
	case DatabaseRelationId:
		attno = Anum_pg_database_datselcon;
		tclass = SECCLASS_DATABASE;
		tcon = sepgsqlGetServerPsid();
		break;
	case RelationRelationId:
		attno = Anum_pg_class_relselcon;
		tclass = SECCLASS_TABLE;
		tcon = sepgsqlGetDatabasePsid();
		break;
	case ProcedureRelationId:
		attno = Anum_pg_proc_proselcon;
		tclass = SECCLASS_PROCEDURE;
		tcon = sepgsqlGetDatabasePsid();
		break;
	case AttributeRelationId:
		attno = Anum_pg_attribute_attselcon;
		tclass = SECCLASS_COLUMN;
		tcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
									 sepgsqlGetDatabasePsid(),
									 SECCLASS_TABLE);
		break;
	default:
		for (attno = 1; attno <= tdesc->natts; attno++) {
			if (sepgsqlAttributeIsPsid(tdesc->attrs[attno - 1]))
				break;
		}
		tclass = SECCLASS_TUPLE;
		tcon = RelationGetForm(rel)->relselcon;
		break;
	}
	if (attno < 1 || attno > tdesc->natts)
		return tuple;

	icon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
								 tcon,
								 tclass);
	econ = ObjectIdGetDatum(heap_getattr(tuple,
										 attno,
										 RelationGetDescr(rel),
										 &isnull));
	if (isnull) {
		HeapTuple newtup;
		Datum *values;
		bool *nulls, *repls;

		/* implicit labeling */
		perms = ((tclass == SECCLASS_TUPLE)
				 ? TUPLE__INSERT : COMMON_DATABASE__SETATTR);
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
									icon, tclass, perms, &audit);
		sepgsql_audit(rc, audit, NULL);

		values = palloc0(sizeof(Datum) * RelationGetNumberOfAttributes(rel));
		nulls  = palloc0(sizeof(bool)  * RelationGetNumberOfAttributes(rel));
		repls  = palloc0(sizeof(bool)  * RelationGetNumberOfAttributes(rel));

		values[attno - 1] = ObjectIdGetDatum(icon);
		nulls[attno - 1] = false;
		repls[attno - 1] = true;

		newtup = heap_modify_tuple(tuple, RelationGetDescr(rel),
								   values, nulls, repls);
		heap_freetuple(tuple);
		tuple = newtup;

		pfree(values);
		pfree(nulls);
		pfree(repls);
	} else {
		/* explicit labeling  */
		perms = ((tclass == SECCLASS_TUPLE)
				 ? TUPLE__INSERT : COMMON_DATABASE__SETATTR);
		if (icon != econ)
			perms |= ((tclass == SECCLASS_TUPLE)
					  ? TUPLE__RELABELFROM : COMMON_DATABASE__RELABELFROM);
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
									icon, tclass, perms, &audit);
		sepgsql_audit(rc, audit, NULL);

		if (icon != econ) {
			perms = ((tclass == SECCLASS_TUPLE)
					 ? TUPLE__RELABELTO : COMMON_DATABASE__RELABELTO);
			rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
										econ, tclass, perms, &audit);
			sepgsql_audit(rc, audit, NULL);
		}
	}
	return tuple;
}
