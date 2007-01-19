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

#define EARLY_PG_SELINUX  "global/pg_selinux.bootstrap"

bool sepgsqlBootstrapPgSelinuxAvailable()
{
	static bool pg_selinux_available = false;
	char fname[MAXPGPATH];
	FILE *filp;

	if (IsBootstrapProcessingMode())
		return false;

	if (pg_selinux_available)
		return true;

	snprintf(fname, sizeof(fname), "%s/%s", DataDir, EARLY_PG_SELINUX);
	filp = fopen(fname, "rb");
	if (filp) {
		Relation rel;
		CatalogIndexState index;
		HeapTuple tup;
		Datum value;
		char isnull;

		PG_TRY();
		{
			char buffer[1024];
			psid sid;

			rel = heap_open(SelinuxRelationId, RowExclusiveLock);
			index = CatalogOpenIndexes(rel);
			while (fscanf(filp, "%u %s", &sid, buffer) == 2) {
				value = DirectFunctionCall1(textin, CStringGetDatum(buffer));
				isnull = ' ';
				tup = heap_formtuple(RelationGetDescr(rel), &value, &isnull);
				HeapTupleSetOid(tup, sid);
				simple_heap_insert(rel, tup);
				CatalogIndexInsert(index, tup);

				heap_freetuple(tup);
			}
			CatalogCloseIndexes(index);
			heap_close(rel, NoLock);

			CommandCounterIncrement();
			CatalogCacheFlushRelation(SelinuxRelationId);
		}
		PG_CATCH();
		{
			fclose(filp);
			PG_RE_THROW();
		}
		PG_END_TRY();
		fclose(filp);
		unlink(fname);
	}
	pg_selinux_available = true;
	return true;
}

psid sepgsqlBootstrapContextToPsid(char *context)
{
	char fname[MAXPGPATH], buffer[1024];
	psid sid, minsid = SelinuxRelationId;
	FILE *filp;

	snprintf(fname, sizeof(fname), "%s/%s", DataDir, EARLY_PG_SELINUX);
	filp = fopen(fname, "a+b");
	if (!filp)
		selerror("could not open '%s'", fname);
	flock(fileno(filp), LOCK_EX);
	while (fscanf(filp, "%u %s", &sid, buffer) == 2) {
		if (!strcmp(context, buffer)) {
			fclose(filp);
			return sid;
		}
		if (sid < minsid)
			minsid = sid;
	}
	if (!sepgsql_check_context(context))
		selerror("'%s' is not valid security context", ((char *)2UL));

	sid = minsid - 1;
	fprintf(filp, "%u %s\n", sid, context);
	fclose(filp);

	return sid;
}

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

int sepgsqlBootstrapInsertOneValue(int index)
{
	psid newcon;
	char *context;
	int rc = 0;

	if (boot_reldesc == NULL)
		selerror("no open relation to assign a security context");

	switch (RelationGetRelid(boot_reldesc)) {
	case DatabaseRelationId:
		if (index == Anum_pg_database_datselcon - 1) {
			newcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										   sepgsqlGetServerPsid(),
										   SECCLASS_DATABASE);
			context = sepgsql_psid_to_context(newcon);
			InsertOneValue(context, index);
			pfree(context);
			rc = 1;
		}
		break;
	case RelationRelationId:
		if (index == Anum_pg_class_relselcon - 1) {
			newcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										   sepgsqlGetDatabasePsid(),
										   SECCLASS_TABLE);
			context = sepgsql_psid_to_context(newcon);
			InsertOneValue(context, index);
			pfree(context);
			rc = 1;
		}
		break;
	case ProcedureRelationId:
		if (index == Anum_pg_proc_proselcon - 1) {
			newcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										   sepgsqlGetDatabasePsid(),
										   SECCLASS_PROCEDURE);
			context = sepgsql_psid_to_context(newcon);
			InsertOneValue(context, index);
			pfree(context);
			rc = 1;
		}
		break;
	case AttributeRelationId:
		if (index == Anum_pg_attribute_attispsid - 1) {
			TupleDesc tdesc = RelationGetDescr(boot_reldesc);
			Form_pg_attribute attr = tdesc->attrs[Anum_pg_attribute_attselcon - 1];
			psid tblcon = attr->attselcon;

			InsertOneValue("f", index++);
			newcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										   tblcon,
										   SECCLASS_COLUMN);
			context = sepgsql_psid_to_context(newcon);
			InsertOneValue(context, index);
			pfree(context);
			rc = 2;
		}
		break;
	}
	return rc;
}
