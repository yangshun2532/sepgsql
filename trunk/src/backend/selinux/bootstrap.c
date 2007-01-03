/*
 * src/backend/selinux/bootstrap.c
 *    SE-PgSQL bootstrap hook functions.
 *
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/htup.h"
#include "bootstrap/bootstrap.h"
#include "catalog/pg_database.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_selinux.h"
#include "miscadmin.h"
#include "sepgsql.h"
#include "utils/builtins.h"

#include <selinux/flask.h>
#include <selinux/av_permissions.h>
#include <selinux/selinux.h>

/* ---- initial security context ---- */
static struct {
	psid sid;
	security_context_t context;
} init_context[7];
#define initcon_server			(init_context[0])
#define initcon_client			(init_context[1])
#define initcon_database		(init_context[2])
#define initcon_table			(init_context[3])
#define initcon_procedure		(init_context[4])
#define initcon_column			(init_context[5])
#define initcon_tuple			(init_context[6])
#define initcon_blob			(init_context[7])
static bool init_context_available = false;
static psid init_context_psid = SelinuxRelationId - 1;

static void setup_init_context()
{
	int i, j;

	for (i=0; i < lengthof(init_context); i++) {

		switch (i) {
		case 0:
			if (getcon_raw(&initcon_server.context) != 0)
				selerror("could not obtain the initial server context");
			break;
		case 1:
			if (getcon_raw(&initcon_client.context) != 0)
				selerror("could not obtain the initial client context");
			break;
		case 2:
			if (security_compute_create_raw(initcon_client.context,
											initcon_server.context,
											SECCLASS_DATABASE,
											&initcon_database.context))
				selerror("could not obtain the initial database context");
			break;
		case 3:
			if (security_compute_create_raw(initcon_client.context,
											initcon_database.context,
											SECCLASS_TABLE,
											&initcon_table.context)!=0)
				selerror("could not obtain the initial table context");
			break;
		case 4:
			if (security_compute_create_raw(initcon_client.context,
											initcon_database.context,
											SECCLASS_PROCEDURE,
											&initcon_procedure.context) != 0)
				selerror("could not obtain the initial procedure context");
			break;
		case 5:
			if (security_compute_create_raw(initcon_client.context,
											initcon_table.context,
											SECCLASS_COLUMN,
											&initcon_column.context) != 0)
				selerror("could not obtain the initial column context");
			break;
		case 6:
			if (security_compute_create_raw(initcon_client.context,
											initcon_table.context,
											SECCLASS_TUPLE,
											&initcon_tuple.context) != 0)
				selerror("could not obtain the initial tuple context");
			break;
		case 7:
			if (security_compute_create_raw(initcon_client.context,
											initcon_database.context,
											SECCLASS_BLOB,
											&initcon_blob.context) != 0)
				selerror("could not obtain the initial blob context");
			break;
		default:
			selerror("overbounds of initial security contexts");
		}

		for (j=0; j < i; j++) {
			if (!strcmp(init_context[i].context, init_context[j].context)) {
				init_context[i].sid = init_context[j].sid;
				break;
			}
		}
		if (j == i)
			init_context[i].sid = init_context_psid--;
	}
	init_context_available = true;
}

psid sepgsqlBootstrap_context_to_psid(char *context)
{
	int i;

	if (!init_context_available)
		setup_init_context();

	for (i=0; i < lengthof(init_context); i++) {
		if (!strcmp(init_context[i].context, context))
			return init_context[i].sid;
	}
	selerror("could find psid in initial security contexts (for context='%s')", context);
	return InvalidOid; /* compiler kindness */
}

char *sepgsqlBootstrap_psid_to_context(psid sid)
{
	int i;

	if (!init_context_available)
		setup_init_context();

	for (i=0; i < lengthof(init_context); i++) {
		if (init_context[i].sid == sid)
			return pstrdup(init_context[i].context);
	}
	selerror("could find context in initial security contexts (for psid=%u)", sid);
	return NULL; /* compiler kindness */
}

void sepgsqlBootstrapPostCreateRelation(Oid relid)
{
	Relation rel;
	HeapTuple tuple;
	psid recent;
	char isnulls[1] = {' '};
	Datum values[1];
	int i;

	if (relid != SelinuxRelationId)
		return;

	rel = relation_open(relid, AccessExclusiveLock);

	for (i=0, recent=SelinuxRelationId; i < lengthof(init_context); i++) {
		if (init_context[i].sid >= recent)
			continue;
		values[0] = DirectFunctionCall1(textin, CStringGetDatum(init_context[i].context));
		tuple = heap_formtuple(RelationGetDescr(rel), values, isnulls);
		HeapTupleSetOid(tuple, init_context[i].sid);
		simple_heap_insert(rel, tuple);
		heap_freetuple(tuple);

		recent = init_context[i].sid;
	}

	relation_close(rel, NoLock);
}

int sepgsqlBootstrapInsertOneValue(int index)
{
	int rc = 0;

	if (!init_context_available)
		setup_init_context();

	if (boot_reldesc == NULL)
		selerror("no open relation to assign a security context");

	switch (boot_reldesc->rd_id) {
	case DatabaseRelationId:
		if (index == Anum_pg_database_datselcon - 1) {
			InsertOneValue(initcon_database.context, index);
			rc = 1;
		}
		break;
	case RelationRelationId:
		if (index == Anum_pg_class_relselcon - 1) {
			InsertOneValue(initcon_table.context, index);
			rc = 1;
		}
		break;
	case ProcedureRelationId:
		if (index == Anum_pg_proc_proselcon - 1) {
			InsertOneValue(initcon_procedure.context, index);
			rc = 1;
		}
		break;
	case AttributeRelationId:
		if (index == Anum_pg_attribute_attispsid - 1) {
			InsertOneValue("f", index);
			InsertOneValue(initcon_column.context, index + 1);
			rc = 2;
		}
		break;
	}
	return rc;
}

void sepgsqlBootstrapFormrdesc(Relation rel)
{
	TupleDesc tupDesc = rel->rd_att;
	int i;

	if (!IsBootstrapProcessingMode())
		return;

	if (!init_context_available)
		setup_init_context();

	for (i=0; i < tupDesc->natts; i++)
		tupDesc->attrs[i]->attselcon = initcon_column.sid;;
}
