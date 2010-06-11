/*
 * label.c
 *
 * It provides security label support in SELinux
 *
 * Author: KaiGai Kohei <kaigai@ak.jp.nec.com>
 *
 * Copyright (c) 2007 - 2010, NEC Corporation
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"




static char *
sepgsql_get_local_label(Oid relOid, Oid objOid, int32 subId)
{
	Relation	rel;
	SysScanDesc	scan;
	ScanKeyData	skey[3];
	HeapTuple	tuple;
	char	   *seclabel = NULL;

	Relation    description;
    ScanKeyData skey[3];
    SysScanDesc sd;
    TupleDesc   tupdesc;
    HeapTuple   tuple;
    char       *comment;

    /* Use the index to search for a matching old tuple */

    ScanKeyInit(&skey[0],
                Anum_pg_description_objoid,
                BTEqualStrategyNumber, F_OIDEQ,
                ObjectIdGetDatum(oid));
    ScanKeyInit(&skey[1],
                Anum_pg_description_classoid,
                BTEqualStrategyNumber, F_OIDEQ,
                ObjectIdGetDatum(classoid));
    ScanKeyInit(&skey[2],
                Anum_pg_description_objsubid,
                BTEqualStrategyNumber, F_INT4EQ,
                Int32GetDatum(subid));

    description = heap_open(DescriptionRelationId, AccessShareLock);
    tupdesc = RelationGetDescr(description);

    sd = systable_beginscan(description, DescriptionObjIndexId, true,
                            SnapshotNow, 3, skey);

    comment = NULL;
    while ((tuple = systable_getnext(sd)) != NULL)
    {
        Datum       value;
        bool        isnull;

        /* Found the tuple, get description field */
        value = heap_getattr(tuple, Anum_pg_description_description, tupdesc, &isnull);
        if (!isnull)
            comment = TextDatumGetCString(value);
        break;                  /* Assume there can be only one match */
    }

    systable_endscan(sd);

    /* Done */
    heap_close(description, AccessShareLock);

    return comment;
}

static char *
sepgsql_get_shared_label(Oid relOid, Oid objOid, int32 subId)
{}

char *
sepgsql_get_label(Oid relOid, Oid objOid, int32 subId)
{
	if (IsSharedRelation(relOid))
		return sepgsql_get_shared_label(relOid, objOid, subId);
	else
		return sepgsql_get_local_label(relOid, objOid, subId);
}
