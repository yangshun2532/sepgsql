/*
 * ace_attribute.c
 *
 * security hooks related to attribute object class.
 *
 * Portions Copyright (c) 1996-2010, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "miscadmin.h"
#include "security/ace.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

void
check_attribute_create(Oid relOid, ColumnDef *cdef)
{}

void
check_attribute_alter(Oid relOid, const char *colName)
{}

void
check_attribute_drop(Oid relOid, const char *colName, bool cascade)
{}

void
check_attribute_grant(Oid relOid, AttrNumber attnum)
{}

void
check_attribute_comment(Oid relOid, const char *colName)
{}
