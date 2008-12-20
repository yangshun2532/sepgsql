/*-------------------------------------------------------------------------
 *
 * src/include/nodes/security.h
 *    definitions for security extention related nodes
 *
 * Portions Copyright (c) 2007-2008, PostgreSQL Global Development Group
 *
 *-------------------------------------------------------------------------
 */
#ifndef NODES_SECURITY_H
#define NODES_SECURITY_H

#include "access/attnum.h"
#include "nodes/nodes.h"

/*
 * SEvalItemRelation
 *
 * SE-PostgreSQL permission evaluation item for a relation
 */
typedef struct SEvalItemRelation {
	NodeTag type;

	uint32 perms;

	Oid relid;
	bool inh;
} SEvalItemRelation;

/*
 * SEvalItemAttribute
 *
 * SE-PostgreSQL permission evaluation item for an attribute
 */
typedef struct SEvalItemAttribute {
	NodeTag type;

	uint32 perms;

	Oid relid;
	bool inh;
	AttrNumber attno;
} SEvalItemAttribute;

/*
 * SEvalItemProcedure
 *
 * SE-PostgreSQL permission evaluation item for a procedure
 */
typedef struct SEvalItemProcedure {
	NodeTag type;

	uint32 perms;

	Oid funcid;
} SEvalItemProcedure;

#endif	/* NODES_SECURITY_H */
