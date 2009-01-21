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
 * SelinuxEvalItem
 *
 * Required permissions on tables/columns used by SE-PostgreSQL.
 * It is constracted just after query rewriter phase, then its
 * list is checked based on the security policy of operating
 * system.
 *
 * NOTE: attperms array can contains system attributes and
 * whole-row-reference, so it is indexed as
 *   attperms[(attnum) + FirstLowInvalidHeapAttributeNumber - 1]
 */
typedef struct SelinuxEvalItem
{
	NodeTag		type;

	Oid			relid;		/* relation id */
	bool		inh;		/* flags to inheritable/only */

	uint32		relperms;	/* required permissions on table */
	uint32		nattrs;		/* length of attperms */
	uint32	   *attperms;	/* required permissions on columns */
} SelinuxEvalItem;

#endif	/* NODES_SECURITY_H */
