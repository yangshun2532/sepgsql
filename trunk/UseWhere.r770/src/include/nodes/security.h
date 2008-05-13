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

/* ----------------
 * SEvalItem
 *
 *   This structure contains what permissions should be evaluated by SE-PostgreSQL.
 *
 *   tclass		object class of SELinux
 *   perms		permissions of SELinux
 *   relid		relation id, not used for SECCLASS_DB_PROCEDURE
 *   inh		indication whether relid is inherited, or not
 *   attno		attribute number, only used for SECCLASS_DB_COLUMN
 *   funcid		procedure id, only used for SECCLASS_DB_PROCEDURE
 * ----------------
 */
typedef struct SEvalItem {
	NodeTag type;

	uint16 tclass;
	uint32 perms;

	Oid relid;
	bool inh;
	AttrNumber attno;
	Oid funcid;
} SEvalItem;

#endif	/* NODES_SECURITY_H */
