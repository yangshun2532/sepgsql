/*
 * src/include/security/sepgsql.h
 *
 * Headers for SE-PostgreSQL
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef SEPGSQL_H
#define SEPGSQL_H

#include "nodes/bitmapset.h"

typedef char *sepgsql_label_t;

/* GUC option to control mode in SE-PostgreSQL */
#define SEPGSQL_MODE_DEFAULT		1
#define SEPGSQL_MODE_ENFORCING		2
#define SEPGSQL_MODE_PERMISSIVE		3
#define SEPGSQL_MODE_INTERNAL		4
#define SEPGSQL_MODE_DISABLED		5

extern int	sepostgresql_mode;

/* GUC option to turn on/off mcstrans */
extern bool	sepostgresql_mcstrans;

/* Internal code for object classes */
enum {
	SEPG_CLASS_DB_DATABASE = 0,
	SEPG_CLASS_DB_SCHEMA,
	SEPG_CLASS_DB_TABLE,
	SEPG_CLASS_DB_COLUMN,
	SEPG_CLASS_MAX
};

/* Internal code for permissions */
#define SEPG_DB_DATABASE__CREATE			(1<<0)
#define SEPG_DB_DATABASE__DROP				(1<<1)
#define SEPG_DB_DATABASE__GETATTR			(1<<2)
#define SEPG_DB_DATABASE__SETATTR			(1<<3)
#define SEPG_DB_DATABASE__RELABELFROM		(1<<4)
#define SEPG_DB_DATABASE__RELABELTO			(1<<5)
#define SEPG_DB_DATABASE__ACCESS			(1<<6)
#define SEPG_DB_DATABASE__LOAD_MODULE		(1<<7)
#define SEPG_DB_DATABASE__SUPERUSER			(1<<8)

#define SEPG_DB_SCHEMA__CREATE				(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_SCHEMA__DROP				(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_SCHEMA__GETATTR				(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_SCHEMA__SETATTR				(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_SCHEMA__RELABELFROM			(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_SCHEMA__RELABELTO			(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_SCHEMA__SEARCH				(1<<6)
#define SEPG_DB_SCHEMA__ADD_NAME			(1<<7)
#define SEPG_DB_SCHEMA__REMOVE_NAME			(1<<8)

#define SEPG_DB_TABLE__CREATE				(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_TABLE__DROP					(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_TABLE__GETATTR				(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_TABLE__SETATTR				(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_TABLE__RELABELFROM			(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_TABLE__RELABELTO			(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_TABLE__SELECT				(1<<6)
#define SEPG_DB_TABLE__UPDATE				(1<<7)
#define SEPG_DB_TABLE__INSERT				(1<<8)
#define SEPG_DB_TABLE__DELETE				(1<<9)
#define SEPG_DB_TABLE__LOCK					(1<<10)
#define SEPG_DB_TABLE__REFERENCE			(1<<11)

#define SEPG_DB_COLUMN__CREATE				(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_COLUMN__DROP				(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_COLUMN__GETATTR				(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_COLUMN__SETATTR				(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_COLUMN__RELABELFROM			(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_COLUMN__RELABELTO			(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_COLUMN__SELECT				(1<<6)
#define SEPG_DB_COLUMN__UPDATE				(1<<7)
#define SEPG_DB_COLUMN__INSERT				(1<<8)
#define SEPG_DB_COLUMN__REFERENCE			(1<<9)

/*
 * selinux.c : communication routines with in-kernel SELinux
 */
extern bool sepgsql_is_enabled(void);

typedef void (*sepgsql_audit_hook_t) (bool denied,
									  const char *scontext,
									  const char *tcontext,
									  const char *tclass,
									  const char *permissions,
									  const char *audit_name);
extern bool
sepgsql_compute_perms(char *scontext, char *tcontext,
					  uint16 tclass, uint32 required,
					  const char *audit_name, bool abort);
extern char *
sepgsql_compute_create(char *scontext, char *tcontext, uint16 tclass);

extern char *sepgsql_mcstrans_out(char *context);
extern char *sepgsql_mcstrans_in(char *context);

/*
 * label.c : management of security context
 */




/*
 * hooks.c : entrypoints of mandatory access controls
 */






#endif	/* SEPGSQL_H */
