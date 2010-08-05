/*
 * sepgsql.h
 *
 * Definitions corresponding to SE-PostgreSQL
 *
 * Author: KaiGai Kohei <kaigai@ak.jp.nec.com>
 *
 * Copyright (c) 2007 - 2010, NEC Corporation
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#ifndef SEPGSQL_H
#define SEPGSQL_H

#include <selinux/selinux.h>

/*
 * SE-PostgreSQL Label Tag
 */
#define SEPGSQL_LABEL_TAG			"selinux"

/*
 * SE-PostgreSQL working mode
 */
#define SEPGSQL_MODE_DEFAULT		1
#define SEPGSQL_MODE_INTERNAL		2
#define SEPGSQL_MODE_DISABLED		3

/*
 * Internally used code of object classes
 */
#define SEPG_CLASS_PROCESS			0
#define SEPG_CLASS_FILE				1
#define SEPG_CLASS_DIR				2
#define SEPG_CLASS_LNK_FILE			3
#define SEPG_CLASS_CHR_FILE			4
#define SEPG_CLASS_BLK_FILE			5
#define SEPG_CLASS_SOCK_FILE		6
#define SEPG_CLASS_FIFO_FILE		7
#define SEPG_CLASS_DB_DATABASE		8
#define SEPG_CLASS_DB_SCHEMA		9
#define SEPG_CLASS_DB_TABLE			10
#define SEPG_CLASS_DB_SEQUENCE		11
#define SEPG_CLASS_DB_PROCEDURE		12
#define SEPG_CLASS_DB_COLUMN		13
#define SEPG_CLASS_DB_TUPLE			14
#define SEPG_CLASS_DB_BLOB			15
#define SEPG_CLASS_DB_LANGUAGE		16
#define SEPG_CLASS_MAX				17

/*
 * Internally used code of access vectors
 */
#define SEPG_PROCESS__TRANSITION			(1<<0)

#define SEPG_FILE__READ						(1<<0)
#define SEPG_FILE__WRITE					(1<<1)
#define SEPG_FILE__CREATE					(1<<2)
#define SEPG_FILE__GETATTR					(1<<3)
#define SEPG_FILE__UNLINK					(1<<4)
#define SEPG_FILE__RENAME					(1<<5)
#define SEPG_FILE__APPEND					(1<<6)

#define SEPG_DIR__READ						(SEPG_FILE__READ)
#define SEPG_DIR__WRITE						(SEPG_FILE__WRITE)
#define SEPG_DIR__CREATE					(SEPG_FILE__CREATE)
#define SEPG_DIR__GETATTR					(SEPG_FILE__GETATTR)
#define SEPG_DIR__UNLINK					(SEPG_FILE__UNLINK)
#define SEPG_DIR__RENAME					(SEPG_FILE__RENAME)
#define SEPG_DIR__SEARCH					(1<<6)
#define SEPG_DIR__ADD_NAME					(1<<7)
#define SEPG_DIR__REMOVE_NAME				(1<<8)
#define SEPG_DIR__RMDIR						(1<<9)
#define SEPG_DIR__REPARENT					(1<<10)

#define SEPG_LNK_FILE__READ					(SEPG_FILE__READ)
#define SEPG_LNK_FILE__WRITE				(SEPG_FILE__WRITE)
#define SEPG_LNK_FILE__CREATE				(SEPG_FILE__CREATE)
#define SEPG_LNK_FILE__GETATTR				(SEPG_FILE__GETATTR)
#define SEPG_LNK_FILE__UNLINK				(SEPG_FILE__UNLINK)
#define SEPG_LNK_FILE__RENAME				(SEPG_FILE__RENAME)

#define SEPG_CHR_FILE__READ					(SEPG_FILE__READ)
#define SEPG_CHR_FILE__WRITE				(SEPG_FILE__WRITE)
#define SEPG_CHR_FILE__CREATE				(SEPG_FILE__CREATE)
#define SEPG_CHR_FILE__GETATTR				(SEPG_FILE__GETATTR)
#define SEPG_CHR_FILE__UNLINK				(SEPG_FILE__UNLINK)
#define SEPG_CHR_FILE__RENAME				(SEPG_FILE__RENAME)

#define SEPG_BLK_FILE__READ					(SEPG_FILE__READ)
#define SEPG_BLK_FILE__WRITE				(SEPG_FILE__WRITE)
#define SEPG_BLK_FILE__CREATE				(SEPG_FILE__CREATE)
#define SEPG_BLK_FILE__GETATTR				(SEPG_FILE__GETATTR)
#define SEPG_BLK_FILE__UNLINK				(SEPG_FILE__UNLINK)
#define SEPG_BLK_FILE__RENAME				(SEPG_FILE__RENAME)

#define SEPG_SOCK_FILE__READ				(SEPG_FILE__READ)
#define SEPG_SOCK_FILE__WRITE				(SEPG_FILE__WRITE)
#define SEPG_SOCK_FILE__CREATE				(SEPG_FILE__CREATE)
#define SEPG_SOCK_FILE__GETATTR				(SEPG_FILE__GETATTR)
#define SEPG_SOCK_FILE__UNLINK				(SEPG_FILE__UNLINK)
#define SEPG_SOCK_FILE__RENAME				(SEPG_FILE__RENAME)

#define SEPG_FIFO_FILE__READ				(SEPG_FILE__READ)
#define SEPG_FIFO_FILE__WRITE				(SEPG_FILE__WRITE)
#define SEPG_FIFO_FILE__CREATE				(SEPG_FILE__CREATE)
#define SEPG_FIFO_FILE__GETATTR				(SEPG_FILE__GETATTR)
#define SEPG_FIFO_FILE__UNLINK				(SEPG_FILE__UNLINK)
#define SEPG_FIFO_FILE__RENAME				(SEPG_FILE__RENAME)

#define SEPG_DB_DATABASE__CREATE			(1<<0)
#define SEPG_DB_DATABASE__DROP				(1<<1)
#define SEPG_DB_DATABASE__GETATTR			(1<<2)
#define SEPG_DB_DATABASE__SETATTR			(1<<3)
#define SEPG_DB_DATABASE__RELABELFROM		(1<<4)
#define SEPG_DB_DATABASE__RELABELTO			(1<<5)
#define SEPG_DB_DATABASE__ACCESS			(1<<6)
#define SEPG_DB_DATABASE__LOAD_MODULE		(1<<7)

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
#define SEPG_DB_TABLE__INDEXON				(1<<11)

#define SEPG_DB_SEQUENCE__CREATE			(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_SEQUENCE__DROP				(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_SEQUENCE__GETATTR			(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_SEQUENCE__SETATTR			(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_SEQUENCE__RELABELFROM		(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_SEQUENCE__RELABELTO			(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_SEQUENCE__GET_VALUE			(1<<6)
#define SEPG_DB_SEQUENCE__NEXT_VALUE		(1<<7)
#define SEPG_DB_SEQUENCE__SET_VALUE			(1<<8)

#define SEPG_DB_PROCEDURE__CREATE			(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_PROCEDURE__DROP				(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_PROCEDURE__GETATTR			(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_PROCEDURE__SETATTR			(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_PROCEDURE__RELABELFROM		(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_PROCEDURE__RELABELTO		(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_PROCEDURE__EXECUTE			(1<<6)
#define SEPG_DB_PROCEDURE__ENTRYPOINT		(1<<7)
#define SEPG_DB_PROCEDURE__INSTALL			(1<<8)

#define SEPG_DB_COLUMN__CREATE				(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_COLUMN__DROP				(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_COLUMN__GETATTR				(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_COLUMN__SETATTR				(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_COLUMN__RELABELFROM			(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_COLUMN__RELABELTO			(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_COLUMN__SELECT				(1<<6)
#define SEPG_DB_COLUMN__UPDATE				(1<<7)
#define SEPG_DB_COLUMN__INSERT				(1<<8)

#define SEPG_DB_TUPLE__RELABELFROM			(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_TUPLE__RELABELTO			(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_TUPLE__SELECT				(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_TUPLE__UPDATE				(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_TUPLE__INSERT				(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_TUPLE__DELETE				(SEPG_DB_DATABASE__DROP)

#define SEPG_DB_BLOB__CREATE				(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_BLOB__DROP					(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_BLOB__GETATTR				(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_BLOB__SETATTR				(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_BLOB__RELABELFROM			(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_BLOB__RELABELTO				(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_BLOB__READ					(1<<6)
#define SEPG_DB_BLOB__WRITE					(1<<7)
#define SEPG_DB_BLOB__IMPORT				(1<<8)
#define SEPG_DB_BLOB__EXPORT				(1<<9)

#define SEPG_DB_LANGUAGE__CREATE			(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_LANGUAGE__DROP				(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_LANGUAGE__GETATTR			(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_LANGUAGE__SETATTR			(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_LANGUAGE__RELABELFROM		(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_LANGUAGE__RELABELTO			(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_LANGUAGE__IMPLEMENTE		(1<<6)
#define SEPG_DB_LANGUAGE__EXECUTE			(1<<7)

/*
 * selinux.c
 */
extern bool sepgsql_is_enabled(void);
extern bool sepgsql_get_enforce(void);
extern int  sepgsql_get_mode(void);
extern int  sepgsql_set_mode(int new_mode);

extern void sepgsql_audit_log(bool denied,
							  char *scontext,
							  char *tcontext,
							  uint16 tclass,
							  uint32 audited,
							  const char *audit_name);

extern void sepgsql_compute_avd(char *scontext,
								char *tcontext,
								uint16 tclass,
								struct av_decision *avd);

extern bool sepgsql_compute_perms(char *scontext,
								  char *tcontext,
								  uint16 tclass,
								  uint32 required,
								  const char *audit_name,
								  bool abort);

extern char *sepgsql_compute_create(char *scontext,
									char *tcontext,
									uint16 tclass);

/*
 * hooks.c
 */
extern void sepgsql_register_hooks(void);

/*
 * label.c
 */
extern char *sepgsql_get_client_label(void);
extern char *sepgsql_set_client_label(char *new_label);
extern char *sepgsql_get_unlabeled_label(void);
extern char *sepgsql_get_label(Oid relOid, Oid objOid, int32 subId);

extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_mcstrans_in(PG_FUNCTION_ARGS);
extern Datum sepgsql_mcstrans_out(PG_FUNCTION_ARGS);
extern Datum sepgsql_initial_labeling(PG_FUNCTION_ARGS);

#endif /* SEPGSQL_H */
