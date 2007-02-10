/*
 * src/include/catalog/pg_selinux.h
 *    definition of the system "security context" relation (pg_selinux)
 *
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#ifndef PG_SELINUX_H
#define PG_SELINUX_H

#ifdef HAVE_SELINUX

#define SelinuxRelationId	3400

CATALOG(pg_selinux,3400) BKI_SHARED_RELATION
{
	text	selcontext;		/* string expression of security context */
} FormData_pg_selinux;

/* ----------------
 *		Form_pg_selinux corresponds to a pointer to a tuple with
 *		the format of pg_selinux relation.
 * ----------------
 */
typedef FormData_pg_selinux *Form_pg_selinux;

/* ----------------
 *		compiler constants for pg_selinux
 * ----------------
 */
#define Natts_pg_selinux				1
#define Anum_pg_selinux_selcontext		1

#endif   /* HAVE_SELINUX */
#endif   /* PG_SELINUX_H */
