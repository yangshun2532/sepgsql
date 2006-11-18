/*-------------------------------------------------------------------------
 *
 * pg_largeobject.h
 *	  definition of the system "largeobject" relation (pg_largeobject)
 *	  along with the relation's initial contents.
 *
 *
 * Portions Copyright (c) 1996-2006, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * $PostgreSQL: pgsql/src/include/catalog/pg_largeobject.h,v 1.20 2006/03/05 15:58:54 momjian Exp $
 *
 * NOTES
 *	  the genbki.sh script reads this file and generates .bki
 *	  information from the DATA() statements.
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_LARGEOBJECT_H
#define PG_LARGEOBJECT_H

/* ----------------
 *		postgres.h contains the system type definitions and the
 *		CATALOG(), BKI_BOOTSTRAP and DATA() sugar words so this file
 *		can be read by both genbki.sh and the C compiler.
 * ----------------
 */

/* ----------------
 *		pg_largeobject definition.	cpp turns this into
 *		typedef struct FormData_pg_largeobject
 * ----------------
 */
#define LargeObjectRelationId  2613

CATALOG(pg_largeobject,2613) BKI_WITHOUT_OIDS
{
	Oid			loid;			/* Identifier of large object */
	int4		pageno;			/* Page number (starting from 0) */
#ifdef HAVE_SELINUX
	psid		selcon;			/* security context */
#endif
	bytea		data;			/* Data for page (may be zero-length) */
} FormData_pg_largeobject;

/* ----------------
 *		Form_pg_largeobject corresponds to a pointer to a tuple with
 *		the format of pg_largeobject relation.
 * ----------------
 */
typedef FormData_pg_largeobject *Form_pg_largeobject;

/* ----------------
 *		compiler constants for pg_largeobject
 * ----------------
 */
#ifdef HAVE_SELINUX
#define Natts_pg_largeobject			4
#else
#define Natts_pg_largeobject			3
#endif
#define Anum_pg_largeobject_loid		1
#define Anum_pg_largeobject_pageno		2
#ifdef HAVE_SELINUX
#define Anum_pg_largeobject_selcon		3
#define Anum_pg_largeobject_data		4
#else
#define Anum_pg_largeobject_data		3
#endif

extern void LargeObjectCreate(Oid loid);
extern void LargeObjectDrop(Oid loid);
extern bool LargeObjectExists(Oid loid);

#endif   /* PG_LARGEOBJECT_H */
