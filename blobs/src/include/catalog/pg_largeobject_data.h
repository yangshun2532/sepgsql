/*-------------------------------------------------------------------------
 *
 * pg_largeobject.h
 *	  definition of the system "largeobject" relation (pg_largeobject)
 *	  along with the relation's initial contents.
 *
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * $PostgreSQL: pgsql/src/include/catalog/pg_largeobject.h,v 1.24 2009/01/01 17:23:57 momjian Exp $
 *
 * NOTES
 *	  the genbki.sh script reads this file and generates .bki
 *	  information from the DATA() statements.
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_LARGEOBJECT_DATA_H
#define PG_LARGEOBJECT_DATA_H

#include "catalog/genbki.h"

/* ----------------
 *		pg_largeobject_data definition.	cpp turns this into
 *		typedef struct FormData_pg_largeobject_data
 * ----------------
 */
#define LargeObjectDataRelationId  2966

CATALOG(pg_largeobject_data,2966) BKI_WITHOUT_OIDS
{
	Oid			loid;			/* Identifier of large object */
	int4		pageno;			/* Page number (starting from 0) */
	bytea		data;			/* Data for page (may be zero-length) */
} FormData_pg_largeobject_data;

/* ----------------
 *		Form_pg_largeobject_data corresponds to a pointer to a tuple
 *		with the format of pg_largeobject relation.
 * ----------------
 */
typedef FormData_pg_largeobject_data *Form_pg_largeobject_data;

/* ----------------
 *		compiler constants for pg_largeobject_data
 * ----------------
 */
#define Natts_pg_largeobject_data			3
#define Anum_pg_largeobject_data_loid		1
#define Anum_pg_largeobject_data_pageno		2
#define Anum_pg_largeobject_data_data		3

#endif   /* PG_LARGEOBJECT_DATA_H */
