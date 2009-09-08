/*-------------------------------------------------------------------------
 *
 * sysattr.h
 *	  POSTGRES system attribute definitions.
 *
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * $PostgreSQL: pgsql/src/include/access/sysattr.h,v 1.2 2009/01/01 17:23:56 momjian Exp $
 *
 *-------------------------------------------------------------------------
 */
#ifndef SYSATTR_H
#define SYSATTR_H


/*
 * Attribute numbers for the system-defined attributes
 */
#define SelfItemPointerAttributeNumber			(-1)
#define ObjectIdAttributeNumber					(-2)
#define MinTransactionIdAttributeNumber			(-3)
#define MinCommandIdAttributeNumber				(-4)
#define MaxTransactionIdAttributeNumber			(-5)
#define MaxCommandIdAttributeNumber				(-6)
#define TableOidAttributeNumber					(-7)
#define SecurityContextAttributeNumber			(-8)
#define FirstLowInvalidHeapAttributeNumber		(-9)

/*
 * Attribute names for the system-defined attributes
 */
#define SelfItemPointerAttributeName			"ctid"
#define ObjectIdAttributeName					"oid"
#define MinTransactionIdAttributeName			"xmin"
#define MinCommandIdAttributeName				"cmin"
#define MaxTransactionIdAttributeName			"xmax"
#define MaxCommandIdAttributeName				"cmax"
#define TableOidAttributeName					"tableoid"
#define SecurityContextAttributeName			"security_context"

#endif   /* SYSATTR_H */
