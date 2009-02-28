/*-------------------------------------------------------------------------
 *
 * syscache.h
 *	  System catalog cache definitions.
 *
 * See also lsyscache.h, which provides convenience routines for
 * common cache-lookup operations.
 *
 * Portions Copyright (c) 1996-2008, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * $PostgreSQL: pgsql/src/include/utils/syscache.h,v 1.71 2008/01/01 19:45:59 momjian Exp $
 *
 *-------------------------------------------------------------------------
 */
#ifndef SYSCACHE_H
#define SYSCACHE_H

#include "utils/catcache.h"

/*
 *		Declarations for util/syscache.c.
 *
 *		SysCache identifiers.
 *
 *		The order of these must match the order
 *		they are entered into the structure cacheinfo[] in syscache.c.
 *		Keep them in alphabetical order.
 */

#define AGGFNOID			0
#define AMNAME				1
#define AMOID				2
#define AMOPOPID			3
#define AMOPSTRATEGY		4
#define AMPROCNUM			5
#define ATTNAME				6
#define ATTNUM				7
#define AUTHMEMMEMROLE		8
#define AUTHMEMROLEMEM		9
#define AUTHNAME			10
#define AUTHOID				11
#define CASTSOURCETARGET	12
#define CLAAMNAMENSP		13
#define CLAOID				14
#define CONDEFAULT			15
#define CONNAMENSP			16
#define CONSTROID			17
#define CONVOID				18
#define DATABASEOID			19
#define ENUMOID				20
#define ENUMTYPOIDNAME		21
#define INDEXRELID			22
#define LANGNAME			23
#define LANGOID				24
#define NAMESPACENAME		25
#define NAMESPACEOID		26
#define OPERNAMENSP			27
#define OPEROID				28
#define OPFAMILYAMNAMENSP	29
#define OPFAMILYOID			30
#define PROCNAMEARGSNSP		31
#define PROCOID				32
#define RELNAMENSP			33
#define RELOID				34
#define RULERELNAME			35
#define SECURITYOID			36
#define SECURITYLABEL		37
#define STATRELATT			38
#define TSCONFIGMAP			39
#define TSCONFIGNAMENSP		40
#define TSCONFIGOID			41
#define TSDICTNAMENSP		42
#define TSDICTOID			43
#define TSPARSERNAMENSP		44
#define TSPARSEROID			45
#define TSTEMPLATENAMENSP	46
#define TSTEMPLATEOID		47
#define TYPENAMENSP			48
#define TYPEOID				49

extern void InitCatalogCache(void);
extern void InitCatalogCachePhase2(void);

extern HeapTuple SearchSysCache(int cacheId,
			   Datum key1, Datum key2, Datum key3, Datum key4);
extern void ReleaseSysCache(HeapTuple tuple);

extern void InsertSysCache(Oid relid, HeapTuple tuple);

/* convenience routines */
extern HeapTuple SearchSysCacheCopy(int cacheId,
				   Datum key1, Datum key2, Datum key3, Datum key4);
extern bool SearchSysCacheExists(int cacheId,
					 Datum key1, Datum key2, Datum key3, Datum key4);
extern Oid GetSysCacheOid(int cacheId,
			   Datum key1, Datum key2, Datum key3, Datum key4);

extern HeapTuple SearchSysCacheAttName(Oid relid, const char *attname);
extern HeapTuple SearchSysCacheCopyAttName(Oid relid, const char *attname);
extern bool SearchSysCacheExistsAttName(Oid relid, const char *attname);

extern Datum SysCacheGetAttr(int cacheId, HeapTuple tup,
				AttrNumber attributeNumber, bool *isNull);

/* list-search interface.  Users of this must import catcache.h too */
extern struct catclist *SearchSysCacheList(int cacheId, int nkeys,
				   Datum key1, Datum key2, Datum key3, Datum key4);

#define ReleaseSysCacheList(x)	ReleaseCatCacheList(x)

#endif   /* SYSCACHE_H */
