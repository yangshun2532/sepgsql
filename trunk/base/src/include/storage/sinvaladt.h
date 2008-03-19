/*-------------------------------------------------------------------------
 *
 * sinvaladt.h
 *	  POSTGRES shared cache invalidation segment definitions.
 *
 * The shared cache invalidation manager is responsible for transmitting
 * invalidation messages between backends.	Any message sent by any backend
 * must be delivered to all already-running backends before it can be
 * forgotten.
 * 
 * The struct type SharedInvalidationMessage, defining the contents of
 * a single message, is defined in sinval.h.
 *
 * Portions Copyright (c) 1996-2008, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * $PostgreSQL: pgsql/src/include/storage/sinvaladt.h,v 1.47 2008/03/17 11:50:27 alvherre Exp $
 *
 *-------------------------------------------------------------------------
 */
#ifndef SINVALADT_H
#define SINVALADT_H

#include "storage/sinval.h"


/*
 * prototypes for functions in sinvaladt.c
 */
extern Size SInvalShmemSize(void);
extern void CreateSharedInvalidationState(void);
extern void SharedInvalBackendInit(void);

extern bool SIInsertDataEntry(SharedInvalidationMessage *data);
extern int SIGetDataEntry(int backendId, SharedInvalidationMessage *data);
extern void SIDelExpiredDataEntries(bool locked);

extern LocalTransactionId GetNextLocalTransactionId(void);

#endif   /* SINVALADT_H */
