/*
 * src/include/security/rowlevel.h
 *    Definition of the facility of row-level access controls
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef ROWLEVEL_H
#define ROWLEVEL_H

#include "nodes/execnodes.h"

extern void
rowlvSetScanPolicy(ScanState *sstate, EState *estate);

#endif	/* ROWLEVEL_H */
