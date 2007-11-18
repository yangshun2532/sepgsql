/*-------------------------------------------------------------------------
 *
 * random.c
 *	  random() wrapper
 *
 * Portions Copyright (c) 1996-2007, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  $PostgreSQL: pgsql/src/port/random.c,v 1.8 2007/01/05 22:20:03 momjian Exp $
 *
 *-------------------------------------------------------------------------
 */

#include "c.h"

#include <math.h>


long
random()
{
	return lrand48();
}
