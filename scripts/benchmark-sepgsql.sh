#!/bin/sh

# PARAMETERS:
#
# $PATH
#   has to be set correctly.
# $PGDATA
#   has to be set to the database cluster
# $MINSCALE (default:  2)
#   is the smallest scaling-factor
# $MAXSCALE (default: 20)
#   is the largest scaling-factor
# $NUMCLIENT (default: # of CPUs)
#   is the -c option of pgbench
# $NUMTRANS (default: 10000)
#   is the -t option of pgbench
# $NUMLOOP (default: 5)
#   is the number of iterations

test -n "$MINSCALE"  || MINSCALE=2
test -n "$MAXSCALE"  || MAXSCALE=20
test -n "$NUMCLIENT" || NUMCLIENT=`grep -ci ^processor /proc/cpuinfo`
test -n "$NUMTRANS"  || NUMTRANS=10000
test -n "$NUMLOOP"   || NUMLOOP=5

for feature in selinux none
do
    pg_ctl -l /dev/null -o "--pgace_feature=$feature" restart >& /dev/null
    while sleep 1
    do
	psql -ac "show pgace_feature" postgres && break
    done

    dropdb ${feature}
    createdb ${feature}

    for scale in `seq $MINSCALE $MAXSCALE`
    do
	pgbench -i -s ${scale} ${feature} 2> /dev/null
	echo "#### SELECT ONLY (${feature}) ########"
	for i in `seq 1 ${NUMLOOP}`
	do
	    pgbench -S -c ${NUMCLIENT} -t ${NUMTRANS} ${feature}
	done

	echo "#### Standard Benchmark (${feature}) ########"
	for i in `seq 1 ${NUMLOOP}`
	do
	    pgbench -c ${NUMCLIENT} -t ${NUMTRANS} ${feature}
	done
    done
done
