#!/bin/sh

#
# Testcases for SE-PostgreSQL
#
# usage: ./sepgsql_test.sh
#
export LANG=C

BASEDIR=`(cd \`dirname $0\`; pwd)`
DBNAME='test'

# testcases requires 'psql' and 'runcon' installed
PSQL=`which psql`
test -x "$PSQL" || exit 1

RUNCON=`which runcon`
test -x "$RUNCON" || exit 1

# check system state
if ! /usr/sbin/selinuxenabled ; then
    echo "notice: SELinux is disabled"
    exit 1
fi

if ! $PSQL -qt -c 'SHOW pgace_security_feature' -d $DBNAME | grep -q selinux; then
    echo "notice: SE-PostgreSQL is unavailable"
    exit 1
fi

if [ -x /etc/init.d/mcstrans ]; then
    /etc/init.d/mcstrans status >& /dev/null
    if [ $? -eq 0 ]; then
	echo "notice: please stop /etc/init.d/mcstrans"
	exit 1
    fi
fi

# check user's domain
$RUNCON -t unconfined_t -l s0-s0:c15 /bin/true >& /dev/null
if [ $? -ne 0 ]; then
    echo "error: tester's shell does not have enough permission"
    exit 1
fi

# create working directory
WORKDIR=`mktemp -d` || exit 1
echo "working directory = ${WORKDIR}"

# run testcases
cd $BASEDIR/sql
TESTCASES=`ls ./*.sql`
NUM_TESTS=`ls ./*.sql | wc -l`
COUNT=1

rm -f ${BASEDIR}/result.diff

for X in $TESTCASES
do
    PREFIX=`basename $X | sed -e 's/.sql$//g'`
    SEUSER=`grep '^-- selinux_user:' $BASEDIR/sql/$X | awk '{print $3}'`
    SEROLE=`grep '^-- selinux_role:' $BASEDIR/sql/$X | awk '{print $3}'`
    SETYPE=`grep '^-- selinux_type:' $BASEDIR/sql/$X | awk '{print $3}'`
    SERANGE=`grep '^-- selinux_range:' $BASEDIR/sql/$X | awk '{print $3}'`

    echo -n "  [${COUNT}/${NUM_TESTS}] ${PREFIX} ... "

    $RUNCON "${SEUSER}:${SEROLE}:${SETYPE}:${SERANGE}" \
	$PSQL -aq -d $DBNAME -f $X >& ${WORKDIR}/${PREFIX}.out

    diff -NU20 $BASEDIR/expected/${PREFIX}.out ${WORKDIR}/${PREFIX}.out > ${WORKDIR}/${PREFIX}.diff
    if [ $? -eq 0 ]; then
	echo "OK"
    else
	echo "FAIL"
    fi
    cat ${WORKDIR}/${PREFIX}.diff >> ${BASEDIR}/result.diff

    COUNT=`expr $COUNT + 1`
done

echo "${BASEDIR}/result.diff shows differences from expected result"
