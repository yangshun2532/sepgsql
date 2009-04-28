#!/bin/sh

# This script pulls the PostgreSQL tree from CVS.
# ---- parametors ----
CVSTAG="HEAD"
SVNBRANCH="/trunk"

SEPGSQL_REPOSITORY=`(cd \`dirname $0\`/..; pwd)`
echo $SEPGSQL_REPOSITORY

if ! env LANG=C svn info $SEPGSQL_REPOSITORY \
    | grep "^URL:" | grep -q "https://sepgsql.googlecode.com/svn"; then
    echo "$SEPGSQL_REPOSITORY is not a SE-PostgreSQL repository"
    exit 1
fi

# ---- make a working directory
WORKDIR=`mktemp -d`
cd ${WORKDIR} || exit 1

# ---- export CVS ----
cvs -z3 -d :pserver:anoncvs@anoncvs.postgresql.org:/projects/cvsroot \
    export -r ${CVSTAG} -d pgsql.cvs pgsql
test $? -eq 0 || exit 1

# ---- export SVN ----
svn update ${SEPGSQL_REPOSITORY}
svn export ${SEPGSQL_REPOSITORY}${SVNBRANCH}/base pgsql.svn
test $? -eq 0 || exit 1

SVNREV=`env LANG=C svn info ${SEPGSQL_REPOSITORY} \
    | grep "^Revision:" \
    | awk '{ print $2; }'`

# ---- make a diff ----
diff -prNU3 pgsql.svn pgsql.cvs > pgsql-updates.diff
(cd pgsql.cvs; find . ) > ./filelist.cvs
(cd pgsql.svn; find . ) > ./filelist.svn
diff -NU3 filelist.svn filelist.cvs > pgsql-filelist.diff

# ---- apply diffs ----
cd ${SEPGSQL_REPOSITORY}${SVNBRANCH}/base
cat ${WORKDIR}/pgsql-updates.diff | patch -p1

cat ${WORKDIR}/pgsql-filelist.diff | egrep "^\+\./" | while read ENT
do
    ENT=`echo $ENT | sed 's/^\+//g'`
    svn add -N ${ENT}
done

cat ${WORKDIR}/pgsql-filelist.diff | egrep "^\-\./" | while read ENT
do
    ENT=`echo $ENT | sed 's/^\-//g'`
    svn del ${ENT}
done

# ---- End ----
echo "$0 done, check diff and following commands"
echo
echo "cd ${SEPGSQL_REPOSITORY}${SVNBRANCH}"
echo "svn diff ./base"
echo "svn commit -m 'CVS pull -r ${CVSTAG} at `env LANG=C date`' ./base"
echo "svn update"
echo
echo "svn merge -c `expr ${SVNREV} + 1` ./base ./sysatt"
echo "svn diff ./sysatt"
echo "svn commit -m 'merge updates of ${SVNBRANCH}/base into ${SVNBRANCH}/sysatt at r`expr ${SVNREV} + 1`' ./sysatt"
echo "svn update"
echo
echo "svn merge -c `expr ${SVNREV} + 2` ./sysatt ./core"
echo "svn diff ./core"
echo "svn commit -m 'merge updates of ${SVNBRANCH}/sysatt into ${SVNBRANCH}/core at r`expr ${SVNREV} + 2`' ./core"
echo "svn update"
echo
echo "svn merge -c `expr ${SVNREV} + 3` ./core ./writable"
echo "svn diff ./writable"
echo "svn commit -m 'merge updates of ${SVNBRANCH}/core into ${SVNBRANCH}/sysatt at r`expr ${SVNREV} + 3`' ./writable"
echo "svn update"
echo
echo "svn merge -c `expr ${SVNREV} + 4` ./writable ./rowlv"
echo "svn diff ./rowlv"
echo "svn commit -m 'merge updates of ${SVNBRANCH}/writable into ${SVNBRANCH}/rowlv at r`expr ${SVNREV} + 4`' ./rowlv"
echo "svn update"
echo
echo "svn merge -c `expr ${SVNREV} + 5` ./rowlv ./perms"
echo "svn diff ./perms"
echo "svn commit -m 'merge updates of ${SVNBRANCH}/rowlv into ${SVNBRANCH}/perms at r`expr ${SVNREV} + 5`' ./perms"
echo "svn update"
echo
echo "svn merge -c `expr ${SVNREV} + 6` ./perms ./sepgsql"
echo "svn diff ./sepgsql"
echo "svn commit -m 'merge updates of ${SVNBRANCH}/perms into ${SVNBRANCH}/sepgsql at r`expr ${SVNREV} + 6`' ./sepgsql"
echo "svn update"

