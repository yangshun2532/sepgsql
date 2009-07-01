#!/bin/sh
export LANG=C

# ---- build parametors
SEPGSQL_BRANCH="/trunk"
DIST="`rpm -E '%{dist}'`"

# -- SE-PostgreSQL repository
SEPGSQL_REPOSITORY=`(cd \`dirname $0\`/..; pwd)`

# -- SE-PostgreSQL version number
BASE_VERSION=`grep AC_INIT ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH}/base/configure.in \
    | head -1 \
    | sed -e 's/,/ /g' -e 's/\[//g' -e 's/\]//g' \
    | awk '{print $2}'`
BASE_MAJOR=`echo $BASE_VERSION | sed 's/\.[0-9]\+$//g'`

svn update ${SEPGSQL_REPOSITORY} || exit 1
SEPGSQL_REVISION=`svn info ${SEPGSQL_REPOSITORY} | egrep '^Revision:' | awk '{print $2}'`

# -- lookup RPMS/SOURCE directory
RPMSOURCE=`rpm -E '%{_sourcedir}'`
test -d ${RPMSOURCE} || exit 1

# -- make a working directory
WORKDIR=`mktemp -d`
cd ${WORKDIR}

# -- make a SE-PostgreSQL patch
echo "Exporting ${SEPGSQL_BRANCH}/base ..."
svn export ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH}/base
echo "Exporting ${SEPGSQL_BRANCH}/blobs ..."
svn export ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH}/blob-toast

echo "Generating pgsql-lobj-perms-${BASE_MAJOR}.patch"
diff -Nrpc base blobs \
    > ${RPMSOURCE}/pgsql-blob-toast-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch

echo "--- LIST OF GENERATED PATCHES ----"
echo "00) ${RPMSOURCE}/pgsql-blob-toast-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch"

# ---- clean up
rm -rf ${WORKDIR}
