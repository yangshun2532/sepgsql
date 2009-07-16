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

svn update ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH} || exit 1
SEPGSQL_REVISION=`svn info ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH} \
    | egrep '^Revision:' | awk '{print $2}'`

# -- lookup RPMS/SOURCE directory
RPMSOURCE=`rpm -E '%{_sourcedir}'`
test -d ${RPMSOURCE} || exit 1

# -- make a working directory
WORKDIR=`mktemp -d`
cd ${WORKDIR}

# -- print notice
echo "==== now Starting SE-PostgreSQL build ===="
echo "  base version: ${BASE_VERSION}"
echo "  revision: ${SEPGSQL_REVISION}"
echo "  working directory: ${WORKDIR}"
echo "  repository: ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH}"
echo

# -- exporting branches
TREES="base tiny"
for name in ${TREES}
do
  echo "Exporting ${SEPGSQL_BRANCH}/${name} ..."
  svn export ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH}/${name} || exit 1
done

# -- generating patches
echo "GEN: sepgsql-01-tiny-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
diff -Nrpc base tiny | gzip -c			\
    > ${RPMSOURCE}/sepgsql-01-tiny-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch.gz

echo "---- LIST OF GENERATED PATCHES ----"
echo "01) ${RPMSOURCE}/sepgsql-01-tiny-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch.gz"

# ---- clean up
rm -rf ${WORKDIR}
