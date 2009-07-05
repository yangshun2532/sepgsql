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

# -- print notice
echo "==== now Starting SE-PostgreSQL build ===="
echo "  base version: ${BASE_VERSION}"
echo "  revision: ${SEPGSQL_REVISION}"
echo "  working directory: ${WORKDIR}"
echo "  repository: ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH}"
echo

# -- exporting branches
TREES="base sysatt core gram writable rowlv rowacl perms sepgsql package"
for name in ${TREES}
do
  echo "Exporting ${SEPGSQL_BRANCH}/${name} ..."
  svn export ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH}/${name} || exit 1
done

# -- generating patches
echo "GEN: sepgsql-05-docs-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
diff -Nrpc base/doc gram/doc			\
    > ${RPMSOURCE}/sepgsql-05-docs-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch
rm -rf ./*/doc

echo "GEN: sepgsql-04-tests-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
diff -Nrpc base/src/test gram/src/test	\
    > ${RPMSOURCE}/sepgsql-04-tests-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch
rm -rf ./*/src/test

# For first commit fest
echo "GEN: sepgsql-01-sysatt-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
diff -Nrpc base sysatt		\
    > ${RPMSOURCE}/sepgsql-01-sysatt-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch

echo "GEN: sepgsql-02-core-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
diff -Nrpc sysatt core		\
    > ${RPMSOURCE}/sepgsql-02-core-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch

echo "GEN: sepgsql-03-gram-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
diff -Nrpc core gram		\
    > ${RPMSOURCE}/sepgsql-03-gram-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch

# For second commit fest
echo "GEN: sepgsql-06-writable-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
diff -Nrpc gram writable	\
    > ${RPMSOURCE}/sepgsql-06-writable-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch

echo "GEN: sepgsql-07-rowlevel-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
diff -Nrpc writable rowlv	\
    > ${RPMSOURCE}/sepgsql-07-rowlevel-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch

echo "GEN: sepgsql-08-rowacl-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
diff -Nrpc rowlv rowacl		\
    > ${RPMSOURCE}/sepgsql-08-rowacl-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch

# For third commit fest?
echo "GEN: sepgsql-09-perms-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
diff -Nrpc rowacl perms		\
    > ${RPMSOURCE}/sepgsql-09-perms-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch

echo "GEN: sepgsql-10-extra-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
diff -Nrpc perms sepgsql	\
    > ${RPMSOURCE}/sepgsql-10-extra-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch

echo "GEN: sepostgresql.init"
cat package/sepostgresql.init					\
    | sed "s/%%__base_version__%%/${BASE_VERSION}/g"		\
    > ${RPMSOURCE}/sepostgresql.init

echo "GEN: sepostgresql.spec"
cat package/sepostgresql.spec					\
    | sed "s/%%__base_version__%%/${BASE_VERSION}/g"		\
    | sed "s/%%__base_major_version__%%/${BASE_MAJOR}/g"	\
    | sed "s/%%__sepgsql_revision__%%/${SEPGSQL_REVISION}/g"	\
    > ${RPMSOURCE}/sepostgresql.spec

echo "CPY: sepostgresql.8"
cp package/sepostgresql.8 ${RPMSOURCE}

echo "CPY: sepostgresql.logrotate"
cp package/sepostgresql.logrotate ${RPMSOURCE}

echo "CPY: sepgsql-fedora-prefix.patch"
cp package/sepgsql-fedora-prefix.patch ${RPMSOURCE}

echo "---- LIST OF GENERATED PATCHES ----"
echo "01) ${RPMSOURCE}/sepgsql-01-sysatt-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch"
echo "02) ${RPMSOURCE}/sepgsql-02-core-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch"
echo "03) ${RPMSOURCE}/sepgsql-03-gram-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch"
echo "04) ${RPMSOURCE}/sepgsql-04-tests-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch"
echo "05) ${RPMSOURCE}/sepgsql-05-docs-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch"
echo "---- 1st commit fest ----"
echo "06) ${RPMSOURCE}/sepgsql-06-writable-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch"
echo "07) ${RPMSOURCE}/sepgsql-07-rowlevel-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch"
echo "08) ${RPMSOURCE}/sepgsql-08-rowacl-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
echo "---- 2nd commit fest ----"
echo "09) ${RPMSOURCE}/sepgsql-09-perms-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch"
echo "10) ${RPMSOURCE}/sepgsql-10-extra-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch"
echo "---- 3rd commit fest ----"

# ---- clean up
rm -rf ${WORKDIR}
