#!/bin/sh
export LANG=C

# ---- build parametors
SEPGSQL_EXTENSION=""
SEPGSQL_BRANCH="/branches/pgsql-8.3.x"
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
SEPGSQL_VERSION=`svn info ${SEPGSQL_REPOSITORY} | egrep '^Revision:' | awk '{print $2}'`

# -- lookup RPMS/SOURCE directory
RPMSOURCE=`rpm -E '%{_sourcedir}'`
test -d ${RPMSOURCE} || exit 1

# -- get base postgresql tar+gz, if necessary
if [ ! -e ${RPMSOURCE}/postgresql-${BASE_VERSION}.tar.bz2 ]; then
    wget -O ${RPMSOURCE}/postgresql-${BASE_VERSION}.tar.bz2 \
	"ftp://ftp.postgresql.org/pub/source/v${BASE_VERSION}/postgresql-${BASE_VERSION}.tar.bz2" || exit 1
fi

# -- make a working directory
WORKDIR=`mktemp -d`
cd ${WORKDIR}

# -- print notice
echo "==== now Starting SE-PostgreSQL build ===="
echo "  sepostgresql-${BASE_VERSION}-${SEPGSQL_VERSION}${SEPGSQL_EXTENSION}${DIST}"
echo "  working directory: ${WORKDIR}"
echo "  repository: ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH}"
echo

# -- make a SE-PostgreSQL patch
svn export ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH} altroot || exit 1
cd altroot

echo "GEN: sepostgresql-utils-${BASE_MAJOR}.patch"
diff -rpNU3 base/src/bin sepgsql-new/src/bin > ${RPMSOURCE}/sepostgresql-utils-${BASE_MAJOR}.patch
rm -rf base/src/bin sepgsql-new/src/bin

echo "GEN: sepostgresql-test-${BASE_MAJOR}.patch"
diff -rpNU3 base/src/test sepgsql-new/src/test > ${RPMSOURCE}/sepostgresql-test-${BASE_MAJOR}.patch
rm -rf base/src/test sepgsql-new/src/test

echo "GEN: sepostgresql-core-${BASE_MAJOR}.patch"
diff -rpNU3 base sepgsql-new > ${RPMSOURCE}/sepostgresql-core-${BASE_MAJOR}.patch

echo "GEN: sepostgresql.init"
cat package/sepostgresql.init					\
    | sed "s/%%__base_postgresql_version__%%/${BASE_VERSION}/g"	\
    | sed "s/%%__sepgsql_version__%%/${SEPGSQL_VERSION}/g"	\
    > ${RPMSOURCE}/sepostgresql.init

echo "GEN: sepostgresql.spec"
cat package/sepostgresql-new.spec				\
    | sed "s/%%__base_version__%%/${BASE_VERSION}/g"		\
    | sed "s/%%__base_major_version__%%/${BASE_MAJOR}/g"	\
    | sed "s/%%__sepgsql_version__%%/${SEPGSQL_VERSION}/g"	\
    > ${RPMSOURCE}/sepostgresql.spec

echo "CPY: sepostgresql.8"
cp package/sepostgresql.8 ${RPMSOURCE}

echo "CPY: sepostgresql.logrotate"
cp package/sepostgresql.logrotate ${RPMSOURCE}

echo "CPY: sepostgresql-fedora-prefix.patch"
cp package/sepostgresql-fedora-prefix.patch ${RPMSOURCE}

echo "CPY: sepostgresql.logrotate"
cp package/sepostgresql.logrotate ${RPMSOURCE}

# ---- build rpm package
rpmbuild -bs ${RPMSOURCE}/sepostgresql.spec

# ---- clean up
rm -rf ${WORKDIR}
