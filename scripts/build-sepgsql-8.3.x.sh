#!/bin/sh
export LANG=C

# ---- build parametors
SEPGSQL_MAJOR_VERSION="2"
SEPGSQL_MINOR_OFFSET="538"
SEPGSQL_EXTENSION=".beta"
SEPGSQL_BRANCH="/trunk"

# -- SE-PostgreSQL repository
SEPGSQL_REPOSITORY=`(cd \`dirname $0\`/..; pwd)`

# -- SE-PostgreSQL version number
BASE_VERSION=`grep AC_INIT ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH}/base/configure.in \
    | head -1 \
    | sed -e 's/,/ /g' -e 's/\[//g' -e 's/\]//g' \
    | awk '{print $2}'`

svn update ${SEPGSQL_REPOSITORY} || exit 1
SEPGSQL_MINOR_VERSION=`svn info ${SEPGSQL_REPOSITORY} | egrep '^Revision:' | awk '{print $2}'`
SEPGSQL_MINOR_VERSION=`expr ${SEPGSQL_MINOR_VERSION} - ${SEPGSQL_MINOR_OFFSET}`
SEPGSQL_VERSION="${SEPGSQL_MAJOR_VERSION}.${SEPGSQL_MINOR_VERSION}"

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

echo "GEN: sepostgresql-pgace-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch"
diff -rpNU3 base pgace > ${RPMSOURCE}/sepostgresql-pgace-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch

echo "GEN: sepostgresql-pg_dump-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch"
diff -rpNU3 pgace/src/bin sepgsql/src/bin > ${RPMSOURCE}/sepostgresql-pg_dump-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch
rm -rf pgace/src/bin sepgsql/src/bin

echo "GEN: sepostgresql-sepgsql-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch"
diff -rpNU3 pgace sepgsql > ${RPMSOURCE}/sepostgresql-sepgsql-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch

echo "GEN: sepostgresql.init"
cat package/sepostgresql.init | \
    sed "s/%%__base_postgresql_version__%%/${BASE_VERSION}/g" | \
    sed "s/%%__sepgsql_version__%%/${SEPGSQL_VERSION}/g" \
        > ${RPMSOURCE}/sepostgresql.init

echo "GEN: sepostgresql.spec"
__SEPGSQL_EXTENSION=""
test -n "${SEPGSQL_EXTENSION}" && \
    __SEPGSQL_EXTENSION="%{!?sepgsql_extension:%define sepgsql_extension ${SEPGSQL_EXTENSION}}"
cat package/sepostgresql.spec | \
    sed "s/%%__base_postgresql_version__%%/${BASE_VERSION}/g" | \
    sed "s/%%__sepgsql_version__%%/${SEPGSQL_VERSION}/g" | \
    sed "s/%%__sepgsql_major_version__%%/${SEPGSQL_MAJOR_VERSION}/g" | \
    sed "s/%%__sepgsql_extension__%%/${__SEPGSQL_EXTENSION}/g" \
    > ${RPMSOURCE}/sepostgresql.spec

echo "CPY: sepostgresql.if"
cp package/sepostgresql.if ${RPMSOURCE}

echo "CPY: sepostgresql.fc"
cp package/sepostgresql.fc ${RPMSOURCE}

echo "CPY: sepostgresql.te"
cat package/sepostgresql.te | \
    sed "s/%%POLICY_VERSION%%/${SEPGSQL_VERSION}/g" \
    > ${RPMSOURCE}/sepostgresql.te

echo "CPY: sepostgresql.8"
cp package/sepostgresql.8 ${RPMSOURCE}

echo "CPY: sepostgresql.logrotate"
cp package/sepostgresql.logrotate ${RPMSOURCE}

echo "CPY: sepostgresql-fedora-prefix.patch"
cp package/sepostgresql-fedora-prefix.patch ${RPMSOURCE}

echo "CPY: sepostgresql.logrotate"
cp package/sepostgresql.logrotate ${RPMSOURCE}

# ---- build rpm package
rpmbuild -ba ${RPMSOURCE}/sepostgresql.spec

# ---- clean up
rm -rf ${WORKDIR}
