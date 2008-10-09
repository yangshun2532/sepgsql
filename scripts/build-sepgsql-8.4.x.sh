#!/bin/sh
export LANG=C

# ---- build parametors
SEPGSQL_MAJOR_VERSION="3"
SEPGSQL_EXTENSION=".alpha"
SEPGSQL_BRANCH="/trunk"

# -- SE-PostgreSQL repository
SEPGSQL_REPOSITORY=`(cd \`dirname $0\`/..; pwd)`

# -- SE-PostgreSQL version number
BASE_VERSION=`grep AC_INIT ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH}/base/configure.in \
    | head -1 \
    | sed -e 's/,/ /g' -e 's/\[//g' -e 's/\]//g' \
    | awk '{print $2}'`

svn update ${SEPGSQL_REPOSITORY} || exit 1
SEPGSQL_REVISION=`svn info ${SEPGSQL_REPOSITORY} | egrep '^Revision:' | awk '{print $2}'`
SEPGSQL_VERSION="${SEPGSQL_MAJOR_VERSION}.${SEPGSQL_REVISION}"

# -- Parse Option
GEN_PATCH_ONLY=0
test "--patch" = "$1" && GEN_PATCH_ONLY=1

# -- lookup RPMS/SOURCE directory
RPMSOURCE=`rpm -E '%{_sourcedir}'`
test -d ${RPMSOURCE} || exit 1

## -- get base postgresql tar+gz, if necessary
#if [ ${GEN_PATCH_ONLY} -ne 0 ]; then
#    if [ ! -e ${RPMSOURCE}/postgresql-${BASE_VERSION}.tar.bz2 ]; then
#        wget -O ${RPMSOURCE}/postgresql-${BASE_VERSION}.tar.bz2 \
#	    "ftp://ftp.postgresql.org/pub/source/v${BASE_VERSION}/postgresql-${BASE_VERSION}.tar.bz2" || exit 1
#    fi
#fi

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

if [ ${GEN_PATCH_ONLY} -eq 0 ]; then
    mv base postgresql-${BASE_VERSION}
    echo "GEN: postgresql-${BASE_VERSION}.tar.bz2"
    chmod a+x postgresql-${BASE_VERSION}/configure
    tar -jcf ${RPMSOURCE}/postgresql-${BASE_VERSION}.tar.bz2 postgresql-${BASE_VERSION}
    mv postgresql-${BASE_VERSION} base
fi

echo "GEN: sepostgresql-row_acl-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch"
diff -rpNU3 sepgsql row_acl				\
    > ${RPMSOURCE}/sepostgresql-row_acl-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch

echo "GEN: sepostgresql-pg_dump-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch"
diff -rpNU3 base/src/bin sepgsql/src/bin		\
    > ${RPMSOURCE}/sepostgresql-pg_dump-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch
rm -rf base/src/bin sepgsql/src/bin

echo "GEN: sepostgresql-policy-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch"
diff -rpNU3 base/src/backend/security/sepgsql/policy	\
            sepgsql/src/backend/security/sepgsql/policy	\
    > ${RPMSOURCE}/sepostgresql-policy-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch
rm -rf sepgsql/src/backend/security/sepgsql/policy

echo "GEN: sepostgresql-docs-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch"
diff -rpNU3 base/doc sepgsql/doc			\
    > ${RPMSOURCE}/sepostgresql-docs-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch
rm -rf base/doc sepgsql/doc

echo "GEN: sepostgresql-tests-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch"
diff -rpNU3 base/src/test sepgsql/src/test		\
    > ${RPMSOURCE}/sepostgresql-tests-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch
rm -rf base/src/test sepgsql/src/test

echo "GEN: sepostgresql-sepgsql-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch"
diff -rpNU3 base sepgsql				\
    > ${RPMSOURCE}/sepostgresql-sepgsql-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch

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

echo "CPY: sepostgresql.8"
cp package/sepostgresql.8 ${RPMSOURCE}

echo "CPY: sepostgresql.logrotate"
cp package/sepostgresql.logrotate ${RPMSOURCE}

echo "CPY: sepostgresql-fedora-prefix.patch"
cp package/sepostgresql-fedora-prefix.patch ${RPMSOURCE}

# ---- build rpm package, if necessary
if [ ${GEN_PATCH_ONLY} -eq 0 ]; then
    rpmbuild -ba ${RPMSOURCE}/sepostgresql.spec
fi

mv ${RPMSOURCE}/sepostgresql-sepgsql-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch	\
    ${RPMSOURCE}/sepostgresql-sepgsql-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepostgresql-pg_dump-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch	\
    ${RPMSOURCE}/sepostgresql-pg_dump-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepostgresql-policy-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch  \
    ${RPMSOURCE}/sepostgresql-policy-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepostgresql-docs-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch \
    ${RPMSOURCE}/sepostgresql-docs-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepostgresql-tests-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch \
    ${RPMSOURCE}/sepostgresql-tests-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepostgresql-row_acl-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch \
    ${RPMSOURCE}/sepostgresql-row_acl-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}-r${SEPGSQL_REVISION}.patch

echo "---- LIST OF GENERATED PATCHES ----"
echo "${RPMSOURCE}/sepostgresql-sepgsql-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}-r${SEPGSQL_REVISION}.patch"
echo "${RPMSOURCE}/sepostgresql-pg_dump-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}-r${SEPGSQL_REVISION}.patch"
echo "${RPMSOURCE}/sepostgresql-policy-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}-r${SEPGSQL_REVISION}.patch"
echo "${RPMSOURCE}/sepostgresql-docs-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}-r${SEPGSQL_REVISION}.patch"
echo "${RPMSOURCE}/sepostgresql-tests-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}-r${SEPGSQL_REVISION}.patch"
echo "${RPMSOURCE}/sepostgresql-row_acl-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}-r${SEPGSQL_REVISION}.patch"

# ---- clean up
rm -rf ${WORKDIR}
