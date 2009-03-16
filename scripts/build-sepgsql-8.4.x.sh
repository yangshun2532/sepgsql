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
NEXT_MAJOR="8.5devel"	# workaround

svn update ${SEPGSQL_REPOSITORY} || exit 1
SEPGSQL_REVISION=`svn info ${SEPGSQL_REPOSITORY} | egrep '^Revision:' | awk '{print $2}'`

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
echo "  sepostgresql-${BASE_VERSION}-${SEPGSQL_REVISION}${DIST}"
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

echo "GEN: sepgsql-sysatt-${BASE_VERSION}.patch"
diff -Nrpc sepgsql sysatt	> ${RPMSOURCE}/sepgsql-sysatt-${BASE_MAJOR}.patch

echo "GEN: sepgsql-rowlv-${BASE_VERSION}.patch"
diff -Nrpc sysatt rowlv		> ${RPMSOURCE}/sepgsql-rowlv-${BASE_MAJOR}.patch

echo "GEN: sepgsql-blobs-${BASE_VERSION}.patch"
diff -Nrpc rowlv blobs		> ${RPMSOURCE}/sepgsql-blobs-${BASE_MAJOR}.patch

echo "GEN: sepgsql-utils-${BASE_VERSION}.patch"
diff -Nrpc base/src/bin sepgsql/src/bin	> ${RPMSOURCE}/sepgsql-utils-${BASE_MAJOR}.patch
rm -rf base/src/bin sepgsql/src/bin

echo "GEN: sepgsql-policy-${BASE_VERSION}.patch"
diff -Nrpc base/src/backend/security/sepgsql/policy	\
           sepgsql/src/backend/security/sepgsql/policy	\
    > ${RPMSOURCE}/sepgsql-policy-${BASE_MAJOR}.patch
rm -rf sepgsql/src/backend/security/sepgsql/policy

echo "GEN: sepgsql-docs-${BASE_VERSION}.patch"
diff -Nrpc base/doc sepgsql/doc				\
    > ${RPMSOURCE}/sepgsql-docs-${BASE_MAJOR}.patch
rm -rf base/doc sepgsql/doc

echo "GEN: sepgsql-tests-${BASE_VERSION}.patch"
diff -Nrpc base/src/test sepgsql/src/test		\
    > ${RPMSOURCE}/sepgsql-tests-${BASE_MAJOR}.patch
rm -rf base/src/test sepgsql/src/test

echo "GEN: sepgsql-core-${BASE_VERSION}.patch"
diff -Nrpc base sepgsql					\
    > ${RPMSOURCE}/sepgsql-core-${BASE_MAJOR}.patch

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

# ---- build rpm package, if necessary
if [ ${GEN_PATCH_ONLY} -eq 0 ]; then
    rpmbuild -ba ${RPMSOURCE}/sepostgresql.spec
fi

mv ${RPMSOURCE}/sepgsql-core-${BASE_MAJOR}.patch	\
    ${RPMSOURCE}/sepgsql-core-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepgsql-utils-${BASE_MAJOR}.patch	\
    ${RPMSOURCE}/sepgsql-utils-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepgsql-policy-${BASE_MAJOR}.patch	\
    ${RPMSOURCE}/sepgsql-policy-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepgsql-docs-${BASE_MAJOR}.patch	\
    ${RPMSOURCE}/sepgsql-docs-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepgsql-tests-${BASE_MAJOR}.patch	\
    ${RPMSOURCE}/sepgsql-tests-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepgsql-sysatt-${BASE_MAJOR}.patch	\
    ${RPMSOURCE}/sepgsql-sysatt-${NEXT_MAJOR}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepgsql-rowlv-${BASE_MAJOR}.patch	\
    ${RPMSOURCE}/sepgsql-rowlv-${NEXT_MAJOR}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepgsql-blobs-${BASE_MAJOR}.patch	\
    ${RPMSOURCE}/sepgsql-blobs-${NEXT_MAJOR}-r${SEPGSQL_REVISION}.patch

echo "---- LIST OF GENERATED PATCHES ----"
echo "[1/5] ${RPMSOURCE}/sepgsql-core-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch"
echo "[2/5] ${RPMSOURCE}/sepgsql-utils-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch"
echo "[3/5] ${RPMSOURCE}/sepgsql-policy-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch"
echo "[4/5] ${RPMSOURCE}/sepgsql-docs-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch"
echo "[5/5] ${RPMSOURCE}/sepgsql-tests-${BASE_MAJOR}-r${SEPGSQL_REVISION}.patch"
echo "[6/5] ${RPMSOURCE}/sepgsql-sysatt-${NEXT_MAJOR}-r${SEPGSQL_REVISION}.patch"
echo "[7/5] ${RPMSOURCE}/sepgsql-rowlv-${NEXT_MAJOR}-r${SEPGSQL_REVISION}.patch"
echo "[8/5] ${RPMSOURCE}/sepgsql-blobs-${NEXT_MAJOR}-r${SEPGSQL_REVISION}.patch"

# ---- clean up
rm -rf ${WORKDIR}
