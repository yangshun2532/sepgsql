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

# -- get base postgresql tar+gz, if necessary
if [ ${GEN_PATCH_ONLY} -eq 0 ]; then
    if [ ! -e ${RPMSOURCE}/postgresql-${BASE_VERSION}.tar.bz2 ]; then
        wget -O ${RPMSOURCE}/postgresql-${BASE_VERSION}.tar.bz2 \
            "ftp://ftp.postgresql.org/pub/source/v${BASE_VERSION}/postgresql-${BASE_VERSION}.tar.bz2" || exit 1
    fi
fi

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

echo "GEN: sepgsql-00-full-${BASE_VERSION}.patch.gz"
diff -Nrpc base sepgsql | gzip -c		\
    > ${RPMSOURCE}/sepgsql-00-full-${BASE_VERSION}.patch.gz

echo "GEN: sepgsql-10-docs-${BASE_VERSION}.patch"
diff -Nrpc base/doc sepgsql/doc			\
    > ${RPMSOURCE}/sepgsql-10-docs-${BASE_VERSION}.patch
rm -rf ./*/doc

echo "GEN: sepgsql-09-tests-${BASE_VERSION}.patch"
diff -Nrpc base/src/test sepgsql/src/test	\
    > ${RPMSOURCE}/sepgsql-09-tests-${BASE_VERSION}.patch
rm -rf ./*/src/test

echo "GEN: sepgsql-08-utils-${BASE_VERSION}.patch"
diff -Nrpc base/src/bin sepgsql/src/bin		\
    > ${RPMSOURCE}/sepgsql-08-utils-${BASE_VERSION}.patch
rm -rf ./*/src/bin

echo "GEN: sepgsql-01-sysatt-${BASE_VERSION}.patch"
diff -Nrpc base sysatt		\
    > ${RPMSOURCE}/sepgsql-01-sysatt-${BASE_VERSION}.patch

echo "GEN: sepgsql-02-core-${BASE_VERSION}.patch"
diff -Nrpc sysatt core		\
    > ${RPMSOURCE}/sepgsql-02-core-${BASE_VERSION}.patch

echo "GEN: sepgsql-03-gram-${BASE_VERSION}.patch"
diff -Nrpc core gram		\
    > ${RPMSOURCE}/sepgsql-03-gram-${BASE_VERSION}.patch

echo "GEN: sepgsql-04-writable-${BASE_VERSION}.patch"
diff -Nrpc gram writable	\
    > ${RPMSOURCE}/sepgsql-04-writable-${BASE_VERSION}.patch

echo "GEN: sepgsql-05-rowlevel-${BASE_VERSION}.patch"
diff -Nrpc writable rowlv	\
    > ${RPMSOURCE}/sepgsql-05-rowlevel-${BASE_VERSION}.patch

echo "GEN: sepgsql-06-perms-${BASE_VERSION}.patch"
diff -Nrpc rowlv perms		\
    > ${RPMSOURCE}/sepgsql-06-perms-${BASE_VERSION}.patch

echo "GEN: sepgsql-07-extra-${BASE_VERSION}.patch"
diff -Nrpc perms sepgsql	\
    > ${RPMSOURCE}/sepgsql-07-extra-${BASE_VERSION}.patch

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

mv ${RPMSOURCE}/sepgsql-00-full-${BASE_VERSION}.patch.gz	\
    ${RPMSOURCE}/sepgsql-00-full-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch.gz
mv ${RPMSOURCE}/sepgsql-01-sysatt-${BASE_VERSION}.patch	\
    ${RPMSOURCE}/sepgsql-01-sysatt-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepgsql-02-core-${BASE_VERSION}.patch	\
    ${RPMSOURCE}/sepgsql-02-core-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepgsql-03-gram-${BASE_VERSION}.patch	\
    ${RPMSOURCE}/sepgsql-03-gram-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepgsql-04-writable-${BASE_VERSION}.patch	\
    ${RPMSOURCE}/sepgsql-04-writable-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepgsql-05-rowlevel-${BASE_VERSION}.patch	\
    ${RPMSOURCE}/sepgsql-05-rowlevel-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepgsql-06-perms-${BASE_VERSION}.patch	\
    ${RPMSOURCE}/sepgsql-06-perms-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepgsql-07-extra-${BASE_VERSION}.patch	\
    ${RPMSOURCE}/sepgsql-07-extra-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepgsql-08-utils-${BASE_VERSION}.patch	\
    ${RPMSOURCE}/sepgsql-08-utils-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepgsql-09-tests-${BASE_VERSION}.patch	\
    ${RPMSOURCE}/sepgsql-09-tests-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch
mv ${RPMSOURCE}/sepgsql-10-docs-${BASE_VERSION}.patch	\
    ${RPMSOURCE}/sepgsql-10-docs-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch

echo "---- LIST OF GENERATED PATCHES ----"
echo "00) ${RPMSOURCE}/sepgsql-00-full-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch.gz"
echo "01) ${RPMSOURCE}/sepgsql-01-sysatt-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
echo "02) ${RPMSOURCE}/sepgsql-02-core-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
echo "03) ${RPMSOURCE}/sepgsql-03-gram-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
echo "03) ${RPMSOURCE}/sepgsql-04-writable-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
echo "04) ${RPMSOURCE}/sepgsql-05-rowlevel-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
echo "05) ${RPMSOURCE}/sepgsql-06-perms-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
echo "09) ${RPMSOURCE}/sepgsql-07-extra-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
echo "06) ${RPMSOURCE}/sepgsql-08-utils-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
echo "07) ${RPMSOURCE}/sepgsql-09-tests-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"
echo "08) ${RPMSOURCE}/sepgsql-10-docs-${BASE_VERSION}-r${SEPGSQL_REVISION}.patch"

# ---- clean up
rm -rf ${WORKDIR}
