#!/bin/sh

# ---- build parametors
SEPGSQL_BRANCH="/trunk"

# ---- repository dir
SEPGSQL_REPOSITORY=`(cd \`dirname $0\`/..; pwd)`

# ---- base version number
BASE_VERSION=`grep AC_INIT ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH}/base/configure.in \
    | head -1 \
    | sed -e 's/,/ /g' -e 's/\[//g' -e 's/\]//g' \
    | awk '{print $2}'`

# ---- repository setup
echo "INFO: svn update ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH}"
svn update ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH} || exit 1
if [ `svn diff ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH} | wc -l` -ne 0 ]; then
    echo "ERROR: There are uncommited features."
    exit 1
fi
SEPGSQL_REVISION=`env LANG=C svn info ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH} \
    | egrep '^Revision:' | awk '{print $2}'`

svn info ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH}

# ---- make a working directory
WORKDIR=`mktemp -d`
cd ${WORKDIR}
echo "INFO: working directory at: ${WORKDIR}"

# ---- generate SE-PostgreSQL patches
echo "INFO: Exporting ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH}"
svn export ${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH} altroot || exit 1
cd altroot

echo "GEN: sepostgresql-${BASE_VERSION}-policy.r${SEPGSQL_REVISION}.patch"
diff -rpNU3 pgace/src/bin sepgsql/src/bin \
    > sepostgresql-${BASE_VERSION}-policy.r${SEPGSQL_REVISION}.patch
rm -rf base/src/bin pgace/src/bin sepgsql/src/bin

echo "GEN: sepostgresql-${BASE_VERSION}-pg_dump.r${SEPGSQL_REVISION}.patch"
diff -rpNU3 pgace/contrib/sepgsql-policy sepgsql/contrib/sepgsql-policy \
    > sepostgresql-${BASE_VERSION}-pg_dump.r${SEPGSQL_REVISION}.patch
rm -rf base/contrib pgace/contrib sepgsql/contrib

echo "GEN: sepostgresql-${BASE_VERSION}-sepgsql.r${SEPGSQL_REVISION}.patch"
diff -rpNU3 base pgace \
    > sepostgresql-${BASE_VERSION}-sepgsql.r${SEPGSQL_REVISION}.patch

echo "GEN: sepostgresql-${BASE_VERSION}-pgace-1-core.r${SEPGSQL_REVISION}.patch"
LIST="src/backend/Makefile
      src/backend/security/Makefile
      src/include/security/pgace.h
      src/backend/security/pgaceCommon.c
      src/backend/security/pgaceHooks.c"
for x in $LIST; do diff -pNU3 base/$x pgace/$x; done \
    > sepostgresql-${BASE_VERSION}-pgace-1-core.r${SEPGSQL_REVISION}.patch
for x in $LIST
do
    if [ -e base/$x ]; then
	cp base/$x pgace/$x
    else
	rm -f pgace/$x
    fi
done
rm -rf src/backend/security src/backend/security

echo "GEN: sepostgresql-${BASE_VERSION}-pgace-2-security-attr.r${SEPGSQL_REVISION}.patch"
LIST="src/backend/access/common/heaptuple.c
      src/backend/access/heap/tuptoaster.c
      src/backend/catalog/Makefile
      src/backend/catalog/catalog.c
      src/backend/catalog/genbki.sh
      src/backend/catalog/heap.c
      src/backend/commands/copy.c
      src/backend/executor/execMain.c
      src/backend/parser/analyze.c
      src/backend/parser/parse_target.c
      src/backend/utils/cache/syscache.c
      src/backend/utils/misc/guc.c
      src/include/access/htup.h
      src/include/catalog/indexing.h
      src/include/catalog/pg_attribute.h
      src/include/catalog/pg_cast.h
      src/include/catalog/pg_proc.h
      src/include/catalog/pg_security.h
      src/include/catalog/pg_type.h
      src/include/pg_config.h.in
      src/include/utils/syscache.h"
for x in $LIST; do diff -pNU3 base/$x pgace/$x; done \
    > sepostgresql-${BASE_VERSION}-pgace-2-security-attr.r${SEPGSQL_REVISION}.patch
for x in $LIST
do
    if [ -e base/$x ]; then
	cp base/$x pgace/$x
    else
	rm -f pgace/$x
    fi
done

echo "GEN: sepostgresql-${BASE_VERSION}-pgace-3-security-hooks.r${SEPGSQL_REVISION}.patch"
diff -rpNU3 base pgace \
    > sepostgresql-${BASE_VERSION}-pgace-3-security-hooks.r${SEPGSQL_REVISION}.patch
