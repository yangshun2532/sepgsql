#!/bin/sh
export LANG=C

BASEVERSION="8.2.4"
SEPGVERSION="0"
# SEPGVERSION_MINOR="0"
SEPGEXTENSION=".beta"

# we can override DEFAULT_REPOSITORY by SEPGSQL_REPOSITORY,
# and DEFAULT_BASETGZ by SEPGSQL_BASETGZ
DEFAULT_REPOSITORY="http://sepgsql.googlecode.com/svn"
DEFAULT_BASETGZ="ftp://ftp.jp.postgresql.org/source/v${BASEVERSION}/postgresql-${BASEVERSION}.tar.gz"
if [ -n "$SEPGEXTENSION" ]; then
    DEFAULT_SEPGEXTENSION="%{!?sepgextension:%define sepgextension ${SEPGEXTENSION}}"
else
    DEFAULT_SEPGEXTENSION=""
fi

#-- make working directory --
WORKDIR=`mktemp -d`
cd ${WORKDIR}

RPMSOURCE=`rpm -E '%{_sourcedir}'`
echo $RPMSOURCE
test -d ${RPMSOURCE} || exit 1

#-- override default repository & tarball
test -z "${SEPGSQL_REPOSITORY}" && SEPGSQL_REPOSITORY=${DEFAULT_REPOSITORY}
test -z "${SEPGSQL_BASETGZ}" && SEPGSQL_BASETGZ=${DEFAULT_BASETGZ}
echo ${SEPGSQL_REPOSITORY} | egrep -q "^http://" || \
    { pushd ${SEPGSQL_REPOSITORY}; svn update; popd; }
if [ -z "${SEPGVERSION_MINOR}" ]; then
    SEPGVERSION_MINOR=`svn info ${SEPGSQL_REPOSITORY} | egrep '^Revision:' | awk '{print $2}'`
fi

echo "starting sepostgresql package:"
echo "  sepostgresql-${BASEVERSION}-${SEPGVERSION}.${SEPGVERSION_MINOR}"
echo "  working directory: ${WORKDIR}"
echo "  repository: ${SEPGSQL_REPOSITORY}"
echo "  base tarball: ${SEPGSQL_BASETGZ}"
echo

#-- export repository --
svn export "${SEPGSQL_REPOSITORY}/trunk" "sepostgresql-${BASEVERSION}" || exit 1
svn export "${SEPGSQL_REPOSITORY}/policy"  || exit 1
svn export "${SEPGSQL_REPOSITORY}/scripts" || exit 1

#-- download base tarball, if necessary --
if echo "${SEPGSQL_BASETGZ}" | egrep -q '^(http|ftp)://'; then
    wget ${SEPGSQL_BASETGZ} || exit 1
    SEPGSQL_BASETGZ=`basename ${SEPGSQL_BASETGZ}`
fi

#-- check distribution dependency --
DIST=`rpm -E '%dist'`
if [ "${DIST}" = ".fc7" ]; then
    SEPGPOLVERSION="= `rpm -q --qf '%{version}-%{release}' selinux-policy-devel`"
    if ! echo "$SEPGPOLVERSION" | grep -q .sepgsql; then
        echo "selinux-policy-devel is NOT SE-PostgreSQL supported version"
        echo "It does not contain the definition of object classes and access"
        echo "vectors related to database objects."
        exit 1
    fi
else
    SEPGPOLVERSION=">= 3.0.6"
fi

#-- create a patch file --
echo "generating: sepostgresql-${BASEVERSION}-${SEPGVERSION}.${SEPGVERSION_MINOR}.patch"
cp "${SEPGSQL_BASETGZ}" ${RPMSOURCE}

cat scripts/sepostgresql.init | \
    sed "s/%%__base_postgresql_version__%%/${BASEVERSION}/g" | \
    sed "s/%%__default_sepgversion__%%/${SEPGVERSION}/g" | \
    sed "s/%%__default_sepgversion_minor__%%/${SEPGVERSION_MINOR}/g" \
        > ${RPMSOURCE}/sepostgresql.init

cat scripts/sepostgresql.spec | \
    sed "s/%%__base_postgresql_version__%%/${BASEVERSION}/g" | \
    sed "s/%%__default_sepgversion__%%/${SEPGVERSION}/g" | \
    sed "s/%%__default_sepgversion_minor__%%/${SEPGVERSION_MINOR}/g" | \
    sed "s/%%__default_sepgextension__%%/${DEFAULT_SEPGEXTENSION}/g" | \
    sed "s/%%__default_sepgpolversion__%%/${SEPGPOLVERSION}/g" \
        > ${RPMSOURCE}/sepostgresql.spec

cp policy/sepostgresql.if policy/sepostgresql.fc ${RPMSOURCE}
cat policy/sepostgresql.te | \
    sed "s/%%POLICY_VERSION%%/${SEPGVERSION}.${SEPGVERSION_MINOR}/g" > ${RPMSOURCE}/sepostgresql.te

cp scripts/sepostgresql.8 ${RPMSOURCE}

cp scripts/sepostgresql-pg_dump-renaming.patch ${RPMSOURCE}

tar zxf "${SEPGSQL_BASETGZ}" || exit 1

rm -f postgresql-${BASEVERSION}/configure
rm -f postgresql-${BASEVERSION}/src/interfaces/libpq/libpq.rc
rm -f postgresql-${BASEVERSION}/src/backend/parser/gram.c
rm -f postgresql-${BASEVERSION}/src/backend/parser/scan.c
rm -f postgresql-${BASEVERSION}/src/backend/parser/parse.h
rm -f postgresql-${BASEVERSION}/src/backend/bootstrap/bootparse.c
rm -f postgresql-${BASEVERSION}/src/backend/bootstrap/bootscanner.c
rm -f postgresql-${BASEVERSION}/src/backend/bootstrap/bootstrap_tokens.h

diff -rpNU3 postgresql-${BASEVERSION} sepostgresql-${BASEVERSION} \
    > ${RPMSOURCE}/sepostgresql-${BASEVERSION}-${SEPGVERSION}.${SEPGVERSION_MINOR}.patch

#-- clean up --
cd ${RPMSOURCE}
rm -rf ${WORKDIR}

#-- build rpm package
rpmbuild -ba ${RPMSOURCE}/sepostgresql.spec
