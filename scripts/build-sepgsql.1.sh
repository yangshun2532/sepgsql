#!/bin/sh
export LANG=C

# ---- build parametors
BASEVERSION="8.2.5"
SEPGSQL_VERSION="1"
SEPGSQL_MINOR_OFFSET="436"
# SEPGSQL_EXTENSION=".beta"
SEPGSQL_BRANCH="branches/sepostgresql-8.2.4-1.0"

# ---- SE-PostgreSQL repository
test -n "${SEPGSQL_REPOSITORY}" || \
    SEPGSQL_REPOSITORY="http://sepgsql.googlecode.com/svn"

# ---- SE-PostgreSQL base tarball
test -n "${SEPGSQL_BASETGZ}" || \
    SEPGSQL_BASETGZ="ftp://ftp.postgresql.org/pub/source/v${BASEVERSION}/postgresql-${BASEVERSION}.tar.gz"

# ---- obtain SEPGSQL_MINOR_VERSION
echo ${SEPGSQL_REPOSITORY} | egrep -q "^http://" || \
    { pushd ${SEPGSQL_REPOSITORY}; svn update; popd; }
SEPGSQL_MINOR_VERSION=`svn info ${SEPGSQL_REPOSITORY} | egrep '^Revision:' | awk '{print $2}'`
SEPGSQL_MINOR_VERSION=`expr ${SEPGSQL_MINOR_VERSION} - ${SEPGSQL_MINOR_OFFSET}`

# ---- make a working directory
WORKDIR=`mktemp -d`
cd ${WORKDIR}

# ---- obtain RPMS/SOURCE
RPMSOURCE=`rpm -E '%{_sourcedir}'`
echo $RPMSOURCE
test -d ${RPMSOURCE} || exit 1

# ---- print notice ----
echo "==== now Starting SE-PostgreSQL build ===="
echo "  sepostgresql-${BASEVERSION}-${SEPGSQL_VERSION}.${SEPGSQL_MINOR_VERSION}"
echo "  working directory: ${WORKDIR}"
echo "  repository: ${SEPGSQL_REPOSITORY}/${SEPGSQL_BRANCH}"
echo "  base tarball: ${SEPGSQL_BASETGZ}"
echo

# ---- download base tarball, if necessary
if echo ${SEPGSQL_BASETGZ} | egrep -q '^(http|ftp)://'; then
    wget ${SEPGSQL_BASETGZ} || exit 1
    SEPGSQL_BASETGZ=`basename ${SEPGSQL_BASETGZ}`
fi

# ---- export repository ----
svn export "${SEPGSQL_REPOSITORY}/${SEPGSQL_BRANCH}" "sepostgresql-${BASEVERSION}" || exit 1
svn export "${SEPGSQL_REPOSITORY}/policy" || exit 1
svn export "${SEPGSQL_REPOSITORY}/scripts" || exit 1

# ---- check distribution dependency
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

# ---- set __SEPGSQL_EXTENSION
__SEPGSQL_EXTENSION=""
test -n "${SEPGSQL_EXTENSION}" && \
    __SEPGSQL_EXTENSION="%{!?sepgextension:%define sepgextension ${SEPGSQL_EXTENSION}}"

# ---- copy to ${RPMSOURCE}
echo "CPY: `basename ${SEPGSQL_BASETGZ}`"
cp ${SEPGSQL_BASETGZ} ${RPMSOURCE}

echo "GEN: sepostgresql.init"
cat scripts/sepostgresql.init | \
    sed "s/%%__base_postgresql_version__%%/${BASEVERSION}/g" | \
    sed "s/%%__default_sepgversion__%%/${SEPGSQL_VERSION}/g" | \
    sed "s/%%__default_sepgversion_minor__%%/${SEPGSQL_MINOR_VERSION}/g" \
        > ${RPMSOURCE}/sepostgresql.init

echo "GEN: sepostgresql.spec"
cat scripts/sepostgresql.spec | \
    sed "s/%%__base_postgresql_version__%%/${BASEVERSION}/g" | \
    sed "s/%%__default_sepgversion__%%/${SEPGSQL_VERSION}/g" | \
    sed "s/%%__default_sepgversion_minor__%%/${SEPGSQL_MINOR_VERSION}/g" | \
    sed "s/%%__default_sepgextension__%%/${__SEPGSQL_EXTENSION}/g" | \
    sed "s/%%__default_sepgpolversion__%%/${SEPGPOLVERSION}/g" \
        > ${RPMSOURCE}/sepostgresql.spec

echo "CPY: sepostgresql.if"
cp policy/sepostgresql.if ${RPMSOURCE}

echo "CPY: sepostgresql.fc"
cp policy/sepostgresql.fc ${RPMSOURCE}

echo "CPY: sepostgresql.te"
cat policy/sepostgresql.te | \
    sed "s/%%POLICY_VERSION%%/${SEPGSQL_VERSION}.${SEPGSQL_MINOR_VERSION}/g" \
    > ${RPMSOURCE}/sepostgresql.te

echo "CPY: sepostgresql.8"
cp scripts/sepostgresql.8 ${RPMSOURCE}

echo "CPY: sepostgresql-fedora-prefix.patch"
cp scripts/sepostgresql-fedora-prefix.patch ${RPMSOURCE}

echo "GEN: sepostgresql-${BASEVERSION}-${SEPGSQL_VERSION}.patch"
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
    > ${RPMSOURCE}/sepostgresql-${BASEVERSION}-${SEPGSQL_VERSION}.patch

# ---- build rpm package
rpmbuild -ba ${RPMSOURCE}/sepostgresql.spec

# ---- clean up
rm -rf ${WORKDIR}
