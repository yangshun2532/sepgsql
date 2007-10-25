#!/bin/sh
export LANG=C

# ---- build parametors
SEPGSQL_MAJOR_VERSION="1"
SEPGSQL_MINOR_OFFSET="436"
# SEPGSQL_EXTENSION=".beta"
SEPGSQL_BRANCH="/branches/pgsql-8.2.x"

# -- SE-PostgreSQL repository
SEPGSQL_REPOSITORY=`(cd \`dirname $0\`/..; pwd)`

# -- SE-PostgreSQL version number
LIBPQ_RC_IN="${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH}/base/src/interfaces/libpq/libpq.rc.in"
BASE_MAJOR_VERSION=`grep PRODUCTVERSION $LIBPQ_RC_IN | \
    sed 's/,/ /g' | awk '{ printf("%u.%u", $2,$3); }'`
BASE_MINOR_VERSION=`grep PRODUCTVERSION $LIBPQ_RC_IN | \
    sed 's/,/ /g' | awk '{ print $4 }'`
BASE_VERSION="${BASE_MAJOR_VERSION}.${BASE_MINOR_VERSION}"

svn update ${SEPGSQL_REPOSITORY} || exit 1
SEPGSQL_MINOR_VERSION=`svn info ${SEPGSQL_REPOSITORY} | egrep '^Revision:' | awk '{print $2}'`
SEPGSQL_MINOR_VERSION=`expr ${SEPGSQL_MINOR_VERSION} - ${SEPGSQL_MINOR_OFFSET}`
SEPGSQL_VERSION="${SEPGSQL_MAJOR_VERSION}.${SEPGSQL_MINOR_VERSION}"

# -- lookup RPMS/SOURCE directory
RPMSOURCE=`rpm -E '%{_sourcedir}'`
test -d ${RPMSOURCE} || exit 1

# -- get base postgresql tar+gz, if necessary
if [ ! -e ${RPMSOURCE}/postgresql-${BASE_VERSION}.tar.gz ]; then
    wget -O ${RPMSOURCE}/postgresql-${BASE_VERSION}.tar.gz \
	"ftp://ftp.postgresql.org/pub/source/v${BASE_VERSION}/postgresql-${BASE_VERSION}.tar.gz" || exit 1
fi

# ---- check distribution dependency
DIST=`rpm -E '%dist'`
if [ "${DIST}" = ".fc7" ]; then
    REQUIRED_POLICY_VERSION="= `rpm -q --qf '%{version}-%{release}' selinux-policy-devel`"
    if ! echo "$SEPGPOLVERSION" | grep -q .sepgsql; then
        echo "selinux-policy-devel is NOT SE-PostgreSQL supported version"
        echo "It does not contain the definition of object classes and access"
        echo "vectors related to database objects."
        exit 1
    fi
else
    REQUIRED_POLICY_VERSION=">= 3.0.6"
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

echo "GEN: sepostgresql-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch"
diff -rpNU3 base sepgsql > ${RPMSOURCE}/sepostgresql-${BASE_VERSION}-${SEPGSQL_MAJOR_VERSION}.patch

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
    sed "s/%%__sepgsql_extension__%%/${__SEPGSQL_EXTENSION}/g" | \
    sed "s/%%__required_policy_version__%%/${REQUIRED_POLICY_VERSION}/g" \
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

echo "CPY: sepostgresql-fedora-prefix.patch"
cp package/sepostgresql-fedora-prefix.patch ${RPMSOURCE}

# ---- build rpm package
rpmbuild -ba ${RPMSOURCE}/sepostgresql.spec

# ---- clean up
rm -rf ${WORKDIR}
