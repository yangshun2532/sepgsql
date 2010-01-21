#!/bin/sh

GIT_BIN=`which git`
GIT_DIR="${HOME}/repo/sepgsql"
PGSQL_GIT="git://git.postgresql.org/git/postgresql.git"
UPSTREAM="master"
LOCAL_GIT="git://git.postgresql.org/git/users/kaigai/sepgsql.git"
BRANCHES="master devel/ace_database devel/ace_schema devel/ace_relation_pre devel/ace_relation devel/ace_proc"
#================================================================

cd ${GIT_DIR}

for tree in ${BRANCHES}
do
    echo "CHECK: ${tree} branch"
    ${GIT_BIN} branch -lr | grep -q "origin/${tree}" || exit 1
    ${GIT_BIN} branch -l | grep -q "${tree}" || exit 1
done

ORIG_BRANCH=`${GIT_BIN} branch -l | grep '^*' | awk '{print $2}'`

REMOTE_GIT=${PGSQL_GIT}
for tree in ${BRANCHES}
do
    ${GIT_BIN} checkout ${tree} || exit 1
    ${GIT_BIN} pull ${REMOTE_GIT} ${UPSTREAM} || exit 1
    ${GIT_BIN} push

    UPSTREAM=${tree}
    REMOTE_GIT=${LOCAL_GIT}
done

${GIT_BIN} checkout ${ORIG_BRANCH}
