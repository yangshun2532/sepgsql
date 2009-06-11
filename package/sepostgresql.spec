#
# Security Enhanced PostgreSQL (SE-PostgreSQL)
#
# Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
# -----------------------------------------------------

# SE-PostgreSQL status extension
%define selinux_policy_stores      targeted mls
%define policy_module_name         sepostgresql-devel

# Optional features
%{!?standalone:%define standalone 1}
%{!?ssl:%define ssl 1}

Summary: Security Enhanced PostgreSQL
Name: sepostgresql
Version: %%__base_version__%%
Release: %%__sepgsql_revision__%%%{?dist}
License: BSD
Group: Applications/Databases
Url: http://code.google.com/p/sepgsql/
Buildroot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
Source0: ftp://ftp.postgresql.org/pub/source/v%{version}/postgresql-%{version}.tar.bz2
Source1: sepostgresql.init
Source2: sepostgresql.8
Source3: sepostgresql.logrotate
Patch1: sepgsql-01-sysatt-%%__base_major_version__%%.patch
Patch2: sepgsql-02-core-%%__base_major_version__%%.patch
Patch3: sepgsql-03-writable-%%__base_major_version__%%.patch
Patch4: sepgsql-04-rowlevel-%%__base_major_version__%%.patch
Patch5: sepgsql-05-perms-%%__base_major_version__%%.patch
Patch6: sepgsql-06-utils-%%__base_major_version__%%.patch
Patch7: sepgsql-07-tests-%%__base_major_version__%%.patch
Patch8: sepgsql-08-docs-%%__base_major_version__%%.patch
Patch9: sepgsql-09-extra-%%__base_major_version__%%.patch
Patch10: sepgsql-fedora-prefix.patch
BuildRequires: perl glibc-devel bison flex readline-devel zlib-devel >= 1.0.4
Buildrequires: checkpolicy libselinux-devel >= 2.0.80 selinux-policy >= 3.4.2
%if %{ssl}
BuildRequires: openssl-devel
%endif
Requires(pre): shadow-utils
Requires(post): policycoreutils /sbin/chkconfig
Requires(preun): /sbin/chkconfig /sbin/service
Requires(postun): policycoreutils
%if !%{standalone}
Requires: postgresql-server = %{version}
%endif
Requires: policycoreutils >= 2.0.16 libselinux >= 2.0.80 selinux-policy >= 3.6.13
Requires: tzdata logrotate
%if %ssl
BuildRequires: openssl-devel
%endif

%description
Security Enhanced PostgreSQL is an extension of PostgreSQL
based on SELinux security policy, that applies fine grained
mandatory access control to many objects within the database,
and takes advantage of user authorization integrated within
the operating system. SE-PostgreSQL works as a userspace
reference monitor to check any SQL query.

%prep
%setup -q -n postgresql-%{version}
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
%patch5 -p1
%patch6 -p1
%patch7 -p1
%patch8 -p1
%patch9 -p1
%patch10 -p1

%build
CFLAGS="${CFLAGS:-%optflags}" ; export CFLAGS
CXXFLAGS="${CXXFLAGS:-%optflags}" ; export CXXFLAGS

# configure SE-PostgreSQL
%configure      --disable-rpath                 \
                --enable-selinux                \
                --enable-debug                  \
                --enable-cassert                \
%if %{standalone}
                --libdir=%{_libdir}/sepgsql     \
%else
                --libdir=%{_libdir}/pgsql       \
%endif
%if %{ssl}
                --with-openssl                  \
%endif
                --datadir=%{_datadir}/sepgsql   \
                --with-system-tzdata=/usr/share/zoneinfo

# parallel build, if possible
make %{?_smp_mflags}
# to create empty .fc file
touch src/backend/security/sepgsql/policy/%{policy_module_name}.fc
make -C src/backend/security/sepgsql/policy

%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install
make DESTDIR=%{buildroot} -C src/backend/security/sepgsql/policy install

# avoid to conflict with native postgresql package
mv %{buildroot}%{_bindir}  %{buildroot}%{_bindir}.orig
install -d %{buildroot}%{_bindir}
mv %{buildroot}%{_bindir}.orig/initdb        %{buildroot}%{_bindir}/initdb.sepgsql
mv %{buildroot}%{_bindir}.orig/pg_ctl        %{buildroot}%{_bindir}/sepg_ctl
mv %{buildroot}%{_bindir}.orig/postgres      %{buildroot}%{_bindir}/sepostgres
mv %{buildroot}%{_bindir}.orig/pg_dump       %{buildroot}%{_bindir}/sepg_dump
mv %{buildroot}%{_bindir}.orig/pg_dumpall    %{buildroot}%{_bindir}/sepg_dumpall
rm -rf %{buildroot}%{_bindir}.orig

# shared library files if neeced
%if %{standalone}
mv %{buildroot}%{_libdir}/sepgsql  %{buildroot}%{_libdir}/sepgsql.orig
install -d %{buildroot}%{_libdir}/sepgsql
mv %{buildroot}%{_libdir}/sepgsql.orig/plpgsql.so   \
   %{buildroot}%{_libdir}/sepgsql.orig/*_and_*.so   \
   %{buildroot}%{_libdir}/sepgsql.orig/dict_*.so    \
   %{buildroot}%{_libdir}/sepgsql

rm -rf %{buildroot}%{_libdir}/sepgsql.orig
%else
rm -rf %{buildroot}%{_libdir}
%endif

# remove unnecessary files
rm -rf %{buildroot}%{_includedir}
rm -rf %{buildroot}%{_defaultdocdir}
rm -rf %{buildroot}%{_datadir}/sepgsql/timezone
rm -rf %{buildroot}%{_mandir}

# /var/lib/sepgsql
install -d -m 700 %{buildroot}%{_localstatedir}/lib/sepgsql
install -d -m 700 %{buildroot}%{_localstatedir}/lib/sepgsql/data
install -d -m 700 %{buildroot}%{_localstatedir}/lib/sepgsql/backups

# /etc/rc.d/init.d/*
mkdir -p %{buildroot}%{_initrddir}
install -p -m 755 %{SOURCE1} %{buildroot}%{_initrddir}/sepostgresql

# /etc/logrotate.d/
mkdir -p %{buildroot}%{_sysconfdir}/logrotate.d
install -p -m 644 %{SOURCE3} %{buildroot}%{_sysconfdir}/logrotate.d/sepostgresql

# /usr/share/man/*
mkdir -p %{buildroot}%{_mandir}/man8
install -p -m 644 %{SOURCE2} %{buildroot}%{_mandir}/man8

%clean
rm -rf %{buildroot}

%pre
getent group  sepgsql >/dev/null || groupadd -r sepgsql
getent passwd sepgsql >/dev/null || \
    useradd -r -g sepgsql -d %{_localstatedir}/lib/sepgsql -s /bin/bash \
            -c "SE-PostgreSQL server" sepgsql
exit 0

%post
/sbin/chkconfig --add %{name}
/sbin/ldconfig

for store in %{selinux_policy_stores}
do
    %{_sbindir}/semodule -s ${store}       \
        -i %{_datadir}/selinux/packages/%{policy_module_name}.pp &> /dev/null || :
done

# Fix up non-standard file contexts
/sbin/fixfiles -R %{name} restore || :
/sbin/restorecon -R %{_localstatedir}/lib/sepgsql || :

%preun
if [ $1 -eq 0 ]; then           # rpm -e case
    /sbin/service %{name} condstop >/dev/null 2>&1
    /sbin/chkconfig --del %{name}
fi

%postun
/sbin/ldconfig
if [ $1 -ge 1 ]; then           # rpm -U case
    /sbin/service %{name} condrestart >/dev/null 2>&1 || :
fi
if [ $1 -eq 0 ]; then           # rpm -e case
    for store in %{selinux_policy_stores}
    do
        %{_sbindir}/semodule -s ${store} -r %{policy_module_name} &> /dev/null || :
    done
    /sbin/fixfiles -R %{name} restore || :
    test -d %{_localstatedir}/lib/sepgsql \
    	 && /sbin/restorecon -R %{_localstatedir}/lib/sepgsql || :
fi

%files
%defattr(-,root,root,-)
%doc COPYRIGHT README
%{_initrddir}/sepostgresql
%{_sysconfdir}/logrotate.d/sepostgresql
%{_bindir}/initdb.sepgsql
%{_bindir}/sepg_ctl
%{_bindir}/sepostgres
%{_bindir}/sepg_dump
%{_bindir}/sepg_dumpall
%{_mandir}/man8/sepostgresql.*
%dir %{_datadir}/sepgsql
%{_datadir}/sepgsql/postgres.bki
%{_datadir}/sepgsql/postgres.description
%{_datadir}/sepgsql/postgres.shdescription
%{_datadir}/sepgsql/system_views.sql
%{_datadir}/sepgsql/*.sample
%{_datadir}/sepgsql/snowball_create.sql
%{_datadir}/sepgsql/timezonesets/
%{_datadir}/sepgsql/tsearch_data/
%{_datadir}/sepgsql/conversion_create.sql
%{_datadir}/sepgsql/information_schema.sql
%{_datadir}/sepgsql/sql_features.txt
%if %{standalone}
%dir %{_libdir}/sepgsql
%{_libdir}/sepgsql/plpgsql.so
%{_libdir}/sepgsql/*_and_*.so
%{_libdir}/sepgsql/dict_*.so
%endif
%attr(644,root,root) %{_datadir}/selinux/packages/%{policy_module_name}.pp
%attr(700,sepgsql,sepgsql) %dir %{_localstatedir}/lib/sepgsql
%attr(700,sepgsql,sepgsql) %dir %{_localstatedir}/lib/sepgsql/data
%attr(700,sepgsql,sepgsql) %dir %{_localstatedir}/lib/sepgsql/backups

%changelog
* Thu Jun 11 2009 KaiGai Kohei <kaigai@ak.jp.nec.com> - 8.4beta2-2007
- update: add support to reclaim orphan security_labels
- update: mls/targeted policy package was unified

* Fri May 29 2009 KaiGai Kohei <kaigai@ak.jp.nec.com> - 8.4beta2-1950
- update: add sepostgresql_mcstrans guc option
- upgrade: base version 8.4beta1 -> 8.4beta2

* Thu May 14 2009 KaiGai Kohei <kaigai@ak.jp.nec.com> - 8.4beta1-1891
- update: add db_table/db_column:{reference} permissions.
- update: base version was upgraded to 8.4beta1

* Thu Apr 16 2009 KaiGai Kohei <kaigai@ak.jp.nec.com> - 8.4devel-1811
- rework: add libselinux-2.0.80 features (permissive domain, deny_unknown,
          avc_netlink_loop)
- update: merge a series of development from v8.4 tree.

* Fri Oct 31 2008 <kaigai@kaigai.gr.jp> - 8.4devel-3.1168
- bugfix: incorrect object class for lo_export(xxx, '/dev/null')
- bugfix: lack of permission checks for per-statement trigger
- bugfix: trusted procedure invocation as per-statement trigger

* Fri Oct 24 2008 <kaigai@kaigai.gr.jp> - 8.4devel-3.1148
- bugfix: checks on TRUNCATE assumed SECCLASS_DB_TUPLE for any tuples
- bugfix: incorrect object class for the target of COPY TO <file>

* Thu Oct 16 2008 <kaigai@kaigai.gr.jp> - 8.4devel-3.1127
- bugfix: theoritical matter on repeating enable<->disable the feature
          and handling TOASTing data.
- bugfix: add a not-NULL constraint for writable security system column.
- cleanup: src/bin/pg_dump/pg_ace_dump.h

* Fri Oct 10 2008 <kaigai@kaigai.gr.jp> - 8.4devel-3.1124
- add a special care for FK constraint triggers. It does not require
  permissions whole of columns on its invocation
- cleanup: remove unused checkSelectFromExpr()
- cleanup: src/backend/security/sepgsql/proxy.c

* Thu Oct 9 2008 <kaigai@kaigai.gr.jp> - 8.4devel-3.1089
- SECURITY_CONTEXT = 'xxx' extention got raised an error when no security
  feature is enabled.
- pgaceSecurityLabelOfLabel() and pgaceUnlabeledSecurityLabel() hooks are
  allowed to return NULL.
- WITH RECURSICE clause support

* Wed Oct 1 2008 <kaigai@kaigai.gr.jp> - 8.4devel-3.1072
- pgaceCopyFile() hook is added to check permission for files.
- bugfix: incorrect audit message for non-cached decision making

* Mon Sep 29 2008 <kaigai@kaigai.gr.jp> - 8.4devel-3.1065
- add a feature to boost userspace avc. It enables to assume the context
  of subject and switch the slot on domain transition, because most of
  access control decision is checks for privileges of client.

* Thu Sep 25 2008 <kaigai@kaigai.gr.jp> - 8.4devel-3.1056
- pgaceValidateSecurityLabel() hook is separated to
  pgaceCheckValidSecurityLabel() and pgaceUnlabeledSecurityLabel().
- hooks got enclosed by #if defined(XXXX) ... #endif, instead of #ifdef

* Mon Sep 22 2008 <kaigai@kaigai.gr.jp> - 8.4devel-3.1037
- bugfix: insert a tuple on FK'ed table with invisible PK got succeeded
- bugfix: Scan->pgaceTuplePerms is not copied at nodes/copyfuncs.c
- Declarations of SE-PostgreSQL functions are moved to security/pgace.h
  to kill warnings at build time.
- bugfix: _equalSEvalItemProcedure() is terminated without 'return true'

* Fri Sep 12 2008 <kaigai@kaigai.gr.jp> - 8.4devel-3.1003
- add pgaceIsAllowExecutorRunHook() hook to prevent override executor.
- add T_SEvalItemXXXX support to nodes/equalfuncs.c

* Fri Aug 15 2008 <kaigai@kaigai.gr.jp> - 8.4devel-3.970
- add a handling of T_SortGroupClause node at sepgsql/proxy.c
- pgaceCallFunction() is moved to init_fcache()
- bugfix: trusted procedure on OpExpr and so on

* Fri Jul 11 2008 <kaigai@kaigai.gr.jp> - 8.4devel-3.952
- Security policy modules updates.

* Fri Jul 11 2008 <kaigai@kaigai.gr.jp> - 8.4devel-3.945
- Design improvement which contains the way to manage security context,
  tuple-level access control changes to avoid patent confliction, 
  pg_dump option name changing and so on.

* Wed Apr 30 2008 <kaigai@kaigai.gr.jp> - 8.4devel-3.82
- BUGFIX: ROW-level control did not work correctly on TRUNCATE
- Code clean up in sepgsql/proxy.c, using expression_tree_walker().
- Inconsistent version number format at Changelogs

* Wed Mar 12 2008 <kaigai@kaigai.gr.jp> - 8.4devel-3.26
- 8.4devel tree was branched.

* Sun Mar  9 2008 <kaigai@kaigai.gr.jp> - 8.3.0-2.129
- BUGFIX: more conprehensive fixes in "SELECT COUNT(*) ..."

* Sun Mar  2 2008 <kaigai@kaigai.gr.jp> - 8.3.0-2.120
- BUGFIX: CREATE TABLE statement with explicit labeled columns
- BUGFIX: SELECT count(*) does not filter unallowed tuples

* Wed Feb 27 2008 <kaigai@kaigai.gr.jp> - 8.3.0-2.117
- ".beta" removed.

* Wed Feb 27 2008 <kaigai@kaigai.gr.jp> - 8.3.0-2.114
- Security policy updates

* Tue Feb 26 2008 <kaigai@kaigai.gr.jp> - 8.3.0-2.113
- BUGFIX: CREATE/ALTER TABLE with CONTEXT='...' did nothing.

* Thu Feb  7 2008 <kaigai@kaigai.gr.jp> - 8.3.0-2.108
- add /etc/logrotate.d/sepostgresql

* Thu Feb  7 2008 <kaigai@kaigai.gr.jp> - 8.3.0-2.105
- update base version to stable 8.3.0
- add tzdata dependency
- allow db_database:{get_param set_param} for generic domain
- error message cleanups
- Improve large object hooks in PGACE framework
- BUGFIX: db_blob:{drop} was checked at loread()
- BUGFIX: incorrect permission in DELETE with RETURNING clause
- incorrect permission when we read and update security_context in same time.

* Fri Jan 25 2008 <kaigai@kaigai.gr.jp> - 8.3RC2-2.62
- BUGFIX: add handling to invalid contexts already stored

* Tue Jan 22 2008 <kaigai@kaigai.gr.jp> - 8.3RC2-2.56
- BUGFIX: lack of locks when refering buffer pages at update/delete hooks
- BUGFIX: explicit labeling using SELECT ... INTO statement.

* Sun Jan 20 2008 <kaigai@kaigai.gr.jp> - 8.3RC2-2.52
- shares /usr/lib/pgsql/*.so libraries, with original postgresql.

* Thu Jan 10 2008 <kaigai@kaigai.gr.jp> - 8.3RC1-2.37
- add sepg_dump/sepg_dumpall support for 8.3base package.

* Mon Nov 26 2007 <kaigai@kaigai.gr.jp> - 8.3beta3-2.0
- Branch from 8.2.x tree

* Wed Nov 21 2007 <kaigai@kaigai.gr.jp> - 8.2.5-1.66
- Add a policy module hotfix for labeled networking

* Thu Nov 1 2007 <kaigai@kaigai.gr.jp> - 8.2.5-1.51
- Re-organize repository to prepare to branch 8.3.x based tree.
  (no differences from 8.2.5-1.33)

* Wed Oct 17 2007 <kaigai@kaigai.gr.jp> - 8.2.5-1.33
- Fix bug: security context was not canonicalized
  when irregular context (but interpretable) was inputed.

* Mon Oct 15 2007 <kaigai@kaigai.gr.jp> - 8.2.5-1.31
- Fix bug: type definitions of security_label_to_text()
  and text_to_security_label() are mismatched.

* Sat Sep 22 2007 <kaigai@kaigai.gr.jp> - 8.2.5-1.23
- update base PostgreSQL to 8.2.5

* Mon Sep 1 2007 <kaigai@kaigai.gr.jp> - 8.2.4-1.0
- mark as SE-PostgreSQL 8.2.4-1.0

* Thu Aug 28 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.434.beta
- add Requires: postgresql-server, instead of Conflicts: tag
  (Some sharable files are removed from sepostgresql package)

* Fri Aug 24 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.429.beta
- add policycoreutils to Requires(post/postun)
- upstreamed selinux-policy got SE-PostgreSQL related object classes definition.

* Sat Aug 18 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.427.beta
- sepg_dumpall uses /usr/bin/sepg_dump

* Fri Aug 17 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.423.beta
- fix policy not to execute sepgsql_user_proc_t from administrative domain

* Fri Aug 10 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.418.beta
- object classes are renamed with "db_" prefix
- /etc/init.d/sepostgresql script is improved.

* Thu Aug 2 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.409.beta
- specfile updated based on the following comments
  https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=249522#c5

* Mon Jul 30 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.407.beta
- fix spec file based on Fedora reviewing process
- add rawhide support

* Mon Jul 23 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.402.beta
- add manpage of sepostgresql
- fix specfile convention for Fedora suitable

* Sun Jul 15 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.398.beta
- SECCLASS_DATABASE is updated (fc7->62, fc6->61)

* Sun Jul  1 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.391.beta
- Mark as a beta version.

* Sat Jun 30 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.384.alpha
- add fallback context support with $SEPGSQL_FALLBACK_CONTEXT
- add sepgsql_enable_users_ddl boolean to restrict sepgsql_sysobj_t
- BUGFIX: incorrect inherited attribute expanding for RECORD type (attno=0)
- BUGFIX: trigger functions were not checked in COPY FROM statement

* Tue Jun 26 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.376.alpha
- add pgaceExecutorStart() to hook ExecutorStart()

* Mon Jun 25 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.372.alpha
- add table name prefix for column name on audit messages
- use security_label_raw_in as an alternative for security_label_in
- add hook for query execution path with SPI_ interface
- add trigger function suppoer
- BUGFIX: remove unnecessary checks for COPY TO/FROM on non-table relation
- BUGFIX: remove unnecessary checks for LOCK on non-table relation
- BUGFIX: incorrect object id for tuples within pg_security
- BUGFIX: CommandCounterIncrement() might be called during heap_create_with_catalog.
- BUGFIX: correct self-deadlock
- update security policy: sepgsql_sysobj_t, sepgsql_user_proc_t, sepgsql_ro_blob_t

* Tue Jun 19 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.351.alpha
- BUGFIX: sepgsql_compute_avc_datum() accessed userspace AVC without
          holding any lock.
- improve build scripts.

* Sat Jun 16 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.320.alpha
- update: sepostgresql.pp security policy fot strict/mls suitable
- BUGFIX: column:drop evaluation for ALTER TABLE tbl DROP col; statement
- add --enable-security option for pg_dumpall command
- add {use} permission for table/column/tuple object classes

* Tue May 29 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.306.alpha
- BUGFIX: RangeTblEntry->requiredPerms are polluted.

* Sun May 27 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.304.alpha
- add support for dynamic object class/access vector mapping
- BUGFIX: Lack of implicit labeling on COPY FROM statement for system catalogs
- BUGFIX: Incorrect security context handling for inherited tables

* Fri May 25 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.292.alpha
- add pg_dump/pg_dumpall/pg_restore with --enable-security option
- add support on OUTER JOIN by rewriting query.
- add security_context support on COPY TO/FROM statement
- add unlabeled security context support (enable to obtain /selinux/initial_contexts/*)
- BUGFIX: lack of checks on JOIN ON condition
- BUGFIX: pseudo relation object (sequence, toast, ...) are not handled as database obj.
- BUGFIX: lack of tuple:insert checks at COPY FROM statement
- BUGFIX: server crash when CREATE TABLE command with newly defined CONTEXT = '...'.

* Wed May 16 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.266.alpha
- BUGFIX: incorrect security context of newly generated system object.
- BUGFIX: missing error text when audit log is disabled.
- BUGFIX: incorrect Oid of newly generated tuples within pg_security.
- BUGFIX: sepgsql_enable_audittuple is misconditioned.
- add checks for T_RowExpr/T_RowCompareExpr/T_BooleanTest
                 T_DistinctExpr/T_ConvertRowtypeExpr
- add support CONTEXT = 'xxx' for CREATE TABLE/FUNCTION/DATABASE statement

* Sun Apr 30 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.240.alpha
- update base version 8.2.3 -> 8.2.4
- BUGFIX: unexpected expose in OUTER JOIN statement.
          add rewrite OUTER JOIN into SUBQUERY to ensure filtering violated tuples.
- BUGFIX: strange operation in text_to_security_label()
- BUGFIX: infinite recursive call on security label -> oid mapping
- BUGFIX: sepgsql_avc_init() is called in policy state monitoring process
          to avoid nonsense initialization of avc_shmem.

* Fri Apr 27 2007 <kaigai@kaigai.gr.jp> - 8.2.3-0.232.alpha
- object class numbers were redefined. (SECCLASS_DATABASE got into 61)
- is_selinux_enabled() was cached on the shared memory segment.
- BUGFIX: server went into infinit loop on foreign key constraint.

* Mon Apr 16 2007 <kaigai@kaigai.gr.jp> - 8.2.3-0.226.alpha
- BUGFIX: cases when several variables with same type in a single table

* Sat Apr 07 2007 <kaigai@kaigai.gr.jp> - 8.2.3-0.214.alpha
- add the first implementation of SE-PostgreSQL on PGACE framework

* Wed Mar 21 2007 <kaigai@kaigai.gr.jp> - 8.2.3-0.212.alpha
- BUGFIX: SetOperation didn't handle its subquery correctly.
  So, it caused server crash.

* Wed Mar 07 2007 <kaigai@kaigai.gr.jp> - 8.2.3-0.209.alpha
- BUGFIX: var->varlevelsup was ignored, so outer references
  from subqueries cause a fault.

* Tue Feb 27 2007 <kaigai@kaigai.gr.jp> - 8.2.3-0.178.alpha
- Initial RPM build
