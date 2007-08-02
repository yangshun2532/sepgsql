#
# Security Enhanced PostgreSQL (SE-PostgreSQL)
#
# Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
# -----------------------------------------------------

# SELinux policy types
%define selinux_variants mls strict targeted

# SE-PostgreSQL requires only server side files
%define _unpackaged_files_terminate_build 0

# SE-PostgreSQL status extension
%%__default_sepgextension__%%

Summary: Security Enhanced PostgreSQL
Name: sepostgresql
Version: %%__base_postgresql_version__%%
Release: %%__default_sepgversion__%%.%%__default_sepgversion_minor__%%%{?sepgextension}%{?dist}
License: BSD
Group: Applications/Databases
Url: http://code.google.com/p/sepgsql/
Buildroot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
Source0: ftp://ftp.postgresql.org/pub/source/v%{version}/postgresql-%{version}.tar.gz
Source1: sepostgresql.init
Source2: sepostgresql.if
Source3: sepostgresql.te
Source4: sepostgresql.fc
Source5: sepostgresql.8
Patch0: sepostgresql-%{version}-%{release}.patch
Conflicts: postgresql-server
AutoProv: no
Buildrequires: checkpolicy libselinux-devel >= %%__default_libselinux_version__%% selinux-policy-devel = %%__default_sepgpolversion__%%
Requires: policycoreutils >= %%__default_policycoreutils_version__%% libselinux >= %%__default_libselinux_version__%% selinux-policy = %%__default_sepgpolversion__%%

%description
Security Enhanced PostgreSQL is an extension of PostgreSQL
based on SELinux security policy, that applies fine grained
mandatory access control to many objects within the database,
and takes advantage of user authorization integrated within
the operating system. SE-PostgreSQL works as a userspace
reference monitor to check any SQL query.

%prep
%setup -q -n postgresql-%{version}
%patch0 -p1
mkdir selinux-policy
cp %{SOURCE2} %{SOURCE3} %{SOURCE4} selinux-policy

%build
CFLAGS="${CFLAGS:-%optflags}" ; export CFLAGS
CXXFLAGS="${CXXFLAGS:-%optflags}" ; export CXXFLAGS

# Strip out -ffast-math from CFLAGS....
CFLAGS=`echo $CFLAGS|xargs -n 1|grep -v ffast-math|xargs -n 100`

# build Binary Policy Module
pushd selinux-policy
for selinuxvariant in %{selinux_variants}
do
    make NAME=${selinuxvariant} -f %{_datadir}/selinux/devel/Makefile
    mv %{name}.pp %{name}.pp.${selinuxvariant}
    make NAME=${selinuxvariant} -f %{_datadir}/selinux/devel/Makefile clean
done
popd

# build SE-PostgreSQL
autoconf
%configure      --disable-rpath                 \
                --enable-selinux                \
%if %{defined sepgextension}
                --enable-debug                  \
                --enable-cassert                \
%endif
                --libdir=%{_libdir}/sepgsql     \
                --datadir=%{_datadir}/sepgsql
# parallel build, if possible
SECCLASS_DATABASE=`grep ^define %{_datadir}/selinux/devel/include/support/all_perms.spt | cat -n | grep all_database_perms | awk '{print $1}'`
make CUSTOM_COPT="%%__default_custom_copt__%% -D SECCLASS_DATABASE=${SECCLASS_DATABASE}" %{?_smp_mflags}

%install
rm -rf %{buildroot}

pushd selinux-policy
for selinuxvariant in %{selinux_variants}
do
    install -d %{buildroot}%{_datadir}/selinux/${selinuxvariant}
    install -p -m 644 %{name}.pp.${selinuxvariant} \
        %{buildroot}%{_datadir}/selinux/${selinuxvariant}/%{name}.pp
done
popd

make DESTDIR=%{buildroot} install

# to avoid conflicts with postgresql package
mv %{buildroot}/%{_bindir}/pg_dump     %{buildroot}/%{_bindir}/sepg_dump
mv %{buildroot}/%{_bindir}/pg_dumpall  %{buildroot}/%{_bindir}/sepg_dumpall

install -d -m 700 %{buildroot}/var/lib/sepgsql
install -d -m 700 %{buildroot}/var/lib/sepgsql/data
install -d -m 700 %{buildroot}/var/lib/sepgsql/backups

mkdir -p %{buildroot}%{_initrddir}
install -m 755 %{SOURCE1} %{buildroot}%{_initrddir}/sepostgresql

mkdir -p %{buildroot}%{_mandir}/man8
install -m 644 %{SOURCE5} %{buildroot}%{_mandir}/man8

%clean
rm -rf $RPM_BUILD_ROOT

%pre
getent group  sepgsql >/dev/null || groupadd -r sepgsql
getent passwd sepgsql >/dev/null || \
    useradd -r -g sepgsql -d /var/lib/sepgsql -s /bin/bash \
            -c "SE-PostgreSQL server" sepgsql
exit 0

%post
/sbin/chkconfig --add %{name}
/sbin/ldconfig

for selinuxvariant in %{selinux_variants}
do
    /usr/sbin/semodule -s ${selinuxvariant} -l >& /dev/null || continue;

    /usr/sbin/semodule -s ${selinuxvariant} -l | egrep -q '^%{name}' && \
        /usr/sbin/semodule -s ${selinuxvariant} -r %{name} >& /dev/null || :
    /usr/sbin/semodule -s ${selinuxvariant} -i %{_datadir}/selinux/${selinuxvariant}/%{name}.pp >& /dev/null || :
done

# Fix up non-standard file contexts
/sbin/fixfiles -R %{name} restore || :
/sbin/restorecon -R /var/lib/sepgsql || :

%preun
if [ $1 -eq 0 ]; then
    %{_initrddir}/sepostgresql condstop
    /sbin/chkconfig --del %{name}
fi

%postun
/sbin/ldconfig
if [ $1 -ge 1 ]; then           # rpm -U case
    %{_initrddir}/sepostgresql condrestart
fi
if [ $1 -eq 0 ]; then           # rpm -e case
#    userdel  sepgsql >/dev/null || :
#    groupdel sepgsql >/dev/null || :
    for selinuxvariant in %{selinux_variants}
    do
        /usr/sbin/semodule -s ${selinuxvariant} -l >& /dev/null || continue;

        /usr/sbin/semodule -s ${selinuxvariant} -l | egrep -q '^%{name}' && \
            /usr/sbin/semodule -s ${selinuxvariant} -r %{name} >& /dev/null || :
    done
    /sbin/fixfiles -R %{name} restore || :
    test -d /var/lib/sepgsql && /sbin/restorecon -R /var/lib/sepgsql || :
fi

%files
%defattr(-,root,root,-)
%doc COPYRIGHT README HISTORY
%{_initrddir}/sepostgresql
%{_bindir}/initdb
%{_bindir}/ipcclean
%{_bindir}/pg_controldata
%{_bindir}/pg_ctl
%{_bindir}/pg_resetxlog
%{_bindir}/postgres
%{_bindir}/postmaster
%{_bindir}/sepg_dump
%{_bindir}/sepg_dumpall
%{_mandir}/man1/initdb.*
%{_mandir}/man1/ipcclean.*
%{_mandir}/man1/pg_controldata.*
%{_mandir}/man1/pg_ctl.*
%{_mandir}/man1/pg_resetxlog.*
%{_mandir}/man1/postgres.*
%{_mandir}/man1/postmaster.*
%{_mandir}/man8/sepostgresql.*
%{_datadir}/sepgsql/postgres.bki
%{_datadir}/sepgsql/postgres.description
%{_datadir}/sepgsql/postgres.shdescription
%{_datadir}/sepgsql/system_views.sql
%{_datadir}/sepgsql/*.sample
%{_datadir}/sepgsql/timezone/
%{_datadir}/sepgsql/timezonesets/
%{_datadir}/sepgsql/conversion_create.sql
%{_datadir}/sepgsql/information_schema.sql
%{_datadir}/sepgsql/sql_features.txt
%{_libdir}/sepgsql/plpgsql.so
%{_libdir}/sepgsql/*_and_*.so
%attr(644,root,root) %{_datadir}/selinux/*/sepostgresql.pp
%attr(700,sepgsql,sepgsql) %dir /var/lib/sepgsql
%attr(700,sepgsql,sepgsql) %dir /var/lib/sepgsql/data
%attr(700,sepgsql,sepgsql) %dir /var/lib/sepgsql/backups

%changelog
* Mon Jul 30 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.407
- fix spec file based on Fedora reviewing process
- add rawhide support

* Mon Jul 23 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.402
- add manpage of sepostgresql
- fix specfile convention for Fedora suitable

* Sun Jul 15 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.398
- SECCLASS_DATABASE is updated (fc7->62, fc6->61)

* Sun Jul  1 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.391
- Mark as a beta version.

* Sat Jun 30 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.384
- add fallback context support with $SEPGSQL_FALLBACK_CONTEXT
- add sepgsql_enable_users_ddl boolean to restrict sepgsql_sysobj_t
- BUGFIX: incorrect inherited attribute expanding for RECORD type (attno=0)
- BUGFIX: trigger functions were not checked in COPY FROM statement

* Tue Jun 26 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.376
- add pgaceExecutorStart() to hook ExecutorStart()

* Mon Jun 25 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.372
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

* Tue Jun 19 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.351
- BUGFIX: sepgsql_compute_avc_datum() accessed userspace AVC without
          holding any lock.
- improve build scripts.

* Sat Jun 16 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.320
- update: sepostgresql.pp security policy fot strict/mls suitable
- BUGFIX: column:drop evaluation for ALTER TABLE tbl DROP col; statement
- add --enable-security option for pg_dumpall command
- add {use} permission for table/column/tuple object classes

* Tue May 29 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.306
- BUGFIX: RangeTblEntry->requiredPerms are polluted.

* Sun May 27 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.304
- add support for dynamic object class/access vector mapping
- BUGFIX: Lack of implicit labeling on COPY FROM statement for system catalogs
- BUGFIX: Incorrect security context handling for inherited tables

* Fri May 25 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.292
- add pg_dump/pg_dumpall/pg_restore with --enable-security option
- add support on OUTER JOIN by rewriting query.
- add security_context support on COPY TO/FROM statement
- add unlabeled security context support (enable to obtain /selinux/initial_contexts/*)
- BUGFIX: lack of checks on JOIN ON condition
- BUGFIX: pseudo relation object (sequence, toast, ...) are not handled as database obj.
- BUGFIX: lack of tuple:insert checks at COPY FROM statement
- BUGFIX: server crash when CREATE TABLE command with newly defined CONTEXT = '...'.

* Wed May 16 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.266
- BUGFIX: incorrect security context of newly generated system object.
- BUGFIX: missing error text when audit log is disabled.
- BUGFIX: incorrect Oid of newly generated tuples within pg_security.
- BUGFIX: sepgsql_enable_audittuple is misconditioned.
- add checks for T_RowExpr/T_RowCompareExpr/T_BooleanTest
                 T_DistinctExpr/T_ConvertRowtypeExpr
- add support CONTEXT = 'xxx' for CREATE TABLE/FUNCTION/DATABASE statement

* Sun Apr 30 2007 <kaigai@kaigai.gr.jp> - 8.2.4-0.240
- update base version 8.2.3 -> 8.2.4
- BUGFIX: unexpected expose in OUTER JOIN statement.
          add rewrite OUTER JOIN into SUBQUERY to ensure filtering violated tuples.
- BUGFIX: strange operation in text_to_security_label()
- BUGFIX: infinite recursive call on security label -> oid mapping
- BUGFIX: sepgsql_avc_init() is called in policy state monitoring process
          to avoid nonsense initialization of avc_shmem.

* Fri Apr 27 2007 <kaigai@kaigai.gr.jp> - 8.2.3-0.232
- object class numbers were redefined. (SECCLASS_DATABASE got into 61)
- is_selinux_enabled() was cached on the shared memory segment.
- BUGFIX: server went into infinit loop on foreign key constraint.

* Mon Apr 16 2007 <kaigai@kaigai.gr.jp> - 8.2.3-0.226
- BUGFIX: cases when several variables with same type in a single table

* Sat Apr 07 2007 <kaigai@kaigai.gr.jp> - 8.2.3-0.214
- add the first implementation of SE-PostgreSQL on PGACE framework

* Wed Mar 21 2007 <kaigai@kaigai.gr.jp> - 8.2.3-0.212
- BUGFIX: SetOperation didn't handle its subquery correctly.
  So, it caused server crash.

* Wed Mar 07 2007 <kaigai@kaigai.gr.jp> - 8.2.3-0.209
- BUGFIX: var->varlevelsup was ignored, so outer references
  from subqueries cause a fault.

* Tue Feb 27 2007 <kaigai@kaigai.gr.jp> - 8.2.3-0.178
- Initial RPM build
