#
# Security Enhanced PostgreSQL (SE-PostgreSQL)
#
# Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
# -----------------------------------------------------

%{!?sepgversion:%define sepgversion %%__default_sepgversion__%%}
%{!?sepgrevision:%define sepgrevision %%__default_sepgrevision__%%}
%{!?sepgextension:%define sepgextension %%__default_sepgextension__%%}
%define _policydir    /usr/share/selinux
%define _prefix       /opt/sepgsql

# definition of SELinux policy types
%define selinux_variants mls strict targeted 

# SE-PostgreSQL requires only server side files
%define _unpackaged_files_terminate_build 0

Summary: Security Enhanced PostgreSQL
Group: Applications/Databases
Name: sepostgresql
Version: %%__base_postgresql_version__%%
Release: %{?sepgversion}.%{?sepgrevision}%{?sepgextension}%{?dist}
License: BSD
Group: Applications/Databases
Url: http://code.google.com/p/sepgsql/
Buildroot: %{_tmppath}/%{name}-%{version}-root
Source0: postgresql-%{version}.tar.gz
Source1: sepostgresql.init
Source2: sepostgresql.if
Source3: sepostgresql.te
Source4: sepostgresql.fc
Patch0: sepostgresql-%{version}-%{release}.patch

Buildrequires: checkpolicy >= 2.0.2 libselinux-devel >= 2.0.13 selinux-policy-devel >= 2.6.4-14
Requires: libselinux >= 2.0.13 policycoreutils >= 2.0.16 selinux-policy >= 2.6.4-14

%description
Security Enhanced PostgreSQL is an extension of PostgreSQL
based on SELinux security policy, that applies fine grained
mandatory access control to many objects within the database,
and takes advantage of user authorization integrated within
the operating system. SE-PostgreSQL works as a userspace
reference monitor to check any SQL query.

%prep
# confirm the release string of selinux-policy-devel
if ! rpm -q selinux-policy-devel | sed 's/^.*-//g' | egrep -q '.sepgsql'; then
   echo ".sepgsql version of selinux-policy-devel is needed for build"
   exit 1
fi

%setup -q -n postgresql-%{version}
%patch0 -p1
mkdir selinux-policy
cp %{SOURCE2} %{SOURCE3} %{SOURCE4} selinux-policy

%build
# build Binary Policy Module
pushd selinux-policy
for selinuxvariant in %{selinux_variants}
do
    make NAME=${selinuxvariant} -f /usr/share/selinux/devel/Makefile
    mv %{name}.pp %{name}.pp.${selinuxvariant}
    make NAME=${selinuxvariant} -f /usr/share/selinux/devel/Makefile clean
done
popd

# build SE-PostgreSQL
autoconf
%configure      --enable-selinux \
                --host=%{_host} --build=%{_build} \
%if %{defined sepgextension}
                --enable-debug \
                --enable-cassert \
%endif
                --prefix=%{_prefix}
# parallel build, if possible
NCPUS=`grep -c ^processor /proc/cpuinfo`
make -j ${NCPUS}

%install
rm -rf %{buildroot}

pushd selinux-policy
for selinuxvariant in %{selinux_variants}
do
    install -d %{buildroot}%{_policydir}/${selinuxvariant}
    install -p -m 644 %{name}.pp.${selinuxvariant} \
        %{buildroot}%{_policydir}/${selinuxvariant}/%{name}.pp
done
popd

make DESTDIR=%{buildroot} install

install -d -m 700 %{buildroot}/var/lib/sepgsql
install -d -m 700 %{buildroot}/var/lib/sepgsql/data
install -d -m 700 %{buildroot}/var/lib/sepgsql/backups
(echo "# .bash_profile"
 echo "if [ -f /etc/bashrc ]; then"
 echo "    . /etc/bashrc"
 echo "fi"
 echo
 echo "PGDATA=/var/lib/sepgsql/data"
 echo "export PGDATA") > %{buildroot}/var/lib/sepgsql/.bash_profile

mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m 755 %{SOURCE1} $RPM_BUILD_ROOT/etc/rc.d/init.d/sepostgresql

%clean
rm -rf $RPM_BUILD_ROOT

%pre
# confirm the release string of selinux-policy-devel
if ! rpm -q selinux-policy | sed 's/^.*-//g' | egrep -q '.sepgsql'; then
   echo ".sepgsql version of selinux-policy is needed to install"
   exit 1
fi

if [ $1 -eq 1 ]; then           # rpm -i cases
    (id -g sepgsql || groupadd -r sepgsql || : ) &> /dev/null
    (id -u sepgsql || useradd -g sepgsql -d /var/lib/sepgsql -s /bin/bash \
                              -r -c "SE-PostgreSQL server" sepgsql || : ) &> /dev/null
fi

%post
/sbin/chkconfig --add sepostgresql
/sbin/ldconfig

for selinuxvariant in %{selinux_variants}
do
    /usr/sbin/semodule -s ${selinuxvariant} -l | egrep -q '^%{name}' && \
        /usr/sbin/semodule -s ${selinuxvariant} -r %{name} &> /dev/null || :
    /usr/sbin/semodule -s ${selinuxvariant} -i \
         %{_policydir}/${selinuxvariant}/%{name}.pp &> /dev/null || :
done
# Fix up non-standard file contexts
/sbin/fixfiles -R %{name} restore || :
/sbin/restorecon -R /var/lib/sepgsql || :

%postun
/sbin/ldconfig
if [ $1 -eq 0 ]; then           # rpm -e cases
    userdel  sepgsql &> /dev/null || :
    groupdel sepgsql &> /dev/null || :
    for selinuxvariant in %{selinux_variants}
    do
        /usr/sbin/semodule -s ${selinuxvariant} -l | egrep -q '^%{name}' && \
            /usr/sbin/semodule -s ${selinuxvariant} -r %{name} &> /dev/null || :
    done
    /sbin/fixfiles -R %{name} restore || :
    test -d /var/lib/sepgsql && /sbin/restorecon -R /var/lib/sepgsql &> /dev/null || :
fi

%files
%defattr(-,root,root,-)
/etc/rc.d/init.d/sepostgresql
%dir %{_prefix}
%dir %{_bindir}
%{_bindir}/initdb
%{_bindir}/ipcclean
%{_bindir}/pg_controldata
%{_bindir}/pg_ctl
%{_bindir}/pg_resetxlog
%{_bindir}/postgres
%{_bindir}/postmaster
%{_bindir}/pg_dump
%{_bindir}/pg_dumpall
%{_bindir}/pg_restore
%dir %{_mandir}
%dir %{_mandir}/man1
%{_mandir}/man1/initdb.*
%{_mandir}/man1/ipcclean.*
%{_mandir}/man1/pg_controldata.*
%{_mandir}/man1/pg_ctl.*
%{_mandir}/man1/pg_resetxlog.*
%{_mandir}/man1/postgres.*
%{_mandir}/man1/postmaster.*
%dir %{_datadir}
%{_datadir}/postgres.bki
%{_datadir}/postgres.description
%{_datadir}/postgres.shdescription
%{_datadir}/system_views.sql
%{_datadir}/*.sample
%{_datadir}/timezone/
%{_datadir}/timezonesets/
%{_datadir}/conversion_create.sql
%{_datadir}/information_schema.sql
%{_datadir}/sql_features.txt
%dir %{_libdir}
%{_libdir}/plpgsql.so
%{_libdir}/libpq.*
%{_libdir}/libpgtypes.*
%{_libdir}/*_and_*.so
%attr(644,root,root) %{_policydir}/*/sepostgresql.pp
%attr(700,sepgsql,sepgsql) %dir /var/lib/sepgsql
%attr(700,sepgsql,sepgsql) %dir /var/lib/sepgsql/data
%attr(700,sepgsql,sepgsql) %dir /var/lib/sepgsql/backups
/var/lib/sepgsql/.bash_profile

%changelog
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
