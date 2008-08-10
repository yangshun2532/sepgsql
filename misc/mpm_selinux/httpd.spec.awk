/^%define[ ]+mpms/ {
    printf("%s selinux\n",$0);
    print "%define selinux_policy_stores targeted mls"
    next;
}
/^License:/ {
    print "# SELinux awared MPM";
    print "Patch99: httpd-mpm-selinux.patch";
    print "Source99: mpm_selinux.conf";
    print;
    next;
}
/^%package[ ]+devel$/ {
    print "%package selinux";
    print "Group: Development/Libraries";
    print "Summary: SELinux awared Apache MPM (prefork base)";
    print "Requires: httpd = %{version}-%{release}";
    print "BuildRequires: checkpolicy, selinux-policy";
    print "";
    print "%description selinux";
    print "SELinux awared Apache MPM (prefork base)";
    print "";
    print;
    next;
}
/^%setup -q$/ {
    print;
    print "%patch99 -p1";
    next;
}
/^%install$/ {
    print "# SELinux security policy"
    print "pushd server/mpm/selinux/policy"
    print "for store in %{selinux_policy_stores}; do"
    print "    make NAME=$x -f %{_datadir}/selinux/devel/Makefile"
    print "    mv httpd-selinux.pp httpd-selinux.$store.pp"
    print "done";
    print "popd";
    print "";
    print;
    next;
}
/^%pre$/ {
    print "# httpd-selinux related installation";
    print "pushd server/mpm/selinux/policy"
    print "for store in %{selinux_policy_stores}; do"
    print "    mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/selinux/${store}"
    print "    install -m 644 -p httpd-selinux.$store.pp ${RPM_BUILD_ROOT}%{_datadir}/selinux/${store}/httpd-selinux.pp"
    print "done"
    print "popd"
    print "install -m 644 -p %SOURCE99 ${RPM_BUILD_ROOT}%{_sysconfdir}/httpd/conf.d/mpm_selinux.conf";
    print "";
    print;
    next;
}
/^%check$/ {
    print "%post selinux"
    print "for store in %{selinux_policy_stores}; do"
    print "    %{_sbindir}/semodule -s ${store} -r httpd-selinux >& /dev/null || :"
    print "    %{_sbindir}/semodule -s ${store} -i %{_datadir}/selinux/${store}/httpd-selinux.pp >& /dev/null || :"
    print "done"
    print "/sbin/fixfiles -R %{name} restore || :"
    print ""
    print "%postun selinux"
    print "if [ $1 -eq 0 ]; then"
    print "    for store in %{selinux_policy_stores}; do"
    print "        %{_sbindir}/semodule -s ${store} -r httpd-selinux >& /dev/null || :"
    print "    done"
    print "fi"
    print ""
    print;
    next;
}
/^%files[ ]+devel/ {
    print "%files selinux"
    print "%{_sbindir}/httpd.selinux"
    print "%config(noreplace) %{_sysconfdir}/httpd/conf.d/mpm_selinux.conf"
    print "%{_datadir}/selinux/*/httpd-selinux.pp"
    print "";
    print;
    next;
}
{
    print;
}
