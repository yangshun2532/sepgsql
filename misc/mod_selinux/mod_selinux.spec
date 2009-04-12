%define selinux_policy_types targeted mls

Name: mod_selinux
Version: 2.%%__mod_selinux_revision__%%
Release: 1%{?dist}
Summary: Apache/SELinux plus module
Group: System Environment/Daemons
License: ASL
URL: http://code.google.com/p/sepgsql/
Source0: %{name}.c
Source1: %{name}.te
Source2: %{name}.conf
Source3: %{name}.map
BuildRequires: httpd-devel checkpolicy selinux-policy
Requires: httpd policycoreutils selinux-policy
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
Apache/SELinux plus module

%prep
rm -rf %{name}-%{version}
mkdir -p %{name}-%{version}
cp %{SOURCE0} %{name}-%{version}
cp %{SOURCE1} %{name}-%{version}

%build
cd %{name}-%{version}

# mod_selinux.so
%{_sbindir}/apxs -c %{name}.c -lselinux

# mod_selinux.pp
for policy in %{selinux_policy_types}
do
    make NAME=${policy} -f %{?policy_devel_root}%{_datadir}/selinux/devel/Makefile
    mv %{name}.pp %{name}.pp.${policy}
done

%install
rm -rf %{buildroot}

cd %{name}-%{version}
install -d %{buildroot}%{_libdir}/httpd/modules
install -d %{buildroot}%{_datadir}/selinux
install -d %{buildroot}%{_sysconfdir}/httpd/conf.d
install -d %{buildroot}%{_var}/www

install -p -m 755 .libs/%{name}.so %{buildroot}%{_libdir}/httpd/modules
install -p -m 644 %{SOURCE2}       %{buildroot}%{_sysconfdir}/httpd/conf.d
install -p -m 644 %{SOURCE3}       %{buildroot}%{_var}/www
for policy in %{selinux_policy_types}
do
    install -d %{buildroot}%{_datadir}/selinux/${policy}
    install -p -m 644 %{name}.pp.${policy} \
               %{buildroot}%{_datadir}/selinux/${policy}/%{name}.pp
done

%clean
rm -rf %{buildroot}

%post
/sbin/fixfiles -R %{name} restore || :

for policy in %{selinux_policy_types}
do
    %{_sbindir}/semodule -s ${policy} -r %{name} >& /dev/null || :
    %{_sbindir}/semodule -s ${policy} \
            -i %{_datadir}/selinux/${policy}/%{name}.pp >& /dev/null || :
done

%postun
if [ $1 -eq 0 ]; then
    for policy in %{selinux_policy_types}
    do
        %{_sbindir}/semodule -s ${policy} -r %{name} >& /dev/null || :
    done
fi

%files
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/httpd/conf.d/%{name}.conf
%config(noreplace) %{_var}/www/%{name}.map
%{_libdir}/httpd/modules/%{name}.so
%{_datadir}/selinux/*/%{name}.pp

%changelog
* Sun Apr 12 2009 KaiGai Kohei <kaigai@kaigai.gr.jp> 2.xxxx
- Initial build
