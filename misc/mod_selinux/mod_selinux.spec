%define selinux_policy_types targeted mls

Summary: SELinux awared CGI script invoker
Name: mod_selinux
Version: 0.1
Release: r%{mod_selinux_revision}
License: ASL 2.0
Group: Applications/Internet
URL: http://code.google.com/p/sepgsql/
Source0: %{name}.c
Source1: %{name}.te
Source2: %{name}.conf
BuildRequires: httpd-devel checkpolicy
Requires: httpd-devel policycoreutils
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description

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
    make NAME=${policy} -f %{_datadir}/selinux/devel/Makefile
    mv %{name}.pp %{name}.pp.${policy}
done

%install
rm -rf %{buildroot}

cd %{name}-%{version}
install -d %{buildroot}%{_libdir}/httpd/modules \
           %{buildroot}/etc/httpd/conf.d  \
           %{buildroot}/%{_datadir}/selinux

install -p -m 755 .libs/%{name}.so %{buildroot}%{_libdir}/httpd/modules
install -p -m 644 %{SOURCE2}       %{buildroot}/etc/httpd/conf.d
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
%{_sysconfdir}/httpd/conf.d/%{name}.conf
%{_libdir}/httpd/modules/%{name}.so
%{_datadir}/selinux/*/%{name}.pp

%changelog
* Sun Jun 22 2008  <kaigai@kaigai.gr.jp> 0.1-r907
- Initial build.

