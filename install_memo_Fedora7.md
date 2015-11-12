# SE-PostgreSQL Instllation Memo on Fedora 7 #
This document describes the way to install SE-PostgreSQL onto Fedora 7 system.

## Preparation & Download ##
You have to set up bare Fedora 7 system, and update them.

SE-PostgreSQL requires the following packages at least, so you have to install them at first.
  * postgresql-server-8.2.4
  * policycoreutils-2.0.16, or later
  * libselinux-2.0.13, or later

All SE-PostgreSQL related packages are available here:
```
http://code.google.com/p/sepgsql/downloads/list
```

In Fedora 7 system, SE-PostgreSQL also requires an modified base security policy, because it does not include the definition of object classes and permissions needed.
  * sepostgresql-8.2.4-1.0.fc7.i386.rpm
  * selinux-policy-2.6.4-38.sepgsql.fc7.noarch.rpm
  * selinux-policy-targeted-2.6.4-38.sepgsql.fc7.noarch.rpm

## Applying RPM packages ##
Apply all SE-PostgreSQL packages at once, as follows:
```
rpm -Uvh selinux-policy-2.6.4-38.sepgsql.fc7.noarch.rpm \
         selinux-policy-targeted-2.6.4-38.sepgsql.fc7.noarch.rpm \
         sepostgresql-8.2.4-1.0.beta.fc7.i386.rpm
```
If you have installed selinux-policy-devel package, you should upgrade the package in same time, bacause it depends on selinux-policy.

Currently, we don't provide selinux-policy-strict and selinux-policy-mls packages, bacause we have not evaluated them enough. If you need those packages, you can generate it from source RPM package (selinux-policy-2.6.4-38.sepgsql.fc7.src.rpm).

Please confirm what SE-PostgreSQL and its security policy are installed without any trouble.

You can use **semodule** to confirm installed binary security policy modules, as follows:
You will be able to found sepostgresql's one.
```
[root@masu ~]# semodule -l
amavis  1.2.1
amtu    1.0.23
      :
    <snip>
      :
screen  1.1.0
sepostgresql    1.0
slocate 1.4.1
      :
    <snip>
      :
zabbix  1.0.0
[root@masu ~]#
```

## Setup SE-PostgreSQL ##
You have to execute **/etc/init.d/sepostgresql** with **initdb** command to initialize a database cluster under **/var/lib/sepgsql**. Please confirm the directory is not exist or empty.
```
[root@masu ~]# /etc/init.d/sepostgresql initdb
Initializing database:                           [  OK  ]
[root@masu ~]# 
```
Then, you can start sepostgresql server. SE-PostgreSQL works with **sepgsql** user on the operating system, so you can create database users as DBA or others on **sepgsql** account at first. This user is created at installation automatically.

In the following example, we create a database role **kaigai** as a DBA.
```
[root@masu ~]# /etc/init.d/sepostgresql start
Starting sepostgresql service:                   [  OK  ]
[root@masu ~]# su - sepgsql
-bash-3.2$ createuser kaigai
Shall the new role be a superuser? (y/n) y
CREATE ROLE
-bash-3.2$
```

## Enjoy SE-PostgreSQL ##
SE-PostgreSQL package does not contain a front-end command.
You can use **psql** command in postgresql package, if necessary.
```
[kaigai@masu ~]$ psql postgres
Welcome to psql 8.2.4, the PostgreSQL interactive terminal.

Type:  \copyright for distribution terms
       \h for help with SQL commands
       \? for help with psql commands
       \g or terminate with semicolon to execute query
       \q to quit

postgres=# select security_context, * from drink;
NOTICE:  SELinux: denied { select } scontext=system_u:system_r:unconfined_t
        tcontext=user_u:object_r:sepgsql_table_t:Classified tclass=db_tuple
NOTICE:  SELinux: denied { select } scontext=system_u:system_r:unconfined_t
        tcontext=user_u:object_r:sepgsql_table_t:Classified tclass=db_tuple
         security_context          | id | name  | price | alcohol
-----------------------------------+----+-------+-------+---------
 system_u:object_r:sepgsql_table_t |  1 | coke  |   110 | f
 system_u:object_r:sepgsql_table_t |  2 | tea   |   120 | f
 system_u:object_r:sepgsql_table_t |  3 | juice |   150 | f
 system_u:object_r:sepgsql_table_t |  4 | water |   120 | f
(4 rows)

postgres=#
```