![http://sepgsql.googlecode.com/files/sepgsql_logo.png](http://sepgsql.googlecode.com/files/sepgsql_logo.png)

# What is SE-PostgreSQL? #

Security-Enhanced PostgreSQL (SE-PostgreSQL) is a security extension built in PostgreSQL.
It works as a reference monitor within relational database management system, and provides fine-grained mandatory access control features collaborating with SELinux and its security policy.

These features enable to deploy a database management system into data flow control scheme, integrated with operating system. We call the most characteristic feature of SE-PostgreSQL as ''system-wide consistency in access controls''. Any other RDBMS cannot provide this feature in current.

# Why we need SE-PostgreSQL #
We can consider RDBMS, including PostgreSQL, is one of the methods to communicate between processes.

![http://sepgsql.googlecode.com/files/sepgsql_dfc.png](http://sepgsql.googlecode.com/files/sepgsql_dfc.png)

SELinux is an operating system feature to apply its security policy whenever we accesses any resource managed by operating system, like files, sockets, IPC objects and so on.
Protection of leaking classified information is the most significant purpose of SELinux. However, it can be leaked via various kind of routes, when we have different security policy for several routes. As frequently said, the most vulnerable route is its security level of whole the system. Therefore, we have to apply a single unified security policy for various kind of resources, as SELinux doing.

It enables to protect leaking ''A Secret Information Asset'' managed by users with clearance into another one.
But you have to pay attention there are several userspace object managers (like X-Window, RDBMS, etc...) which can be used as a method of inter-processes communication. The data-flows in the userspace are invisible from SELinux, because it works in the kernel.

It means they need to refer the security policy of SELinux to check whether the required access on userspace resources should be allowed, or not. One representative userspace object manager is relational database management systems which can manage massive amount of userspace resources.

SE-PostgreSQL can control accesses on its managing resources, based on the security policy of SELinux.
It enables to apply a single unified policy onto database objects (like tables, columns, etc...) as SELinux doing on resources managed by operating system.

## Information flow control unified with operating system ##

![http://sepgsql.googlecode.com/files/sepgsql_and_pgsql.png](http://sepgsql.googlecode.com/files/sepgsql_and_pgsql.png)

The above figure compares the original PostgreSQL with SE-PostgreSQL.

When a `SystemHigh` user holds classified information and he writes it into filesystem as a file,
this file is labeled as `Classified` by SELinux.
If a `SystemLow` user tries to access the information stored in this file, it is not succeeded
because SELinux prevents users with lower clearance to access files with higher one.

However, when a `SystemHigh` user inserts his classified information into PostgreSQL as a database record,
PostgreSQL does not handle it based on the security policy of SELinux, so this record does not have any available security context. Therefore, the `SystemLow` user can access this recored. It means breakage of data flow control scheme.

Meanwhile, the inserted record into SE-PostgreSQL is labeled as `Classified`, as SELinux doing on filesystem.
`SystemLow` user cannot access this record, because the security policy of SELinux does not allow him to access and SE-PostgreSQL makes its decision according to the security policy.

In the result, same access control policy is applied for both passes, and there is no breakage of data flow control in SE-PostgreSQL.

## mandatory access control ##

The original PostgreSQL has special privilleged users called as superuser.
They can refere, modify and remove any database object without any limitation,
as a traditional `root` can do anything on operating system.

SE-PostgreSQL provides mandatory access control (MAC) feature, and
it is applied for any database client including privileged users.

When either MAC or database ACL configured with GRANT/REVOKE statement
does not allow a client to access the reuired database object, it is not succeeded.

## fine-grained access control ##

SE-PostgreSQL provides fine-grainer access control than the original PostgreSQL.
It includes column- and tuple- level access control.

![http://sepgsql.googlecode.com/files/sepgsql_fine_grained.png](http://sepgsql.googlecode.com/files/sepgsql_fine_grained.png)

The table of drink contains six tuples. The four tuples have `Unclassified` label, and rest of them have `Secret` one.
These attributes are stored in system column named as `security_context`.
When `SystemHigh` user tries to dump this table with `SELECT * FROM drink`, the result set contains six tuples.
However, `SystemLow` user get only four tuples, because all tuples labeled as `Secret` are filtered from the result set.

In column level access control, the current transaction is aborted when a user tries to access violated column.
For example, consider the column `salary` of the following table is labeled as `Secret`.
```
+------------------------------+
| TABLE: person                |
+----+----------+-----+--------+
| id | name     | age | salary |
+----+----------+-----+--------+
| 10 | T.Yamada |  28 | $2500  |
| 12 | K.Suzuki |  31 | $3000  |
|  : |    :     |  :  |   :    |
```
When `SystemLow` user tries to execute "`SELECT * FROM person;`", it will be aborted because this query refers `salary` column without appropriate permission.
It is necessary to drop violated columns like "`SELECT id, name, age FROM person;`".

# Examples of SE-PostgreSQL #

## Row-level access controls ##
This section shows an example of row-level access controls.

Execute the following SQL operations at `unconfined_t` domain with `SystemLow-SystemHigh`,
to set up a sample table and function.
```
CREATE TABLE genre (
    gid     integer primary key,
    dsc     varchar (32)
);
GRANT ALL ON genre TO PUBLIC;
 
CREATE TABLE drink (
    id      integer primary key,
    gid     integer references genre(gid),
    name    varchar(32),
    price   integer
);
GRANT ALL ON drink TO PUBLIC;
 
INSERT INTO genre (gid, dsc)
    VALUES (5, 'soft drink'),
           (6, 'fizzwater'),
           (7, 'alcohol');
 
INSERT INTO drink (id, gid, name, price)
    VALUES (11, NULL, 'water', 100),
           (12,    6, 'coke',  120),
           (13,    5, 'milk',  150),
           (14,    5, 'juice', 130),
           (15,    6, 'cider', 140),
           (16, NULL, 'soup',  180),
           (17,    7, 'beer',  240),
           (18,    7, 'wine',  480);
 
UPDATE genre SET security_context = 'system_u:object_r:sepgsql_table_t:s0:c0' WHERE gid = 6;
UPDATE drink SET security_context = 'system_u:object_r:sepgsql_table_t:s0:c0' WHERE id IN (15,16,17);
```

`...:unconfined_t:SystemLow-SystemHigh` will get the following result, without any filtered tuple.
```
kaigai=# SELECT security_context, * FROM drink;
             security_context             | id | gid | name  | price
------------------------------------------+----+-----+-------+-------
 unconfined_u:object_r:sepgsql_table_t:s0 | 11 |     | water |   100
 unconfined_u:object_r:sepgsql_table_t:s0 | 12 |   6 | coke  |   120
 unconfined_u:object_r:sepgsql_table_t:s0 | 13 |   5 | milk  |   150
 unconfined_u:object_r:sepgsql_table_t:s0 | 14 |   5 | juice |   130
 unconfined_u:object_r:sepgsql_table_t:s0 | 18 |   7 | wine  |   480
 system_u:object_r:sepgsql_table_t:s0:c0  | 15 |   6 | cider |   140
 system_u:object_r:sepgsql_table_t:s0:c0  | 16 |     | soup  |   180
 system_u:object_r:sepgsql_table_t:s0:c0  | 17 |   7 | beer  |   240
(8 rows)
 
kaigai=#
```

If you have weaker permissions, any violated tuples are filtered from result set.
```
[kaigai@saba test]$ runcon -l s0 psql -q
kaigai=# SELECT sepgsql_getcon();
              sepgsql_getcon
-------------------------------------------
 unconfined_u:unconfined_r:unconfined_t:s0
(1 row)
 
kaigai=# SELECT security_context, * FROM drink;
             security_context             | id | gid | name  | price
------------------------------------------+----+-----+-------+-------
 unconfined_u:object_r:sepgsql_table_t:s0 | 11 |     | water |   100
 unconfined_u:object_r:sepgsql_table_t:s0 | 12 |   6 | coke  |   120
 unconfined_u:object_r:sepgsql_table_t:s0 | 13 |   5 | milk  |   150
 unconfined_u:object_r:sepgsql_table_t:s0 | 14 |   5 | juice |   130
 unconfined_u:object_r:sepgsql_table_t:s0 | 18 |   7 | wine  |   480
(5 rows)
 
kaigai=#
```

SE-PostgreSQL filters any violated tuple, even if a query contains multiple relations.
It is done before joining relations, as if filtered tuples don't exist.

Pay attention, 'fizzwater' is filtered but 'coke' is remain in the result set.
```
[kaigai@saba test]$ runcon -l s0 psql -q
kaigai=# SELECT sepgsql_getcon();
              sepgsql_getcon
-------------------------------------------
 unconfined_u:unconfined_r:unconfined_t:s0
(1 row)
 
kaigai=# SELECT * FROM drink left join genre on drink.gid = genre.gid;
 id | gid | name  | price | gid |    dsc
----+-----+-------+-------+-----+------------
 11 |     | water |   100 |     |
 12 |   6 | coke  |   120 |     |
 13 |   5 | milk  |   150 |   5 | soft drink
 14 |   5 | juice |   130 |   5 | soft drink
 18 |   7 | wine  |   480 |   7 | alcohol
(5 rows)
 
kaigai=#
```

## Column level access controls ##

This section shows an example of column-level access controls.

Execute the following SQL operations at `unconfined_t` domain, to set up a sample table and function.

```
CREATE TABLE customer (
    cid     integer primary key,
    cname   varchar(32),
    credit  varchar(32)  CONTEXT = 'system_u:object_r:sepgsql_secret_table_t:s0'
);
GRANT ALL ON customer TO PUBLIC;
 
INSERT INTO customer (cid, cname, credit)
    VALUES ( 10, 'jack', '1111-2222-3333-4444'),
           ( 13, 'adam', '5555-6666-7777-8888'),
           ( 14, 'liza', '9876-5432-1098-7654');
 
CREATE OR REPLACE FUNCTION show_credit (integer) RETURNS text
    LANGUAGE 'sql'
    CONTEXT = 'system_u:object_r:sepgsql_trusted_proc_t'
    AS 'SELECT substring(credit from ''^[0-9]+-'') || ''xxxx-xxxx-xxxx'' FROM customer WHERE CID = $1';
```

Pay attention `customer.credit` is declared as `sepgsql_secret_table_t`.

It means non-administrative domain canno read this column, as follows:
```
[tak@saba ~]$ id -Z
user_u:user_r:user_t:s0
 
[tak@saba ~]$ psql postgres
Welcome to psql 8.3.0, the PostgreSQL interactive terminal.
 
Type:  \copyright for distribution terms
       \h for help with SQL commands
       \? for help with psql commands
       \g or terminate with semicolon to execute query
       \q to quit
 
postgres=# SELECT sepgsql_getcon();
     sepgsql_getcon
-------------------------
 user_u:user_r:user_t:s0
(1 row)
 
postgres=# SELECT * FROM customer;
ERROR:  SELinux: denied { select }                            \
        scontext=user_u:user_r:user_t:s0                      \
        tcontext=system_u:object_r:sepgsql_secret_table_t:s0  \
        tclass=db_column name=customer.credit
```

The following example shows clearly that refering `customer.credit` prevents to execute SQL.
```
postgres=# SELECT cid, cname FROM customer;
 cid | cname
-----+-------
  10 | jack
  13 | adam
  14 | liza
(3 rows)
```

The idea of ''trusted-procedure'' enables to provide safe methods to access prevented database objects.

Pay attention `show_credit(integer)` is declared as `sepgsql_trusted_proc_t`.
Invokation of `sepgsql_trusted_proc_t` makes domain transition to `sepgsql_trusted_domain_t`. The default security policy allows this domain to access widespread database objects.
`show_credit(integer)` returns head of 4 chars in credit card number and rest of turned letter. It can refer `sepgsql_secret_table_t` column, but it does not leak the contains.
```
postgres=# SELECT cid, cname, show_credit(cid) FROM customer;
 cid | cname |     show_credit
-----+-------+---------------------
  10 | jack  | 1111-xxxx-xxxx-xxxx
  13 | adam  | 5555-xxxx-xxxx-xxxx
  14 | liza  | 9876-xxxx-xxxx-xxxx
(3 rows)
 
postgres=#
```

# How to build/install SE-PostgreSQL #

To apply RPM package is a recommended way to install/set up SE-PostgreSQL.
We now provide `sepostgresql` RPM package, and you can obtain it from:

http://download.fedora.redhat.com/pub/fedora/linux/development/

However, you can build it by yourself.

## ENVIRONMENT ##
Please confirm your system environment.
  * Fedora 8 or later system
  * SELinux is enabled and working
  * kernel-2.6.23 or later
  * selinux-policy and selinux-policy-devel v3.0.8 or later
  * libselinux, policycoreutils, checkpolicy

## BUILD ##
```
$ tar jxvf postgresql-snapshot.tar.bz2
$ cd postgresql-snapshot
$ patch -p1 < sepostgresql-sepgsql-8.4devel-3-r914.patch
$ patch -p1 < sepostgresql-pg_dump-8.4devel-3-r914.patch
$ patch -p1 < sepostgresql-policy-8.4devel-3-r914.patch
$ patch -p1 < sepostgresql-docs-8.4devel-3-r914.patch
$ ./configure --enable-selinux
$ make
$ make -C ./contrib/sepgsql_policy

$ su
# /usr/sbin/semodule -i ./contrib/sepgsql_policy/sepostgresql.pp
  (NOTE: apply sepostgresql-devel.pp for selinux-policy-3.4.2, or later.)
# make install
# /sbin/restorecon -R /usr/local/pgsql
```

## SETUP ##
```
$ mkdir -p $PGDATA
$ chcon -t postgresql_db_t -R $PGDATA
$ initdb
$ pg_ctl start
```

## SUMMARYS FOR EVERY PATCHES ##

### [1/4] - sepostgresql-sepgsql-8.4devel-3-[r914](https://code.google.com/p/sepgsql/source/detail?r=914).patch ###

This patch provides core facilities of PGACE/SE-PostgreSQL.

PGACE (PostgreSQL Access Control Extension) framework has a similar concept
of LSM (Linux Security Module).
It can provide a guest module several hooks at strategic points.
The guest module can make its decision whether required actions should be
allowed, or not.
In addition, PGACE also provides falicilites to manage security attribute
of database objects. A security attribute is associated with any database
object, and PGACE enables to translate it between internal identifier and
text representation.

Security-Enhanced PostgreSQL (SE-PostgreSQL) is a security extension
built in PostgreSQL, to provide system-wide consistency in access
controls. It enables to apply a single unigied security policy of
SELinux for both operating system and database management system.
In addition, it also provides fine-grained mandatory access which
includes column-/row- level non-bypassable access control even if
privileged database users.

### [2/4] - sepostgresql-pg\_dump-8.4devel-3-[r914](https://code.google.com/p/sepgsql/source/detail?r=914).patch ###

This patch gives us a feature to dump database with security attribute.
It is turned on with '--enable-selinux' option at pg\_dump/pg\_dumpall,
when the server works as SE- version.
No need to say, users need to have enough capabilities to dump whole of
database. It it same when they tries to restore the database.

### [3/4] - sepostgresql-policy-8.4devel-3-[r914](https://code.google.com/p/sepgsql/source/detail?r=914).patch ###

This patch gives us the default (development) security policy of SE-PostgreSQL.
You can build it as a security poicy module, and link it with the existing
distributor's policy.

`selinux-policy-3.4.2` or later contains most of the policy.
If it is instaleld on your system, use `sepostgresql-devel.pp` instead.
It provides several booleans useful for development.
  * sepgsql\_enable\_auditallow
> > It enables to print/write access allowed logs (default: off).
  * sepgsql\_enable\_auditdeny
> > It enables to print/write access denied logs (default: on).
  * sepgsql\_regression\_test\_mode
> > It gives us additional permissions to run regression test (default: off).

### [4/4] - sepostgresql-docs-8.4devel-3-[r914](https://code.google.com/p/sepgsql/source/detail?r=914).patch ###

This patch gives us documentation updates which include a step by step guide of
build & installation, a feature description of SE-PostgreSQL, administration
hints and design of the PGACE security framework.