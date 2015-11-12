![http://sepgsql.googlecode.com/files/sepgsql_logo.png](http://sepgsql.googlecode.com/files/sepgsql_logo.png)

# Now v8.3 based SE-PostgreSQL is available #
SE-PostgreSQL development team published v8.3 based SE-PostgreSQL at:

http://download.fedora.redhat.com/pub/fedora/linux/development

You can obtain the v8.3 based sepostgresql package which contains
its security policy module from here.
```
NOTE: This version is not available at Fedora 8 or prior.
      Please wait for Fedora 9, or update your system to rawhide.
```
The following official documentation will help your understanding:
> http://sepgsql.googlecode.com/files/sepgsql_security_guide.20080214.en.pdf

Updates from v8.2 based SE-PostgreSQL
  * The base version was upgraded to PostgreSQL 8.3.0
  * It enabled to share external libraries (like -contrib package) with original PostgreSQL.
  * Cumulative bugfixes.

## The features of SE-PostgreSQL ##
Security-Enhanced PostgreSQL (SE-PostgreSQL) is a security extension
built in PostgreSQL, to provide system-wide consistency in access
controls. It enables to apply a single unigied security policy of
SELinux for both operating system and database management system.
In addition, it also provides fine-grained mandatory access which
includes column-/row- level non-bypassable access control even if
privileged database users.
These features enables to deploy SE-PostgreSQL into data flow control
scheme integrated with operating system, to protect our information
asset from threats like leaking, manupulation and so on.

> http://code.google.com/p/sepgsql/wiki/WhatIsSEPostgreSQL

# v8.3 ベースの SE-PostgreSQL を公開 #
SE-PostgreSQL 開発チームは、v8.3 ベース SE-PostgreSQL を公開しました。

> http://download.fedora.redhat.com/pub/fedora/linux/development

上記のURLより、セキュリティポリシーモジュールを含む、SE-PostgreSQLの
パッケージを取得することができます。
```
注意: このバージョンは、Fedora 8 以前のシステムには対応していません。
      システムを Rawhide (開発者版) にアップデートするか、Fedora 9 を
      お待ちください。
```
以下の公式ドキュメントは、SE-PostgreSQLの理解の助けになるでしょう。
> http://sepgsql.googlecode.com/files/sepgsql_security_guide.20080214.jp.pdf

v8.2ベース SE-PostgreSQL から、以下の点が変更されています。
  * ベースバージョンを PostgreSQL 8.3.0 にアップグレードしました。
  * contrib パッケージで提供されているような、外部のライブラリを、オリジナルの PostgreSQL と共有することが可能になりました。
  * 累積的なバグ修正を行なっています。

## SE-PostgreSQLの特徴 ##
Security-Enhanced PostgreSQL (SE-PostgreSQL) は、システムワイドで一貫
したアクセス制御を提供することを目的に開発された、PostgreSQLのセキュ
リティ拡張機能です。本機能は、一個の統合された SELinux セキュリティポ
リシーを、OSとRDBMSの双方に適用することを可能にします。
加えて、行レベル・列レベルで適用され、特権ユーザでさえも回避不可能な
細粒度の強制アクセス制御も提供されています。
これらの機能は、SE-PostgreSQLをOSと統合された情報フロー制御の枠組みに
組込むことを可能にし、我々の情報資産を漏えいや改ざんといった脅威から
保護することを可能にします。

> http://code.google.com/p/sepgsql/wiki/WhatIsSEPostgreSQL