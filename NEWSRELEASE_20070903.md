# SE-PostgreSQL 8.2.4-1.0 Released #

SE-PostgreSQL development team released "SE-PostgreSQL 8.2.4-1.0" and
"The SE-PostgreSQL Security Guide (Japanese/English)".

You can get these packages from the following URL:

```
http://code.google.com/p/sepgsql/downloads/list
```

**NOTE:** Any packages built for Fedora development edition (rawhide) will be distributed via Fedora mirrors.

### SE-PostgreSQL 8.2.4-1.0 ###
  * sepostgresql-8.2.4-1.0.fc7.i386.rpm
  * sepostgresql-8.2.4-1.0.fc7.src.rpm

### The base security policy for Fedora 7 ###
  * selinux-policy-devel-2.6.4-38.sepgsql.fc7.noarch.rpm
  * selinux-policy-targeted-2.6.4-38.sepgsql.fc7.noarch.rpm
  * selinux-policy-2.6.4-38.sepgsql.fc7.noarch.rpm
  * selinux-policy-2.6.4-38.sepgsql.fc7.src.rpm

### The official documentation ###
  * sepgsql\_security\_guide.20070903.jp.pdf
  * sepgsql\_security\_guide.20070903.en.pdf

See the following URL, for installation details.

```
SE-PostgreSQL Installation Memo (Fedora 7)
  http://code.google.com/p/sepgsql/wiki/install_memo_Fedora7
```

## The features of SE-PostgreSQL ##
Security-Enhanced PostgreSQL (SE-PostgreSQL) is a security extension built in PostgreSQL.
It enables to apply a unified security policy of SELinux to both operating system and database management system.
In addition, it also provides fine-grained access control including column and row level, and mandatory access control being non-bypassable, even if privileged database users.
These features enables to build a database management system into information flow control scheme integrated with operating system, and to protect our information asset from threats like manipulation or leaking.

## The position of this version ##
This is the first official version of SE-PostgreSQL based on PostgreSQL 8.2.4. However, it does not have enough achievement of works compared to the original PostgreSQL. Therefore, we recommend you to have enough evaluation and verification on its introduction.
The series of SE-PostgreSQL 8.2.4-1.x got into maintenance phase after the release of this version, and we don't have any plan to release new version in this series, except for bug fixes.
The SE-PostgreSQL development team has a plan to develop next major version of SE-PostgreSQL based on PostgreSQL 8.3, with several new features.

## Acknowledgment ##
The development of SE-PostgreSQL is supported by Exploratory Software Project, IPA(Information-technology Promotion Agency, Japan).


# SE-PostgreSQL 8.2.4-1.0 リリース #

2007年9月3日、SE-PostgreSQL開発チームは、SE-PostgreSQL 8.2.4-1.0 及び
「The SE-PostgreSQL Security Guide (日本語/英語)」をリリースしました。

以下のURLより、これらのパッケージ群を取得することができます。

```
http://code.google.com/p/sepgsql/downloads/list
```

**注釈:** なお、Fedora 開発版(rawhide) 用のパッケージは順次 Fedora のミラーから取得可能になる予定です。

### SE-PostgreSQL 8.2.4-1.0 ###
  * sepostgresql-8.2.4-1.0.fc7.i386.rpm
  * sepostgresql-8.2.4-1.0.fc7.src.rpm

### Fedora 7 向け ベースセキュリティポリシー ###
  * selinux-policy-devel-2.6.4-38.sepgsql.fc7.noarch.rpm
  * selinux-policy-targeted-2.6.4-38.sepgsql.fc7.noarch.rpm
  * selinux-policy-2.6.4-38.sepgsql.fc7.noarch.rpm
  * selinux-policy-2.6.4-38.sepgsql.fc7.src.rpm

### 公式ドキュメント ###
  * sepgsql\_security\_guide.20070903.jp.pdf
  * sepgsql\_security\_guide.20070903.en.pdf

インストール手順については、下記のURLを参照してください。

```
SE-PostgreSQL Installation Memo (Fedora 7)
  http://code.google.com/p/sepgsql/wiki/install_memo_Fedora7
```

## SE-PostgreSQL とは ##
SE-PostgreSQL (Security Enhanced PostgreSQL) は PostgreSQL にビルトインの
セキュリティ拡張機能で、オペレーティングシステムとデータベース管理システム
に対して共通のSELinuxセキュリティポリシーを適用します。
加えて、SE-PostgreSQLは行レベル/列レベルを含む細粒度のアクセス制御機能と、
特権DBユーザに対しても回避不可能な強制アクセス制御機能を提供しています。
このような SE-PostgreSQL の特徴は、データベース管理システムを、オペレーテ
ィングシステムと一体化した情報フロー制御の枠組みに組み込むことを可能にし、
情報資産を漏えいや改ざんといった脅威から保護します。

## 本バージョンの位置づけ ##
本バージョンは、PostgreSQL 8.2.4 をベースにした SE-PostgreSQL の最初の公式な
リリースです。しかしながら、オリジナルの PostgreSQL と比較して、動作実績は未
だ十分ではありません。従って、SE-PostgreSQLの導入においては、自身で十分な評価
検証を行なうことを推奨します。
本バージョンのリリース以降、SE-PostgreSQL 8.2.4-1.x 系列はメンテナンスフェー
ズに入り、バグ修正以外の新規機能の追加は行ないません。
今後、SE-PostgreSQL 開発チームは、各種の新機能と共に、PostgreSQL 8.3 ベースの
SE-PostgreSQLの開発を計画しています。

## 謝辞 ##
SE-PostgreSQLの開発は、IPA/未踏ソフトウェア創造事業(2006年度/下期)の支援を受
けて開発が進められました。
