drop table �t�Ӹ��;
create table �t�Ӹ�� (��~�O text, ���q���Y varchar, �a�} varchar(16));
create index �t�Ӹ��index1 on �t�Ӹ�� using btree (��~�O);
create index �t�Ӹ��index2 on �t�Ӹ�� using hash (���q���Y);
insert into �t�Ӹ�� values ('�q���~', '�F�F���', '�_A01��');
insert into �t�Ӹ�� values ('�s�y�~', '�]���������q', '��B10��');
insert into �t�Ӹ�� values ('�\���~', '�����ѥ��������q', '��Z01�E');
vacuum �t�Ӹ��;
select * from �t�Ӹ��;
select * from �t�Ӹ�� where �a�} = '��Z01�E';
select * from �t�Ӹ�� where �a�} ~* '��z01�E';
select * from �t�Ӹ�� where �a�} like '_Z01_';
select * from �t�Ӹ�� where �a�} like '_Z%';
select * from �t�Ӹ�� where ���q���Y ~ '�F�F��[�H�O��]';
select * from �t�Ӹ�� where ���q���Y ~* '�F�F��[�H�O��]';

select *, character_length(��~�O) from �t�Ӹ��;
select *, octet_length(��~�O) from �t�Ӹ��;
select *, position('����' in ���q���Y) from �t�Ӹ��;
select *, substring(���q���Y from 3 for 6 ) from �t�Ӹ��;