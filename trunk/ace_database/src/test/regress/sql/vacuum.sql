--
-- VACUUM
--

CREATE TABLE vactst (i INT);
INSERT INTO vactst VALUES (1);
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst VALUES (0);
SELECT count(*) FROM vactst;
DELETE FROM vactst WHERE i != 0;
SELECT * FROM vactst;
VACUUM FULL vactst;
UPDATE vactst SET i = i + 1;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst SELECT * FROM vactst;
INSERT INTO vactst VALUES (0);
SELECT count(*) FROM vactst;
DELETE FROM vactst WHERE i != 0;
VACUUM (FULL) vactst;
DELETE FROM vactst;
SELECT * FROM vactst;

VACUUM (FULL, FREEZE) vactst;
VACUUM (ANALYZE, FULL INPLACE) vactst;

CREATE TABLE vaccluster (i INT PRIMARY KEY);
ALTER TABLE vaccluster CLUSTER ON vaccluster_pkey;
INSERT INTO vaccluster SELECT * FROM vactst;

CREATE TEMP TABLE vacid (
  relid  regclass,
  filenode_0 oid,
  filenode_1 oid,
  filenode_2 oid,
  filenode_3 oid
);

INSERT INTO vacid (relid, filenode_0)
SELECT oid, relfilenode FROM pg_class WHERE oid::regclass IN (
  'pg_am',       -- normal catalog
  'pg_class',    -- fundamental catalog
  'pg_database', -- shared catalog
  'vaccluster' , -- clustered table
  'vacid',       -- temp table
  'vactst'       -- normal table
);

-- only clusterd table should be changed
CLUSTER vaccluster;
UPDATE vacid SET filenode_1 = relfilenode
  FROM pg_class WHERE oid = relid;

-- all tables should not be changed
VACUUM (FULL INPLACE) pg_am;
VACUUM (FULL INPLACE) pg_class;
VACUUM (FULL INPLACE) pg_database;
VACUUM (FULL INPLACE) vaccluster;
VACUUM (FULL INPLACE) vacid;
VACUUM (FULL INPLACE) vactst;
UPDATE vacid SET filenode_2 = relfilenode
  FROM pg_class WHERE oid = relid;

-- only non-system tables should be changed
VACUUM FULL pg_am;
VACUUM FULL pg_class;
VACUUM FULL pg_database;
VACUUM FULL vaccluster;
VACUUM FULL vacid;
VACUUM FULL vactst;
UPDATE vacid SET filenode_3 = relfilenode
  FROM pg_class WHERE oid = relid;

SELECT relid,
       filenode_0 = filenode_1 AS cluster,
       filenode_1 = filenode_2 AS full_inplace,
       filenode_2 = filenode_3 AS full
  FROM vacid
 ORDER BY relid::text;

DROP TABLE vaccluster;
DROP TABLE vacid;
DROP TABLE vactst;
