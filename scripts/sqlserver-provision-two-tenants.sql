SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @loginA sysname=N'proxima_tenant_a', @loginB sysname=N'proxima_tenant_b';
DECLARE @dbA sysname=N'proxima_tenant_a_db', @dbB sysname=N'proxima_tenant_b_db';
DECLARE @pwA nvarchar(128)=N'$(TENANT_A_PASSWORD)', @pwB nvarchar(128)=N'$(TENANT_B_PASSWORD)';
DECLARE @sql nvarchar(max);

IF DB_ID(@dbA) IS NOT NULL
BEGIN
  SET @sql=N'ALTER DATABASE '+QUOTENAME(@dbA)+N' SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE '+QUOTENAME(@dbA)+N';';
  EXEC(@sql);
END;
IF DB_ID(@dbB) IS NOT NULL
BEGIN
  SET @sql=N'ALTER DATABASE '+QUOTENAME(@dbB)+N' SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE '+QUOTENAME(@dbB)+N';';
  EXEC(@sql);
END;
IF SUSER_ID(@loginA) IS NOT NULL BEGIN SET @sql=N'DROP LOGIN '+QUOTENAME(@loginA)+N';'; EXEC(@sql); END;
IF SUSER_ID(@loginB) IS NOT NULL BEGIN SET @sql=N'DROP LOGIN '+QUOTENAME(@loginB)+N';'; EXEC(@sql); END;

SET @sql=N'CREATE DATABASE '+QUOTENAME(@dbA)+N';'; EXEC(@sql);
SET @sql=N'CREATE DATABASE '+QUOTENAME(@dbB)+N';'; EXEC(@sql);
SET @sql=N'CREATE LOGIN '+QUOTENAME(@loginA)+N' WITH PASSWORD='+QUOTENAME(@pwA,'''')+N', DEFAULT_DATABASE='+QUOTENAME(@dbA)+N', CHECK_POLICY=OFF;'; EXEC(@sql);
SET @sql=N'CREATE LOGIN '+QUOTENAME(@loginB)+N' WITH PASSWORD='+QUOTENAME(@pwB,'''')+N', DEFAULT_DATABASE='+QUOTENAME(@dbB)+N', CHECK_POLICY=OFF;'; EXEC(@sql);

SET @sql=N'DENY VIEW ANY DATABASE TO '+QUOTENAME(@loginA)+N'; DENY ALTER ANY LOGIN TO '+QUOTENAME(@loginA)+N';'; EXEC(@sql);
SET @sql=N'DENY VIEW ANY DATABASE TO '+QUOTENAME(@loginB)+N'; DENY ALTER ANY LOGIN TO '+QUOTENAME(@loginB)+N';'; EXEC(@sql);

SET @sql=N'ALTER DATABASE '+QUOTENAME(@dbA)+N' SET TRUSTWORTHY OFF; ALTER DATABASE '+QUOTENAME(@dbA)+N' SET DB_CHAINING OFF;'; EXEC(@sql);
SET @sql=N'ALTER DATABASE '+QUOTENAME(@dbB)+N' SET TRUSTWORTHY OFF; ALTER DATABASE '+QUOTENAME(@dbB)+N' SET DB_CHAINING OFF;'; EXEC(@sql);

SET @sql=N'USE '+QUOTENAME(@dbA)+N'; DENY CONNECT TO guest; EXEC(N''CREATE SCHEMA app AUTHORIZATION dbo;''); CREATE USER '+QUOTENAME(@loginA)+N' FOR LOGIN '+QUOTENAME(@loginA)+N'; CREATE TABLE app.records(id int NOT NULL PRIMARY KEY,payload nvarchar(100) NOT NULL); INSERT app.records VALUES(1,N''tenant-a''); GRANT SELECT,INSERT,UPDATE,DELETE ON SCHEMA::app TO '+QUOTENAME(@loginA)+N';'; EXEC(@sql);
SET @sql=N'USE '+QUOTENAME(@dbB)+N'; DENY CONNECT TO guest; EXEC(N''CREATE SCHEMA app AUTHORIZATION dbo;''); CREATE USER '+QUOTENAME(@loginB)+N' FOR LOGIN '+QUOTENAME(@loginB)+N'; CREATE TABLE app.records(id int NOT NULL PRIMARY KEY,payload nvarchar(100) NOT NULL); INSERT app.records VALUES(1,N''tenant-b''); GRANT SELECT,INSERT,UPDATE,DELETE ON SCHEMA::app TO '+QUOTENAME(@loginB)+N';'; EXEC(@sql);

IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE name=@dbA) THROW 51000, 'Tenant A database was not provisioned', 1;
IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE name=@dbB) THROW 51000, 'Tenant B database was not provisioned', 1;
SET @sql=N'IF NOT EXISTS (SELECT 1 FROM '+QUOTENAME(@dbA)+N'.sys.tables t JOIN '+QUOTENAME(@dbA)+N'.sys.schemas s ON s.schema_id=t.schema_id WHERE t.name=N''records'' AND s.name=N''app'') THROW 51001, ''Tenant A table was not provisioned'', 1;';
EXEC(@sql);
SET @sql=N'IF NOT EXISTS (SELECT 1 FROM '+QUOTENAME(@dbB)+N'.sys.tables t JOIN '+QUOTENAME(@dbB)+N'.sys.schemas s ON s.schema_id=t.schema_id WHERE t.name=N''records'' AND s.name=N''app'') THROW 51002, ''Tenant B table was not provisioned'', 1;';
EXEC(@sql);
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name=@loginA AND default_database_name=@dbA) THROW 51003, 'Tenant A login default database is incorrect', 1;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name=@loginB AND default_database_name=@dbB) THROW 51004, 'Tenant B login default database is incorrect', 1;
PRINT 'SQL Server tenant principals and isolated databases provisioned.';
