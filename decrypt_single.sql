-- ============================================================
-- Decrypt a single MSSQL encrypted stored procedure via DAC
-- ============================================================
-- HOW IT WORKS (XOR key cancellation):
--   stored_enc  = key XOR original_source
--   fake_enc    = key XOR fake_source        (same key, same object)
--   original    = stored_enc XOR fake_enc XOR fake_source
--
-- PREREQUISITES:
--   1. Connect via DAC:  ADMIN:ServerName  or  ADMIN:ServerName\Instance
--      To allow remote DAC (one-time):
--        EXEC sp_configure 'remote admin connections', 1; RECONFIGURE;
--   2. sysadmin role required
--   3. STRONGLY RECOMMENDED: run against a backup/copy of the DB, not
--      live production — the target proc is temporarily replaced with
--      a fake version during decryption (see RESTORE NOTE below)
-- ============================================================

USE [YourDatabase];   -- << change to your database
GO

SET NOCOUNT ON;

-- ===== CONFIGURE =====
DECLARE @schema_name SYSNAME = N'dbo';
DECLARE @proc_name   SYSNAME = N'YourProcedureName';  -- << change
-- =====================

DECLARE @obj_id    INT,
        @encrypted NVARCHAR(MAX) = N'',
        @fake_src  NVARCHAR(MAX),
        @fake_enc  NVARCHAR(MAX) = N'',
        @decrypted NVARCHAR(MAX) = N'',
        @chunk     NVARCHAR(MAX),
        @len       INT,
        @i         INT,
        @subobjid  INT = 1;

-- 1. Resolve object id
SET @obj_id = OBJECT_ID(QUOTENAME(@schema_name) + N'.' + QUOTENAME(@proc_name));

IF @obj_id IS NULL
BEGIN
    RAISERROR(N'Object not found: [%s].[%s]', 16, 1, @schema_name, @proc_name);
    RETURN;
END

IF NOT EXISTS (
    SELECT 1 FROM sys.objects
    WHERE object_id = @obj_id
      AND type IN ('P','PC','RF','TR','FN','IF','TF','V')
)
BEGIN
    RAISERROR(N'Object is not a procedure, function, trigger, or view.', 16, 1);
    RETURN;
END

-- 2. Concatenate all chunks from sys.sysobjvalues (subobjid 1, 2, 3 ...)
--    Very long objects are stored in multiple 8000-char chunks
WHILE EXISTS (
    SELECT 1 FROM sys.sysobjvalues
    WHERE objid = @obj_id AND valclass = 1 AND subobjid = @subobjid
)
BEGIN
    SELECT @chunk = CAST(imageval AS NVARCHAR(MAX))
    FROM sys.sysobjvalues
    WHERE objid = @obj_id AND valclass = 1 AND subobjid = @subobjid;

    SET @encrypted = @encrypted + @chunk;
    SET @subobjid  = @subobjid + 1;
END

IF LEN(@encrypted) = 0
BEGIN
    RAISERROR(N'No encrypted text found — is WITH ENCRYPTION actually used?', 16, 1);
    RETURN;
END

SET @len = LEN(@encrypted);

-- 3. Build fake ALTER text of exactly the same length (padding with dashes)
SET @fake_src = N'ALTER PROCEDURE '
              + QUOTENAME(@schema_name) + N'.'
              + QUOTENAME(@proc_name)
              + N' WITH ENCRYPTION AS ';

IF LEN(@fake_src) > @len
BEGIN
    RAISERROR(N'Computed fake header (%d chars) exceeds encrypted blob length (%d). Unexpected.',
              16, 1, LEN(@fake_src), @len);
    RETURN;
END

SET @fake_src = @fake_src + REPLICATE(N'-', @len - LEN(@fake_src));

-- 4. Inject fake proc to obtain encryption of a known plaintext
EXEC sp_executesql @fake_src;

-- 5. Read back the freshly encrypted fake text (chunks again)
SET @subobjid = 1;
WHILE EXISTS (
    SELECT 1 FROM sys.sysobjvalues
    WHERE objid = @obj_id AND valclass = 1 AND subobjid = @subobjid
)
BEGIN
    SELECT @chunk = CAST(imageval AS NVARCHAR(MAX))
    FROM sys.sysobjvalues
    WHERE objid = @obj_id AND valclass = 1 AND subobjid = @subobjid;

    SET @fake_enc = @fake_enc + @chunk;
    SET @subobjid  = @subobjid + 1;
END

-- 6. XOR decrypt: original_enc XOR fake_enc XOR fake_plaintext = original
SET @i = 1;
WHILE @i <= @len
BEGIN
    SET @decrypted = @decrypted + NCHAR(
        UNICODE(SUBSTRING(@encrypted, @i, 1)) ^
        UNICODE(SUBSTRING(@fake_enc,  @i, 1)) ^
        UNICODE(SUBSTRING(@fake_src,  @i, 1))
    );
    SET @i = @i + 1;
END

-- 7. Output
PRINT N'=== DECRYPTED SOURCE ===';
PRINT @decrypted;          -- PRINT splits at 4000 chars automatically
SELECT @decrypted AS decrypted_source;  -- full text in result grid

-- ============================================================
-- RESTORE NOTE:
--   The procedure is now replaced with the fake dash-filled version.
--   Options to restore:
--     a) Restore the database from backup (recommended)
--     b) Paste the decrypted source above and run it as CREATE/ALTER PROCEDURE
--        (remove WITH ENCRYPTION if you want the source readable going forward)
-- ============================================================
