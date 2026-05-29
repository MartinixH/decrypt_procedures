# MSSQL Encrypted Procedure Decryptor

Scripts to recover the source code of SQL Server stored procedures, functions, triggers, and views encrypted with `WITH ENCRYPTION`.

## How it works

SQL Server's `WITH ENCRYPTION` applies a simple XOR cipher over the UTF-16 encoded source text:

```
stored = key XOR original_source
```

The key is bound to the object (same object_id → same key). By temporarily replacing the object with a known-plaintext stub of identical length, we can cancel the key out:

```
fake_stored = key XOR fake_source
original    = stored XOR fake_stored XOR fake_source   ← key cancels
```

The plaintext is read from `sys.sysobjvalues`, a system table only accessible via the Dedicated Administrator Connection (DAC).

## Prerequisites

| Requirement | Notes |
|---|---|
| **DAC connection** | Connect as `ADMIN:ServerName`. Only one DAC session at a time is allowed. |
| **Remote DAC** (if not on the server) | `EXEC sp_configure 'remote admin connections', 1; RECONFIGURE;` |
| **sysadmin** role | Required to read `sys.sysobjvalues` |
| **Backup / copy of the DB** | Each target object is **temporarily overwritten** with a fake stub. Restore from backup or re-apply the decrypted source afterward. |

## Files

| File | Description |
|---|---|
| `decrypt_single.sql` | T-SQL script — decrypt one object, run in SSMS via DAC |
| `decrypt_all.ps1` | PowerShell script — decrypt every encrypted object and save to `.sql` files |

---

## `decrypt_single.sql` — T-SQL (single object)

### Setup

1. Open SSMS
2. In the *Server name* field enter `ADMIN:YourServer` (or `ADMIN:YourServer\Instance`)
3. Open `decrypt_single.sql` and edit the three variables at the top:

```sql
USE [YourDatabase];          -- your database
DECLARE @schema_name SYSNAME = N'dbo';
DECLARE @proc_name   SYSNAME = N'YourProcedureName';
```

4. Execute. The decrypted source appears in both the **Messages** pane (via `PRINT`) and the **Results** grid.

---

## `decrypt_all.ps1` — PowerShell (all objects)

Decrypts every encrypted object in a database and writes each one to `schema.ObjectName.sql`.

### Usage

```powershell
# Windows Authentication (most common)
.\decrypt_all.ps1 -Server "YourServer" -Database "YourDatabase" -OutputDir ".\output"

# Named instance
.\decrypt_all.ps1 -Server "YourServer\SQLEXPRESS" -Database "YourDatabase"

# SQL Server Authentication
.\decrypt_all.ps1 -Server "YourServer" -Database "YourDatabase" -SqlUser "sa" -SqlPass "secret"
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Server` | `localhost` | SQL Server instance name |
| `-Database` | `YourDatabase` | Target database |
| `-OutputDir` | `.\DecryptedProcs` | Folder for output `.sql` files |
| `-SqlUser` | *(empty)* | SQL login (omit for Windows auth) |
| `-SqlPass` | *(empty)* | SQL password |

### Example output

```
Connecting to DAC: ADMIN:localhost / MyAppDB ...
Connected.
Found 12 encrypted object(s):
  dbo.usp_GetOrders [P]
  dbo.usp_UpdateUser [P]
  dbo.fn_FormatPhone [FN]
  ...

Decrypting dbo.usp_GetOrders ... OK  -> .\output\dbo.usp_GetOrders.sql
Decrypting dbo.usp_UpdateUser ... OK  -> .\output\dbo.usp_UpdateUser.sql
Decrypting dbo.fn_FormatPhone ... OK  -> .\output\dbo.fn_FormatPhone.sql
...
Done. 12 decrypted, 0 failed.
```

---

## After decryption

The output files contain the original `CREATE PROCEDURE` (or `CREATE FUNCTION` / `CREATE TRIGGER` / `CREATE VIEW`) statement.

If you want to restore the objects **without** encryption:

1. Open the `.sql` file
2. Remove the `WITH ENCRYPTION` clause
3. Execute against the database

To restore **with** encryption, execute the file as-is (it already contains `WITH ENCRYPTION`).

> **Important:** because each object is temporarily replaced with a fake stub during decryption, you must either restore the database from backup or re-execute the decrypted `.sql` files to bring the objects back to a working state.

---

## Supported object types

| SQL Server type code | Object |
|---|---|
| `P` | Stored procedure |
| `FN` | Scalar function |
| `IF` | Inline table-valued function |
| `TF` | Multi-statement table-valued function |
| `TR` | Trigger |
| `V` | View |

## Limitations

- Requires `sysadmin` — standard users cannot access `sys.sysobjvalues`
- Only one DAC session is allowed at a time on a SQL Server instance
- Does not handle CLR objects (`PC`) that are binary, not T-SQL source
- The temporary object replacement is **not transactional** (DDL auto-commits); always work on a backup

## License

MIT
