## ============================================================
## Decrypt ALL encrypted objects in an MSSQL database via DAC
## Saves each object's source to a .sql file in $OutputDir
## ============================================================
## Prerequisites:
##   - SQL Server sysadmin rights
##   - DAC must be reachable (localhost DAC is always on; for remote:
##       EXEC sp_configure 'remote admin connections', 1; RECONFIGURE;)
##   - Run PowerShell as a user with SQL sysadmin access
##   - System.Data.SqlClient (built into .NET / Windows PowerShell)
## ============================================================

param(
    [string]$Server     = "localhost",       # SQL Server instance (no ADMIN: prefix here)
    [string]$Database   = "YourDatabase",    # Target database
    [string]$OutputDir  = ".\DecryptedProcs",# Where to write .sql files
    [switch]$WindowsAuth,                    # Use Windows auth (default)
    [string]$SqlUser    = "",                # SQL login (if not using Windows auth)
    [string]$SqlPass    = ""                 # SQL password
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

## ----- helpers ---------------------------------------------------------------

function New-DacConnection {
    param([string]$Server, [string]$Database, [string]$User, [string]$Pass)

    # DAC requires the "ADMIN:" prefix
    $dacServer = "ADMIN:$Server"

    if ($User) {
        $cs = "Data Source=$dacServer;Initial Catalog=$Database;User Id=$User;Password=$Pass;Encrypt=False;"
    } else {
        $cs = "Data Source=$dacServer;Initial Catalog=$Database;Integrated Security=SSPI;Encrypt=False;"
    }

    $conn = New-Object System.Data.SqlClient.SqlConnection($cs)
    $conn.Open()
    return $conn
}

function Invoke-Sql {
    param([System.Data.SqlClient.SqlConnection]$Conn, [string]$Sql, [int]$Timeout = 120)
    $cmd = $Conn.CreateCommand()
    $cmd.CommandText = $Sql
    $cmd.CommandTimeout = $Timeout
    $reader = $cmd.ExecuteReader()
    $results = @()
    while ($reader.Read()) {
        $row = @{}
        for ($i = 0; $i -lt $reader.FieldCount; $i++) {
            $row[$reader.GetName($i)] = $reader.GetValue($i)
        }
        $results += [PSCustomObject]$row
    }
    $reader.Close()
    return $results
}

function Invoke-SqlNonQuery {
    param([System.Data.SqlClient.SqlConnection]$Conn, [string]$Sql, [int]$Timeout = 120)
    $cmd = $Conn.CreateCommand()
    $cmd.CommandText = $Sql
    $cmd.CommandTimeout = $Timeout
    $cmd.ExecuteNonQuery() | Out-Null
}

function Get-ScalarString {
    param([System.Data.SqlClient.SqlConnection]$Conn, [string]$Sql)
    $cmd = $Conn.CreateCommand()
    $cmd.CommandText = $Sql
    $val = $cmd.ExecuteScalar()
    if ($val -eq [System.DBNull]::Value) { return $null }
    return [string]$val
}

## ----- core decrypt ----------------------------------------------------------

function Decrypt-SqlObject {
    param(
        [System.Data.SqlClient.SqlConnection]$Conn,
        [int]$ObjId,
        [string]$SchemaName,
        [string]$ObjName,
        [string]$ObjType   # P, FN, IF, TF, TR, V, RF
    )

    # Map type to DDL keyword
    $ddlKeyword = switch ($ObjType.Trim()) {
        'P'  { 'PROCEDURE' }
        'PC' { 'PROCEDURE' }
        'RF' { 'PROCEDURE' }
        'FN' { 'FUNCTION'  }
        'IF' { 'FUNCTION'  }
        'TF' { 'FUNCTION'  }
        'TR' { 'TRIGGER'   }
        'V'  { 'VIEW'      }
        default { 'PROCEDURE' }
    }

    $qSchema = "[$SchemaName]"
    $qName   = "[$ObjName]"

    # 1. Read all encrypted chunks
    $encChunks = @()
    $sub = 1
    while ($true) {
        $sql = "SELECT CAST(imageval AS NVARCHAR(MAX)) AS chunk
                FROM sys.sysobjvalues
                WHERE objid = $ObjId AND valclass = 1 AND subobjid = $sub"
        $rows = Invoke-Sql -Conn $Conn -Sql $sql
        if ($rows.Count -eq 0) { break }
        $encChunks += $rows[0].chunk
        $sub++
    }

    if ($encChunks.Count -eq 0) {
        Write-Warning "  No encrypted text found for $qSchema.$qName — skipping."
        return $null
    }

    $encrypted = $encChunks -join ""
    $totalLen  = $encrypted.Length

    # 2. Build fake ALTER of exact same length
    $fakeHeader = "ALTER $ddlKeyword $qSchema.$qName WITH ENCRYPTION AS "
    if ($fakeHeader.Length -gt $totalLen) {
        Write-Warning "  Fake header longer than encrypted blob for $qSchema.$qName — skipping."
        return $null
    }
    $fakeSrc = $fakeHeader + ("-" * ($totalLen - $fakeHeader.Length))

    # 3. Inject fake object
    Invoke-SqlNonQuery -Conn $Conn -Sql $fakeSrc

    # 4. Read back fake encrypted text
    $fakeChunks = @()
    $sub = 1
    while ($true) {
        $sql = "SELECT CAST(imageval AS NVARCHAR(MAX)) AS chunk
                FROM sys.sysobjvalues
                WHERE objid = $ObjId AND valclass = 1 AND subobjid = $sub"
        $rows = Invoke-Sql -Conn $Conn -Sql $sql
        if ($rows.Count -eq 0) { break }
        $fakeChunks += $rows[0].chunk
        $sub++
    }
    $fakeEnc = $fakeChunks -join ""

    # 5. XOR decrypt
    $sb = [System.Text.StringBuilder]::new($totalLen)
    for ($i = 0; $i -lt $totalLen; $i++) {
        $origChar = [int][char]$encrypted[$i]
        $fakeChar = [int][char]$fakeEnc[$i]
        $knwChar  = [int][char]$fakeSrc[$i]
        [void]$sb.Append([char]($origChar -bxor $fakeChar -bxor $knwChar))
    }

    return $sb.ToString()
}

## ----- main ------------------------------------------------------------------

Write-Host "Connecting to DAC: ADMIN:$Server / $Database ..." -ForegroundColor Cyan

$conn = $null
try {
    $conn = New-DacConnection -Server $Server -Database $Database -User $SqlUser -Pass $SqlPass
    Write-Host "Connected." -ForegroundColor Green
} catch {
    Write-Error "DAC connection failed: $_`n`nTips:`n  - Are you connecting from the same machine as SQL Server?`n  - For remote DAC: EXEC sp_configure 'remote admin connections', 1; RECONFIGURE;`n  - Check firewall for TCP port 1434 (DAC port)"
    exit 1
}

# Query all encrypted objects
$encObjects = Invoke-Sql -Conn $conn -Sql @"
SELECT
    o.object_id,
    SCHEMA_NAME(o.schema_id) AS schema_name,
    o.name                   AS obj_name,
    o.type                   AS obj_type
FROM sys.objects o
JOIN sys.sql_modules m ON m.object_id = o.object_id
WHERE m.definition IS NULL          -- encrypted (definition hidden)
  AND o.type IN ('P','PC','RF','FN','IF','TF','TR','V')
ORDER BY SCHEMA_NAME(o.schema_id), o.name;
"@

if ($encObjects.Count -eq 0) {
    Write-Host "No encrypted objects found in [$Database]." -ForegroundColor Yellow
    $conn.Close()
    exit 0
}

Write-Host "Found $($encObjects.Count) encrypted object(s):" -ForegroundColor Cyan
$encObjects | ForEach-Object { Write-Host "  $($_.schema_name).$($_.obj_name) [$($_.obj_type.Trim())]" }
Write-Host ""

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

$success = 0
$failed  = 0

foreach ($obj in $encObjects) {
    $label = "$($obj.schema_name).$($obj.obj_name)"
    Write-Host "Decrypting $label ..." -NoNewline

    try {
        $src = Decrypt-SqlObject -Conn $conn `
            -ObjId $obj.object_id `
            -SchemaName $obj.schema_name `
            -ObjName $obj.obj_name `
            -ObjType $obj.obj_type

        if ($null -eq $src) {
            $failed++
            continue
        }

        $outFile = Join-Path $OutputDir "$($obj.schema_name).$($obj.obj_name).sql"
        $src | Set-Content -Path $outFile -Encoding UTF8

        Write-Host " OK  -> $outFile" -ForegroundColor Green
        $success++
    } catch {
        Write-Host " FAILED: $_" -ForegroundColor Red
        $failed++
    }
}

$conn.Close()

Write-Host ""
Write-Host "Done. $success decrypted, $failed failed." -ForegroundColor Cyan
Write-Host ""
Write-Host "RESTORE WARNING:" -ForegroundColor Yellow
Write-Host "  Each decrypted object was temporarily replaced with a fake stub."
Write-Host "  Restore the database from backup, or reapply the decrypted .sql files."
Write-Host "  The decrypted files start with CREATE PROCEDURE — remove WITH ENCRYPTION"
Write-Host "  if you no longer want them encrypted."
