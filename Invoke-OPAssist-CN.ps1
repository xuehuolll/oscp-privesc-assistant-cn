<#
.SYNOPSIS
  OSCP Privesc Assistant - Windows (PowerShell) v1.8.9
.DESCRIPTION
  Local privilege-escalation enumeration + ranked hints only.
  Does NOT exploit, does NOT change services/tasks/registry persistence,
  does NOT upload payloads, does NOT brute force.
  Default: privesc-only summary (like Linux opassist-linux-cn.sh). Use -Full for raw dumps.
.NOTES
  Prefer this script when PowerShell is available.
  If only cmd.exe: use opassist-win-cn.bat or windows-cmd-checklist.txt.
#>

param(
    [string]$OutFile = "",
    [switch]$Quick,
    [switch]$Full,
    [switch]$NoColor,
    [switch]$Report,
    [switch]$Help
)

$ErrorActionPreference = "SilentlyContinue"
$Version = "1.9.9-en-ps"
# English-first output: reliable under Evil-WinRM / EN-US consoles (Chinese often shows as ???).
$script:DomainCtx = $null
$script:AlreadySystem = $false
$script:SkipWriteChecks = $false  # true when SYSTEM / high-integrity admin (write checks are meaningless noise)
$script:IsEvilWinRM = $false      # WinRM remoting host (Evil-WinRM-style); gates download/upload Next text only
# Priority: higher prints first within same severity (domain playbook > local noise)
$Mode = if ($Full) { "full" } else { "summary" }
if ($Quick) { $Mode = "summary" }
if ($Report) { $NoColor = $true }

$script:FindingKeys = @{}
$script:Findings = New-Object System.Collections.ArrayList
$script:High = 0; $script:Med = 0; $script:Info = 0
$script:Details = New-Object System.Collections.ArrayList
$script:MaxMedSummary = 10
$script:CredHitCap = if ($Mode -eq "full") { 20 } else { 8 }
$script:CredHits = 0

function Show-Help {
@"
OSCP Privesc Assistant Windows PowerShell v$Version

Usage:
  powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1
  powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1 -Full
  powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1 -OutFile report.txt
  powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1 -Report -OutFile report.txt
  powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1 -Help

Modes:
  default / -Quick   privesc-only summary (first pass after shell)
  -Full              detailed enum dumps + more credential search
  -NoColor           no colors
  -Report            Finding/Evidence/Manual verification fields
  -OutFile PATH      also save output (via transcript)

Boundary (exam-safe):
  Enumerate + highlight + suggest manual next steps ONLY.
  No auto exploit, no service/task/registry persistence changes,
  no payload download/exec, no credential spraying.

Coverage (OSCP-oriented Windows local):
  tokens, AlwaysInstallElevated, Autologon, Unattend, SAM backups,
  service bin/dir write, unquoted path (writable prefix only), weak service DACL,
  scheduled tasks, PATH hijack, autoruns/startup, GPO/script paths (if readable),
  creds (history/cmdkey/web.config/clients/PuTTY), localhost services,
  interesting groups, UAC/language-mode hints, domain hint.
  Kernel/CVE is NOT primary line (mentioned only as last resort in -Full).
"@
}

if ($Help) { Show-Help; exit 0 }

# ---------- transcript ----------
$transcriptOn = $false
if ($OutFile -ne "") {
    try {
        Start-Transcript -Path $OutFile -Force | Out-Null
        $transcriptOn = $true
    } catch {
        Write-Host "[WARN] cannot start transcript: $OutFile"
    }
}

function Section([string]$Name) {
    Write-Host ""
    Write-Host "========== $Name =========="
}

function Add-Finding {
    param(
        [ValidateSet("HIGH","MED","INFO")][string]$Severity,
        [string]$Title,
        [string]$Reason,
        [string]$Next = "",
        [string]$Key = "",
        [int]$Priority = 50
    )
    if (-not $Key) { $Key = "$Severity`:$Title" }
    if ($script:FindingKeys.ContainsKey($Key)) { return }
    $script:FindingKeys[$Key] = $true
    [void]$script:Findings.Add([pscustomobject]@{
        Severity = $Severity
        Title    = $Title
        Reason   = $Reason
        Next     = $Next
        Priority = $Priority
        Order    = $script:Findings.Count
    })
    switch ($Severity) {
        "HIGH" { $script:High++ }
        "MED"  { $script:Med++ }
        default { $script:Info++ }
    }
}

function Get-SortedFindings([string]$Severity) {
    return @($script:Findings | Where-Object { $_.Severity -eq $Severity } | Sort-Object -Property @{e='Priority';Descending=$true}, @{e='Order';Ascending=$true})
}

function Write-FindingObj($f) {
    $tag = switch ($f.Severity) {
        "HIGH" { "!!! [HIGH]" }
        "MED"  { ">>> [MED]" }
        default { "--- [INFO]" }
    }
    $color = switch ($f.Severity) {
        "HIGH" { "Red" }
        "MED"  { "Yellow" }
        default { "Cyan" }
    }
    if ($NoColor) { Write-Host "$tag $($f.Title)" }
    else { Write-Host "$tag $($f.Title)" -ForegroundColor $color }
    if ($f.Reason) { Write-Host "    Reason: $($f.Reason)" }
    if ($f.Next) {
        Write-Host "    Next:"
        foreach ($line in ($f.Next -split "`n")) {
            if ($line.Trim()) { Write-Host "      $line" }
        }
    }
    if ($Report) {
        Write-Host "    [Report Finding] $($f.Title)"
        Write-Host "    [Evidence] $($f.Reason)"
        Write-Host "    [Manual verification]"
        foreach ($line in ($f.Next -split "`n")) {
            if ($line.Trim()) { Write-Host "      $line" }
        }
    }
}

function Print-Summary {
    Section "Priority Findings"
    Write-Host "Privesc-only summary (OSCP first pass). Use -Full for raw dumps."
    Write-Host "English-only UI for WinRM/EN consoles. Manual verification only."
    if ($script:IsEvilWinRM) {
        Write-Host "[SESSION] Evil-WinRM-style (WinRM remoting): loot Next uses client download/upload verbs."
    }
    if ($script:DomainCtx -and $script:DomainCtx.IsDomain) {
        Write-Host ("[DOMAIN] {0} | user={1} | DC={2}" -f $script:DomainCtx.Dns, $script:DomainCtx.User, $script:DomainCtx.IsDC)
        if ($script:High -eq 0) {
            Write-Host "[DOMAIN] No local HIGH -> read findings tagged DOMAIN / SYSVOL first, then AD enum."
        }
    }
    Write-Host ""

    if ($script:Findings.Count -eq 0) {
        Write-Host "No clear local privesc leads in summary filters."
        if ($script:DomainCtx -and $script:DomainCtx.IsDomain) {
            Write-Host "You are domain-joined: go to SYSVOL/NETLOGON + domain user/group enum (see DOMAIN findings if any)."
        } else {
            Write-Host "Next: whoami /priv, services/tasks ACLs, or WinPEAS/Seatbelt."
        }
        return
    }

    $n = 1
    $medPrinted = 0
    foreach ($sev in @("HIGH","MED")) {
        foreach ($f in (Get-SortedFindings $sev)) {
            if ($sev -eq "MED" -and $Mode -ne "full") {
                if ($medPrinted -ge $script:MaxMedSummary) { continue }
                $medPrinted++
            }
            Write-Host "[$n]"
            Write-FindingObj $f
            Write-Host ""
            $n++
        }
    }

    if ($Mode -eq "full") {
        foreach ($f in (Get-SortedFindings "INFO")) {
            Write-Host "[$n]"
            Write-FindingObj $f
            Write-Host ""
            $n++
        }
    }

    if ($Mode -ne "full" -and $script:Med -gt $script:MaxMedSummary) {
        $left = $script:Med - $script:MaxMedSummary
        if ($left -gt 0) {
            Write-Host "[tip] $left MED findings folded; use -Full."
        }
    }
}

# ---------- helpers ----------
function Get-CurrentSids {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $sids = New-Object System.Collections.Generic.List[string]
        $sids.Add($id.User.Value) | Out-Null
        foreach ($g in $id.Groups) { $sids.Add($g.Value) | Out-Null }
        # common writable principals
        foreach ($x in @("S-1-1-0","S-1-5-11","S-1-5-32-545","S-1-5-32-546")) {
            if (-not $sids.Contains($x)) { $sids.Add($x) | Out-Null }
        }
        return $sids
    } catch {
        return @()
    }
}

$script:MySids = Get-CurrentSids

function Test-IsEvilWinRMSession {
    <#
    .SYNOPSIS
      Detect WinRM remoting host used by Evil-WinRM (and Enter-PSSession).
    .NOTES
      Server cannot see the client binary name. Signals: PS Host.Name + parent wsmprovhost.exe.
      When true, Next text may use Evil-WinRM client verbs (download/upload).
    #>
    try {
        if ($Host -and $Host.Name -eq 'ServerRemoteHost') { return $true }
    } catch {}
    try {
        if ($PSSenderInfo) { return $true }
    } catch {}
    $parentName = $null
    try {
        $cur = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop
        if ($cur -and $cur.ParentProcessId) {
            $par = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($cur.ParentProcessId)" -ErrorAction Stop
            if ($par) { $parentName = [string]$par.Name }
        }
    } catch {
        try {
            $cur = Get-WmiObject -Class Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop
            if ($cur -and $cur.ParentProcessId) {
                $par = Get-WmiObject -Class Win32_Process -Filter "ProcessId=$($cur.ParentProcessId)" -ErrorAction Stop
                if ($par) { $parentName = [string]$par.Name }
            }
        } catch {}
    }
    if ($parentName -and ($parentName -match '(?i)^wsmprovhost(\.exe)?$')) { return $true }
    return $false
}

function Join-NextLines {
    param([string[]]$Parts)
    $lines = @()
    foreach ($p in $Parts) {
        if ($null -eq $p) { continue }
        $t = [string]$p
        if ($t.Trim().Length -eq 0) { continue }
        $lines += $t
    }
    return ($lines -join "`n")
}

function Get-EvilWinRMLootNext {
    param(
        [string]$LocalPath = "",
        [ValidateSet("hive","pair","system","admin","generic")][string]$Kind = "generic"
    )
    if (-not $script:IsEvilWinRM) { return "" }
    $stage = "C:\Users\Public"
    $leaf = if ($LocalPath) { Split-Path -Leaf $LocalPath } else { "FILE" }
    switch ($Kind) {
        "hive" {
            return @(
                "# Evil-WinRM loot (only when this session is WinRM remoting):",
                "copy /y `"$LocalPath`" $stage\",
                "# if denied: copy /y `"$LocalPath`" `$env:TEMP\",
                "download $stage\$leaf",
                "# Offline on attack host: secretsdump.py -sam SAM -system SYSTEM LOCAL"
            ) -join "`n"
        }
        "pair" {
            return @(
                "# Evil-WinRM: stage both hives then download from client:",
                "copy /y C:\Windows.old\Windows\System32\config\SAM $stage\",
                "copy /y C:\Windows.old\Windows\System32\config\SYSTEM $stage\",
                "download $stage\SAM",
                "download $stage\SYSTEM",
                "# Prefer same tree for both files; then secretsdump.py -sam SAM -system SYSTEM LOCAL"
            ) -join "`n"
        }
        "system" {
            return @(
                "# Evil-WinRM + already SYSTEM: local privesc done; stage loot then client download",
                "whoami",
                "hostname",
                "# proof: type proof.txt / local.txt as required by lab",
                "# Prefer Windows.old SAM+SYSTEM if present (see other HIGH):",
                "dir C:\Windows.old\Windows\System32\config",
                "copy /y C:\Windows.old\Windows\System32\config\SAM $stage\",
                "copy /y C:\Windows.old\Windows\System32\config\SYSTEM $stage\",
                "download $stage\SAM",
                "download $stage\SYSTEM",
                "# Optional tool: upload tool.exe  then  .\tool.exe  (PATH often thin; use .\ name)",
                "# Domain: crack/reuse offline; do not spray passwords from this shell"
            ) -join "`n"
        }
        "admin" {
            return @(
                "# Evil-WinRM + elevated admin: loot/creds/domain next (not service ACL noise)",
                "copy /y <loot> $stage\",
                "download $stage\<loot>",
                "# upload tool.exe ; .\tool.exe"
            ) -join "`n"
        }
        default {
            return @(
                "# Evil-WinRM: copy loot to $stage\ then client: download $stage\<file>",
                "# upload tool.exe ; run with .\tool.exe"
            ) -join "`n"
        }
    }
}

function Test-AclWritable {
    param([string]$Path)
    if (-not $Path) { return $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne "Allow") { continue }
            $sid = $null
            try {
                $sid = ($ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])).Value
            } catch {
                $name = [string]$ace.IdentityReference
                if ($name -match 'Everyone|Authenticated Users|BUILTIN\\Users|NT AUTHORITY\\Authenticated Users') {
                    $sid = "match-by-name"
                } elseif ($name -match [regex]::Escape($env:USERNAME)) {
                    $sid = "match-by-name"
                } else { continue }
            }
            if ($sid -ne "match-by-name" -and $script:MySids -notcontains $sid) { continue }

            if ($ace.FileSystemRights) {
                $r = $ace.FileSystemRights.ToString()
                if ($r -match 'FullControl|Modify|Write|CreateFiles|Delete|TakeOwnership|ChangePermissions') {
                    # inheritance flags still count for "can write something here"
                    return $true
                }
            }
            if ($ace.RegistryRights) {
                $r = $ace.RegistryRights.ToString()
                if ($r -match 'FullControl|SetValue|CreateSubKey|Delete|WriteKey|ChangePermissions') {
                    return $true
                }
            }
        }
    } catch { return $false }
    return $false
}

function Get-ServiceExePath([string]$RawPath) {
    if (-not $RawPath) { return $null }
    $p = $RawPath.Trim()
    if ($p.StartsWith('"')) {
        $m = [regex]::Match($p, '^"([^"]+\.(?i:exe))"')
        if ($m.Success) { return $m.Groups[1].Value }
    }
    $m2 = [regex]::Match($p, '^(.*?\.exe)', 'IgnoreCase')
    if ($m2.Success) { return $m2.Groups[1].Value.Trim() }
    return $null
}

function Test-UnquotedServicePath([string]$RawPath) {
    if (-not $RawPath) { return $false }
    $p = $RawPath.Trim()
    if ($p.StartsWith('"')) { return $false }
    if ($p -notmatch '(?i)\.exe') { return $false }
    if ($p -notmatch '\s') { return $false }
    return $true
}

function Test-PrivilegedAccount([string]$StartName) {
    if (-not $StartName) { return $false }
    return ($StartName -match '(?i)LocalSystem|Local Service|Network Service|NT AUTHORITY|SYSTEM|Administrator')
}

function Get-UnquotedWritablePrefix([string]$ExePath) {
    if (-not $ExePath) { return $null }
    try {
        $full = [System.IO.Path]::GetFullPath($ExePath)
    } catch { $full = $ExePath }
    $parts = $full -split '\\'
    if ($parts.Count -lt 2) { return $null }
    # Skip bare drive roots (C:\, D:\) - almost always writable for admins and too noisy.
    # Real unquoted hijack needs a writable *intermediate folder* before .exe.
    $acc = $parts[0]  # C:
    for ($i = 1; $i -lt $parts.Count - 1; $i++) {
        $acc = $acc + '\' + $parts[$i]
        if (Test-Path -LiteralPath $acc) {
            if (Test-AclWritable $acc) { return $acc }
        }
    }
    return $null
}

function Test-StrongCredContent([string]$FilePath) {
    if (-not (Test-Path -LiteralPath $FilePath)) { return $false }
    try {
        $item = Get-Item -LiteralPath $FilePath -ErrorAction Stop
        if ($item.Length -gt 2MB -or $item.Length -lt 20) { return $false }
        # skip obvious framework/product noise
        if ($FilePath -match '(?i)\\WinSxS\\|\\Windows\\Microsoft\.NET\\|VisualStudio\\SetupWMI\\|\\Packages\\') { return $false }
        $text = Get-Content -LiteralPath $FilePath -Raw -ErrorAction Stop
        if (-not $text) { return $false }
        # require assignment-like values, not schema words alone
        if ($text -match '(?i)(password|passwd|pwd)\s*[=:]\s*[''"][^''"]{3,}[''"]') { return $true }
        if ($text -match '(?i)(password|passwd|pwd)\s*[=:]\s*[^\s''"<>]{3,}') { return $true }
        if ($text -match '(?i)connectionString\s*=\s*[''"][^''"]{8,}[''"]') { return $true }
        if ($text -match '(?i)(Data Source|Initial Catalog)\s*=\s*\S+') { return $true }
        if ($text -match '(?i)BEGIN [A-Z ]*PRIVATE KEY') { return $true }
        if ($text -match '(?i)(aws_secret_access_key|API[_-]?KEY)\s*[=:]\s*\S{6,}') { return $true }
        return $false
    } catch { return $false }
}

function Get-ExecutableFromCommand([string]$Command) {
    if (-not $Command) { return $null }
    $c = $Command.Trim()
    if ($c -match '(?i)N/A|COM handler') { return $null }
    if ($c.StartsWith('"')) {
        $m = [regex]::Match($c, '^"([^"`r`n]+\.(?i:exe|bat|cmd|ps1|vbs|js))"')
        if ($m.Success) { return $m.Groups[1].Value }
    }
    $m2 = [regex]::Match($c, '^([^\s]+\.(?i:exe|bat|cmd|ps1|vbs|js))')
    if ($m2.Success) { return $m2.Groups[1].Value }
    $m3 = [regex]::Match($c, '([A-Za-z]:\\[^"`r`n<>|]+\.(?i:exe|bat|cmd|ps1|vbs|js))')
    if ($m3.Success) { return $m3.Groups[1].Value.Trim() }
    return $null
}

function Test-IsSystemPath([string]$Path) {
    if (-not $Path) { return $true }
    return ($Path -match '(?i)\\Windows\\System32\\|\\Windows\\SysWOW64\\|\\Windows\\WinSxS\\|\\Windows\\servicing\\')
}

# ---------- domain context ----------
function Get-DomainContext {
    $ctx = [ordered]@{
        IsDomain = $false
        IsDC     = $false
        DcHow    = ""
        NetBios  = $env:USERDOMAIN
        Dns      = $env:USERDNSDOMAIN
        Computer = $env:COMPUTERNAME
        User     = "$env:USERDOMAIN\$env:USERNAME"
    }
    if ($env:USERDNSDOMAIN) {
        $ctx.IsDomain = $true
        $ctx.Dns = $env:USERDNSDOMAIN
    }
    if ($env:USERDOMAIN -and $env:COMPUTERNAME -and ($env:USERDOMAIN -ne $env:COMPUTERNAME)) {
        $ctx.IsDomain = $true
    }
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($cs.PartOfDomain) {
            $ctx.IsDomain = $true
            if ($cs.Domain) { $ctx.Dns = $cs.Domain }
        }
        # DomainRole: 0=standalone ws, 1=member ws, 2=standalone server, 3=member server, 4=BDC, 5=PDC
        if ($null -ne $cs.DomainRole -and [int]$cs.DomainRole -ge 4) {
            $ctx.IsDC = $true
            $ctx.IsDomain = $true
            $ctx.DcHow = "DomainRole=$($cs.DomainRole)"
        }
    } catch {
        try {
            $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
            if ($cs.PartOfDomain) { $ctx.IsDomain = $true; if ($cs.Domain) { $ctx.Dns = $cs.Domain } }
            if ($null -ne $cs.DomainRole -and [int]$cs.DomainRole -ge 4) {
                $ctx.IsDC = $true
                $ctx.IsDomain = $true
                $ctx.DcHow = "DomainRole=$($cs.DomainRole)"
            }
        } catch {}
    }

    # Fallback DC signals (WMI often fails or lies under low priv / WinRM)
    if (-not $ctx.IsDC) {
        # ProductType: WinNT=workstation, ServerNT=member server, LanmanNT=domain controller
        $pt = $null
        try {
            $pt = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions" -ErrorAction Stop).ProductType
        } catch {}
        if ($pt -eq "LanmanNT") {
            $ctx.IsDC = $true
            $ctx.IsDomain = $true
            $ctx.DcHow = "ProductType=LanmanNT"
        }
    }
    if (-not $ctx.IsDC) {
        # NTDS service present is a strong DC indicator
        try {
            $ntds = Get-Service -Name NTDS -ErrorAction SilentlyContinue
            if ($ntds) {
                $ctx.IsDC = $true
                $ctx.IsDomain = $true
                $ctx.DcHow = "Service=NTDS"
            }
        } catch {}
    }
    if (-not $ctx.IsDC) {
        # Shared SYSVOL folder locally (DC hosts it)
        if (Test-Path -LiteralPath "C:\Windows\SYSVOL\domain" -PathType Container -ErrorAction SilentlyContinue) {
            $ctx.IsDC = $true
            $ctx.IsDomain = $true
            $ctx.DcHow = "LocalPath=C:\Windows\SYSVOL\domain"
        } elseif (Test-Path -LiteralPath "C:\Windows\SYSVOL\sysvol" -PathType Container -ErrorAction SilentlyContinue) {
            $ctx.IsDC = $true
            $ctx.IsDomain = $true
            $ctx.DcHow = "LocalPath=C:\Windows\SYSVOL\sysvol"
        }
    }
    if (-not $ctx.IsDC) {
        $cn = [string]$env:COMPUTERNAME
        # RESOURCEDC, DC01, CORP-DC, DC-01, etc.
        if ($cn -match '(?i)DC\d*$' -or $cn -match '(?i)(^|-)DC($|-|\d)' -or $cn -match '(?i)DOMAINCONTROLLER') {
            $ctx.IsDC = $true
            $ctx.IsDomain = $true
            $ctx.DcHow = "HostnameHeuristic=$cn"
        }
    }
    if (-not $ctx.IsDC -and $env:LOGONSERVER) {
        $ls = $env:LOGONSERVER.TrimStart('\').Trim()
        if ($ls -and ($ls -ieq $env:COMPUTERNAME)) {
            $ctx.IsDC = $true
            $ctx.IsDomain = $true
            $ctx.DcHow = "LOGONSERVER=$ls"
        }
    }

    if (-not $ctx.Dns -and $ctx.IsDomain -and $ctx.NetBios) { $ctx.Dns = $ctx.NetBios }
    if ($env:LOGONSERVER) { $ctx.LogonServer = $env:LOGONSERVER.TrimStart('\') }
    return $ctx
}

function Complete-DomainGuidance {
    # Call AFTER all local checks so we know HIGH count.
    # Emit ONE clear domain block when no local HIGH (avoids 3-4 redundant MED lines).
    $ctx = $script:DomainCtx
    if (-not $ctx -or -not $ctx.IsDomain) { return }

    $dns = if ($ctx.Dns) { $ctx.Dns } else { $ctx.NetBios }
    $sysvol = "\\$dns\SYSVOL"
    $netlogon = "\\$dns\NETLOGON"
    $nl = [Environment]::NewLine

    $sysvolOk = $false
    $netlogonOk = $false
    try { if (Test-Path -LiteralPath $sysvol) { $sysvolOk = $true } } catch {}
    try { if (Test-Path -LiteralPath $netlogon) { $netlogonOk = $true } } catch {}

    # GPP cpassword = always HIGH if found (quick probe, capped)
    if ($sysvolOk) {
        try {
            $gppHits = Get-ChildItem -Path $sysvol -Recurse -Include "Groups.xml","Services.xml","Scheduledtasks.xml","DataSources.xml","Drives.xml" -ErrorAction SilentlyContinue | Select-Object -First 20
            foreach ($f in $gppHits) {
                $raw = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
                if ($raw -match 'cpassword=') {
                    Add-Finding HIGH "GPP cpassword in SYSVOL: $($f.FullName)" `
                        "Legacy Group Policy Preferences password. Decrypt offline; script does not decrypt." `
                        "type `"$($f.FullName)`"" `
                        "gpp_sysvol:$($f.FullName)" `
                        -Priority 100
                }
            }
        } catch {}
    }

    $role = if ($ctx.IsDC) { "Domain Controller ($($ctx.Computer)" + $(if ($ctx.DcHow) { "; $($ctx.DcHow)" } else { "" }) + ")" } else { "domain member ($($ctx.Computer))" }
    $sysvolLine = if ($sysvolOk) { "SYSVOL=YES $sysvol" } else { "SYSVOL=NO (try \\$($ctx.NetBios)\SYSVOL)" }
    $netLine = if ($netlogonOk) { "NETLOGON=YES $netlogon" } else { "NETLOGON=?" }

    if ($script:High -eq 0) {
        # Single top MED: role + playbook + SYSVOL commands (no separate duplicate findings)
        $play = @(
            "# === WHAT TO DO NOW (domain, no local HIGH) ===",
            "# You are: $($ctx.User) on $role",
            "# Shares: $sysvolLine | $netLine",
            "#",
            "# STEP 1 - Loot domain file shares (do this first)",
            "dir `"$sysvol`"",
            "dir `"$sysvol\$dns`"",
            "dir `"$sysvol\$dns\Policies`"",
            "dir `"$sysvol\$dns\scripts`"",
            "dir `"$netlogon`"",
            "findstr /s /i /m cpassword `"$sysvol\*.xml`" 2>nul",
            "findstr /s /i password `"$sysvol\*.xml`" `"$sysvol\*.bat`" `"$sysvol\*.ps1`" `"$sysvol\*.vbs`" `"$netlogon\*.*`" 2>nul | more",
            "#",
            "# STEP 2 - Domain identity / groups",
            "whoami /all",
            "net user $env:USERNAME /domain",
            "net group /domain",
            "net group `"Domain Admins`" /domain",
            "nltest /dclist:$dns",
            "nltest /dsgetdc:$dns",
            "#",
            "# STEP 3 - From attack host (exam-allowed tools only)",
            "# BloodHound: path to Domain Admins",
            "# Kerberoast / AS-REP if in scope",
            "#",
            "# STEP 4 - Privileges already noted (if any)",
            "# SeMachineAccountPrivilege => machine account / quota paths (manual)",
            "#",
            "# STEP 5 - After new creds, re-run this script as better user/host"
        ) -join $nl

        Add-Finding MED "DOMAIN MODE: no local HIGH -> follow domain playbook" `
            "Local high-confidence privesc not found. Host is $role; user $($ctx.User). This is common. Stop weak local noise; loot SYSVOL/NETLOGON then enum domain." `
            $play `
            "domain_playbook_no_local_high" `
            -Priority 95

        if (-not $sysvolOk) {
            Add-Finding INFO "SYSVOL not reachable: $sysvol" `
                "Playbook step 1 may fail until DNS/name works. Try NetBIOS path." `
                "dir `"$sysvol`"`ndir `"\\$($ctx.NetBios)\SYSVOL`"" `
                "domain_sysvol_miss" `
                -Priority 40
        }
    } else {
        # Have local HIGH: short domain note only, do not bury local leads
        $short = @(
            "dir `"$sysvol`"",
            "dir `"$netlogon`"",
            "findstr /s /i /m cpassword `"$sysvol\*.xml`" 2>nul",
            "whoami /all",
            "net user $env:USERNAME /domain"
        ) -join $nl
        Add-Finding MED "DOMAIN also in play: $role (finish local HIGH first)" `
            "You have local HIGH findings. Verify those first, then domain loot/lateral. $sysvolLine" `
            $short `
            "domain_after_local_high" `
            -Priority 30
    }
}

# ---------- checks ----------
function Invoke-AllChecks {
    $script:DomainCtx = Get-DomainContext
    if ($script:DomainCtx.IsDomain) {
        Write-Host "[*] Domain detected: DNS=$($script:DomainCtx.Dns) NetBIOS=$($script:DomainCtx.NetBios) DC=$($script:DomainCtx.IsDC)"
    }

    $script:IsEvilWinRM = Test-IsEvilWinRMSession
    if ($script:IsEvilWinRM) {
        Write-Host "[*] WinRM remoting host detected (Evil-WinRM-style). Loot Next will use download/upload hints."
    }

    Write-Host "[*] identity / groups / tokens ..."
    Test-IdentityAndTokens

    if ($script:AlreadySystem) {
        Write-Host "[*] Already SYSTEM - skipping write/ACL privesc checks (they only produce noise)."
        Write-Host "[*] OS loot catalog / credentials / configs / domain still run ..."
        # Still hunt Windows.old SAM/SYSTEM + Autologon; AIE is harmless noise if present
        Test-ClassicMisconfigs
        Test-Credentials
        Test-AppConfigInventory
        Test-LocalPorts
        Test-EnvHints
        Complete-DomainGuidance
        return
    }

    Write-Host "[*] AlwaysInstallElevated / Autologon / Unattend / SAM ..."
    Test-ClassicMisconfigs
    if ($script:SkipWriteChecks) {
        Write-Host "[*] Elevated admin - skipping service/task/PATH write sweeps (ACL always true)."
    } else {
        Write-Host "[*] services (write / unquoted / weak DACL) ..."
        Test-Services
        Write-Host "[*] scheduled tasks ..."
        Test-ScheduledTasks
        Write-Host "[*] PATH / autorun / startup / GPO ..."
        Test-PathAndAutorun
    }
    Write-Host "[*] credentials & local services ..."
    Test-Credentials
    Write-Host "[*] web/DB config file locations ..."
    Test-AppConfigInventory
    Test-LocalPorts
    Write-Host "[*] environment hints ..."
    Test-EnvHints
    Write-Host "[*] domain guidance ..."
    Complete-DomainGuidance
}

function Test-IdentityAndTokens {
    $who = whoami 2>$null
    $privs = whoami /priv 2>$null
    $groups = whoami /groups 2>$null
    $privText = ($privs | Out-String)
    $grpText = ($groups | Out-String)
    $whoText = ($who | Out-String)

    # --- Already privileged? Stop generating 300 fake "writable" HIGHs ---
    $isSystem = $false
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        if ($id.User -and $id.User.Value -eq 'S-1-5-18') { $isSystem = $true }
        if ($id.Name -match '(?i)NT AUTHORITY\\SYSTEM|^SYSTEM$') { $isSystem = $true }
    } catch {}
    if (-not $isSystem) {
        if ($whoText -match '(?i)nt authority\\system' -or $grpText -match 'S-1-5-18' -or $grpText -match 'S-1-16-16384') {
            $isSystem = $true
        }
    }
    if ($isSystem) {
        $script:AlreadySystem = $true
        $script:SkipWriteChecks = $true
        $sysNext = if ($script:IsEvilWinRM) {
            Get-EvilWinRMLootNext -Kind system
        } else {
            "whoami`nwhoami /priv`nwhoami /groups`nhostname`n# proof: type proof.txt / type local.txt as required by lab`n# If domain machine account context: consider domain pivot with care`n# Loot: Windows.old SAM+SYSTEM, Unattend, configs (see other findings)"
        }
        Add-Finding HIGH "ALREADY NT AUTHORITY\SYSTEM - local privesc complete" `
            "Current token is SYSTEM (S-1-5-18). Do NOT hunt 'writable services/tasks' - as SYSTEM everything looks writable and is NOT a privesc lead. Collect proof/loot, then domain actions if needed." `
            $sysNext `
            "already_system" `
            -Priority 100
        [void]$script:Details.Add("whoami:`n$who`n`nprivs:`n$privText`ngroups:`n$grpText")
        return
    }

    # High-integrity local admin: write checks on System32/Microsoft are useless noise
    $highIntegrity = $grpText -match 'S-1-16-12288'
    $inAdmins = $grpText -match 'S-1-5-32-544'
    if ($inAdmins -and $highIntegrity) {
        $script:SkipWriteChecks = $true
        $adminNext = if ($script:IsEvilWinRM) {
            Join-NextLines @("whoami /groups", "whoami /priv", (Get-EvilWinRMLootNext -Kind admin))
        } else {
            "whoami /groups`nwhoami /priv"
        }
        Add-Finding HIGH "Already elevated local Administrator (High Integrity)" `
            "Full admin token. Skip service/task XML write hunting - ACL will show write on almost all system objects. Focus on loot/creds/domain." `
            $adminNext `
            "already_admin_high" `
            -Priority 100
    } elseif ($inAdmins) {
        $filtNext = "whoami /groups`nwhoami /priv`nwhoami /all`nnet localgroup administrators`n# If filtered admin: need another path or UAC bypass (manual)"
        if ($script:IsEvilWinRM) {
            $filtNext = Join-NextLines @($filtNext, "# Evil-WinRM: Medium integrity is common; full admin may need another privesc path first")
        }
        Add-Finding HIGH "User may be in local Administrators" `
            "If token is full admin, you may already have admin rights. Remote shells are often UAC-filtered (Medium integrity)." `
            $filtNext `
            "admin_group" `
            -Priority 95
    }

    # Privesc-relevant groups only. RDP/WinRM membership is access method, not local privesc.
    $interesting = @{
        "S-1-5-32-551" = "Backup Operators"
        "S-1-5-32-550" = "Print Operators"
        "S-1-5-32-549" = "Server Operators"
        "S-1-5-32-548" = "Account Operators"
        "S-1-5-32-552" = "Replicator"
        "S-1-5-32-578" = "Hyper-V Administrators"
        "S-1-5-32-562" = "Distributed COM Users"
    }
    foreach ($sid in $interesting.Keys) {
        $gname = $interesting[$sid]
        if ($grpText -match [regex]::Escape($sid) -or $grpText -match [regex]::Escape($gname)) {
            $sev = if ($sid -in @("S-1-5-32-551","S-1-5-32-549","S-1-5-32-548","S-1-5-32-578")) { "HIGH" } else { "MED" }
            $gnext = "whoami /groups" + [Environment]::NewLine + "net localgroup `"$gname`""
            Add-Finding $sev "Interesting group: $gname" `
                "Often has dedicated privesc techniques. Check HackTricks for this group (manual)." `
                $gnext `
                "group_$sid"
        }
    }
    # Access groups: only note in -Full (noise on Evil-WinRM/RDP shells)
    if ($Mode -eq "full") {
        if ($grpText -match 'S-1-5-32-580|Remote Management Users') {
            Add-Finding INFO "Group: Remote Management Users" "Explains WinRM access; not a local privesc by itself." "whoami /groups" "group_winrm"
        }
        if ($grpText -match 'S-1-5-32-555|Remote Desktop Users') {
            Add-Finding INFO "Group: Remote Desktop Users" "Explains RDP access; not a local privesc by itself." "whoami /groups" "group_rdp"
        }
    }

    if ($privText -match 'SeImpersonatePrivilege\s+.*Enabled') {
        Add-Finding HIGH "SeImpersonatePrivilege = Enabled" `
            "High-value. Potato/PrintSpoofer-class paths depend on OS build and services. Script does NOT exploit." `
            "whoami /priv`nsysteminfo`ntasklist /v`n# Confirm build + service context, then choose a technique manually" `
            "priv_impersonate"
    }
    if ($privText -match 'SeAssignPrimaryTokenPrivilege\s+.*Enabled') {
        Add-Finding HIGH "SeAssignPrimaryTokenPrivilege = Enabled" `
            "High-value token privilege (similar class to impersonation)." `
            "whoami /priv`nsysteminfo" `
            "priv_assign"
    }
    if ($privText -match 'SeBackupPrivilege\s+.*Enabled') {
        Add-Finding HIGH "SeBackupPrivilege = Enabled" `
            "May read sensitive files/registry via backup semantics. reg save writes disk - manual only." `
            "whoami /priv`ndir C:\Windows\Repair 2>`$null`ndir C:\Windows\System32\config\RegBack`nicacls C:\Windows\System32\config\SAM" `
            "priv_backup"
    }
    if ($privText -match 'SeRestorePrivilege\s+.*Enabled') {
        Add-Finding HIGH "SeRestorePrivilege = Enabled" `
            "Restore-class privilege; manual verification only." `
            "whoami /priv" `
            "priv_restore"
    }
    if ($privText -match 'SeDebugPrivilege\s+.*Enabled') {
        Add-Finding HIGH "SeDebugPrivilege = Enabled" `
            "May debug privileged processes / read memory." `
            "whoami /priv`ntasklist /v" `
            "priv_debug"
    }
    if ($privText -match 'SeTakeOwnershipPrivilege\s+.*Enabled') {
        Add-Finding MED "SeTakeOwnershipPrivilege = Enabled" `
            "Useful in some ACL cases; rarely first path." `
            "whoami /priv" `
            "priv_takeown"
    }
    if ($privText -match 'SeLoadDriverPrivilege\s+.*Enabled') {
        Add-Finding MED "SeLoadDriverPrivilege = Enabled" `
            "Driver-load related; rarely first OSCP path." `
            "whoami /priv" `
            "priv_loaddriver"
    }
    if ($privText -match 'SeManageVolumePrivilege\s+.*Enabled') {
        Add-Finding MED "SeManageVolumePrivilege = Enabled" `
            "Volume management; niche disk-read techniques exist." `
            "whoami /priv" `
            "priv_managevolume"
    }
    if ($privText -match 'SeMachineAccountPrivilege\s+.*Enabled') {
        # Only meaningful on domain; high priority so it sits under domain playbook
        if ($script:DomainCtx -and $script:DomainCtx.IsDomain) {
            Add-Finding MED "SeMachineAccountPrivilege = Enabled (domain-relevant)" `
                "May add machine accounts if MachineAccountQuota allows. Used in some AD chains (machine account / RBCD-style). Manual only." `
                "whoami /priv`nnet user /domain`n# Review MachineAccountQuota / exam notes before abusing machine accounts" `
                "priv_machineaccount" `
                -Priority 85
        }
    }

    [void]$script:Details.Add("whoami:`n$who`n`nprivs:`n$privText`ngroups(admin-related):`n$(($groups | Select-String -Pattern 'Administrators|S-1-5-32|Label|Mandatory'))")
}

function Test-ClassicMisconfigs {
    $hkcu = reg query "HKCU\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>$null
    $hklm = reg query "HKLM\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>$null
    $hkcuOn = ($hkcu | Out-String) -match '0x1'
    $hklmOn = ($hklm | Out-String) -match '0x1'
    if ($hkcuOn -and $hklmOn) {
        Add-Finding HIGH "AlwaysInstallElevated enabled (HKCU+HKLM)" `
            "Classic MSI local privesc misconfig. Do not auto-build/install MSI; manual only per exam rules." `
            "reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`nreg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated" `
            "aie"
    } elseif ($hkcuOn -or $hklmOn) {
        Add-Finding INFO "AlwaysInstallElevated only one-sided" `
            "Both HKCU and HKLM must be 1 for classic abuse." `
            "reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`nreg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated" `
            "aie_partial"
    }

    $winlogon = reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>$null
    if (($winlogon | Out-String) -match 'DefaultPassword') {
        Add-Finding HIGH "Winlogon AutoLogon may store cleartext password" `
            "DefaultPassword/DefaultUserName often reusable." `
            "reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`"`ncmdkey /list`nnet user" `
            "autologon"
    }

    # Catalog-driven loot checks (OSCP categories), not ad-hoc path patches.
    Test-OsLootCatalog
}

function Test-FileReadableNonEmpty([string]$Path, [int]$MinSize = 16) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $len = 0
    try { $len = [int64](Get-Item -LiteralPath $Path -ErrorAction Stop).Length } catch { return $null }
    if ($len -lt $MinSize) { return @{ Ok = $false; Len = $len; Why = "tiny" } }
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        $fs.Close()
        return @{ Ok = $true; Len = $len; Why = "readable" }
    } catch {
        try {
            $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'Read')
            $fs.Close()
            return @{ Ok = $true; Len = $len; Why = "readable" }
        } catch {
            return @{ Ok = $false; Len = $len; Why = "locked_or_denied" }
        }
    }
}

function Get-OsLootRoots {
    # Roots that historically hold credential material on Windows labs/exams.
    # Design: category-first (upgrade leftovers, install leftovers, backups), not one path after a miss.
    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($r in @(
        # Current OS
        "C:\Windows",
        "C:\Windows\System32\config",
        "C:\Windows\System32\config\RegBack",
        "C:\Windows\Repair",
        "C:\Windows\Panther",
        "C:\Windows\System32\Sysprep",
        "C:\sysprep",
        # Upgrade / migration leftovers (OSCP classic)
        "C:\Windows.old",
        "C:\windows.old",
        "C:\`$WINDOWS.~BT",
        "C:\`$WINDOWS.~WS",
        # Common backup / admin dump dirs
        "C:\Backup", "C:\Backups", "C:\backup", "C:\backups",
        "C:\Temp", "C:\temp", "C:\Windows\Temp",
        "C:\Users\Public",
        "C:\inetpub",
        "C:\PerfLogs"
    )) {
        if (Test-Path -LiteralPath $r) { [void]$roots.Add($r) }
    }
    # Any drive-root Windows.old style folders
    try {
        Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | ForEach-Object {
            $root = $_.Root  # C:\
            foreach ($name in @("Windows.old", "windows.old", "Windows.old.000", "Windows.old.001")) {
                $p = Join-Path $root $name
                if ((Test-Path -LiteralPath $p) -and -not ($roots -contains $p)) { [void]$roots.Add($p) }
            }
        }
    } catch {}
    return @($roots | Select-Object -Unique)
}

function Get-HivePathTemplates([string]$WindowsRoot) {
    # $WindowsRoot examples: C:\Windows  OR  C:\Windows.old\Windows  OR  C:\windows.old\windows
    $w = $WindowsRoot.TrimEnd('\')
    return @(
        "$w\System32\config\SAM",
        "$w\System32\config\SYSTEM",
        "$w\System32\config\SECURITY",
        "$w\System32\config\SOFTWARE",
        "$w\System32\config\DEFAULT",
        "$w\System32\config\RegBack\SAM",
        "$w\System32\config\RegBack\SYSTEM",
        "$w\System32\config\RegBack\SECURITY",
        "$w\Repair\SAM",
        "$w\Repair\SYSTEM",
        "$w\Repair\SECURITY",
        # Non-standard lab placements (hive copies left beside System32 tree)
        "$w\System32\SAM",
        "$w\System32\SYSTEM",
        "$w\System32\SECURITY"
    )
}

function Get-UnattendPathTemplates([string]$WindowsRoot) {
    $w = $WindowsRoot.TrimEnd('\')
    return @(
        "$w\Panther\Unattend.xml",
        "$w\Panther\Unattended.xml",
        "$w\Panther\unattend.xml",
        "$w\Panther\unattend\unattend.xml",
        "$w\System32\Sysprep\Unattend.xml",
        "$w\System32\Sysprep\Unattended.xml",
        "$w\System32\Sysprep\sysprep.xml",
        "$w\System32\Sysprep\Panther\Unattend.xml"
    )
}

function Test-OsLootCatalog {
    <#
    .SYNOPSIS
      Category-driven credential/loot discovery for OSCP-style Windows boxes.
    .NOTES
      Categories (maintain this list when extending - do not only patch one missed path):
        1) OS upgrade leftovers (Windows.old, $WINDOWS.~BT)
        2) Registry hive copies (SAM/SYSTEM/SECURITY) under config/Repair/RegBack/odd copies
        3) Unattend/Sysprep leftovers (current + old Windows trees)
        4) Old user profile credential artifacts under Windows.old\Users
        5) Named backup folders (Backup/Temp/Public) for hive filenames
    #>
    $candidatesHive = New-Object System.Collections.Generic.List[string]
    $candidatesUnattend = New-Object System.Collections.Generic.List[string]
    $oldUserRoots = New-Object System.Collections.Generic.List[string]

    # --- Category 1: upgrade leftovers as first-class roots ---
    $windowsTrees = New-Object System.Collections.Generic.List[string]
    if (Test-Path "C:\Windows") { [void]$windowsTrees.Add("C:\Windows") }

    foreach ($old in @("C:\Windows.old", "C:\windows.old")) {
        if (-not (Test-Path -LiteralPath $old)) { continue }
        $oldNext = "dir `"$old`"`ndir `"$old\Windows\System32\config`"`ndir `"$old\Windows\System32`"`ndir `"$old\Users`"`ndir `"$old\Windows\Panther`""
        if ($script:IsEvilWinRM) {
            $oldNext = Join-NextLines @(
                $oldNext,
                "# Evil-WinRM: if SAM+SYSTEM exist under config\, copy to C:\Users\Public\ then download both"
            )
        }
        Add-Finding HIGH "OS leftover root present: $old" `
            "Upgrade/migration leftover. Systematically check old config hives (SAM/SYSTEM), Unattend, and old user profiles. High-value OSCP category." `
            $oldNext `
            "loot_oldroot:$old" `
            -Priority 98
        foreach ($w in @("$old\Windows", "$old\windows")) {
            if (Test-Path -LiteralPath $w) { [void]$windowsTrees.Add($w) }
        }
        if (Test-Path -LiteralPath "$old\Users") { [void]$oldUserRoots.Add("$old\Users") }
    }
    foreach ($bt in @("C:\`$WINDOWS.~BT", "C:\`$WINDOWS.~WS")) {
        if (Test-Path -LiteralPath $bt) {
            Add-Finding MED "Windows setup leftover folder: $bt" `
                "May contain setup logs/unattend fragments. Enumerate carefully." `
                "dir /s /b `"$bt\*unattend*`" 2>nul`ndir /s /b `"$bt\*sam*`" 2>nul" `
                "loot_winbt:$bt" -Priority 70
        }
    }

    # --- Categories 2+3: expand hive + unattend templates for every Windows tree ---
    foreach ($wt in ($windowsTrees | Select-Object -Unique)) {
        foreach ($p in (Get-HivePathTemplates $wt)) { [void]$candidatesHive.Add($p) }
        foreach ($p in (Get-UnattendPathTemplates $wt)) { [void]$candidatesUnattend.Add($p) }
    }
    foreach ($p in @("C:\sysprep\sysprep.xml", "C:\sysprep\Unattend.xml", "C:\sysprep\unattend.xml")) {
        [void]$candidatesUnattend.Add($p)
    }

    # Name search under loot roots for hive basenames (depth-capped)
    $hiveNames = @('SAM', 'SYSTEM', 'SECURITY')
    foreach ($root in (Get-OsLootRoots)) {
        if ($root -match '(?i)\\Windows$' -and $root -notmatch '(?i)windows\.old') {
            # live C:\Windows tree is huge; only search config/repair/regback already in templates
            continue
        }
        try {
            $depth = if ($root -match '(?i)windows\.old') { 7 } else { 4 }
            Get-ChildItem -Path $root -Recurse -File -Depth $depth -ErrorAction SilentlyContinue |
                Where-Object { $hiveNames -contains $_.Name } |
                Select-Object -First 40 |
                ForEach-Object { [void]$candidatesHive.Add($_.FullName) }
        } catch {}
        try {
            Get-ChildItem -Path $root -Recurse -File -Depth 5 -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '(?i)^unattend(ed)?\.xml$|^sysprep\.xml$' } |
                Select-Object -First 20 |
                ForEach-Object { [void]$candidatesUnattend.Add($_.FullName) }
        } catch {}
    }

    # --- Report Unattend ---
    $seenU = @{}
    foreach ($p in $candidatesUnattend) {
        if (-not $p) { continue }
        $k = $p.ToLowerInvariant()
        if ($seenU.ContainsKey($k)) { continue }
        $seenU[$k] = $true
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $uNext = "dir `"$p`"`nfindstr /ni /i `"password administrator username domain`" `"$p`""
        if ($script:IsEvilWinRM) {
            $uNext = Join-NextLines @($uNext, "copy /y `"$p`" C:\Users\Public\", "download C:\Users\Public\$(Split-Path -Leaf $p)")
        }
        Add-Finding HIGH "Unattend/Sysprep found: $p" `
            "Install/sysprep leftovers often store local admin or domain passwords (current OS or Windows.old)." `
            $uNext `
            "unattend:$p" -Priority 94
    }

    # --- Report hives ---
    $seenH = @{}
    $haveSam = $false
    $haveSystem = $false
    foreach ($p in $candidatesHive) {
        if (-not $p) { continue }
        $k = $p.ToLowerInvariant()
        if ($seenH.ContainsKey($k)) { continue }
        $seenH[$k] = $true

        $st = Test-FileReadableNonEmpty $p 16
        if (-not $st) { continue }
        $base = Split-Path -Leaf $p

        # Live hives under current OS config are usually locked for low-priv; still note in full
        $isLiveConfig = $p -match '(?i)^[A-Z]:\\Windows\\System32\\config\\(SAM|SYSTEM|SECURITY)$'

        if ($st.Ok) {
            if ($base -ieq 'SAM') { $haveSam = $true }
            if ($base -ieq 'SYSTEM') { $haveSystem = $true }
            $hiveNext = if ($script:IsEvilWinRM) {
                Get-EvilWinRMLootNext -LocalPath $p -Kind hive
            } else {
                "dir `"$p`"`nicacls `"$p`"`ncopy /y `"$p`" %TEMP%\`n# On attack host: secretsdump.py -sam SAM -system SYSTEM LOCAL"
            }
            Add-Finding HIGH "Readable registry hive: $p (size=$($st.Len))" `
                "Readable by current user. Offline hash extraction typically needs SAM + SYSTEM together (e.g. from Windows.old)." `
                $hiveNext `
                "hive_read:$p" -Priority 97
        } else {
            if ($isLiveConfig) {
                if ($Mode -eq "full") {
                    Add-Finding INFO "Live hive not readable (expected): $p" `
                        "Current OS hives are usually locked. Prefer Windows.old / Repair / RegBack copies." `
                        "dir `"$p`"`nicacls `"$p`"" `
                        "hive_live:$p" -Priority 15
                }
            } elseif ($p -match '(?i)windows\.old' -or $Mode -eq "full") {
                if ($st.Why -ne "tiny") {
                    Add-Finding INFO "Hive present but not readable: $p (size=$($st.Len); $($st.Why))" `
                        "Exists but open failed (ACL). Still note the path." `
                        "dir `"$p`"`nicacls `"$p`"" `
                        "hive_locked:$p" -Priority 25
                }
            }
        }
    }

    if ($haveSam -and $haveSystem) {
        $pairNext = if ($script:IsEvilWinRM) {
            Get-EvilWinRMLootNext -Kind pair
        } else {
            "# Prefer copies from the same Windows tree (e.g. both under Windows.old)`n# secretsdump.py -sam SAM -system SYSTEM LOCAL"
        }
        Add-Finding HIGH "Readable SAM + SYSTEM pair available" `
            "You have both hive types readable. Copy offline and extract local account hashes on the attack host." `
            $pairNext `
            "hive_pair_ready" -Priority 99
    } elseif ($haveSam -or $haveSystem) {
        $partialNext = "dir C:\Windows.old\Windows\System32\config`ndir C:\windows.old\windows\System32"
        if ($script:IsEvilWinRM) {
            $partialNext = Join-NextLines @($partialNext, "# Evil-WinRM: after both files exist, copy to C:\Users\Public\ then download SAM + SYSTEM")
        }
        Add-Finding MED "Partial hive set readable (need SAM + SYSTEM)" `
            "One of SAM/SYSTEM is readable. Hunt the sibling hive in the same folder tree (especially under Windows.old)." `
            $partialNext `
            "hive_pair_partial" -Priority 90
    }

    # --- Category 4: old user profile artifacts under Windows.old\Users ---
    foreach ($ur in $oldUserRoots) {
        try {
            $hist = Get-ChildItem -Path $ur -Recurse -Filter "ConsoleHost_history.txt" -File -ErrorAction SilentlyContinue |
                Select-Object -First 15
            foreach ($h in $hist) {
                Add-Finding MED "Old profile PowerShell history: $($h.FullName)" `
                    "Credential clues may survive in Windows.old user profiles." `
                    "type `"$($h.FullName)`"`nfindstr /ni /i `"password passwd pwd credential`" `"$($h.FullName)`"" `
                    "old_pshist:$($h.FullName)" -Priority 72
            }
        } catch {}
        try {
            foreach ($name in @("web.config", ".env", "unattend.xml", "sysprep.xml")) {
                Get-ChildItem -Path $ur -Recurse -Filter $name -File -Depth 5 -ErrorAction SilentlyContinue |
                    Select-Object -First 10 |
                    ForEach-Object {
                        Add-Finding MED "Interesting file under Windows.old Users: $($_.FullName)" `
                            "Review for passwords/connection strings." `
                            "type `"$($_.FullName)`" | more`nfindstr /ni /i `"password connectionString`" `"$($_.FullName)`"" `
                            "old_userfile:$($_.FullName)" -Priority 68
                    }
            }
        } catch {}
    }
}

function Test-ServiceDaclWeak([string]$ServiceName) {
    # Heuristic parse of sc sdshow SDDL for low principals with CHANGE_CONFIG / WRITE_DAC / GA
    $out = & sc.exe sdshow $ServiceName 2>$null
    if (-not $out) { return $null }
    $sddl = ($out | Out-String)
    if (-not $sddl) { return $null }
    $bad = New-Object System.Collections.ArrayList
    # DC = SERVICE_CHANGE_CONFIG; WD principal = Everyone; AU/BU/IU = AuthUsers/Users/Interactive
    $low = @('WD', 'AU', 'BU', 'IU')
    foreach ($p in $low) {
        if ($sddl -match ("DC;;;" + $p)) { [void]$bad.Add(('CHANGE_CONFIG->' + $p)) }
        if ($sddl -match ("WD;;;" + $p) -and $sddl -match 'A;;') {
            # WRITE_DAC right appears as WD in rights list; principal also WD for Everyone - loose heuristic
        }
        if ($sddl -match ("GA;;;" + $p)) { [void]$bad.Add(('GENERIC_ALL->' + $p)) }
    }
    # clearer: ACE snippets
    if ($sddl -match 'DC;;;WD' -or $sddl -match 'DC;;;AU' -or $sddl -match 'DC;;;BU' -or $sddl -match 'DC;;;IU') {
        if (-not ($bad -join ',').Contains('CHANGE_CONFIG')) { [void]$bad.Add('SERVICE_CHANGE_CONFIG to low principal') }
    }
    if ($sddl -match 'GA;;;WD' -or $sddl -match 'GA;;;AU' -or $sddl -match 'GA;;;BU') {
        if (-not ($bad -join ',').Contains('GENERIC_ALL')) { [void]$bad.Add('GENERIC_ALL to low principal') }
    }
    if ($bad.Count -gt 0) { return ($bad -join '; ') }
    return $null
}

function Test-Services {
    $services = @()
    try { $services = Get-CimInstance Win32_Service -ErrorAction Stop } catch {
        try { $services = Get-WmiObject Win32_Service -ErrorAction Stop } catch { $services = @() }
    }
    if (-not $services) {
        Add-Finding INFO "Cannot enumerate services (WMI/CIM failed)" "Try: sc query state= all" "sc query state= all" "svc_enum_fail"
        return
    }

    $svcLines = New-Object System.Collections.ArrayList
    foreach ($s in $services) {
        $raw = [string]$s.PathName
        $name = [string]$s.Name
        $start = [string]$s.StartName
        $state = [string]$s.State
        $mode = [string]$s.StartMode
        [void]$svcLines.Add(("{0} | {1} | {2} | {3} | {4}" -f $name,$start,$state,$mode,$raw))

        $exe = Get-ServiceExePath $raw
        $priv = Test-PrivilegedAccount $start
        $sysPath = Test-IsSystemPath $exe

        # Skip expensive sdshow + ACL on default Windows service binaries (speed + noise)
        if ($sysPath -and -not (Test-UnquotedServicePath $raw)) { continue }

        # weak DACL only for non-system paths or privileged start accounts outside System32
        if (-not $sysPath) {
            $daclIssue = Test-ServiceDaclWeak $name
            if ($daclIssue) {
                $sev = if ($priv) { "HIGH" } else { "MED" }
                $prio = if ($priv) { 90 } else { 55 }
                Add-Finding $sev "Weak service DACL: $name" `
                    "$daclIssue; StartName=$start State=$state. May allow service config change. Confirm with sc qc/sdshow; do NOT auto sc config." `
                    ("sc qc `"$name`"" + [Environment]::NewLine + "sc sdshow `"$name`"") `
                    "svc_dacl:$name" `
                    -Priority $prio
            }
        }

        if ($exe -and (Test-Path -LiteralPath $exe) -and -not $sysPath) {
            $dir = Split-Path -Parent $exe
            if (Test-AclWritable $exe) {
                $sev = if ($priv) { "HIGH" } else { "MED" }
                $prio = if ($priv) { 92 } else { 55 }
                Add-Finding $sev "Writable service binary: $exe" `
                    "Service $name runs as $start ($state/$mode). Writable binary is high-confidence; need restart/start trigger." `
                    ("sc qc `"$name`"" + [Environment]::NewLine + "sc sdshow `"$name`"" + [Environment]::NewLine + "icacls `"$exe`"") `
                    "svc_bin:$name" `
                    -Priority $prio
            } elseif ($dir -and (Test-AclWritable $dir)) {
                $sev = if ($priv) { "HIGH" } else { "MED" }
                $prio = if ($priv) { 91 } else { 55 }
                Add-Finding $sev "Writable service directory: $dir" `
                    "Service $name runs as $start. Common path: replace bin/DLL/config then trigger service." `
                    ("sc qc `"$name`"" + [Environment]::NewLine + "sc sdshow `"$name`"" + [Environment]::NewLine + "icacls `"$dir`"") `
                    "svc_dir:$name" `
                    -Priority $prio
            }
        }

        # unquoted: only if writable prefix
        if (Test-UnquotedServicePath $raw) {
            $exe2 = Get-ServiceExePath $raw
            $prefix = Get-UnquotedWritablePrefix $exe2
            if ($prefix) {
                $sev = if ($priv) { "HIGH" } else { "MED" }
                $prio = if ($priv) { 88 } else { 55 }
                Add-Finding $sev "Unquoted service path + writable prefix: $name" `
                    "Path=$raw; StartName=$start; WritablePrefix=$prefix. Confirm start/restart conditions." `
                    ("sc qc `"$name`"" + [Environment]::NewLine + "icacls `"$prefix`"") `
                    "svc_uq:$name" `
                    -Priority $prio
            } elseif ($Mode -eq "full" -and -not $sysPath) {
                Add-Finding INFO "Unquoted path (prefix not writable): $name" `
                    "Path=$raw. Not useful without write on a prefix." `
                    "sc qc `"$name`"" `
                    "svc_uq_info:$name" `
                    -Priority 20
            }
        }
    }
    if ($Mode -eq "full") {
        [void]$script:Details.Add("Services:`n" + ($svcLines -join "`n"))
    }
}

function Test-IsHighPrivTaskPrincipal([string]$runAs) {
    if (-not $runAs) { return $false }
    # Real high-priv principals only. NOT Users / INTERACTIVE / Authenticated Users.
    return [bool]($runAs -match '(?i)^(SYSTEM|LOCAL SYSTEM|NT AUTHORITY\\SYSTEM|LOCAL SERVICE|NT AUTHORITY\\LOCAL SERVICE|NETWORK SERVICE|NT AUTHORITY\\NETWORK SERVICE|S-1-5-18|S-1-5-19|S-1-5-20)$' -or
        $runAs -match '(?i)\\SYSTEM$' -or
        $runAs -match '(?i)Administrator')
}

function Test-IsMicrosoftBuiltinTaskPath([string]$taskPath, [string]$taskFile) {
    # Built-in Microsoft tasks under System32\Tasks\Microsoft are almost never a real OSCP privesc
    # for low-priv users; admin ACL false-positives create hundreds of HIGH noise findings.
    if ($taskPath -match '(?i)\\Microsoft\\') { return $true }
    if ($taskFile -match '(?i)\\System32\\Tasks\\Microsoft\\') { return $true }
    return $false
}

function Test-ScheduledTasks {
    $taskXmlHits = 0
    $taskXmlCap = if ($Mode -eq "full") { 8 } else { 3 }
    $taskOtherCap = if ($Mode -eq "full") { 15 } else { 8 }
    $taskOtherHits = 0
    $skippedMsXml = 0

    $tasks = @()
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
    } catch {
        # fallback schtasks csv
        try {
            $csv = schtasks /query /fo CSV /v 2>$null
            if ($csv) {
                $parsed = $csv | ConvertFrom-Csv
                foreach ($t in $parsed) {
                    if ($taskOtherHits -ge $taskOtherCap) { break }
                    $runAs = $t.'Run As User'
                    $toRun = $t.'Task To Run'
                    $tname = $t.TaskName
                    if (-not $toRun) { continue }
                    if ($toRun -match 'N/A|COM handler') { continue }
                    if (-not (Test-IsHighPrivTaskPrincipal $runAs)) { continue }
                    # Skip Microsoft\Windows\... noise in CSV path if present in TaskName
                    if ($tname -match '(?i)\\Microsoft\\Windows\\') { continue }
                    $path = Get-ExecutableFromCommand $toRun
                    if ($path) {
                        if (Test-IsSystemPath $path) { continue }
                        $dir = Split-Path -Parent $path
                        if ((Test-Path -LiteralPath $path) -and (Test-AclWritable $path)) {
                            Add-Finding HIGH "Writable privileged scheduled-task binary: $path" `
                                "Task=$tname RunAs=$runAs" `
                                "schtasks /query /tn `"$tname`" /fo LIST /v`nicacls `"$path`"" `
                                "task_file:$tname" -Priority 90
                            $taskOtherHits++
                        } elseif ($dir -and (Test-Path -LiteralPath $dir) -and (Test-AclWritable $dir)) {
                            Add-Finding HIGH "Writable privileged scheduled-task directory: $dir" `
                                "Task=$tname RunAs=$runAs Cmd=$toRun" `
                                "schtasks /query /tn `"$tname`" /fo LIST /v`nicacls `"$dir`"" `
                                "task_dir:$tname" -Priority 89
                            $taskOtherHits++
                        } elseif ($path -match '(?i)\\Users\\|\\Temp\\|\\ProgramData\\|\\inetpub\\|\\xampp\\') {
                            Add-Finding MED "Privileged task points to non-standard path: $path" `
                                "Task=$tname RunAs=$runAs" `
                                "schtasks /query /tn `"$tname`" /fo LIST /v" `
                                "task_ns:$tname" -Priority 60
                            $taskOtherHits++
                        }
                    } elseif ($toRun -match '(?i)powershell|cmd\.exe|wscript|cscript|\.bat|\.cmd|\.ps1|\.vbs') {
                        if ($toRun -match '(?i)%SystemRoot%|\\Windows\\System32\\') { continue }
                        Add-Finding MED "Privileged task runs script/interpreter: $tname" `
                            "RunAs=$runAs Cmd=$toRun. Extract script path and check ACL manually." `
                            "schtasks /query /tn `"$tname`" /fo LIST /v" `
                            "task_script:$tname" -Priority 55
                        $taskOtherHits++
                    }
                }
            }
        } catch {}
        return
    }

    foreach ($t in $tasks) {
        try {
            $prin = $t.Principal
            $runAs = $prin.UserId
            if (-not $runAs) { $runAs = $prin.GroupId }
            $isPriv = Test-IsHighPrivTaskPrincipal ([string]$runAs)
            # Do NOT treat RunLevel=Highest alone as priv (causes Users/INTERACTIVE spam)
            if (-not $isPriv) { continue }

            $actions = $t.Actions
            foreach ($a in $actions) {
                $exec = $a.Execute
                $args = $a.Arguments
                $cmd = ("$exec $args").Trim()
                $fullName = ($t.TaskPath.TrimEnd('\','/') + '\' + $t.TaskName)
                if (-not $exec) { continue }

                $isMs = Test-IsMicrosoftBuiltinTaskPath $t.TaskPath ""

                # Task XML write: ONLY non-Microsoft tasks (real privesc surface).
                # Checking System32\Tasks\Microsoft\* as admin creates 200+ false HIGH findings.
                if (-not $isMs -and $taskXmlHits -lt $taskXmlCap) {
                    $taskFile = "C:\Windows\System32\Tasks" + ($t.TaskPath -replace '/','\') + $t.TaskName
                    $taskFile = $taskFile -replace '\\+','\'
                    if ((Test-Path -LiteralPath $taskFile -PathType Leaf) -and (Test-AclWritable $taskFile)) {
                        Add-Finding HIGH "Writable scheduled task definition: $taskFile" `
                            "Task=$fullName RunAs=$runAs. Non-Microsoft task XML writable by current user — verify you can actually modify it (icacls + non-admin shell)." `
                            "schtasks /query /tn `"$($t.TaskName)`" /fo LIST /v`nicacls `"$taskFile`"" `
                            "task_xml:$fullName" -Priority 91
                        $taskXmlHits++
                    }
                } elseif ($isMs) {
                    $skippedMsXml++
                }

                if ($taskOtherHits -ge $taskOtherCap) { continue }

                $path = Get-ExecutableFromCommand $cmd
                if (-not $path) { $path = $exec.Trim('"') }
                # Skip pure Windows system binaries for "writable bin" noise when already admin
                if ($path -and (Test-IsSystemPath $path)) {
                    if ($Mode -ne "full") { continue }
                }

                if ($path -and (Test-Path -LiteralPath $path)) {
                    $dir = Split-Path -Parent $path
                    if ((-not (Test-IsSystemPath $path)) -and (Test-AclWritable $path)) {
                        Add-Finding HIGH "Writable privileged scheduled-task binary: $path" `
                            "Task=$fullName RunAs=$runAs" `
                            "schtasks /query /tn `"$($t.TaskName)`" /fo LIST /v`nicacls `"$path`"" `
                            "task_bin:$fullName" -Priority 90
                        $taskOtherHits++
                    } elseif ($dir -and (-not (Test-IsSystemPath $dir)) -and (Test-AclWritable $dir)) {
                        Add-Finding HIGH "Writable privileged scheduled-task directory: $dir" `
                            "Task=$fullName RunAs=$runAs Cmd=$cmd" `
                            "icacls `"$dir`"`ndir `"$dir`"" `
                            "task_dir2:$fullName" -Priority 89
                        $taskOtherHits++
                    } elseif ($path -match '(?i)\\Users\\|\\Temp\\|\\ProgramData\\|\\inetpub\\') {
                        Add-Finding MED "Privileged task non-standard path: $path" `
                            "Task=$fullName RunAs=$runAs" `
                            "schtasks /query /tn `"$($t.TaskName)`" /fo LIST /v" `
                            "task_ns2:$fullName" -Priority 60
                        $taskOtherHits++
                    }
                } elseif ((-not $isMs) -and $cmd -match '(?i)powershell|cmd\.exe|wscript|cscript|\.ps1|\.bat') {
                    if ($cmd -match '(?i)%SystemRoot%|\\Windows\\System32\\') { continue }
                    Add-Finding MED "Privileged task script/interpreter: $fullName" `
                        "RunAs=$runAs Cmd=$cmd" `
                        "schtasks /query /tn `"$($t.TaskName)`" /fo LIST /v" `
                        "task_sc2:$fullName" -Priority 55
                    $taskOtherHits++
                }
            }
        } catch {}
    }

    if ($skippedMsXml -gt 0 -and $Mode -eq "full") {
        Add-Finding INFO "Skipped $skippedMsXml Microsoft\\Windows built-in task XML write checks" `
            "Built-in tasks under System32\Tasks\Microsoft are filtered to avoid admin ACL false positives. Not listed as HIGH." `
            "# No action. If you need raw ACLs: icacls C:\Windows\System32\Tasks\Microsoft" `
            "task_ms_skipped" -Priority 10
    }
}

function Test-PathAndAutorun {
    # PATH hijack - skip always-writable user noise (WindowsApps, profile dirs)
    $pathWritten = 0
    foreach ($d in ($env:Path -split ';' | Where-Object { $_ })) {
        if ($d -match '^\\\\') { continue } # UNC skip
        if (-not (Test-Path -LiteralPath $d)) { continue }
        # Noise filters: default user-writable locations rarely help local privesc
        if ($d -match '(?i)\\WindowsApps$|\\AppData\\Local\\Microsoft\\WindowsApps') { continue }
        if ($env:USERPROFILE -and ($d.StartsWith($env:USERPROFILE, [System.StringComparison]::OrdinalIgnoreCase))) { continue }
        if ($env:TEMP -and ($d.StartsWith($env:TEMP, [System.StringComparison]::OrdinalIgnoreCase))) { continue }
        if (Test-AclWritable $d) {
            $pathWritten++
            if ($pathWritten -le 4) {
                Add-Finding MED "Writable PATH directory: $d" `
                    "Only useful if a privileged process starts a relative command with this PATH." `
                    "echo `$env:Path`nicacls `"$d`"" `
                    "path:$d"
            }
        }
    }
    if ($pathWritten -gt 4) {
        Add-Finding INFO "More writable PATH dirs" "About $pathWritten; summary shows first 4." "echo `$env:Path" "path_more"
    }

    # Run keys
    foreach ($root in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")) {
        if (-not (Test-Path $root)) { continue }
        $props = Get-ItemProperty $root -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -match '^PS') { continue }
            $val = [string]$p.Value
            if ($val -match '(?i)\\Users\\|\\Temp\\|\\ProgramData\\|\\AppData\\') {
                $sev = if ($root -match 'HKLM') { "MED" } else { "INFO" }
                Add-Finding $sev "Run key points to user/temp-like path: $root\$($p.Name)" `
                    "Value=$val. Check if target path is writable." `
                    "reg query $($root -replace ':','')`nicacls (extract path from value)" `
                    "run:$root`:$($p.Name)"
            }
            $exe = Get-ExecutableFromCommand $val
            if ($exe -and (Test-Path -LiteralPath $exe)) {
                $dir = Split-Path -Parent $exe
                if ((Test-AclWritable $exe) -or ($dir -and (Test-AclWritable $dir))) {
                    $sev = if ($root -match 'HKLM') { "HIGH" } else { "MED" }
                    Add-Finding $sev "Writable Run key target: $exe" `
                        "Key=$root Name=$($p.Name) Value=$val" `
                        "icacls `"$exe`"" `
                        "run_wr:$root`:$($p.Name)"
                }
            }
        }
    }

    # Startup folders
    $starts = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    )
    foreach ($s in $starts) {
        if (-not (Test-Path -LiteralPath $s)) { continue }
        $items = Get-ChildItem -LiteralPath $s -Force -ErrorAction SilentlyContinue
        $isCommon = $s -match '(?i)ProgramData'
        $isOwnProfile = $env:USERPROFILE -and $s.StartsWith($env:USERPROFILE, [StringComparison]::OrdinalIgnoreCase)
        if (Test-AclWritable $s) {
            if ($isCommon) {
                Add-Finding HIGH "Writable common Startup folder: $s" `
                    "Writable ALL-USERS startup may affect other logons." `
                    "dir /a `"$s`"`nicacls `"$s`"" `
                    "startup:$s" -Priority 88
            } elseif ($isOwnProfile) {
                # Own user Startup is almost always writable - not a privesc lead
                if ($Mode -eq "full") {
                    Add-Finding INFO "Own user Startup is writable (expected): $s" `
                        "Not a privilege escalation path by itself." `
                        "dir /a `"$s`"" `
                        "startup_own:$s" -Priority 5
                }
            } else {
                Add-Finding MED "Writable Startup folder: $s" `
                    "Writable startup may affect logon items." `
                    "dir /a `"$s`"`nicacls `"$s`"" `
                    "startup:$s" -Priority 50
            }
        } elseif ($items -and $Mode -eq "full") {
            Add-Finding INFO "Startup folder non-empty: $s" "Review contents and ACLs." "dir /a `"$s`"" "startup_info:$s"
        }
    }

    # GPO scripts / scripts.ini if readable
    $gpoRoots = @(
        "C:\Windows\System32\GroupPolicy\Machine\Scripts",
        "C:\Windows\System32\GroupPolicy\User\Scripts",
        "C:\Windows\SysWOW64\GroupPolicy\Machine\Scripts"
    )
    foreach ($g in $gpoRoots) {
        if (Test-Path -LiteralPath $g) {
            $files = Get-ChildItem -LiteralPath $g -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 20
            if ($files) {
                Add-Finding MED "Local GPO scripts directory: $g" `
                    "Check scripts/scripts.ini and ACLs. Domain GPOs also live under SYSVOL if readable." `
                    "dir /s `"$g`"`n# also: dir \\$env:USERDNSDOMAIN\SYSVOL 2>nul" `
                    "gpo:$g"
            }
        }
    }
    # SYSVOL deep guidance is centralized in Complete-DomainGuidance (avoids duplicate noise).
}

function Test-Credentials {
    # PS history
    $hist = @()
    if ($env:APPDATA) {
        $hist += Join-Path $env:APPDATA "Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    }
    try {
        $hist += Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue | ForEach-Object FullName
    } catch {}
    foreach ($h in ($hist | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $h)) { continue }
        $hit = Select-String -Path $h -Pattern 'password|passwd|pwd|credential|cmdkey|runas|net use|sqlcmd|ConvertTo-SecureString|ssh |winrm' -SimpleMatch:$false -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) {
            Add-Finding HIGH "PowerShell history has credential-like keywords" `
                "File=$h hit: $($hit.Line.Trim())" `
                "type `"$h`"`nfindstr /ni /i `"password passwd pwd credential cmdkey runas`" `"$h`"" `
                "pshist:$h"
        }
    }

    # cmdkey
    $ck = cmdkey /list 2>$null | Out-String
    if ($ck -match 'Target:') {
        Add-Finding MED "Saved credentials present (cmdkey)" `
            "Usability depends on target type/context. Do not auto runas." `
            "cmdkey /list" `
            "cmdkey"
    }

    # client configs
    $clients = @(
        "$env:APPDATA\FileZilla\sitemanager.xml",
        "$env:APPDATA\FileZilla\recentservers.xml",
        "$env:APPDATA\WinSCP.ini",
        "$env:APPDATA\mRemoteNG\confCons.xml",
        "$env:LOCALAPPDATA\mRemoteNG\confCons.xml",
        "$env:USERPROFILE\.aws\credentials",
        "$env:USERPROFILE\.azure\accessTokens.json",
        "$env:APPDATA\SuperPuTTY\Sessions.xml"
    )
    foreach ($f in $clients) {
        if ($f -and (Test-Path -LiteralPath $f)) {
            Add-Finding MED "Client credential config: $f" `
                "May contain host/user/saved password." `
                "dir `"$f`"`nfindstr /ni /i `"password pass user host key`" `"$f`"" `
                "client:$f"
        }
    }

    if (Test-Path "HKCU:\Software\SimonTatham\PuTTY\Sessions") {
        Add-Finding MED "PuTTY sessions found" `
            "HostName/UserName/PublicKeyFile often useful for lateral movement." `
            "reg query `"HKCU\Software\SimonTatham\PuTTY\Sessions`" /s" `
            "putty"
    }

    # Strong-content cred hits are handled in Test-AppConfigInventory (locations + optional cred flag).

    # unattend already; also look for vnc/registry passwords
    $vnc = @(
        "HKLM:\SOFTWARE\RealVNC\WinVNC4",
        "HKLM:\SOFTWARE\TightVNC\Server",
        "HKCU:\SOFTWARE\TightVNC\Server"
    )
    foreach ($v in $vnc) {
        if (Test-Path $v) {
            Add-Finding MED "VNC-related registry: $v" `
                "May contain Password fields." `
                "reg query $($v -replace ':','') /s" `
                "vnc:$v" `
                -Priority 45
        }
    }
}

function Get-IisSiteRoots {
    $roots = New-Object System.Collections.Generic.List[string]
    $appHost = "C:\Windows\System32\inetsrv\config\applicationHost.config"
    if (-not (Test-Path -LiteralPath $appHost)) { return @() }
    try {
        [xml]$xml = Get-Content -LiteralPath $appHost -Raw -ErrorAction Stop
        $sites = $xml.SelectNodes("//site")
        foreach ($site in $sites) {
            foreach ($app in $site.application) {
                foreach ($vdir in $app.virtualDirectory) {
                    $p = [string]$vdir.GetAttribute("physicalPath")
                    if (-not $p) { continue }
                    $p = [Environment]::ExpandEnvironmentVariables($p)
                    if ($p -and (Test-Path -LiteralPath $p)) { [void]$roots.Add($p) }
                }
            }
        }
    } catch {
        # Fallback: regex physicalPath= if XML parse fails
        try {
            $raw = Get-Content -LiteralPath $appHost -Raw -ErrorAction Stop
            foreach ($m in [regex]::Matches($raw, 'physicalPath\s*=\s*"([^"]+)"', 'IgnoreCase')) {
                $p = [Environment]::ExpandEnvironmentVariables($m.Groups[1].Value)
                if ($p -and (Test-Path -LiteralPath $p)) { [void]$roots.Add($p) }
            }
        } catch {}
    }
    return @($roots | Select-Object -Unique)
}

function Test-ConfigLooksSensitive([string]$Path) {
    # Lightweight peek: flag if connection/password keywords present. Does NOT print secrets.
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($item.Length -gt 1MB -or $item.Length -lt 10) { return $false }
        $head = Get-Content -LiteralPath $Path -TotalCount 200 -ErrorAction Stop | Out-String
        return [bool]($head -match '(?i)connectionString|password\s*=|pwd\s*=|Data Source|Initial Catalog|DB_PASSWORD|DATABASE_URL|requirepass|jdbc:|mysql://|postgres://|mongodb://|private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY')
    } catch { return $false }
}

function Test-AppConfigInventory {
    # List interesting web/DB/app config LOCATIONS (paths). Keyword peek only; never print secret values.
    # Fast path: fixed known files + one filtered recurse per root (not N patterns x full tree).

    $nameRe = '(?i)^(web\.config|appsettings(\.[^\\/]+)?\.json|\.env(\..+)?|wp-config\.php|config\.inc\.php|config\.php|database\.php|settings\.php|local\.xml|application\.(properties|yml|yaml)|database\.yml|secrets\.yml|my\.ini|my\.cnf|\.my\.cnf|\.pgpass|pg_hba\.conf|redis\.conf|mongod\.conf|httpd\.conf|nginx\.conf|php\.ini|tomcat-users\.xml|server\.xml|context\.xml|app\.config|connectionstrings\.config)$'

    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($r in @(
        "C:\inetpub",
        "C:\xampp", "C:\wamp64", "C:\wamp", "C:\laragon",
        "C:\phpstudy_pro", "C:\phpStudy", "C:\www", "C:\wwwroot",
        "C:\Users\Public",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        # Old OS user trees (loot category, not a one-off path)
        "C:\Windows.old\Users",
        "C:\windows.old\Users"
    )) {
        if ($r -and (Test-Path -LiteralPath $r)) { [void]$roots.Add($r) }
    }
    foreach ($iis in (Get-IisSiteRoots)) {
        if ($iis -and -not ($roots -contains $iis)) { [void]$roots.Add($iis) }
    }
    foreach ($r in @("C:\Program Files\MySQL", "C:\Program Files\PostgreSQL", "C:\Program Files\MongoDB")) {
        if (Test-Path -LiteralPath $r) { [void]$roots.Add($r) }
    }

    $fixed = @(
        "C:\inetpub\wwwroot\web.config",
        "C:\inetpub\wwwroot\.env",
        "C:\xampp\phpMyAdmin\config.inc.php",
        "C:\xampp\mysql\bin\my.ini",
        "C:\xampp\apache\conf\httpd.conf",
        "C:\xampp\apache\conf\extra\httpd-vhosts.conf",
        "C:\Windows\System32\inetsrv\config\applicationHost.config",
        "$env:USERPROFILE\.my.cnf",
        "$env:USERPROFILE\.pgpass",
        "$env:USERPROFILE\.aws\credentials"
    )

    $found = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $maxList = if ($Mode -eq "full") { 40 } else { 18 }
    $maxPerRoot = if ($Mode -eq "full") { 30 } else { 15 }

    foreach ($f in $fixed) {
        if (-not $f) { continue }
        $key = $f.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        if (-not (Test-Path -LiteralPath $f)) { continue }
        $seen[$key] = $true
        $sens = Test-ConfigLooksSensitive $f
        [void]$found.Add([pscustomobject]@{ Path = $f; Sensitive = $sens })
    }

    # Also include known stack dirs discovered from running services (e.g. D:\phpstudy_pro)
    try {
        $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PathName
        foreach ($sp in $svcs) {
            if ($sp -match '(?i)(phpstudy|xampp|wamp|laragon|inetpub|tomcat|mysql|mariadb|postgres)') {
                $exe = Get-ServiceExePath ([string]$sp)
                if ($exe) {
                    $dir = Split-Path -Parent $exe
                    # walk up a few parents as possible install roots
                    for ($i = 0; $i -lt 4 -and $dir; $i++) {
                        if ($dir -match '(?i)phpstudy|xampp|wamp|laragon|tomcat|mysql|mariadb|postgres|inetpub' -and -not ($roots -contains $dir)) {
                            [void]$roots.Add($dir)
                        }
                        $parent = Split-Path -Parent $dir
                        if (-not $parent -or $parent -eq $dir) { break }
                        $dir = $parent
                    }
                }
            }
        }
    } catch {}

    foreach ($root in $roots) {
        if ($found.Count -ge $maxList) { break }
        try {
            $depth = if ($Mode -eq "full") { 8 } else { 5 }
            $enum = Get-ChildItem -Path $root -File -Recurse -Depth $depth -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Name -match $nameRe -and
                    $_.FullName -notmatch '(?i)\\WinSxS\\|\\node_modules\\|\\Packages\\|\\Temporary ASP.NET'
                } |
                Select-Object -First $maxPerRoot
            foreach ($it in $enum) {
                if ($found.Count -ge $maxList) { break }
                $path = $it.FullName
                $key = $path.ToLowerInvariant()
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true
                $sens = Test-ConfigLooksSensitive $path
                [void]$found.Add([pscustomobject]@{ Path = $path; Sensitive = $sens })
            }
        } catch {}
    }

    if ($found.Count -eq 0) {
        if ($Mode -eq "full") {
            Add-Finding INFO "No common web/DB config paths found in scanned roots" `
                "Checked inetpub/xampp/wamp/site roots/user folders. Manual: dir /s web.config .env" `
                "dir /s /b C:\inetpub\web.config 2>nul" `
                "cfg_none" -Priority 15
        }
        return
    }

    $ordered = @($found | Sort-Object -Property @{e = { -not $_.Sensitive } }, Path)
    $lines = New-Object System.Collections.Generic.List[string]
    $sensCount = 0
    foreach ($h in $ordered) {
        if ($h.Sensitive) {
            $sensCount++
            [void]$lines.Add("[maybe-secret] $($h.Path)")
        } else {
            [void]$lines.Add($h.Path)
        }
    }

    $nl = [Environment]::NewLine
    $listText = ($lines | Select-Object -First $maxList) -join $nl
    $inspect = New-Object System.Collections.Generic.List[string]
    [void]$inspect.Add("# Inspect manually; do NOT paste secrets into exam report.")
    foreach ($h in ($ordered | Select-Object -First 10)) {
        if ($h.Sensitive) {
            [void]$inspect.Add("findstr /ni /i `"password connectionString pwd= Data.Source DATABASE`" `"$($h.Path)`"")
        } else {
            [void]$inspect.Add("type `"$($h.Path)`" | more")
        }
    }
    [void]$inspect.Add("dir /s /b C:\inetpub\web.config 2>nul")

    Add-Finding MED "Web/DB/app config locations ($($found.Count) files)" `
        "Found $($found.Count) interesting config path(s). $sensCount flagged [maybe-secret] via keyword peek only (values not printed)." `
        ($listText + $nl + ($inspect -join $nl)) `
        "cfg_inventory" `
        -Priority 75

    foreach ($h in $ordered) {
        if ($script:CredHits -ge $script:CredHitCap) { break }
        if (-not $h.Sensitive) { continue }
        if (Test-StrongCredContent $h.Path) {
            $script:CredHits++
            $sev = if ($h.Path -match '(?i)web\.config|\.env$|appsettings|wp-config|config\.inc\.php') { "HIGH" } else { "MED" }
            $prio = if ($sev -eq "HIGH") { 93 } else { 70 }
            Add-Finding $sev "Config may contain credentials: $($h.Path)" `
                "Strong keyword/value patterns detected. Review with findstr; do not paste plaintext secrets into reports." `
                "dir `"$($h.Path)`"`nfindstr /ni /i `"password passwd pwd connectionString secret token Data.Source`" `"$($h.Path)`"" `
                "cred:$($h.Path)" `
                -Priority $prio
        }
    }

    if ($Mode -eq "full") {
        [void]$script:Details.Add("Config inventory:`n" + ($lines -join "`n"))
    }
}

function Test-LocalPorts {
    $net = netstat -ano 2>$null | Out-String
    # Loopback DB/admin only. Exclude 445/139 (SMB noise) and general WinRM unless full.
    $interesting = @(3306,5432,6379,27017,1433,8080,8000,5000,9200,8443,11211)
    $hits = @()
    foreach ($port in $interesting) {
        if ($net -match "127\.0\.0\.1:$port\s" -or $net -match "\[::1\]:$port\s") {
            $hits += $port
        }
    }
    if ($hits.Count -gt 0) {
        Add-Finding MED "Interesting localhost listeners: $($hits -join ', ')" `
            "Local DB/admin services often pair with app config credentials." `
            "netstat -ano | findstr LISTENING`nnetstat -ano | findstr 127.0.0.1" `
            "ports"
    }
    if ($Mode -eq "full") {
        if ($net -match "127\.0\.0\.1:5985\s" -or $net -match "127\.0\.0\.1:5986\s") {
            Add-Finding INFO "WinRM listening on localhost" "Expected on many boxes; not a privesc by itself." "netstat -ano | findstr 5985" "ports_winrm"
        }
        [void]$script:Details.Add("netstat LISTENING:`n" + (($net -split "`n" | Select-String LISTENING | Select-Object -First 80) -join "`n"))
    }
}

function Test-EnvHints {
    try {
        $lm = $ExecutionContext.SessionState.LanguageMode
        if ($lm -ne "FullLanguage") {
            Add-Finding MED "PowerShell language mode restricted: $lm" `
                "ConstrainedLanguage may block cmdlets. Prefer built-in cmd commands." `
                "`$ExecutionContext.SessionState.LanguageMode`nwhoami /priv" `
                "langmode"
        }
    } catch {}

    # UAC
    try {
        $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
        if ($uac) {
            $consent = $uac.ConsentPromptBehaviorAdmin
            $enableLua = $uac.EnableLUA
            if ($Mode -eq "full") {
                Add-Finding INFO "UAC policy EnableLUA=$enableLua ConsentPromptBehaviorAdmin=$consent" `
                    "Affects elevation/token filtering; not a vulnerability by itself." `
                    "reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                    "uac"
            }
        }
    } catch {}

    # Domain playbook is emitted in Complete-DomainGuidance (after HIGH count is known).

    # service account profile lite
    if ("$env:USERDOMAIN\$env:USERNAME" -match 'IIS APPPOOL|IUSR') {
        Add-Finding MED "Identity looks like IIS app pool / web user" `
            "Check inetpub, site roots, web.config, connection strings." `
            "whoami`ndir C:\inetpub`ndir C:\inetpub\wwwroot" `
            "prof_iis"
    }
    if ($env:USERNAME -match '(?i)mssql|sqlserver|sqlsvc') {
        Add-Finding MED "Username looks like SQL service account" `
            "Check SQL install dirs, error logs, connection strings." `
            "sc query state= all | findstr /i SQL" `
            "prof_sql"
    }

    if ($Mode -eq "full") {
        $os = systeminfo 2>$null | Select-String -Pattern 'OS Name|OS Version|System Type|Hotfix|Domain' | Out-String
        Add-Finding INFO "OS info snapshot (CVE is last resort)" `
            "Kernel CVE is NOT primary. Only check after standard privesc paths fail." `
            "systeminfo`nwmic qfe get HotFixID,InstalledOn" `
            "sysinfo_cve_note"
        [void]$script:Details.Add("systeminfo snippet:`n$os")
    }
}

function Print-Basic {
    Section "Basic Environment"
    Write-Host "Time: $(Get-Date)"
    Write-Host "Host: $env:COMPUTERNAME"
    Write-Host "User: $env:USERDOMAIN\$env:USERNAME"
    Write-Host "PS LanguageMode: $($ExecutionContext.SessionState.LanguageMode)"
    whoami /user 2>$null
    Write-Host ""
    Write-Host "--- whoami /priv (Enabled only) ---"
    whoami /priv 2>$null | Select-String "Enabled|Privilege Name"
    Write-Host ""
    Write-Host "--- interesting groups / integrity ---"
    whoami /groups 2>$null | Select-String "Administrators|S-1-5-32-544|Mandatory|Label|Backup|Operator|Remote"
}

function Print-FullDetails {
    Section "Full Details"
    foreach ($d in $script:Details) {
        Write-Host $d
        Write-Host ""
    }
    Section "net user / local admins"
    net user 2>$null
    net localgroup administrators 2>$null
    Section "Listening ports"
    netstat -ano 2>$null | Select-String "LISTENING"
    Section "cmdkey"
    cmdkey /list 2>$null
    Section "LIMITS"
    Write-Host "* Enumerate + suggest only; no auto exploit"
    Write-Host "* Service DACL parse is heuristic; confirm with sc sdshow"
    Write-Host "* Write checks use ACL read-only (no temp file)"
    Write-Host "* Kernel CVE is not primary line"
}

# ---------- main ----------
Write-Host "============================================================"
Write-Host " OSCP Privesc Assistant - Windows PowerShell v$Version"
Write-Host " Mode=$Mode  Host=$env:COMPUTERNAME  User=$env:USERDOMAIN\$env:USERNAME"
Write-Host " Enum-only. No auto exploit. Exam-safe design."
Write-Host "============================================================"
Write-Host ""

Invoke-AllChecks
Print-Summary
Print-Basic
if ($Mode -eq "full") { Print-FullDetails }

Section "Result"
Write-Host "HIGH: $High  MED: $Med  INFO: $Info"
if ($script:AlreadySystem) {
    Write-Host "Context: ALREADY SYSTEM - ignore any leftover write/ACL noise; local privesc is done."
    Write-Host "Recommended: proof/loot files, then domain actions if this is a domain machine."
    if ($script:IsEvilWinRM) {
        Write-Host "Evil-WinRM: stage under C:\Users\Public\ then client 'download'; tools via 'upload' + '.\tool.exe'."
    }
} elseif ($script:DomainCtx -and $script:DomainCtx.IsDomain) {
    Write-Host "Context: DOMAIN=$($script:DomainCtx.Dns)  DC=$($script:DomainCtx.IsDC)  User=$($script:DomainCtx.User)"
    if ($High -eq 0) {
        Write-Host "Recommended flow: DOMAIN loot (SYSVOL) -> domain enum -> better creds -> local privesc again."
        Write-Host "Do NOT waste time on weak local noise (RDP group, empty RegBack, WindowsApps PATH)."
    } else {
        Write-Host "Recommended flow: local HIGH first -> then DOMAIN (SYSVOL/lateral)."
    }
    if ($script:IsEvilWinRM) {
        Write-Host "Evil-WinRM: for hive/file loot, copy to C:\Users\Public\ then client download (see HIGH Next)."
    }
} else {
    Write-Host "Flow: verify HIGH then MED; then WinPEAS/Seatbelt; CVE last."
    if ($script:IsEvilWinRM) {
        Write-Host "Evil-WinRM: stage loot under C:\Users\Public\ then client download."
    }
}
Write-Host "No PowerShell? Use opassist-win-cn.bat or windows-cmd-checklist.txt"
if ($Mode -ne "full") { Write-Host "Tip: re-run with -Full for raw dumps." }

if ($transcriptOn) {
    try { Stop-Transcript | Out-Null } catch {}
}
exit 0
