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
$Version = "1.9.1-en-ps"
# English-first output: reliable under Evil-WinRM / EN-US consoles (Chinese often shows as ???).
$script:DomainCtx = $null
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
        [string]$Key = ""
    )
    if (-not $Key) { $Key = "$Severity`:$Title" }
    if ($script:FindingKeys.ContainsKey($Key)) { return }
    $script:FindingKeys[$Key] = $true
    [void]$script:Findings.Add([pscustomobject]@{
        Severity = $Severity
        Title    = $Title
        Reason   = $Reason
        Next     = $Next
    })
    switch ($Severity) {
        "HIGH" { $script:High++ }
        "MED"  { $script:Med++ }
        default { $script:Info++ }
    }
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
        foreach ($f in $script:Findings) {
            if ($f.Severity -ne $sev) { continue }
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
        foreach ($f in $script:Findings) {
            if ($f.Severity -ne "INFO") { continue }
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
        }
    } catch {
        try {
            $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
            if ($cs.PartOfDomain) { $ctx.IsDomain = $true; if ($cs.Domain) { $ctx.Dns = $cs.Domain } }
            if ($null -ne $cs.DomainRole -and [int]$cs.DomainRole -ge 4) { $ctx.IsDC = $true; $ctx.IsDomain = $true }
        } catch {}
    }
    if (-not $ctx.Dns -and $ctx.IsDomain -and $ctx.NetBios) { $ctx.Dns = $ctx.NetBios }
    if ($env:LOGONSERVER) { $ctx.LogonServer = $env:LOGONSERVER.TrimStart('\') }
    return $ctx
}

function Complete-DomainGuidance {
    # Call AFTER all local checks so we know HIGH count.
    $ctx = $script:DomainCtx
    if (-not $ctx -or -not $ctx.IsDomain) { return }

    $dns = if ($ctx.Dns) { $ctx.Dns } else { $ctx.NetBios }
    $sysvol = "\\$dns\SYSVOL"
    $netlogon = "\\$dns\NETLOGON"

    if ($ctx.IsDC) {
        Add-Finding MED "Host appears to be a Domain Controller ($($ctx.Computer))" `
            "You are on a DC as $($ctx.User). Local misconfig privesc is often sparse for domain users. Prefer AD/domain paths (creds in SYSVOL, ACLs, kerberos, delegation) over hunting random local services." `
            "whoami /all`nnltest /dsgetdc:$dns`n# You are already on DC - protect OPSEC; enum domain objects carefully" `
            "domain_is_dc"
    } else {
        Add-Finding MED "Domain-joined host: $dns (user $($ctx.User))" `
            "Machine is domain-joined. After local HIGH/MED, pivot to domain enum if local path is empty." `
            "echo %USERDOMAIN% %USERDNSDOMAIN%`nnltest /dsgetdc:$dns`nnet time /domain" `
            "domain_joined"
    }

    # SYSVOL / NETLOGON reachability (always try when domain)
    $sysvolOk = $false
    $netlogonOk = $false
    try { if (Test-Path -LiteralPath $sysvol) { $sysvolOk = $true } } catch {}
    try { if (Test-Path -LiteralPath $netlogon) { $netlogonOk = $true } } catch {}

    if ($sysvolOk) {
        Add-Finding MED "SYSVOL reachable: $sysvol  <-- prioritize domain file loot" `
            "Best first domain step on many OSCP boxes: hunt GPO/scripts for passwords (Groups.xml cpassword, scripts, old configs). Do not full-recurse blindly if slow." `
            "dir `"$sysvol`"`ndir `"$sysvol\$dns`"`ndir `"$sysvol\$dns\Policies`"`ndir `"$sysvol\$dns\scripts`"`ndir `"$netlogon`"`n# GPP (if present):`nfindstr /s /i /m cpassword `"$sysvol\*.xml`" 2>nul`nfindstr /s /i /m password `"$sysvol\*.xml`" `"$sysvol\*.ini`" `"$sysvol\*.bat`" `"$sysvol\*.ps1`" `"$sysvol\*.vbs`" 2>nul | more" `
            "domain_sysvol"
        # light GPP probe (already may have run in Test-PathAndAutorun; keep key if found)
        try {
            $gppHits = Get-ChildItem -Path $sysvol -Recurse -Include "Groups.xml","Services.xml","Scheduledtasks.xml","DataSources.xml","Drives.xml" -ErrorAction SilentlyContinue | Select-Object -First 20
            foreach ($f in $gppHits) {
                $raw = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
                if ($raw -match 'cpassword=') {
                    Add-Finding HIGH "GPP cpassword in SYSVOL: $($f.FullName)" `
                        "Legacy Group Policy Preferences password. Decrypt offline (e.g. gpp-decrypt); script does not decrypt." `
                        "type `"$($f.FullName)`"" `
                        "gpp_sysvol:$($f.FullName)"
                }
            }
        } catch {}
    } elseif ($ctx.IsDomain) {
        Add-Finding INFO "SYSVOL not reachable from here: $sysvol" `
            "Try from another host or check DNS/name: \\$($ctx.NetBios)\SYSVOL" `
            "dir `"$sysvol`"`ndir `"\\$($ctx.NetBios)\SYSVOL`"" `
            "domain_sysvol_miss"
    }

    if ($netlogonOk -and -not $sysvolOk) {
        Add-Finding MED "NETLOGON reachable: $netlogon" `
            "Logon scripts sometimes contain credentials or share paths." `
            "dir `"$netlogon`"`ntype `"$netlogon\*.bat`" 2>nul`ntype `"$netlogon\*.cmd`" 2>nul`ntype `"$netlogon\*.vbs`" 2>nul" `
            "domain_netlogon"
    }

    # No local HIGH => explicit "switch to domain" playbook (this is what confused users)
    if ($script:High -eq 0) {
        $nl = [Environment]::NewLine
        $play = @(
            "# === DOMAIN PLAYBOOK (no local HIGH found) ===",
            "# 1) Loot SYSVOL / NETLOGON for passwords and scripts",
            "dir `"$sysvol`"",
            "dir `"$netlogon`"",
            "findstr /s /i /m cpassword `"$sysvol\*.xml`" 2>nul",
            "findstr /s /i password `"$sysvol\*.xml`" `"$sysvol\*.bat`" `"$sysvol\*.ps1`" `"$netlogon\*.*`" 2>nul | more",
            "# 2) Who am I in the domain?",
            "whoami /all",
            "net user $env:USERNAME /domain",
            "net group /domain",
            "net group `"Domain Admins`" /domain",
            "nltest /dclist:$dns",
            "nltest /dsgetdc:$dns",
            "# 3) From attack host (only tools allowed in exam): BloodHound path to DA, kerberoast if in scope",
            "# 4) If SeMachineAccountPrivilege enabled: review MachineAccountQuota / machine-account paths (manual)",
            "# 5) After better domain creds, re-run local enum on new host/user"
        ) -join $nl
        Add-Finding MED "NO local HIGH leads -> switch to DOMAIN enum now" `
            "Local privesc has no high-confidence items. On domain boxes (esp. DCs) this is normal for a low-priv domain user. Stop grinding weak local noise; follow domain playbook (SYSVOL, users/groups, kerberos, ACLs)." `
            $play `
            "domain_playbook_no_local_high"
    } else {
        Add-Finding INFO "Domain context active; still verify local HIGH first" `
            "You have local HIGH findings AND domain membership. Finish local HIGH, then domain loot/lateral." `
            "whoami /all`ndir `"$sysvol`"" `
            "domain_after_local_high"
    }
}

# ---------- checks ----------
function Invoke-AllChecks {
    $script:DomainCtx = Get-DomainContext
    if ($script:DomainCtx.IsDomain) {
        Write-Host "[*] Domain detected: DNS=$($script:DomainCtx.Dns) NetBIOS=$($script:DomainCtx.NetBios) DC=$($script:DomainCtx.IsDC)"
    }

    Write-Host "[*] identity / groups / tokens ..."
    Test-IdentityAndTokens
    Write-Host "[*] AlwaysInstallElevated / Autologon / Unattend / SAM ..."
    Test-ClassicMisconfigs
    Write-Host "[*] services (write / unquoted / weak DACL) ..."
    Test-Services
    Write-Host "[*] scheduled tasks ..."
    Test-ScheduledTasks
    Write-Host "[*] PATH / autorun / startup / GPO ..."
    Test-PathAndAutorun
    Write-Host "[*] credentials & local services ..."
    Test-Credentials
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

    if ($grpText -match 'S-1-5-32-544|Administrators') {
        Add-Finding HIGH "User may be in local Administrators" `
            "If token is full admin, you may already have admin rights. Remote shells are often UAC-filtered." `
            "whoami /groups`nwhoami /priv`nwhoami /all`nnet localgroup administrators`n# If filtered admin: need another path or UAC bypass (manual)" `
            "admin_group"
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
        Add-Finding MED "SeMachineAccountPrivilege = Enabled" `
            "Can add machine accounts to the domain (ms-DS-MachineAccountQuota). Relevant for some AD attack chains (e.g. machine account / RBCD style paths). Manual only; confirm domain policy." `
            "whoami /priv`nnet user /domain`n# Check MachineAccountQuota / domain attack notes for current exam rules" `
            "priv_machineaccount"
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

    $unattend = @(
        "C:\Windows\Panther\Unattend.xml",
        "C:\Windows\Panther\Unattended.xml",
        "C:\Windows\System32\Sysprep\Unattend.xml",
        "C:\Windows\System32\Sysprep\Panther\Unattend.xml",
        "C:\Windows\System32\Sysprep\sysprep.xml",
        "C:\sysprep\sysprep.xml",
        "C:\sysprep\Unattend.xml",
        "C:\Windows\Panther\unattend\unattend.xml"
    )
    foreach ($p in $unattend) {
        if (Test-Path -LiteralPath $p) {
            Add-Finding HIGH "Unattend/Sysprep found: $p" `
                "Historically often contains local admin or domain passwords." `
                "dir `"$p`"`nfindstr /ni /i `"password administrator username domain`" `"$p`"" `
                "unattend:$p"
        }
    }

    # Only report SAM/SYSTEM backups that are REALLY readable and non-empty.
    # Mere existence of RegBack stubs is extremely common and not a lead.
    $sam = @(
        "C:\Windows\Repair\SAM","C:\Windows\Repair\SYSTEM","C:\Windows\Repair\SECURITY",
        "C:\Windows\System32\config\RegBack\SAM","C:\Windows\System32\config\RegBack\SYSTEM","C:\Windows\System32\config\RegBack\SECURITY"
    )
    foreach ($p in $sam) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $len = 0
        try { $len = (Get-Item -LiteralPath $p -ErrorAction Stop).Length } catch { $len = 0 }
        if ($len -lt 16) {
            if ($Mode -eq "full") {
                Add-Finding INFO "SAM/SYSTEM path exists but empty/tiny: $p" "Common RegBack stub; not useful alone." "dir `"$p`"" "sam_empty:$p"
            }
            continue
        }
        $readable = $false
        try {
            $fs = [System.IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
            $fs.Close(); $readable = $true
        } catch { $readable = $false }
        if ($readable) {
            Add-Finding HIGH "Readable SAM/SYSTEM backup: $p (size=$len)" `
                "Looks readable. Copy offline and extract hashes manually." `
                "dir `"$p`"`nicacls `"$p`"`n# copy to writable dir then offline parse" `
                "sam_read:$p"
        } elseif ($Mode -eq "full") {
            Add-Finding INFO "SAM/SYSTEM backup present but not readable: $p" `
                "Only interesting with SeBackup or other read path." `
                "dir `"$p`"`nicacls `"$p`"" `
                "sam_exist:$p"
        }
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

        # weak DACL
        $daclIssue = Test-ServiceDaclWeak $name
        if ($daclIssue) {
            $sev = if ($priv) { "HIGH" } else { "MED" }
            Add-Finding $sev "Weak service DACL: $name" `
                "$daclIssue; StartName=$start State=$state. May allow service config change. Confirm with sc qc/sdshow; do NOT auto sc config." `
                "sc qc $name`nsc sdshow $name`nsc qc $name" `
                "svc_dacl:$name"
        }

        if ($exe -and (Test-Path -LiteralPath $exe)) {
            $dir = Split-Path -Parent $exe
            if (-not $sysPath) {
                if (Test-AclWritable $exe) {
                    $sev = if ($priv) { "HIGH" } else { "MED" }
                    Add-Finding $sev "Writable service binary: $exe" `
                        "Service $name runs as $start ($state/$mode). Writable binary is high-confidence; need restart/start trigger." `
                        ("sc qc `"$name`"" + [Environment]::NewLine + "sc sdshow `"$name`"" + [Environment]::NewLine + "icacls `"$exe`"") `
                        "svc_bin:$name"
                } elseif ($dir -and (Test-AclWritable $dir)) {
                    $sev = if ($priv) { "HIGH" } else { "MED" }
                    Add-Finding $sev "Writable service directory: $dir" `
                        "Service $name runs as $start. Common path: replace bin/DLL/config then trigger service." `
                        ("sc qc `"$name`"" + [Environment]::NewLine + "sc sdshow `"$name`"" + [Environment]::NewLine + "icacls `"$dir`"") `
                        "svc_dir:$name"
                }
            }
        }

        # unquoted: only if writable prefix
        if (Test-UnquotedServicePath $raw) {
            $exe2 = Get-ServiceExePath $raw
            $prefix = Get-UnquotedWritablePrefix $exe2
            if ($prefix) {
                $sev = if ($priv) { "HIGH" } else { "MED" }
                Add-Finding $sev "Unquoted service path + writable prefix: $name" `
                    "Path=$raw; StartName=$start; WritablePrefix=$prefix. Confirm start/restart conditions." `
                    "sc qc $name`nicacls `"$prefix`"" `
                    "svc_uq:$name"
            } elseif ($Mode -eq "full" -and -not $sysPath) {
                Add-Finding INFO "Unquoted path (prefix not writable): $name" `
                    "Path=$raw. Not useful without write on a prefix." `
                    "sc qc $name" `
                    "svc_uq_info:$name"
            }
        }
    }
    if ($Mode -eq "full") {
        [void]$script:Details.Add("Services:`n" + ($svcLines -join "`n"))
    }
}

function Test-ScheduledTasks {
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
                    $runAs = $t.'Run As User'
                    $toRun = $t.'Task To Run'
                    $tname = $t.TaskName
                    if (-not $toRun) { continue }
                    if ($toRun -match 'N/A|COM handler') { continue }
                    $isPriv = $runAs -match '(?i)SYSTEM|Administrator|LOCAL SERVICE|NETWORK SERVICE|LocalSystem|NT AUTHORITY'
                    if (-not $isPriv) { continue }
                    $path = Get-ExecutableFromCommand $toRun
                    if ($path) {
                        $dir = Split-Path -Parent $path
                        if ((Test-Path -LiteralPath $path) -and (Test-AclWritable $path)) {
                            Add-Finding HIGH "Writable privileged scheduled-task binary: $path" `
                                "Task=$tname RunAs=$runAs" `
                                "schtasks /query /tn `"$tname`" /fo LIST /v`nicacls `"$path`"" `
                                "task_file:$tname"
                        } elseif ($dir -and (Test-Path -LiteralPath $dir) -and (Test-AclWritable $dir)) {
                            Add-Finding HIGH "Writable privileged scheduled-task directory: $dir" `
                                "Task=$tname RunAs=$runAs Cmd=$toRun" `
                                "schtasks /query /tn `"$tname`" /fo LIST /v`nicacls `"$dir`"" `
                                "task_dir:$tname"
                        } elseif ($path -match '(?i)\\Users\\|\\Temp\\|\\ProgramData\\|\\inetpub\\|\\xampp\\') {
                            Add-Finding MED "Privileged task points to non-standard path: $path" `
                                "Task=$tname RunAs=$runAs" `
                                "schtasks /query /tn `"$tname`" /fo LIST /v" `
                                "task_ns:$tname"
                        }
                    } elseif ($toRun -match '(?i)powershell|cmd\.exe|wscript|cscript|\.bat|\.cmd|\.ps1|\.vbs') {
                        Add-Finding MED "Privileged task runs script/interpreter: $tname" `
                            "RunAs=$runAs Cmd=$toRun. Extract script path and check ACL manually." `
                            "schtasks /query /tn `"$tname`" /fo LIST /v" `
                            "task_script:$tname"
                    }
                }
            }
        } catch {}
        return
    }

    foreach ($t in $tasks) {
        try {
            $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
            $prin = $t.Principal
            $runAs = $prin.UserId
            if (-not $runAs) { $runAs = $prin.GroupId }
            $isPriv = $runAs -match '(?i)SYSTEM|Administrator|LOCAL SERVICE|NETWORK SERVICE|LocalSystem|NT AUTHORITY|S-1-5-18|S-1-5-19|S-1-5-20'
            if (-not $isPriv) {
                # also treat RunLevel Highest + InteractiveToken carefully as MED later; skip most
                if ($prin.RunLevel -ne "Highest") { continue }
            }
            $actions = $t.Actions
            foreach ($a in $actions) {
                $exec = $a.Execute
                $args = $a.Arguments
                $cmd = ("$exec $args").Trim()
                $fullName = Join-Path $t.TaskPath $t.TaskName
                if (-not $exec) { continue }

                # task definition writable?
                $taskFile = "C:\Windows\System32\Tasks" + ($t.TaskPath -replace '/','\') + $t.TaskName
                $taskFile = $taskFile -replace '\\+','\'
                if (Test-Path -LiteralPath $taskFile -PathType Leaf) {
                    if (Test-AclWritable $taskFile) {
                        Add-Finding HIGH "Writable scheduled task definition: $taskFile" `
                            "Task=$fullName RunAs=$runAs. Writable task XML is high-value." `
                            "schtasks /query /tn `"$($t.TaskName)`" /fo LIST /v`nicacls `"$taskFile`"" `
                            "task_xml:$fullName"
                    }
                }

                $path = Get-ExecutableFromCommand $cmd
                if (-not $path) { $path = $exec.Trim('"') }
                if ($path -and (Test-Path -LiteralPath $path)) {
                    $dir = Split-Path -Parent $path
                    if (Test-AclWritable $path) {
                        Add-Finding HIGH "Writable privileged scheduled-task binary: $path" `
                            "Task=$fullName RunAs=$runAs" `
                            "Get-ScheduledTask -TaskName '$($t.TaskName)' | fl *`nicacls `"$path`"" `
                            "task_bin:$fullName"
                    } elseif ($dir -and (Test-AclWritable $dir)) {
                        Add-Finding HIGH "Writable privileged scheduled-task directory: $dir" `
                            "Task=$fullName RunAs=$runAs Cmd=$cmd" `
                            "icacls `"$dir`"`ndir `"$dir`"" `
                            "task_dir2:$fullName"
                    }
                } elseif ($path -match '(?i)\\Users\\|\\Temp\\|\\ProgramData\\|\\inetpub\\') {
                    Add-Finding MED "Privileged task non-standard path: $path" `
                        "Task=$fullName RunAs=$runAs" `
                        "schtasks /query /tn `"$($t.TaskName)`" /fo LIST /v" `
                        "task_ns2:$fullName"
                } elseif ($cmd -match '(?i)powershell|cmd\.exe|wscript|cscript|\.ps1|\.bat') {
                    Add-Finding MED "Privileged task script/interpreter: $fullName" `
                        "RunAs=$runAs Cmd=$cmd" `
                        "schtasks /query /tn `"$($t.TaskName)`" /fo LIST /v" `
                        "task_sc2:$fullName"
                }
            }
        } catch {}
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
        if (Test-AclWritable $s) {
            $sev = if ($s -match 'ProgramData') { "HIGH" } else { "MED" }
            Add-Finding $sev "Writable Startup folder: $s" `
                "Writable startup may affect logon items." `
                "dir /a `"$s`"`nicacls `"$s`"" `
                "startup:$s"
        } elseif ($items) {
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

    # IIS / web configs
    $roots = @("C:\inetpub", "C:\xampp", "C:\wamp64", "C:\wamp", "C:\ProgramData")
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $configs = @()
        try {
            $configs = Get-ChildItem -Path $root -Include "web.config","*.config","appsettings.json",".env","config.inc.php" -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch '\\WinSxS\\|\\Windows\\Microsoft|\\node_modules\\|\\Packages\\' } |
                Select-Object -First $(if ($Mode -eq "full") { 80 } else { 30 })
        } catch {}
        foreach ($c in $configs) {
            if ($script:CredHits -ge $script:CredHitCap) { break }
            if (Test-StrongCredContent $c.FullName) {
                $script:CredHits++
                $sev = if ($c.Name -match 'web\.config|\.env|appsettings') { "HIGH" } else { "MED" }
                Add-Finding $sev "Config looks like real credential assignment: $($c.FullName)" `
                    "Hit password=/connectionString/token-like values. Do not paste secrets into reports." `
                    "dir `"$($c.FullName)`"`nfindstr /ni /i `"password passwd pwd connectionString secret token`" `"$($c.FullName)`"" `
                    "cred:$($c.FullName)"
            }
        }
    }

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
                "vnc:$v"
        }
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
if ($script:DomainCtx -and $script:DomainCtx.IsDomain) {
    Write-Host "Context: DOMAIN=$($script:DomainCtx.Dns)  DC=$($script:DomainCtx.IsDC)  User=$($script:DomainCtx.User)"
    if ($High -eq 0) {
        Write-Host "Recommended flow: DOMAIN loot (SYSVOL) -> domain enum -> better creds -> local privesc again."
        Write-Host "Do NOT waste time on weak local noise (RDP group, empty RegBack, WindowsApps PATH)."
    } else {
        Write-Host "Recommended flow: local HIGH first -> then DOMAIN (SYSVOL/lateral)."
    }
} else {
    Write-Host "Flow: verify HIGH then MED; then WinPEAS/Seatbelt; CVE last."
}
Write-Host "No PowerShell? Use opassist-win-cn.bat or windows-cmd-checklist.txt"
if ($Mode -ne "full") { Write-Host "Tip: re-run with -Full for raw dumps." }

if ($transcriptOn) {
    try { Stop-Transcript | Out-Null } catch {}
}
exit 0
