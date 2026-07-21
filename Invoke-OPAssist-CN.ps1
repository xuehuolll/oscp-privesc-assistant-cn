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
$Version = "1.8.9-cn-ps"
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
        "HIGH" { "!!! [高危/HIGH]" }
        "MED"  { ">>> [中危/MED]" }
        default { "--- [信息/INFO]" }
    }
    $color = switch ($f.Severity) {
        "HIGH" { "Red" }
        "MED"  { "Yellow" }
        default { "Cyan" }
    }
    if ($NoColor) { Write-Host "$tag $($f.Title)" }
    else { Write-Host "$tag $($f.Title)" -ForegroundColor $color }
    if ($f.Reason) { Write-Host "    原因/Reason: $($f.Reason)" }
    if ($f.Next) {
        Write-Host "    下一步/Next:"
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
    Section "优先级发现清单 / Priority Findings"
    Write-Host "默认只显示能推进提权的证据 (privesc-only summary)。详情用 -Full。"
    Write-Host "Default: privesc-advancing evidence only. Use -Full for raw dumps."
    Write-Host ""

    if ($script:Findings.Count -eq 0) {
        Write-Host "未发现明确提权重点 / No clear high-value leads."
        Write-Host "建议: whoami /priv, 手工查服务/任务 ACL, 或 WinPEAS/Seatbelt 作第二意见。"
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
            Write-Host "[提示] $left 条中危已折叠，使用 -Full 查看 / $left MED folded; use -Full."
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

# ---------- checks ----------
function Invoke-AllChecks {
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
}

function Test-IdentityAndTokens {
    $who = whoami 2>$null
    $privs = whoami /priv 2>$null
    $groups = whoami /groups 2>$null
    $privText = ($privs | Out-String)
    $grpText = ($groups | Out-String)

    if ($grpText -match 'S-1-5-32-544|Administrators') {
        Add-Finding HIGH "当前用户可能已在本地 Administrators 组" `
            "若令牌有效则接近管理员；远程 shell 仍可能是过滤管理员令牌 (UAC)。" `
            "whoami /groups`nwhoami /priv`nwhoami /all`nnet localgroup administrators`n# 若 Filtered: 需要 UAC bypass 或另找完整高权进程" `
            "admin_group"
    }

    # interesting groups
    $interesting = @{
        "S-1-5-32-551" = "Backup Operators"
        "S-1-5-32-550" = "Print Operators"
        "S-1-5-32-549" = "Server Operators"
        "S-1-5-32-548" = "Account Operators"
        "S-1-5-32-552" = "Replicator"
        "S-1-5-32-578" = "Hyper-V Administrators"
        "S-1-5-32-580" = "Remote Management Users"
        "S-1-5-32-555" = "Remote Desktop Users"
        "S-1-5-32-562" = "Distributed COM Users"
    }
    foreach ($sid in $interesting.Keys) {
        $gname = $interesting[$sid]
        if ($grpText -match [regex]::Escape($sid) -or $grpText -match [regex]::Escape($gname)) {
            $sev = if ($sid -in @("S-1-5-32-551","S-1-5-32-549","S-1-5-32-548","S-1-5-32-578")) { "HIGH" } else { "MED" }
            $gnext = "whoami /groups" + [Environment]::NewLine + "net localgroup `"$gname`""
            Add-Finding $sev "敏感组/Sensitive group: $gname" `
                "该组常有专用提权/横向手法。对照 HackTricks 手工验证。 / Often has dedicated privesc paths." `
                $gnext `
                "group_$sid"
        }
    }

    if ($privText -match 'SeImpersonatePrivilege\s+.*Enabled') {
        Add-Finding HIGH "SeImpersonatePrivilege = Enabled" `
            "高价值令牌权限。OSCP 常见土豆类/PrintSpoofer 等场景，但必须结合系统版本、服务与考试规则手工选择手法，脚本不自动利用。" `
            "whoami /priv`nsysteminfo`ntasklist /v`n# 确认 build + 可用服务后，再手工选兼容工具" `
            "priv_impersonate"
    }
    if ($privText -match 'SeAssignPrimaryTokenPrivilege\s+.*Enabled') {
        Add-Finding HIGH "SeAssignPrimaryTokenPrivilege = Enabled" `
            "与 impersonation 类似的高价值权限。" `
            "whoami /priv`nsysteminfo" `
            "priv_assign"
    }
    if ($privText -match 'SeBackupPrivilege\s+.*Enabled') {
        Add-Finding HIGH "SeBackupPrivilege = Enabled" `
            "可能以备份语义读敏感文件/注册表。reg save 会写盘，仅手工、确认环境后操作。" `
            "whoami /priv`ndir C:\Windows\Repair 2>`$null`ndir C:\Windows\System32\config\RegBack`nicacls C:\Windows\System32\config\SAM" `
            "priv_backup"
    }
    if ($privText -match 'SeRestorePrivilege\s+.*Enabled') {
        Add-Finding HIGH "SeRestorePrivilege = Enabled" `
            "恢复类权限可能写敏感位置；只做授权环境手工验证。" `
            "whoami /priv" `
            "priv_restore"
    }
    if ($privText -match 'SeDebugPrivilege\s+.*Enabled') {
        Add-Finding HIGH "SeDebugPrivilege = Enabled" `
            "可能调试高权限进程/读内存。高价值线索。" `
            "whoami /priv`ntasklist /v" `
            "priv_debug"
    }
    if ($privText -match 'SeTakeOwnershipPrivilege\s+.*Enabled') {
        Add-Finding MED "SeTakeOwnershipPrivilege = Enabled" `
            "特定 ACL 场景有用，通常不是第一路径。" `
            "whoami /priv" `
            "priv_takeown"
    }
    if ($privText -match 'SeLoadDriverPrivilege\s+.*Enabled') {
        Add-Finding MED "SeLoadDriverPrivilege = Enabled" `
            "加载驱动相关；OSCP 中较少作为第一路径。" `
            "whoami /priv" `
            "priv_loaddriver"
    }
    if ($privText -match 'SeManageVolumePrivilege\s+.*Enabled') {
        Add-Finding MED "SeManageVolumePrivilege = Enabled" `
            "卷管理相关，特定手法可能读磁盘。" `
            "whoami /priv" `
            "priv_managevolume"
    }

    [void]$script:Details.Add("whoami:`n$who`n`nprivs:`n$privText`ngroups(admin-related):`n$(($groups | Select-String -Pattern 'Administrators|S-1-5-32|Label|Mandatory'))")
}

function Test-ClassicMisconfigs {
    $hkcu = reg query "HKCU\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>$null
    $hklm = reg query "HKLM\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>$null
    $hkcuOn = ($hkcu | Out-String) -match '0x1'
    $hklmOn = ($hklm | Out-String) -match '0x1'
    if ($hkcuOn -and $hklmOn) {
        Add-Finding HIGH "AlwaysInstallElevated 同时在 HKCU/HKLM 启用" `
            "经典 MSI 本地提权配置错误。利用前确认考试规则；脚本不生成/安装 MSI。" `
            "reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`nreg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated" `
            "aie"
    } elseif ($hkcuOn -or $hklmOn) {
        Add-Finding INFO "AlwaysInstallElevated 仅单边启用 (不足)" `
            "需要 HKCU 与 HKLM 同时为 1 才经典可利用。" `
            "reg query HKCU\...\AlwaysInstallElevated`nreg query HKLM\...\AlwaysInstallElevated" `
            "aie_partial"
    }

    $winlogon = reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>$null
    if (($winlogon | Out-String) -match 'DefaultPassword') {
        Add-Finding HIGH "Winlogon AutoLogon 可能含明文密码" `
            "DefaultPassword/DefaultUserName 常可直接复用。" `
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
            Add-Finding HIGH "发现 Unattend/Sysprep: $p" `
                "历史上常残留本地管理员或域账号密码。" `
                "dir `"$p`"`nfindstr /ni /i `"password administrator username domain`" `"$p`"" `
                "unattend:$p"
        }
    }

    $sam = @(
        "C:\Windows\Repair\SAM","C:\Windows\Repair\SYSTEM","C:\Windows\Repair\SECURITY",
        "C:\Windows\System32\config\RegBack\SAM","C:\Windows\System32\config\RegBack\SYSTEM","C:\Windows\System32\config\RegBack\SECURITY",
        "C:\Windows\System32\config\RegBack\DEFAULT"
    )
    foreach ($p in $sam) {
        if (Test-Path -LiteralPath $p) {
            $readable = $false
            try {
                $fs = [System.IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
                $fs.Close(); $readable = $true
            } catch { $readable = $false }
            if ($readable) {
                Add-Finding HIGH "可读 SAM/SYSTEM 备份: $p" `
                    "当前用户似乎可读。可 copy 到可写目录后离线提取哈希 (手工)。" `
                    "dir `"$p`"`nicacls `"$p`"`n# copy to writable dir then offline parse" `
                    "sam_read:$p"
            } else {
                Add-Finding MED "存在 SAM/SYSTEM 备份路径: $p" `
                    "文件在，但当前可能不可读。若有 SeBackup 等权限可另法读取。" `
                    "dir `"$p`"`nicacls `"$p`"" `
                    "sam_exist:$p"
            }
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
        Add-Finding INFO "无法枚举服务 (WMI/CIM 失败)" "可手工 sc query state= all" "sc query state= all" "svc_enum_fail"
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
            Add-Finding $sev "服务 DACL 可能过弱: $name" `
                "$daclIssue; StartName=$start State=$state。可能允许修改服务配置。请用 sc qc/sdshow 手工确认，勿自动 sc config。" `
                "sc qc $name`nsc sdshow $name`nsc qc $name" `
                "svc_dacl:$name"
        }

        if ($exe -and (Test-Path -LiteralPath $exe)) {
            $dir = Split-Path -Parent $exe
            if (-not $sysPath) {
                if (Test-AclWritable $exe) {
                    $sev = if ($priv) { "HIGH" } else { "MED" }
                    Add-Finding $sev "服务二进制当前用户可写: $exe" `
                        "服务 $name 以 $start 运行 ($state/$mode)。可写二进制是高确定性线索；需能触发重启/启动。" `
                        ("sc qc `"$name`"" + [Environment]::NewLine + "sc sdshow `"$name`"" + [Environment]::NewLine + "icacls `"$exe`"") `
                        "svc_bin:$name"
                } elseif ($dir -and (Test-AclWritable $dir)) {
                    $sev = if ($priv) { "HIGH" } else { "MED" }
                    Add-Finding $sev "服务目录当前用户可写: $dir" `
                        "服务 $name 以 $start 运行。OSCP 常见: 替换二进制/DLL/配置后触发服务。" `
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
                Add-Finding $sev "未加引号服务路径 + 可写中间目录: $name" `
                    "Path=$raw; StartName=$start; WritablePrefix=$prefix。仍需确认服务启动/重启条件。" `
                    "sc qc $name`nicacls `"$prefix`"" `
                    "svc_uq:$name"
            } elseif ($Mode -eq "full" -and -not $sysPath) {
                Add-Finding INFO "未加引号服务路径 (中间目录当前不可写): $name" `
                    "Path=$raw。无写权限通常不可利用。" `
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
                            Add-Finding HIGH "高权限计划任务执行文件可写: $path" `
                                "Task=$tname RunAs=$runAs" `
                                "schtasks /query /tn `"$tname`" /fo LIST /v`nicacls `"$path`"" `
                                "task_file:$tname"
                        } elseif ($dir -and (Test-Path -LiteralPath $dir) -and (Test-AclWritable $dir)) {
                            Add-Finding HIGH "高权限计划任务目录可写: $dir" `
                                "Task=$tname RunAs=$runAs Cmd=$toRun" `
                                "schtasks /query /tn `"$tname`" /fo LIST /v`nicacls `"$dir`"" `
                                "task_dir:$tname"
                        } elseif ($path -match '(?i)\\Users\\|\\Temp\\|\\ProgramData\\|\\inetpub\\|\\xampp\\') {
                            Add-Finding MED "高权限计划任务指向非标准路径: $path" `
                                "Task=$tname RunAs=$runAs" `
                                "schtasks /query /tn `"$tname`" /fo LIST /v" `
                                "task_ns:$tname"
                        }
                    } elseif ($toRun -match '(?i)powershell|cmd\.exe|wscript|cscript|\.bat|\.cmd|\.ps1|\.vbs') {
                        Add-Finding MED "高权限计划任务执行脚本/解释器: $tname" `
                            "RunAs=$runAs Cmd=$toRun。请手工提取脚本路径与 ACL。" `
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
                        Add-Finding HIGH "计划任务定义文件可写: $taskFile" `
                            "Task=$fullName RunAs=$runAs。可写任务 XML 是高价值线索。" `
                            "schtasks /query /tn `"$($t.TaskName)`" /fo LIST /v`nicacls `"$taskFile`"" `
                            "task_xml:$fullName"
                    }
                }

                $path = Get-ExecutableFromCommand $cmd
                if (-not $path) { $path = $exec.Trim('"') }
                if ($path -and (Test-Path -LiteralPath $path)) {
                    $dir = Split-Path -Parent $path
                    if (Test-AclWritable $path) {
                        Add-Finding HIGH "高权限计划任务执行文件可写: $path" `
                            "Task=$fullName RunAs=$runAs" `
                            "Get-ScheduledTask -TaskName '$($t.TaskName)' | fl *`nicacls `"$path`"" `
                            "task_bin:$fullName"
                    } elseif ($dir -and (Test-AclWritable $dir)) {
                        Add-Finding HIGH "高权限计划任务目录可写: $dir" `
                            "Task=$fullName RunAs=$runAs Cmd=$cmd" `
                            "icacls `"$dir`"`ndir `"$dir`"" `
                            "task_dir2:$fullName"
                    }
                } elseif ($path -match '(?i)\\Users\\|\\Temp\\|\\ProgramData\\|\\inetpub\\') {
                    Add-Finding MED "高权限计划任务非标准路径: $path" `
                        "Task=$fullName RunAs=$runAs" `
                        "schtasks /query /tn `"$($t.TaskName)`" /fo LIST /v" `
                        "task_ns2:$fullName"
                } elseif ($cmd -match '(?i)powershell|cmd\.exe|wscript|cscript|\.ps1|\.bat') {
                    Add-Finding MED "高权限计划任务脚本/解释器: $fullName" `
                        "RunAs=$runAs Cmd=$cmd" `
                        "schtasks /query /tn `"$($t.TaskName)`" /fo LIST /v" `
                        "task_sc2:$fullName"
                }
            }
        } catch {}
    }
}

function Test-PathAndAutorun {
    # PATH hijack
    $pathWritten = 0
    foreach ($d in ($env:Path -split ';' | Where-Object { $_ })) {
        if ($d -match '^\\\\') { continue } # UNC skip
        if (-not (Test-Path -LiteralPath $d)) { continue }
        if (Test-AclWritable $d) {
            $pathWritten++
            if ($pathWritten -le 4) {
                Add-Finding MED "PATH 目录当前用户可写: $d" `
                    "仅当高权限程序以相对命令名启动并继承该 PATH 时才有用。优先对照服务/任务。" `
                    "echo `$env:Path`nicacls `"$d`"" `
                    "path:$d"
            }
        }
    }
    if ($pathWritten -gt 4) {
        Add-Finding INFO "更多可写 PATH 目录" "约 $pathWritten 个；summary 只显示前 4。" "echo `$env:Path" "path_more"
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
                Add-Finding $sev "Run 键指向用户/临时类路径: $root\$($p.Name)" `
                    "Value=$val。检查目标 ACL 是否可写。" `
                    "reg query $($root -replace ':','')`nicacls (extract path from value)" `
                    "run:$root`:$($p.Name)"
            }
            $exe = Get-ExecutableFromCommand $val
            if ($exe -and (Test-Path -LiteralPath $exe)) {
                $dir = Split-Path -Parent $exe
                if ((Test-AclWritable $exe) -or ($dir -and (Test-AclWritable $dir))) {
                    $sev = if ($root -match 'HKLM') { "HIGH" } else { "MED" }
                    Add-Finding $sev "Run 键目标可写: $exe" `
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
            Add-Finding $sev "Startup 目录可写: $s" `
                "可写启动目录可能影响登录启动项。" `
                "dir /a `"$s`"`nicacls `"$s`"" `
                "startup:$s"
        } elseif ($items) {
            Add-Finding INFO "Startup 目录非空: $s" "检查内容与 ACL。" "dir /a `"$s`"" "startup_info:$s"
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
                Add-Finding MED "发现本地 GPO 脚本目录: $g" `
                    "检查 scripts/scripts.ini 与脚本 ACL；域 GPO 也可能在 SYSVOL (需域可读)。" `
                    "dir /s `"$g`"`n# also: dir \\$env:USERDNSDOMAIN\SYSVOL 2>nul" `
                    "gpo:$g"
            }
        }
    }
    if ($env:USERDNSDOMAIN) {
        $sysvol = "\\$($env:USERDNSDOMAIN)\SYSVOL"
        if (Test-Path $sysvol) {
            Add-Finding MED "SYSVOL 可读: $sysvol" `
                "域脚本/GPO 可能含凭据或可写脚本路径。请手工枚举，注意噪音与时间。" `
                "dir `"$sysvol`"`n# look for scripts, Registry.xml, Groups.xml (GPP)" `
                "sysvol"
            # GPP cpassword classic (often patched but still check)
            try {
                $gpp = Get-ChildItem -Path $sysvol -Recurse -Include "Groups.xml","Services.xml","Scheduledtasks.xml","DataSources.xml","Drives.xml" -ErrorAction SilentlyContinue | Select-Object -First 15
                foreach ($f in $gpp) {
                    $raw = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
                    if ($raw -match 'cpassword=') {
                        Add-Finding HIGH "GPP 可能含 cpassword: $($f.FullName)" `
                            "历史 GPP 凭据。可手工解密；脚本不自动解密利用。" `
                            "type `"$($f.FullName)`"`n# find cpassword= ..." `
                            "gpp:$($f.FullName)"
                    }
                }
            } catch {}
        }
    }
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
            Add-Finding HIGH "PowerShell 历史含凭据/登录线索" `
                "File=$h 命中: $($hit.Line.Trim())" `
                "type `"$h`"`nfindstr /ni /i `"password passwd pwd credential cmdkey runas`" `"$h`"" `
                "pshist:$h"
        }
    }

    # cmdkey
    $ck = cmdkey /list 2>$null | Out-String
    if ($ck -match 'Target:') {
        Add-Finding MED "存在 Windows 保存凭据 (cmdkey)" `
            "是否可用取决于目标类型与上下文。不要自动 runas。" `
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
            Add-Finding MED "客户端凭据配置: $f" `
                "可能含主机/用户/保存密码。" `
                "dir `"$f`"`nfindstr /ni /i `"password pass user host key`" `"$f`"" `
                "client:$f"
        }
    }

    if (Test-Path "HKCU:\Software\SimonTatham\PuTTY\Sessions") {
        Add-Finding MED "发现 PuTTY Sessions" `
            "HostName/UserName/PublicKeyFile 常有横向价值。" `
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
                Add-Finding $sev "配置疑似真实凭据赋值: $($c.FullName)" `
                    "命中 password=/connectionString/token 等强特征。报告勿粘贴明文。" `
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
            Add-Finding MED "发现 VNC 相关注册表: $v" `
                "可能含 Password 等字段。" `
                "reg query $($v -replace ':','') /s" `
                "vnc:$v"
        }
    }
}

function Test-LocalPorts {
    $net = netstat -ano 2>$null | Out-String
    $interesting = @(3306,5432,6379,27017,1433,8080,8000,5000,9200,5985,5986,445,139)
    $hits = @()
    foreach ($port in $interesting) {
        if ($net -match "127\.0\.0\.1:$port\s" -or $net -match "\[::1\]:$port\s") {
            $hits += $port
        }
    }
    if ($hits.Count -gt 0) {
        Add-Finding MED "本机回环高价值端口: $($hits -join ', ')" `
            "本地 DB/WinRM/管理服务常见路径: 配置找账密 → 本地连接/复用。" `
            "netstat -ano | findstr LISTENING`nnetstat -ano | findstr 127.0.0.1" `
            "ports"
    }
    if ($Mode -eq "full") {
        [void]$script:Details.Add("netstat LISTENING:`n" + (($net -split "`n" | Select-String LISTENING | Select-Object -First 80) -join "`n"))
    }
}

function Test-EnvHints {
    try {
        $lm = $ExecutionContext.SessionState.LanguageMode
        if ($lm -ne "FullLanguage") {
            Add-Finding MED "PowerShell 语言模式受限: $lm" `
                "ConstrainedLanguage 等可能限制脚本/cmdlet。优先用 cmd 内置命令验证。" `
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
                Add-Finding INFO "UAC 策略 EnableLUA=$enableLua ConsentPromptBehaviorAdmin=$consent" `
                    "影响提权后令牌与提权体验；不是直接漏洞。" `
                    "reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                    "uac"
            }
        }
    } catch {}

    if ($env:USERDOMAIN -and $env:COMPUTERNAME -and ($env:USERDOMAIN -ne $env:COMPUTERNAME)) {
        Add-Finding INFO "可能处于域环境: $env:USERDOMAIN" `
            "提权后关注横向；本脚本不做大规模 AD 攻击枚举。" `
            "whoami /fqdn`nnet user /domain`nnet group `"Domain Admins`" /domain" `
            "domain"
    }

    # service account profile lite
    if ("$env:USERDOMAIN\$env:USERNAME" -match 'IIS APPPOOL|IUSR') {
        Add-Finding MED "当前身份疑似 IIS 应用池/Web 用户" `
            "优先 inetpub、站点物理路径、web.config、连接串。" `
            "whoami`ndir C:\inetpub`ndir C:\inetpub\wwwroot" `
            "prof_iis"
    }
    if ($env:USERNAME -match '(?i)mssql|sqlserver|sqlsvc') {
        Add-Finding MED "用户名疑似 SQL 服务账号" `
            "优先 SQL 安装目录、错误日志、连接串。" `
            "sc query state= all | findstr /i SQL" `
            "prof_sql"
    }

    if ($Mode -eq "full") {
        $os = systeminfo 2>$null | Select-String -Pattern 'OS Name|OS Version|System Type|Hotfix|Domain' | Out-String
        Add-Finding INFO "系统信息摘要 (CVE 仅后备)" `
            "发行版补丁情况复杂，内核 CVE 不作为主线。无常规路径时再人工核对。" `
            "systeminfo`nwmic qfe get HotFixID,InstalledOn" `
            "sysinfo_cve_note"
        [void]$script:Details.Add("systeminfo snippet:`n$os")
    }
}

function Print-Basic {
    Section "基础环境 / Basic"
    Write-Host "Time: $(Get-Date)"
    Write-Host "Host: $env:COMPUTERNAME"
    Write-Host "User: $env:USERDOMAIN\$env:USERNAME"
    Write-Host "PS LanguageMode: $($ExecutionContext.SessionState.LanguageMode)"
    whoami /user 2>$null
    Write-Host ""
    Write-Host "--- whoami /priv (Enabled only) ---"
    whoami /priv 2>$null | Select-String "Enabled|Privilege Name"
    Write-Host ""
    Write-Host "--- admin-related groups ---"
    whoami /groups 2>$null | Select-String "Administrators|S-1-5-32-544|Mandatory|Label|Backup|Operator"
}

function Print-FullDetails {
    Section "详细枚举 -Full / Details"
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
    Section "LIMITS / 合规"
    Write-Host "* 只枚举/提示，不自动利用"
    Write-Host "* 服务 DACL 解析为启发式 SDDL 匹配，需手工 sc sdshow 确认"
    Write-Host "* 写权限基于 ACL 只读判断 (不创建临时文件)"
    Write-Host "* 内核 CVE 不作为主线"
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

Section "结果汇总 / Result"
Write-Host "HIGH: $High  MED: $Med  INFO: $Info"
Write-Host "流程: 先验证 HIGH → MED；无结果再 WinPEAS/Seatbelt/SharpUp；CVE 最后。"
Write-Host "Flow: verify HIGH then MED; then WinPEAS as 2nd opinion; CVE last."
Write-Host "无 PowerShell 时用: opassist-win-cn.bat 或 windows-cmd-checklist.txt"
if ($Mode -ne "full") { Write-Host "Tip: re-run with -Full for raw dumps." }

if ($transcriptOn) {
    try { Stop-Transcript | Out-Null } catch {}
}
exit 0
