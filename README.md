# OSCP Privesc Assistant (CN)

Local privilege-escalation **enumeration + hints** helper for **Linux / Windows**.

本地提权枚举 + 提示助手（Linux / Windows）。

- Collect evidence, rank priority, suggest **manual** next commands  
  只收集证据、标优先级、给下一步手工验证命令
- **No** auto exploit / service-task-registry persistence / payload upload / brute force  
  **不**自动利用、**不**改服务/计划任务/注册表持久化、**不**上传 payload、**不**爆破
- For OSCP / PG / authorized labs only  
  仅用于 OSCP / PG / 授权实验环境

> Use only on systems you are allowed to test.  
> 仅用于你有权测试的系统，滥用后果自负。

---

## Files / 文件

`	ext
.
├── README.md
├── LICENSE
├── .gitignore
├── opassist-linux-cn.sh          # Linux
├── Invoke-OPAssist-CN.ps1        # Windows PowerShell (recommended)
├── opassist-win-cn.bat           # Windows CMD fallback
└── windows-cmd-checklist.txt     # paste checklist
`

| Scenario / 场景 | Use / 用什么 |
|----------|-----|
| Linux shell | opassist-linux-cn.sh |
| Windows + PowerShell | Invoke-OPAssist-CN.ps1 |
| Windows cmd only | opassist-win-cn.bat |
| Cannot drop files / 不能传文件 | windows-cmd-checklist.txt |

---

## Quick start / 快速开始

### Linux

`ash
chmod +x opassist-linux-cn.sh
./opassist-linux-cn.sh
./opassist-linux-cn.sh --full
./opassist-linux-cn.sh -o report.txt
`

### Windows (PowerShell)

`powershell
powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1
powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1 -Full
powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1 -OutFile C:\Users\Public\opassist.txt
`

### Windows (CMD)

`at
opassist-win-cn.bat
opassist-win-cn.bat --full
opassist-win-cn.bat -o C:\Users\Public\opassist.txt
`

---

## Output / 输出

Default **privesc-only summary** (默认只显示能推进提权的证据).

`	ext
[n]
!!! [HIGH] title
    Reason: ...
    Next:
      manual command ...
`

- HIGH first; MED capped; use -Full / --full for more  
- Kernel CVE is not primary  

### Windows PS special behavior / Windows 特殊逻辑

| Situation | Behavior |
|-----------|----------|
| Already **SYSTEM** | Skip fake writable service/task spam; still scan creds/configs/domain loot |
| Domain + no local HIGH | **DOMAIN MODE** playbook (SYSVOL / identity / AD next steps) |
| Web/DB configs | List interesting config **paths** ([maybe-secret] flag only; no secret dump) |

---

## Compliance / 合规

| Allowed | Forbidden |
|---------|-----------|
| Local enumeration | Auto exploit |
| Hints + suggested commands | Change services/tasks/registry persistence |
| Optional report file | Upload/run payload |
| ACL-based write checks (PS) | Credential brute force |

---

## Coverage / 覆盖 (摘要)

**Linux:** groups, sudo, SUID/caps, cron/systemd write chains, cred/config scoring, service profiles, PATH, NFS/container.  

**Windows PS:** tokens, AIE, Autologon, Unattend, SAM backups, service write/unquoted/DACL, tasks (Microsoft noise filtered), PATH/Run/Startup, GPO/SYSVOL/GPP, creds, web/DB config inventory, ports, domain playbook, SYSTEM short-circuit.  

**Windows CMD:** main checks in pure cmd; less depth than PS.

---

## Workflow / 建议流程

1. Get shell -> run matching script  
2. Verify HIGH, then MED  
3. If empty -> linpeas / WinPEAS as second opinion  
4. Domain + no local HIGH -> SYSVOL + AD enum first  
5. CVE last  

---

## Versions

| Component | Version |
|-----------|---------|
| Linux | 1.8.8-cn |
| Windows PowerShell | 1.9.6-en-ps |
| Windows CMD | 1.8.8-cn-cmd |

---

## License

MIT — see [LICENSE](./LICENSE).

Authorized testing / learning only. Redact secrets in reports.
