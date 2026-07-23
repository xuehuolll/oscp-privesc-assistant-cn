# OSCP Privesc Assistant (CN)

Local privilege-escalation **enumeration + hints** helper for Linux and Windows.

- Collect evidence, rank findings, suggest **manual** next-step commands
- Does **not** auto-exploit, modify services/tasks/registry persistence, upload payloads, or brute-force credentials
- Intended for OSCP / PG / authorized lab environments only

> Use only on systems you own or have explicit permission to test.

---

## Repository layout

`	ext
.
|-- README.md
|-- LICENSE
|-- .gitignore
|-- opassist-linux-cn.sh          # Linux main script
|-- Invoke-OPAssist-CN.ps1        # Windows PowerShell (recommended)
|-- opassist-win-cn.bat           # Windows pure CMD fallback
|-- windows-cmd-checklist.txt     # paste checklist when file drop is hard
`

| Scenario | Use this |
|----------|----------|
| Linux shell | opassist-linux-cn.sh |
| Windows + PowerShell | Invoke-OPAssist-CN.ps1 |
| Windows cmd only | opassist-win-cn.bat |
| Cannot transfer files | windows-cmd-checklist.txt |

---

## Quick start

### Linux

`ash
chmod +x opassist-linux-cn.sh
./opassist-linux-cn.sh
./opassist-linux-cn.sh --full
./opassist-linux-cn.sh -o report.txt
./opassist-linux-cn.sh --report -o report.txt
`

### Windows (PowerShell, recommended)

`powershell
powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1
powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1 -Full
powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1 -OutFile C:\Users\Public\opassist.txt
`

### Windows (pure CMD)

`at
opassist-win-cn.bat
opassist-win-cn.bat --full
opassist-win-cn.bat -o C:\Users\Public\opassist.txt
`

---

## Output style

Default mode is a **privesc-only summary**: only evidence that can advance privilege escalation.

`	ext
[n]
!!! [HIGH] title
    Reason: ...
    Next:
      manual command ...
`

- **HIGH** first; **MED** is capped; use -Full / --full for more detail
- Kernel CVE is not the primary path

### Windows PowerShell special behavior

| Situation | Behavior |
|-----------|----------|
| Already **SYSTEM** | Skip fake writable service/task spam; still scan creds, configs, domain loot |
| Domain + no local HIGH | Emit **DOMAIN MODE** playbook (SYSVOL / identity / AD next steps) |
| Web / DB configs | List interesting config **paths** (optional [maybe-secret] flag; secrets are not dumped) |

---

## Compliance boundary

| Allowed | Forbidden |
|---------|-----------|
| Local enumeration | Auto exploit / auto privesc |
| Risk highlight + suggested commands | Changing services, tasks, or registry persistence |
| Optional report save | Uploading or running payloads |
| ACL-based write checks (PowerShell) | Credential spraying / brute force |

PowerShell edition prefers ACL-based write checks.  
CMD edition may use short-lived temp write probes (deleted immediately).

---

## Coverage (short)

**Linux (opassist-linux-cn.sh):** sensitive groups, sudo, SUID/capabilities, writable cron/systemd chains, credential/config scoring, service profiles, PATH, NFS/container hints.

**Windows PS (Invoke-OPAssist-CN.ps1):** tokens, AlwaysInstallElevated, Autologon, Unattend, SAM backups, service write/unquoted/weak DACL, scheduled tasks (Microsoft built-in noise filtered), PATH/Run/Startup, GPO/SYSVOL/GPP, credentials, web/DB config inventory, local ports, domain playbook, SYSTEM short-circuit.

**Windows CMD (opassist-win-cn.bat):** main checks in pure cmd; less depth than the PowerShell edition.

---

## Suggested workflow

1. Get a shell, then run the matching script (default summary).
2. Verify **HIGH**, then **MED**.
3. If empty, use linpeas / WinPEAS / Seatbelt as a second opinion.
4. On domain hosts with no local HIGH, prioritize SYSVOL and AD enum.
5. Leave CVE hunting for last.

---

## Versions

| Component | Version |
|-----------|---------|
| Linux | 1.8.8-cn |
| Windows PowerShell | 1.9.6-en-ps |
| Windows CMD | 1.8.8-cn-cmd |

---

## License

MIT. See [LICENSE](./LICENSE).

Authorized testing and learning only. Redact secrets from reports.
