# OSCP Privesc Assistant (CN) v1.8.9

本地提权**枚举 + 提示**助手（Linux / Windows）。

- 只收集证据、标优先级、给下一步**手工**验证命令  
- **不**自动利用、**不**改服务/计划任务/注册表持久化、**不**上传 payload、**不**爆破  
- 面向 OSCP / PG / 授权实验环境  

> 仅用于你有权测试的系统。滥用后果自负。

---

## 文件结构

```text
.
├── README.md
├── LICENSE
├── .gitignore
├── opassist-linux-cn.sh          # Linux 主脚本
├── Invoke-OPAssist-CN.ps1        # Windows 完整版（有 PowerShell 时推荐）
├── opassist-win-cn.bat           # Windows 纯 CMD 兜底
└── windows-cmd-checklist.txt     # 无法落地脚本时的粘贴清单
```

| 场景 | 用什么 |
|------|--------|
| Linux shell | `opassist-linux-cn.sh` |
| Windows + PowerShell | `Invoke-OPAssist-CN.ps1` |
| Windows 只有 cmd | `opassist-win-cn.bat` |
| 不能传文件 | `windows-cmd-checklist.txt` 分段粘贴 |

---

## 快速开始

### Linux

```bash
chmod +x opassist-linux-cn.sh
./opassist-linux-cn.sh              # 默认 summary
./opassist-linux-cn.sh --full       # 详细枚举
./opassist-linux-cn.sh -o report.txt
./opassist-linux-cn.sh --report -o report.txt
```

### Windows (PowerShell，推荐)

```powershell
powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1
powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1 -Full
powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1 -OutFile C:\Users\Public\opassist.txt
```

### Windows (纯 CMD)

```bat
opassist-win-cn.bat
opassist-win-cn.bat --full
opassist-win-cn.bat -o C:\Users\Public\opassist.txt
```

---

## 输出原则

默认 **privesc-only summary**：只显示能推进提权的证据。

每条发现大致包含：

```text
[n]
!!! [高危/HIGH] 标题
    原因/Reason: ...
    下一步/Next:
      手工命令 ...
```

- **HIGH** 优先，**MED** 有上限，其余用 `--full` / `-Full`  
- 内核 CVE **不作为主线**（常规路径无结果再考虑）  

---

## 合规边界

| 允许 | 禁止 |
|------|------|
| 本地只读枚举 | 自动利用 / 自动提权 |
| 风险高亮 + 建议命令 | 修改服务 / 任务 / 注册表持久化 |
| 可选保存报告 | 上传/执行 payload |
| ACL 只读判断写权限 (PS) | 爆破凭据 |

PowerShell 版用 ACL 判断写权限（尽量不写临时文件）。CMD 版对部分目录使用短时临时文件探针（用后删除）。

---

## 覆盖范围（摘要）

### Linux (`opassist-linux-cn.sh`)

敏感组、sudo、SUID/capabilities、cron/systemd 可写链、凭据/配置强特征、服务画像评分、PATH、NFS/容器线索等。

### Windows (`Invoke-OPAssist-CN.ps1`)

Token 权限、AlwaysInstallElevated、Autologon、Unattend、SAM 备份、服务可写/未加引号/弱 DACL、计划任务、PATH/Run/Startup、GPO/SYSVOL/GPP、凭据源、本地端口、敏感组等。

### Windows CMD (`opassist-win-cn.bat`)

上述主干的 CMD 实现；服务 DACL / 部分 ACL 深度弱于 PS 版。

---

## 建议流程

1. 拿 shell → 跑对应脚本（默认 summary）  
2. 先验证 **HIGH**，再 **MED**  
3. 无结果 → linpeas / WinPEAS / Seatbelt 等第二意见  
4. 最后才考虑 CVE  

---

## 版本

| 组件 | 版本 |
|------|------|
| Linux | 1.8.8-cn |
| Windows PowerShell | **1.9.0-en-ps** (English UI for WinRM/EN consoles) |
| Windows CMD | 1.8.8-cn-cmd |

### v1.9.0 notes (from real Evil-WinRM run)

- English-only findings UI (fixes Chinese mojibake under WinRM)
- Drop RDP/WinRM groups from MED noise (INFO only in `-Full`)
- RegBack SAM: only report **readable + non-empty** (existence alone is noise)
- PATH: skip `WindowsApps` and user profile dirs
- Ports: drop 445/139 noise; focus localhost DB/admin ports
- Add `SeMachineAccountPrivilege` detection

---

## License

MIT — 见 [LICENSE](./LICENSE)。

仅用于授权测试与学习。报告中请脱敏，勿粘贴无意义明文密码。
