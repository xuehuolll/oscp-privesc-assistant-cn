# OSCP Privesc Assistant (CN) v1.8.9

鏈湴鎻愭潈**鏋氫妇 + 鎻愮ず**鍔╂墜锛圠inux / Windows锛夈€?
- 鍙敹闆嗚瘉鎹€佹爣浼樺厛绾с€佺粰涓嬩竴姝?*鎵嬪伐**楠岃瘉鍛戒护  
- **涓?*鑷姩鍒╃敤銆?*涓?*鏀规湇鍔?璁″垝浠诲姟/娉ㄥ唽琛ㄦ寔涔呭寲銆?*涓?*涓婁紶 payload銆?*涓?*鐖嗙牬  
- 闈㈠悜 OSCP / PG / 鎺堟潈瀹為獙鐜  

> 浠呯敤浜庝綘鏈夋潈娴嬭瘯鐨勭郴缁熴€傛互鐢ㄥ悗鏋滆嚜璐熴€?
---

## 鏂囦欢缁撴瀯

```text
.
鈹溾攢鈹€ README.md
鈹溾攢鈹€ LICENSE
鈹溾攢鈹€ .gitignore
鈹溾攢鈹€ opassist-linux-cn.sh          # Linux 涓昏剼鏈?鈹溾攢鈹€ Invoke-OPAssist-CN.ps1        # Windows 瀹屾暣鐗堬紙鏈?PowerShell 鏃舵帹鑽愶級
鈹溾攢鈹€ opassist-win-cn.bat           # Windows 绾?CMD 鍏滃簳
鈹斺攢鈹€ windows-cmd-checklist.txt     # 鏃犳硶钀藉湴鑴氭湰鏃剁殑绮樿创娓呭崟
```

| 鍦烘櫙 | 鐢ㄤ粈涔?|
|------|--------|
| Linux shell | `opassist-linux-cn.sh` |
| Windows + PowerShell | `Invoke-OPAssist-CN.ps1` |
| Windows 鍙湁 cmd | `opassist-win-cn.bat` |
| 涓嶈兘浼犳枃浠?| `windows-cmd-checklist.txt` 鍒嗘绮樿创 |

---

## 蹇€熷紑濮?
### Linux

```bash
chmod +x opassist-linux-cn.sh
./opassist-linux-cn.sh              # 榛樿 summary
./opassist-linux-cn.sh --full       # 璇︾粏鏋氫妇
./opassist-linux-cn.sh -o report.txt
./opassist-linux-cn.sh --report -o report.txt
```

### Windows (PowerShell锛屾帹鑽?

```powershell
powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1
powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1 -Full
powershell -ExecutionPolicy Bypass -File .\Invoke-OPAssist-CN.ps1 -OutFile C:\Users\Public\opassist.txt
```

### Windows (绾?CMD)

```bat
opassist-win-cn.bat
opassist-win-cn.bat --full
opassist-win-cn.bat -o C:\Users\Public\opassist.txt
```

---

## 杈撳嚭鍘熷垯

榛樿 **privesc-only summary**锛氬彧鏄剧ず鑳芥帹杩涙彁鏉冪殑璇佹嵁銆?
姣忔潯鍙戠幇澶ц嚧鍖呭惈锛?
```text
[n]
!!! [楂樺嵄/HIGH] 鏍囬
    鍘熷洜/Reason: ...
    涓嬩竴姝?Next:
      鎵嬪伐鍛戒护 ...
```

- **HIGH** 浼樺厛锛?*MED** 鏈変笂闄愶紝鍏朵綑鐢?`--full` / `-Full`  
- 鍐呮牳 CVE **涓嶄綔涓轰富绾?*锛堝父瑙勮矾寰勬棤缁撴灉鍐嶈€冭檻锛? 

---

## 鍚堣杈圭晫

| 鍏佽 | 绂佹 |
|------|------|
| 鏈湴鍙鏋氫妇 | 鑷姩鍒╃敤 / 鑷姩鎻愭潈 |
| 椋庨櫓楂樹寒 + 寤鸿鍛戒护 | 淇敼鏈嶅姟 / 浠诲姟 / 娉ㄥ唽琛ㄦ寔涔呭寲 |
| 鍙€変繚瀛樻姤鍛?| 涓婁紶/鎵ц payload |
| ACL 鍙鍒ゆ柇鍐欐潈闄?(PS) | 鐖嗙牬鍑嵁 |

PowerShell 鐗堢敤 ACL 鍒ゆ柇鍐欐潈闄愶紙灏介噺涓嶅啓涓存椂鏂囦欢锛夈€侰MD 鐗堝閮ㄥ垎鐩綍浣跨敤鐭椂涓存椂鏂囦欢鎺㈤拡锛堢敤鍚庡垹闄わ級銆?
---

## 瑕嗙洊鑼冨洿锛堟憳瑕侊級

### Linux (`opassist-linux-cn.sh`)

鏁忔劅缁勩€乻udo銆丼UID/capabilities銆乧ron/systemd 鍙啓閾俱€佸嚟鎹?閰嶇疆寮虹壒寰併€佹湇鍔＄敾鍍忚瘎鍒嗐€丳ATH銆丯FS/瀹瑰櫒绾跨储绛夈€?
### Windows (`Invoke-OPAssist-CN.ps1`)

Token 鏉冮檺銆丄lwaysInstallElevated銆丄utologon銆乁nattend銆丼AM 澶囦唤銆佹湇鍔″彲鍐?鏈姞寮曞彿/寮?DACL銆佽鍒掍换鍔°€丳ATH/Run/Startup銆丟PO/SYSVOL/GPP銆佸嚟鎹簮銆佹湰鍦扮鍙ｃ€佹晱鎰熺粍绛夈€?
### Windows CMD (`opassist-win-cn.bat`)

涓婅堪涓诲共鐨?CMD 瀹炵幇锛涙湇鍔?DACL / 閮ㄥ垎 ACL 娣卞害寮变簬 PS 鐗堛€?
---

## 寤鸿娴佺▼

1. 鎷?shell 鈫?璺戝搴旇剼鏈紙榛樿 summary锛? 
2. 鍏堥獙璇?**HIGH**锛屽啀 **MED**  
3. 鏃犵粨鏋?鈫?linpeas / WinPEAS / Seatbelt 绛夌浜屾剰瑙? 
4. 鏈€鍚庢墠鑰冭檻 CVE  

---

## 鐗堟湰

| 缁勪欢 | 鐗堟湰 |
|------|------|
| Linux | 1.8.8-cn |
| Windows PowerShell | **1.9.4-en-ps** |
| Windows CMD | 1.8.8-cn-cmd |

### Windows PS recent hardening

- English-only UI (WinRM-safe)
- Less noise: RDP/WinRM groups, empty RegBack, WindowsApps PATH, SMB ports
- Domain playbook when no local HIGH (single consolidated MED + commands)
- Finding **priority sort** (domain playbook / GPP / service write first)
- Faster service pass; list web/DB config file locations (paths only)
- Stronger DC detection (ProductType, NTDS, local SYSVOL, hostname)

---

## License

MIT 鈥?瑙?[LICENSE](./LICENSE)銆?
浠呯敤浜庢巿鏉冩祴璇曚笌瀛︿範銆傛姤鍛婁腑璇疯劚鏁忥紝鍕跨矘璐存棤鎰忎箟鏄庢枃瀵嗙爜銆?
