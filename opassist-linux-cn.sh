#!/usr/bin/env bash
# OSCP Privesc Assistant - Linux Chinese Concise Edition
# 只枚举/提示/生成建议命令；不自动利用、不修改系统、不上传 payload。

VERSION="1.9.1-cn"
MODE="summary"
NO_COLOR=0
REPORT_MODE=0
OUTFILE=""
HIGH=0; MED=0; INFO=0
FINDING_KEYS=(); SEVS=(); TITLES=(); REASONS=(); NEXTS=()
DETAILS=()
shopt -s lastpipe 2>/dev/null || true

usage() {
  cat <<'USAGE'
用法：
  ./opassist-linux-cn.sh
  ./opassist-linux-cn.sh --quick
  ./opassist-linux-cn.sh --full
  ./opassist-linux-cn.sh --no-color -o report.txt
  ./opassist-linux-cn.sh --report -o report.txt
  ./opassist-linux-cn.sh -h | --help | -help

模式：
  默认/--quick  只输出重点摘要，适合 OSCP 拿 shell 后第一轮判断。
  --full        输出详细枚举，包括完整 cron、mount、更多凭据候选。
  --no-color    关闭颜色，适合保存文本。
  --report      报告友好模式，关闭颜色并补充英文 Finding/Evidence 字段。

设计边界：
  只做本地枚举、高亮和手工验证建议；不会自动利用漏洞、修改文件、写 cron、替换服务、下载 payload 或自动提权。
  v1.9.1 降噪：关联目录合并为一条；软链按目标树聚合；过滤发行版自带 cron.d。
  v1.9.0 root 执行链类别目录：非默认 root cron、/root 脚本、用户属主 /opt|/srv、bin symlink 指向可写目标。
  v1.8.9 排除 /dev/null 等设备节点假“可写 cron 目标”；不可读配置不再刷 Permission denied。
  v1.8.8 privesc-only summary：summary 只显示能直接推进提权的证据；普通服务发现/反代/Web root 放到 --full。
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    -o|--out) OUTFILE="$2"; shift 2 ;;
    --quick) MODE="summary"; shift ;;
    --full) MODE="full"; shift ;;
    --no-color) NO_COLOR=1; shift ;;
    --report) REPORT_MODE=1; NO_COLOR=1; shift ;;
    -h|--help|-help) usage; exit 0 ;;
    *) echo "未知参数：$1"; usage; exit 1 ;;
  esac
done

[ -n "$OUTFILE" ] && exec > >(tee -a "$OUTFILE") 2>&1

if { [ -t 1 ] || [ -n "$FORCE_COLOR" ]; } && [ "$NO_COLOR" != "1" ]; then
  RED='\033[1;31m'; YELLOW='\033[1;33m'; BLUE='\033[1;34m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; YELLOW=''; BLUE=''; BOLD=''; RESET=''
fi

section(){ echo; echo "========== $1 =========="; }
cmd_exists(){ command -v "$1" >/dev/null 2>&1; }
is_writable(){ [ -e "$1" ] && [ -w "$1" ] 2>/dev/null; }

# Device nodes / VFS: often world-writable by design (e.g. /dev/null from cron ">/dev/null").
# Not a privesc "writable cron target".
is_noise_path(){
  local p="$1"
  [ -n "$p" ] || return 0
  case "$p" in
    /dev/null|/dev/zero|/dev/full|/dev/random|/dev/urandom|/dev/tty|/dev/console|/dev/stdin|/dev/stdout|/dev/stderr)
      return 0 ;;
    /dev/fd/*|/dev/pts/*|/proc/*|/sys/*)
      return 0 ;;
    # /dev/* except /dev/shm (staging sometimes real); parent-only /dev also noise
    /dev|/dev/*)
      case "$p" in /dev/shm|/dev/shm/*) return 1 ;; esac
      return 0 ;;
    /proc|/sys) return 0 ;;
  esac
  # character/block device, named pipe, socket
  if [ -c "$p" ] || [ -b "$p" ] || [ -p "$p" ] || [ -S "$p" ]; then
    return 0
  fi
  return 1
}

# Writable in a way that could mean file replace / hijack for root execution chains.
is_writable_exec_target(){
  local p="$1"
  is_noise_path "$p" && return 1
  is_writable "$p" || return 1
  return 0
}

is_writable_exec_parent(){
  local d="$1"
  [ -n "$d" ] || return 1
  is_noise_path "$d" && return 1
  case "$d" in
    /|/bin|/sbin|/usr|/usr/bin|/usr/sbin|/lib|/lib64|/etc|/boot) return 1 ;;
  esac
  [ -d "$d" ] && is_writable "$d"
}

# OSCP-common "interesting" install/script locations (category list — extend here, not one-off patches).
is_custom_path(){
  case "$1" in
    /opt/*|/var/www/*|/home/*|/srv/*|/usr/local/*|/var/opt/*|/tmp/*|/var/tmp/*|/dev/shm/*|/root/*)
      return 0 ;;
    *) return 1 ;;
  esac
}

# Paths worth reporting when seen in root cron/systemd even if not currently writable by us.
is_interesting_exec_path(){
  local p="$1"
  [ -n "$p" ] || return 1
  is_noise_path "$p" && return 1
  is_custom_path "$p" && return 0
  case "$p" in
    *.sh|*.bash|*.py|*.pl|*.rb|*.php|*.js)
      case "$p" in /usr/*|/lib/*|/lib64/*|/etc/cron.*) return 1 ;; esac
      return 0 ;;
  esac
  return 1
}

# Stock Debian/Ubuntu crontab + common package cron.d noise — not a privesc lead by itself.
is_default_os_cron_line(){
  local line="$1"
  echo "$line" | grep -Eq 'run-parts[[:space:]].*/etc/cron\.(hourly|daily|weekly|monthly)' && return 0
  echo "$line" | grep -Eq '[[:space:]]anacron([[:space:]]|$)' && return 0
  echo "$line" | grep -Eq 'debian-sa1|/usr/lib/sysstat|logrotate' && return 0
  echo "$line" | grep -Eq '^[[:space:]]*[A-Z_]+=' && return 0  # SHELL= PATH= etc.
  # Common distro package jobs
  echo "$line" | grep -Eqi 'popularity-contest|sessionclean|e2scrub|mdadm|certbot|logwatch|apticron|chkrootkit|rkhunter| ban' && return 0
  # Paths only under system package locations (no OSCP-interesting roots)
  if ! echo "$line" | grep -Eq '/(opt|home|root|srv|var/www|var/opt|usr/local|tmp|var/tmp|dev/shm)/'; then
    if echo "$line" | grep -Eq '/(usr/lib|lib/x86_64|lib/systemd|sbin/|/etc/cron\.(daily|hourly|weekly|monthly)/)'; then
      return 0
    fi
  fi
  return 1
}

# Writable files that are plausible execution/hijack targets (not docs/jars spam).
is_plausible_hijack_file(){
  local p="$1"
  [ -n "$p" ] || return 1
  is_noise_path "$p" && return 1
  case "$p" in
    *.md|*.txt|*.html|*.htm|*.pdf|*.png|*.jpg|*.gif|*.css|*.po|*.mo|*.jar|*.war|*.zip|*.gz|*.tgz|*.deb|*.rpm)
      return 1 ;;
    */doc/*|*/docs/*|*/man/*|*/share/doc/*|*/examples/*|*/test/*|*/tests/*)
      return 1 ;;
  esac
  # Prefer bin/sbin, scripts, or executable bit
  case "$p" in
    */bin/*|*/sbin/*|*.sh|*.bash|*.py|*.pl|*.rb|*.php) return 0 ;;
  esac
  [ -x "$p" ] && [ -f "$p" ] && return 0
  [ -L "$p" ] && return 0
  return 1
}

# Group path into service tree root e.g. /opt/aerospike/bin/x -> /opt/aerospike
service_tree_root(){
  local p="$1"
  case "$p" in
    /opt/*|/srv/*|/var/www/*|/var/opt/*|/usr/local/*|/home/*)
      echo "$p" | awk -F/ '{print "/"$2"/"$3}'
      ;;
    *)
      dirname "$p"
      ;;
  esac
}

# Basename tokens from path/line for correlating cron <-> /opt/<service>
cron_name_tokens(){
  local s="$1" t base
  # path basenames and path components
  echo "$s" | grep -oE '/[A-Za-z0-9._+-]+' | sed 's#^/##' | while read -r t; do
    case "$t" in
      bin|sbin|etc|var|opt|usr|lib|lib64|home|root|tmp|dev|run|srv|www|local|share|cron*|anacron|sh|bash|python*|perl|php|node)
        continue ;;
    esac
    echo "$t"
    base="${t%.*}"
    [ "$base" != "$t" ] && [ -n "$base" ] && echo "$base"
  done
  # bare commands on the line (asinfo, asadm, backup.sh)
  echo "$s" | grep -oE '(^|[[:space:]])[A-Za-z][A-Za-z0-9._+-]+' | sed 's/^[[:space:]]*//' | while read -r t; do
    case "$t" in
      root|cd|test|run-parts|command|echo|grep|python*|perl|php|bash|sh|sudo|nice|ionice|start|stop|status|report)
        continue ;;
    esac
    echo "$t"
    base="${t%.*}"
    [ "$base" != "$t" ] && [ -n "$base" ] && echo "$base"
  done
}

path_owner_name(){
  local p="$1"
  [ -e "$p" ] || { echo ""; return; }
  if cmd_exists stat; then
    stat -c '%U' "$p" 2>/dev/null || stat -f '%Su' "$p" 2>/dev/null || echo ""
  else
    ls -ld "$p" 2>/dev/null | awk '{print $3}'
  fi
}

is_owned_by_me(){
  local p="$1" o
  o="$(path_owner_name "$p")"
  [ -n "$o" ] && [ "$o" = "$CURRENT_USER" ]
}

# True if path or any parent up to interesting root is owned by me / writable for hijack.
is_user_controlled_path(){
  local p="$1"
  [ -n "$p" ] || return 1
  is_noise_path "$p" && return 1
  if is_writable_exec_target "$p" || is_owned_by_me "$p"; then
    return 0
  fi
  local d="$p"
  local i=0
  while [ "$i" -lt 8 ]; do
    d="$(dirname "$d")"
    [ -z "$d" ] || [ "$d" = "/" ] && break
    if is_owned_by_me "$d" || is_writable_exec_parent "$d"; then
      case "$d" in
        /opt|/opt/*|/home|/home/*|/srv|/srv/*|/var/www|/var/www/*|/usr/local|/usr/local/*|/var/opt|/var/opt/*|/tmp|/var/tmp|/dev/shm)
          return 0 ;;
      esac
    fi
    i=$((i+1))
  done
  return 1
}

resolve_symlink_target(){
  local p="$1"
  if cmd_exists readlink; then
    readlink -f "$p" 2>/dev/null || readlink "$p" 2>/dev/null || echo ""
  else
    echo ""
  fi
}

TO=""; command -v timeout >/dev/null 2>&1 && TO="timeout 8"
TO2=""; command -v timeout >/dev/null 2>&1 && TO2="timeout 2"
first_lines(){ head -n "${2:-8}" 2>/dev/null <<<"$1"; }

add_finding(){
  local sev="$1" title="$2" reason="$3" next="$4" key="${5:-$sev:$title}"
  local k
  for k in "${FINDING_KEYS[@]}"; do [ "$k" = "$key" ] && return 0; done
  FINDING_KEYS+=("$key"); SEVS+=("$sev"); TITLES+=("$title"); REASONS+=("$reason"); NEXTS+=("$next")
  case "$sev" in HIGH) HIGH=$((HIGH+1));; MED) MED=$((MED+1));; INFO) INFO=$((INFO+1));; esac
}

hline(){
  case "$1" in
    HIGH) printf "%b!!! [高危] %s%b\n" "$RED" "$2" "$RESET" ;;
    MED) printf "%b>>> [中危] %s%b\n" "$YELLOW" "$2" "$RESET" ;;
    INFO) printf "%b--- [信息] %s%b\n" "$BLUE" "$2" "$RESET" ;;
  esac
}

print_finding(){
  hline "$1" "$2"
  [ -n "$3" ] && echo "    原因：$3"
  if [ -n "$4" ]; then
    echo "    下一步建议命令："
    printf '%s\n' "$4" | sed 's/^/      /'
  fi
}

print_summary(){
  section "优先级发现清单"
  echo "默认只显示 OSCP 常见重点；pkexec/CVE 等后备候选默认不抢主线，详细枚举请用 --full。"
  echo
  if [ "${#SEVS[@]}" -eq 0 ]; then
    echo "未发现明显高价值提权点。建议手工补充 sudo -l、linpeas/lse、pspy。"
    return
  fi
  local i n=1 printed=0 max_med=8
  for i in "${!SEVS[@]}"; do
    [ "${SEVS[$i]}" = "HIGH" ] || continue
    echo "[$n]"; print_finding "${SEVS[$i]}" "${TITLES[$i]}" "${REASONS[$i]}" "${NEXTS[$i]}"; echo
    if [ "$REPORT_MODE" = "1" ]; then echo "    [Report Finding] ${TITLES[$i]}"; echo "    [Evidence] ${REASONS[$i]}"; fi
    n=$((n+1)); printed=$((printed+1))
  done
  local med_printed=0
  for i in "${!SEVS[@]}"; do
    [ "${SEVS[$i]}" = "MED" ] || continue
    if [ "$MODE" != "full" ] && [ "$med_printed" -ge "$max_med" ]; then continue; fi
    echo "[$n]"; print_finding "${SEVS[$i]}" "${TITLES[$i]}" "${REASONS[$i]}" "${NEXTS[$i]}"; echo
    n=$((n+1)); printed=$((printed+1)); med_printed=$((med_printed+1))
  done
  if [ "$printed" -eq 0 ]; then
    if [ "$MODE" = "full" ]; then
      for i in "${!SEVS[@]}"; do
        [ "${SEVS[$i]}" = "INFO" ] || continue
        echo "[$n]"; print_finding "${SEVS[$i]}" "${TITLES[$i]}" "${REASONS[$i]}" "${NEXTS[$i]}"; echo
        n=$((n+1)); printed=$((printed+1))
      done
    else
      echo "未发现明确提权相关重点。"
      echo "summary 仅显示可直接推进提权的证据：凭据/token/私钥、可写高权限执行链、sudo/SUID/capabilities、可用数据库凭据等。"
      echo "普通服务发现、Nginx 反代、Web root、当前服务画像已隐藏；使用 --full 查看枚举导航信息。"
    fi
  fi
  if [ "$MODE" != "full" ]; then
    local remaining=$(( MED - med_printed ))
    [ "$remaining" -gt 0 ] && echo "[提示] 还有 $remaining 条中危候选已折叠，使用 --full 查看。"
  fi
}

banner(){
cat <<'BANNER'
   ____  ____   ____ ____    助手
  / __ \/ __ \ / ___|  _ \   Linux 本地提权枚举
 | |  | | |  | | |   | |_) |  只看重点 + 中文建议
 | |__| | |__| | |___|  __/   不自动利用
  \____/\____/ \____|_|      
BANNER
  echo "OSCP Privesc Assistant Linux 中文版 v$VERSION"
  echo "合规边界：只枚举/提示，不自动利用、不修改系统。"
  echo "模式：$MODE"
}

# ---------- 收集与分析 ----------
CURRENT_USER="$(id -un 2>/dev/null || whoami 2>/dev/null)"
ID_OUT="$(id 2>/dev/null)"
KERNEL="$(uname -a 2>/dev/null)"
OSREL="$(grep -E '^(PRETTY_NAME|NAME|VERSION)=' /etc/os-release 2>/dev/null | head -n 3 | sed 's/"//g' | tr '\n' ' ')"

check_root(){
  [ "$(id -u 2>/dev/null)" = "0" ] && add_finding INFO "当前已经是 root" "已是最高权限，提权枚举意义不大；建议读取 proof/local 并整理报告。" $'whoami\nid' "already_root"
}

check_groups(){
  local g
  for g in docker lxd disk shadow sudo admin adm; do
    if echo "$ID_OUT" | grep -qw "$g"; then
      local sev="MED"; [ "$g" = "docker" ] || [ "$g" = "lxd" ] || [ "$g" = "disk" ] || [ "$g" = "shadow" ] && sev="HIGH"
      add_finding "$sev" "当前用户属于敏感组：$g" "该组在 Linux 提权中经常能读取敏感文件、访问宿主资源或执行高权限操作。" $'id\ngroups\n# 根据组名查 GTFOBins/HackTricks 对应手工利用方式' "group:$g"
    fi
  done
}

check_sudo(){
  if cmd_exists sudo; then
    local out
    out="$(sudo -n -l 2>&1)"
    if echo "$out" | grep -qiE 'NOPASSWD|may run|\(ALL\)'; then
      local sev="MED"
      echo "$out" | grep -qi 'NOPASSWD' && sev="HIGH"
      add_finding "$sev" "sudo 权限可列出/可能存在 NOPASSWD" "sudo -n -l 有输出。优先检查是否包含 GTFOBins 可利用程序。" $'sudo -l\n# 将允许执行的命令拿到 GTFOBins 查询' "sudo:list"
      DETAILS+=("sudo -n -l 输出：\n$out")
    fi
  fi
}

check_suid(){
  local suids high_names found p
  suids="$($TO find / -perm -4000 -type f 2>/dev/null | sort 2>/dev/null)"
  high_names='/(bash|dash|sh|find|vim|vi|nano|cp|tar|nmap|python|python3|perl|ruby|node|env)$'
  found="$(echo "$suids" | grep -E "$high_names" | head -n 10)"
  if [ -n "$found" ]; then
    add_finding HIGH "发现高价值 SUID 程序" "命中 GTFOBins 常见可利用二进制。" "$(printf '%s\n' "$found"; printf '%s\n' '# 对具体二进制查询 GTFOBins，并手工验证。')" "suid:high"
  fi
  if echo "$suids" | grep -qx '/usr/bin/pkexec'; then
    add_finding INFO "发现 pkexec SUID（后备候选）" "pkexec 常见但不等于可利用；仅在常规提权路径无结果时确认版本/补丁。" $'ls -la /usr/bin/pkexec\npkexec --version 2>/dev/null\nuname -a\ncat /etc/os-release' "suid:pkexec"
  fi
  if [ "$MODE" = "full" ]; then DETAILS+=("SUID 文件：\n$suids"); fi
}

check_caps(){
  cmd_exists getcap || return 0
  local caps high
  caps="$($TO getcap -r / 2>/dev/null | sort 2>/dev/null)"
  high="$(echo "$caps" | grep -E 'cap_setuid|cap_setgid|cap_dac_read_search|cap_dac_override' | head -n 10)"
  if [ -n "$high" ]; then
    add_finding HIGH "发现高价值 Linux capabilities" "cap_setuid/cap_dac_* 等能力位可能直接绕过权限限制。" "$(printf '%s\n' "$high"; printf '%s\n' '# 对具体程序查询 GTFOBins capabilities 条目。')" "caps:high"
  fi
  [ "$MODE" = "full" ] && [ -n "$caps" ] && DETAILS+=("Capabilities：\n$caps")
}

extract_abs_paths(){
  grep -oE "(/[^[:space:]\"'\`;&|)]+)" | sed 's/[),;]$//' | sort -u
}

# Correlate cron/service name tokens with user-controlled trees under OSCP-common roots.
# Categories (maintain as a list; do not only patch one missed product name):
#   /opt /srv /var/www /var/opt /usr/local /home /tmp /var/tmp /dev/shm
check_cron_path_correlations(){
  local line="$1" src="$2"
  local tok cand owner next roots samples sample
  roots="/opt /srv /var/www /var/opt /usr/local /home /tmp /var/tmp /dev/shm"
  while IFS= read -r tok; do
    [ -z "$tok" ] && continue
    [ "${#tok}" -lt 3 ] && continue
    echo "$tok" | grep -Eqi '^(root|cron|bash|python|perl|php|node|http|https|true|false|null|status|start|stop)$' && continue
    for base in $roots; do
      cand="$base/$tok"
      [ -e "$cand" ] || continue
      owner="$(path_owner_name "$cand")"
      if is_user_controlled_path "$cand" || is_owned_by_me "$cand"; then
        # Sample plausible hijack files under tree (into Next only — one HIGH per tree)
        samples=""
        if [ -d "$cand" ]; then
          while IFS= read -r sample; do
            [ -z "$sample" ] && continue
            is_writable_exec_target "$sample" || continue
            is_plausible_hijack_file "$sample" || continue
            samples="${samples}${sample}"$'\n'
          done < <($TO find "$cand/bin" "$cand/sbin" "$cand" -maxdepth 3 \( -type f -o -type l \) 2>/dev/null | head -n 80)
          samples="$(printf '%s' "$samples" | sed '/^$/d' | head -n 8)"
        fi
        next="$(printf "ls -la '%s'\nls -la '%s/bin' 2>/dev/null\nfind '%s/bin' -writable 2>/dev/null | head -n 30\n# 优先可劫持样本（bin/脚本/可执行，已过滤 doc/jar）：\n%s\n# root cron 行：\n%s\n# 来源：%s\n# 验证：pspy；ls -la /usr/bin | grep -E '->.*%s'\n# 替换 bin 内被 root 调用的目标后等待 cron" \
          "$cand" "$cand" "$cand" "${samples:-#(未抽样到 bin/可执行，仍 ls bin/)}" "$line" "$src" "$tok")"
        add_finding HIGH "root cron 关联用户可控目录：$cand" \
          "非默认 root cron 与目录名/服务名 '$tok' 相关，且该路径属主或可写属于当前用户(owner=$owner)。OSCP 常见：root 跑 /root/<svc>.sh，实际依赖 /opt/<svc>/bin 等你可控文件。单文件可写不再逐条刷屏，见下方样本。" \
          "$next" "cron:corr:$cand"
      fi
    done
  done < <(cron_name_tokens "$line" | sort -u)
}

check_cron(){
  # Category-driven root cron enum (OSCP):
  #  1) Non-default root cron lines (not only writable path)
  #  2) Direct writable target / writable parent
  #  3) Interesting paths (/root /opt /home /srv ...) even if not writable
  #  4) Name correlation: cron tokens <-> user-controlled trees under /opt etc.
  #  5) Readable scripts: internal paths we control
  # Do NOT require the cron script itself to be writable (/root/svc.sh -> /opt/svc/bin).
  local files f line path paths parent next reason extra rel_hits path_hit
  files="/etc/crontab"
  if [ -d /etc/cron.d ]; then
    files="$files $(find /etc/cron.d -maxdepth 1 -type f 2>/dev/null | tr '\n' ' ')"
  fi

  for f in $files; do
    [ -r "$f" ] || continue
    while IFS= read -r line || [ -n "$line" ]; do
      [ -z "$line" ] && continue
      echo "$line" | grep -qE '^\s*#' && continue
      # user field: root (system crontab / cron.d format)
      echo "$line" | grep -Eq '(^|[[:space:]])root([[:space:]]|$)' || continue
      is_default_os_cron_line "$line" && continue

      paths="$(printf '%s\n' "$line" | extract_abs_paths)"
      path_hit=0

      while IFS= read -r path; do
        [ -z "$path" ] && continue
        is_noise_path "$path" && continue
        parent="$(dirname "$path")"
        reason="root cron 调用 $path。来源 $f。行：$line"

        if is_writable_exec_target "$path"; then
          path_hit=1
          next="$(printf "ls -la '%s'\nls -ld '%s'\n# 备份后替换/劫持，等待 cron\ncat '%s' 2>/dev/null | head\n# 关联枚举：\nfind /opt /srv /var/www /home /usr/local -maxdepth 3 -writable 2>/dev/null | head" "$path" "$parent" "$path")"
          add_finding HIGH "root cron 执行的目标当前用户可写：$path" "$reason 高确定性提权点。" "$next" "cron:wtarget:$path"
        elif is_writable_exec_parent "$parent"; then
          path_hit=1
          next="$(printf "ls -la '%s'\nls -ld '%s'\n# 父目录可写：尝试替换同名文件/软链（注意 sticky bit）" "$path" "$parent")"
          add_finding HIGH "root cron 目标父目录当前用户可写：$parent" "$reason 可尝试文件替换或软链，需手工验证 sticky/属主。" "$next" "cron:wparent:$parent"
        elif is_interesting_exec_path "$path"; then
          path_hit=1
          extra=""
          if [ -r "$path" ] && [ -f "$path" ]; then
            rel_hits="$(grep -nE '^[[:space:]]*(tar|cp|mv|find|bash|sh|python|python3|perl|php|exiftool|convert|magick|zip|rsync|[A-Za-z0-9._-]+)[[:space:]]' "$path" 2>/dev/null | head -n 5)"
            [ -n "$rel_hits" ] && extra=" 可读脚本摘录命令行需核对 PATH/绝对路径/输入目录。"
            # Paths inside readable script that we control
            local ip
            while IFS= read -r ip; do
              [ -z "$ip" ] && continue
              is_noise_path "$ip" && continue
              if is_user_controlled_path "$ip" || is_writable_exec_target "$ip"; then
                add_finding HIGH "root cron 脚本内引用用户可控路径：$ip" \
                  "可读脚本 $path 引用了当前用户可控路径。来源 cron：$f" \
                  "$(printf "sed -n '1,200p' '%s'\nls -la '%s'\nfind '%s' -writable 2>/dev/null | head" "$path" "$ip" "$ip")" \
                  "cron:scriptpath:$ip"
              fi
            done < <(printf '%s\n' "$(cat "$path" 2>/dev/null)" | extract_abs_paths)
          else
            extra=" 脚本可能不可读（常见 /root/*）：用 pspy 看 root 实际执行的子命令，并按服务名查 /opt|/srv 是否你属主。"
          fi
          next="$(printf "ls -la '%s' 2>/dev/null\ncat '%s' 2>/dev/null | head -n 80\n# 脚本不可读时：\n# 1) pspy 观察 UID=0 子进程\n# 2) ls -la /opt /srv /var/www | head\n# 3) find /opt /srv -user %s 2>/dev/null | head\n# 4) ls -la /usr/bin /bin | grep -E 'l.*->.*(opt|home|srv)' \n# cron 行：\n%s" \
            "$path" "$path" "$CURRENT_USER" "$line")"
          add_finding MED "root 非默认 cron 调用自定义路径：$path" \
            "$reason 路径本身未必可写，但仍是主线：检查脚本内容、子命令、PATH、以及 /opt 等用户属主服务树。$extra" \
            "$next" "cron:custom:$path"
        fi
      done <<< "$paths"

      # Always surface non-default root cron even when path parser only sees /bin/bash
      if [ "$path_hit" -eq 0 ]; then
        next="$(printf "grep -n . '%s' 2>/dev/null | head\n# 完整行：\n%s\n# 后续：pspy；find /opt /srv /home -user %s 2>/dev/null | head\nls -la /opt 2>/dev/null" "$f" "$line" "$CURRENT_USER")"
        add_finding MED "root 非默认 cron 任务" \
          "系统 crontab/cron.d 中存在非 Debian 默认的 root 任务（来源 $f）。即使命令路径在 /root 不可读，也应用 pspy + 服务目录属主关联继续挖。行：$line" \
          "$next" "cron:nondefault:$f:$(echo "$line" | cksum | awk '{print $1}')"
      fi

      # Name correlation: aerospike.sh / opt/foo / bare asinfo -> /opt/aerospike owned by user
      check_cron_path_correlations "$line" "$f"
    done < "$f"
  done

  if [ "$MODE" = "full" ]; then
    local fullcron
    fullcron="$( { echo '--- /etc/crontab ---'; cat /etc/crontab 2>/dev/null; echo '--- /etc/cron.d ---'; ls -la /etc/cron.d 2>/dev/null; echo '--- /etc/cron.daily ---'; ls -la /etc/cron.daily 2>/dev/null; } )"
    DETAILS+=("Cron 详细信息：\n$fullcron")
  fi
}

# Category: service trees under OSCP-common roots owned by current user (root often still runs tools from there).
check_user_owned_service_trees(){
  local root d owner next n k already
  for root in /opt /srv /var/www /var/opt /usr/local; do
    [ -d "$root" ] || continue
    while IFS= read -r d; do
      [ -z "$d" ] && continue
      [ -d "$d" ] || continue
      is_owned_by_me "$d" || is_writable_exec_parent "$d" || continue
      # Already covered by stronger cron correlation finding — avoid duplicate HIGH
      already=0
      for k in "${FINDING_KEYS[@]}"; do
        [ "$k" = "cron:corr:$d" ] && already=1 && break
      done
      [ "$already" -eq 1 ] && continue
      owner="$(path_owner_name "$d")"
      n="$(find "$d" -maxdepth 3 \( -type f -o -type l \) -perm -0111 2>/dev/null | head -n 15 | wc -l | tr -d ' ')"
      next="$(printf "ls -la '%s'\nls -la '%s/bin' 2>/dev/null\nfind '%s/bin' -writable 2>/dev/null | head -n 40\nfind '%s' -maxdepth 3 \\( -type f -o -type l \\) -perm -0111 2>/dev/null | head -n 30\n# 交叉验证 root 是否调用：\ngrep -Rns '%s' /etc/crontab /etc/cron.d 2>/dev/null | head\nls -la /usr/bin /bin 2>/dev/null | grep -E '-> *%s|%s'\n# pspy 看 UID=0 是否执行该树中的文件" \
        "$d" "$d" "$d" "$d" "$(basename "$d")" "$d" "$(basename "$d")")"
      if [ "${n:-0}" -gt 0 ] || [ -d "$d/bin" ]; then
        add_finding HIGH "当前用户拥有的服务/应用目录：$d" \
          "属主=$owner。OSCP 常见：目录属低权用户，但 root cron/systemd/PATH/symlink 仍会执行其中 bin。交叉检查 crontab、/usr/bin 软链、pspy。" \
          "$next" "own:tree:$d"
      else
        add_finding MED "当前用户拥有的目录（未见明显 bin）：$d" \
          "属主=$owner。仍检查配置/脚本与 root 任务是否引用。" \
          "$next" "own:dir:$d"
      fi
    done < <(find "$root" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | head -n 40)
  done
}

# Category: /usr/bin|/bin|/usr/local/bin symlinks into user-controlled paths — aggregate by service tree.
check_hijackable_bin_symlinks(){
  local link target tree next list count t tmpmap
  tmpmap="$(mktemp 2>/dev/null || echo "/tmp/.opa_sym.$$")"
  : >"$tmpmap" 2>/dev/null || return 0

  while IFS= read -r link; do
    [ -z "$link" ] && continue
    [ -L "$link" ] || continue
    target="$(resolve_symlink_target "$link")"
    [ -n "$target" ] || target="$(readlink "$link" 2>/dev/null || true)"
    [ -n "$target" ] || continue
    case "$target" in
      /opt/*|/home/*|/srv/*|/var/www/*|/var/opt/*|/usr/local/*|/tmp/*|/var/tmp/*|/dev/shm/*) ;;
      *) continue ;;
    esac
    if is_user_controlled_path "$target" || is_writable_exec_target "$target" || is_owned_by_me "$target"; then
      tree="$(service_tree_root "$target")"
      [ -n "$tree" ] || tree="$(dirname "$target")"
      # tree|link -> target  (use | so paths with spaces are less painful)
      printf '%s|%s -> %s\n' "$tree" "$link" "$target" >>"$tmpmap"
    fi
  done < <($TO find /usr/bin /bin /usr/local/bin -maxdepth 1 -type l 2>/dev/null | head -n 300)

  # One HIGH per target tree
  while IFS= read -r t; do
    [ -z "$t" ] && continue
    list="$(awk -F'|' -v tr="$t" '$1==tr {print $2}' "$tmpmap" 2>/dev/null | head -n 20)"
    count="$(printf '%s\n' "$list" | sed '/^$/d' | wc -l | tr -d ' ')"
    [ "${count:-0}" -gt 0 ] || continue
    next="$(printf "ls -la '%s/bin' 2>/dev/null\n# 共 %s 条 PATH 软链落入该树（优先 pspy 确认实际调用名，如 asinfo/asadm）：\n%s\n# 验证：grep -Rns . /etc/crontab /etc/cron.d 2>/dev/null | head\n# 替换软链目标文件后等待 cron/服务调用" \
      "$t" "$count" "$list")"
    add_finding HIGH "系统软链指向用户可控树：$t（${count} 条）" \
      "多个 /usr/bin|/bin 命令名解析到属主/可写树 $t。root 若调用其中任一命令名即可劫持。summary 按树聚合，不逐条刷屏。" \
      "$next" "symlink:tree:$t"
  done < <(awk -F'|' '{print $1}' "$tmpmap" 2>/dev/null | sort -u)

  rm -f "$tmpmap" 2>/dev/null || true
}

check_systemd(){
  cmd_exists systemctl || return 0
  local count=0 unit base state enabled execs e p parent
  # 只把 /etc/systemd/system 和自定义 ExecStart 放进默认清单；/lib 默认 unit 仅 full 展示，避免噪音。
  local units="/etc/systemd/system/*.service /etc/systemd/system/*.timer"
  [ "$MODE" = "full" ] && units="$units /lib/systemd/system/*.service"
  for unit in $units; do
    [ -e "$unit" ] || continue
    base="$(basename "$unit")"
    state="$($TO2 systemctl is-active "$base" 2>/dev/null || true)"
    enabled="$($TO2 systemctl is-enabled "$base" 2>/dev/null || true)"
    execs="$(grep -E '^Exec(Start|Reload|Stop)=' "$unit" 2>/dev/null | cut -d= -f2- | extract_abs_paths | head -n 5)"
    # 可写 unit 只有在 /etc 或 active/enabled 时才进摘要；/lib 中大量候选默认不刷屏。
    if is_writable "$unit" && { [[ "$unit" == /etc/systemd/system/* ]] || [ "$state" = "active" ] || [ "$enabled" = "enabled" ]; }; then
      local sev="MED"; [ "$state" = "active" ] || [ "$enabled" = "enabled" ] && sev="HIGH"
      add_finding "$sev" "systemd unit 文件当前用户可写：$unit" "状态 active=$state enabled=$enabled。需确认是否能触发重载/重启或等待系统触发。" "$(printf "ls -la '%s'\nsystemctl cat '%s'\nsystemctl status '%s' --no-pager" "$unit" "$base" "$base")" "systemd:unit:$unit"
    fi
    while IFS= read -r e; do
      [ -z "$e" ] && continue
      p="$e"; parent="$(dirname "$p")"
      if is_writable_exec_target "$p" || is_writable_exec_parent "$parent"; then
        add_finding HIGH "systemd Exec 路径或父目录当前用户可写：$p" "unit=$base active=$state enabled=$enabled。systemd/root 可能执行该路径。" "$(printf "systemctl cat '%s'\nls -la '%s'\nls -ld '%s'" "$base" "$p" "$parent")" "systemd:exec:$p"
      elif is_custom_path "$p" && { [ "$state" = "active" ] || [ "$enabled" = "enabled" ]; }; then
        [ "$count" -lt 3 ] && add_finding MED "systemd 服务指向自定义路径：$p" "unit=$base active=$state enabled=$enabled。当前不可写，检查程序目录和配置文件。" "$(printf "systemctl cat '%s'\nls -la '%s'\nls -ld '%s'" "$base" "$p" "$parent")" "systemd:custom:$p"
        count=$((count+1))
      fi
    done <<< "$execs"
  done
  [ "$MODE" = "full" ] && DETAILS+=("systemd timers：\n$($TO2 systemctl list-timers --all 2>/dev/null | head -n 80)")
}

check_sensitive_files(){
  local f
  for f in /etc/passwd /etc/shadow /etc/sudoers /etc/crontab; do
    if is_writable "$f"; then
      add_finding HIGH "当前用户可写敏感文件：$f" "这是高确定性提权/凭据读取方向。" "$(printf "ls -la '%s'\n# 手工确认风险，谨慎操作并记录证据。" "$f")" "sensitive:$f"
    fi
  done
}


file_content_hit(){
  # 只在非注释、非空行里判断内容命中，减少默认配置/示例文件误报。
  local f="$1" re="$2"
  [ -r "$f" ] || return 1
  head -c 200000 "$f" 2>/dev/null | \
    grep -aEv '^[[:space:]]*(#|//|;|<!--|\*)|^[[:space:]]*$' | \
    grep -aEiq "$re"
}

STRONG_VALUE_RE='password[[:space:]]*[:=][[:space:]]*[^[:space:]<>"$]{2,}|passwd[[:space:]]*[:=][[:space:]]*[^[:space:]<>"$]{2,}|pwd[[:space:]]*[:=][[:space:]]*[^[:space:]<>"$]{2,}|token[[:space:]]*[:=][[:space:]]*[^[:space:]<>"$]{2,}|secret[[:space:]]*[:=][[:space:]]*[^[:space:]<>"$]{2,}|credential|jdbc:|mysql://|postgres://|redis://|mongodb://|ssh-rsa|BEGIN [A-Z ]*PRIVATE KEY|proxy_pass[[:space:]]+https?://(127\.0\.0\.1|localhost|[0-9])|root[[:space:]]+/|alias[[:space:]]+/'

check_creds_and_local_services(){
  local ports db_local="" files="" best="" roots="/var/www /opt /home /srv"
  ports="$(ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null || true)"
  db_local="$(echo "$ports" | grep -E '127\.0\.0\.1:(3306|5432|6379|27017|1433)|\[::1\]:(3306|5432|6379|27017|1433)' | head -n 8)"
  # 默认只找高价值配置文件名，不扫所有 php，避免爆炸。
  files="$($TO find $roots -maxdepth 7 -type f \( -iname '.env' -o -iname 'wp-config.php' -o -iname 'config.php' -o -iname 'config.inc.php' -o -iname 'database.php' -o -iname 'settings.py' -o -iname 'settings.php' -o -iname 'web.config' -o -iname '*.bak' -o -iname '*.old' -o -iname '*backup*' \) 2>/dev/null)"
  files="$(printf '%s\n' "$files" | grep -Ev '/site-packages/|/node_modules/|/vendor/|/dist-packages/|/\.cache/|/htmlpurifier/|/HTMLPurifier/|/i18n/|readme|changelog')"
  # v1.8.7.2：备份/bak/old 文件只有内容出现强凭据/连接串特征时才进 summary；避免空 backup-config.xml、<list/> 这类噪音。
  local validated="" cf
  while IFS= read -r cf; do
    [ -n "$cf" ] || continue
    case "$cf" in
      *.bak|*.old|*backup*)
        file_content_hit "$cf" "$STRONG_VALUE_RE" && validated="$validated\n$cf"
        ;;
      *)
        file_content_hit "$cf" "$STRONG_VALUE_RE" && validated="$validated\n$cf"
        ;;
    esac
  done <<EOF_CREDS
$files
EOF_CREDS
  files="$(printf '%b\n' "$validated" | sed '/^$/d' | awk 'BEGIN{IGNORECASE=1} /\/config\.inc\.php$|\/database\.php$|\/\.env$|\/wp-config\.php$|\/web\.config$|\/settings\.(py|php)$/ {print "1 " $0; next} /\/config\.php$/ {print "2 " $0; next} /backup|\.bak$|\.old$/ {print "9 " $0; next}' | sort -k1,1n | cut -d' ' -f2-)"
  if [ -n "$files" ]; then
    # 默认只展示最高价值的 2 个文件；弱备份/空 XML 留给 --full。
    best="$(printf '%s\n' "$files" | grep -Ei '/config\.inc\.php$|/database\.php$|/\.env$|/wp-config\.php$|/web\.config$|/settings\.(py|php)$|/config\.php$' | head -n 2)"
    [ -z "$best" ] && best="$(printf '%s\n' "$files" | head -n 2)"
    local reason="发现 Web/应用配置候选或本地数据库服务。OSCP 中常见路径是：配置文件找数据库密码 → 登录本地 DB → 凭据复用。"
    [ -n "$db_local" ] && reason="$reason 本地服务：$(echo "$db_local" | awk '{print $5}' | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
    local next="$(printf "# 重点文件（默认只显示最高价值 2 个）：\n%s\n# 搜索数据库/密码关键字：\ngrep -RniE 'password|passwd|pwd|db_pass|mysql|postgres|redis|connection' /var/www /opt /home 2>/dev/null | head -n 50\nss -tulpen 2>/dev/null | grep 127.0.0.1" "$best")"
    add_finding MED "Web 配置/本地数据库凭据候选" "$reason" "$next" "creds:webdb"
  fi
  if [ "$MODE" = "full" ]; then
    local more="$($TO find $roots -maxdepth 7 -type f 2>/dev/null | grep -Ei 'pass|passwd|pwd|secret|token|credential|config|backup|\.bak|\.old|\.env' | head -n 80)"
    DETAILS+=("凭据候选文件（full）：\n$more")
  fi
}


check_env_profile(){
  local envout sens pathvars interesting name val shown paths next
  envout="$(env 2>/dev/null | sort || true)"
  [ -z "$envout" ] && return 0

  # 1) 明确凭据类环境变量：只显示命中行，避免全量 env 刷屏。
  sens="$(printf '%s\n' "$envout" | grep -Ei '(^|_)(PASS|PASSWORD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|DATABASE_URL|DB_PASS|MYSQL_PWD|POSTGRES_PASSWORD|REDIS_URL|MONGO.*URI)=' | head -n 8)"
  if [ -n "$sens" ]; then
    next="$(printf "env | grep -Ei 'PASS|PASSWORD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|DATABASE_URL|DB_PASS|MYSQL_PWD|POSTGRES_PASSWORD|REDIS_URL|MONGO.*URI'\n# 手工确认变量是否可复用；报告里避免无意义粘贴完整明文。\n# 命中摘要：\n%s" "$sens")"
    add_finding HIGH "环境变量疑似包含凭据" "发现 password/secret/token/key/database URL 等变量。此类信息可能直接用于凭据复用、数据库连接或横向移动。" "$next" "env:secrets"
  fi

  # 2) PWD/OLDPWD/HOME/*_HOME/*_BASE/*_CONF/*_CONFIG/*_DATA/*_DIR 路径画像。
  pathvars="$(printf '%s\n' "$envout" | grep -Ei '^(PWD|OLDPWD|HOME|[A-Z0-9_]+_(HOME|BASE|ROOT|CONF|CONFIG|DATA|DIR|PATH))=' | head -n 80)"
  interesting=""
  while IFS='=' read -r name val; do
    [ -n "$name" ] || continue
    [ -n "$val" ] || continue
    case "$val" in *embedded-db*|*database*|*db*|*backup*|*conf*|*config*|*plugin*|*plugins*|*log*|*logs*|*www*|*webapp*|*app*|*data*)
      [ -e "$val" ] && interesting="$interesting\n$name=$val"
      ;;
    esac
  done <<< "$pathvars"
  if [ -n "$interesting" ]; then
    # 取第一个可用路径作为默认命令目标。
    paths="$(printf '%b\n' "$interesting" | sed '/^$/d' | head -n 3)"
    val="$(printf '%s\n' "$paths" | head -n 1 | cut -d= -f2-)"
    next="$(printf "env | sort | grep -Ei 'PWD|OLDPWD|HOME|_HOME|_BASE|_CONF|_CONFIG|_DATA|_DIR|PASS|SECRET|TOKEN|KEY'\nls -la '%s' 2>/dev/null\nfind '%s' -maxdepth 3 -type f \\( -name '*.script' -o -name '*.log' -o -name '*.xml' -o -name '*.properties' -o -name '*.conf' -o -name '*.ini' -o -name '.env' \\) -ls 2>/dev/null | head -n 30\ngrep -RniE 'password|passwd|pwd|admin|smtp|jdbc|secret|token|connection|database' '%s' 2>/dev/null | head -n 50\n# 命中变量：\n%s" "$val" "$val" "$val" "$paths")"
    add_finding INFO "环境变量发现应用/历史目录线索" "PWD/OLDPWD/HOME 或 *_HOME/*_CONF 等变量指向疑似应用、数据库、配置、日志或插件目录。" "$next" "env:paths"
  fi

  [ "$MODE" = "full" ] && DETAILS+=("环境变量（full）：\n$envout")
}

score_app_files(){
  # v1.8.7 通用证据评分降噪：模板/资源文件降权，命中原因中文化。
  # 候选收集不依赖每个服务的复杂 find 表达式，统一收集高价值应用数据/配置文件。
  # 分数来源：应用数据路径、配置/DB/secret 路径、文件名/后缀、内容关键字、当前服务用户路径。
  local paths="$1" patterns="$2" grepkw="$3" out="" f score content_score reason penalty size
  [ -n "$paths" ] || return 0
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    score=0; reason=""; penalty=""

    # 模板/资源/文档文件降权：这些常见是产品自带 schema、示例或说明，不应压过真实运行数据。
    case "$f" in
      */usr/share/*/resources/*|*/usr/share/*/doc/*|*/usr/share/*/docs/*|*/usr/share/*/example*/*|*/usr/share/*/examples/*|*/usr/share/*/schema/*) score=$((score-35)); penalty="$penalty 模板/资源路径降权" ;;
    esac
    case "$f" in
      */usr/share/*/resources/database/*|*/usr/share/*/database/*) score=$((score-45)); penalty="$penalty 产品自带数据库模板降权" ;;
    esac
    case "$f" in
      *schema*.sql|*install*.sql|*upgrade*.sql|*create*.sql|*_mysql.sql|*_postgres*.sql|*_pgsql.sql|*_oracle.sql|*_db2.sql|*_mssql.sql|*_hsqldb.sql) score=$((score-35)); penalty="$penalty 初始化/兼容 SQL 降权" ;;
    esac
    case "$f" in
      /etc/nginx/nginx.conf|/etc/nginx/fastcgi.conf|/etc/nginx/fastcgi_params|/etc/nginx/proxy_params|/etc/nginx/mime.types|/etc/nginx/scgi_params|/etc/nginx/uwsgi_params|/etc/nginx/snippets/snakeoil.conf|/etc/nginx/snippets/fastcgi-php.conf) score=$((score-70)); penalty="$penalty Nginx 默认模板文件降权" ;;
    esac
    case "$f" in
      /etc/nginx/sites-enabled/*|/etc/nginx/sites-available/*|/etc/nginx/conf.d/*) score=$((score+25)); reason="$reason path:web-site" ;;
    esac

    # 路径权重：应用数据库/数据目录优先级高于普通 /etc 配置。
    case "$f" in
      *embedded-db*|*/database/*|*/databases/*|*/db/*|*/data/*) score=$((score+55)); reason="$reason path:data/db" ;;
    esac
    case "$f" in
      *conf*|*config*|*/etc/*) score=$((score+20)); reason="$reason path:config" ;;
    esac
    case "$f" in
      *secret*|*secrets*|*credential*|*credentials*) score=$((score+40)); reason="$reason path:secret" ;;
    esac
    case "$f" in
      *backup*|*.bak|*.old|*.orig|*.save) score=$((score+18)); reason="$reason path:backup" ;;
    esac
    case "$f" in
      *plugin*|*plugins*) score=$((score+10)); reason="$reason path:plugin" ;;
    esac
    case "$f" in
      *log*|*logs*) score=$((score+8)); reason="$reason path:log" ;;
    esac

    # 文件名/后缀权重：DB/script/env/credentials 明显优先。
    case "$f" in
      *.script|*.db|*.sqlite|*.sqlite3|*.h2.db|*.mv.db) score=$((score+50)); reason="$reason file:db/script" ;;
      *.env|*/.env) score=$((score+45)); reason="$reason file:env" ;;
      *credentials*.xml|*credentials*|*secret*|*master.key|*hudson.util.Secret|*id_rsa|*.kdbx) score=$((score+55)); reason="$reason file:secret" ;;
      *config*.php|*config*.xml|*config*.json|*config*.yml|*config*.yaml|*config*.ini|*settings.py|*settings.php|*application.properties|*application.yml|*app.ini|*database.yml|*openfire.xml|*web.config) score=$((score+30)); reason="$reason file:config" ;;
      *.properties|*.xml|*.yml|*.yaml|*.ini|*.conf|*.toml) score=$((score+18)); reason="$reason file:settings" ;;
      *.log) score=$((score+10)); reason="$reason file:log" ;;
      *.sql|*.dump|*.backup) score=$((score+35)); reason="$reason file:backup/db" ;;
    esac

    # 内容关键字只看非注释、非空行；强凭据/连接串额外加分。避免 nginx 默认注释、空 XML、示例文件误报。
    if file_content_hit "$f" "$grepkw"; then
      score=$((score+18)); reason="$reason content:keyword"
    fi
    if file_content_hit "$f" "$STRONG_VALUE_RE"; then
      score=$((score+45)); reason="$reason content:value"
    fi
    size=0
    if [ -r "$f" ]; then
      size="$(wc -c <"$f" 2>/dev/null | tr -d '[:space:]')"
      size="${size:-0}"
    fi
    if [ "${size:-0}" -lt 80 ]; then
      score=$((score-45)); penalty="$penalty 内容过短/空文件降权"
    fi
    if [ -r "$f" ] && head -c 5000 "$f" 2>/dev/null | grep -aEiq '^[[:space:]]*<list[[:space:]]*/>[[:space:]]*$|<backup-dir[[:space:]]+path='; then
      score=$((score-45)); penalty="$penalty 空列表/弱备份配置降权"
    fi

    # 真实运行数据目录优先：/var/lib、/etc、/opt、/home 下的服务目录通常比 /usr/share/resources 更值得看。
    case "$f" in
      /var/lib/*|/etc/*|/opt/*|/home/*) score=$((score+12)); reason="$reason path:runtime" ;;
    esac

    # 当前服务用户名出现在路径中，加分；文件属于当前用户也小幅加分。
    case "$f" in *"$CURRENT_USER"*) score=$((score+10)); reason="$reason path:service" ;; esac
    if [ -r "$f" ]; then score=$((score+5)); reason="$reason readable"; fi

    [ "$score" -gt 0 ] && printf '%03d|%s|%s|%s\n' "$score" "$f" "$reason" "$penalty"
  done < <(
    $TO find $paths -maxdepth 7 -type f \( \
      -name '.env' -o \
      -name '*.script' -o -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' -o -name '*.h2.db' -o -name '*.mv.db' -o \
      -name '*credentials*' -o -name '*secret*' -o -name 'master.key' -o -name 'hudson.util.Secret' -o \
      -name '*config*' -o -name '*settings*' -o -name 'application.properties' -o -name 'application.yml' -o -name 'app.ini' -o -name 'database.yml' -o -name 'web.config' -o -name 'openfire.xml' -o \
      -name '*.properties' -o -name '*.xml' -o -name '*.yml' -o -name '*.yaml' -o -name '*.ini' -o -name '*.conf' -o -name '*.toml' -o \
      -name '*.log' -o -name '*.sql' -o -name '*.dump' -o -name '*.backup' -o \
      -path '*/embedded-db/*' -o -path '*/database/*' -o -path '*/db/*' -o -path '*/data/*' \
    \) 2>/dev/null | grep -Evi '/cache/|/tmp/|/node_modules/|/vendor/|/i18n/|/locale/|/translations/|readme|changelog|available-plugins\.xml$|/\.git/'
  ) | sort -t'|' -k1,1nr | awk -F'|' '!seen[$2]++' | head -n 12
}

reason_to_cn(){
  # 把内部评分标签转成实战阅读友好的中文说明。
  local r="$1" p="$2" out=""
  case " $r " in *" path:data/db "*) out="$out、数据/数据库目录" ;; esac
  case " $r " in *" path:config "*) out="$out、配置目录" ;; esac
  case " $r " in *" path:secret "*) out="$out、secrets/credentials 路径" ;; esac
  case " $r " in *" path:backup "*) out="$out、备份/旧文件线索" ;; esac
  case " $r " in *" path:plugin "*) out="$out、插件目录" ;; esac
  case " $r " in *" path:log "*) out="$out、日志目录" ;; esac
  case " $r " in *" path:runtime "*) out="$out、真实运行目录" ;; esac
  case " $r " in *" path:web-site "*) out="$out、Nginx 站点/虚拟主机配置" ;; esac
  case " $r " in *" path:service "*) out="$out、路径关联当前服务用户" ;; esac
  case " $r " in *" file:db/script "*) out="$out、数据库/脚本类文件" ;; esac
  case " $r " in *" file:env "*) out="$out、环境配置文件" ;; esac
  case " $r " in *" file:secret "*) out="$out、凭据/密钥类文件名" ;; esac
  case " $r " in *" file:config "*) out="$out、主配置文件名" ;; esac
  case " $r " in *" file:settings "*) out="$out、配置格式文件" ;; esac
  case " $r " in *" file:log "*) out="$out、日志文件" ;; esac
  case " $r " in *" file:backup/db "*) out="$out、数据库备份/SQL 文件" ;; esac
  case " $r " in *" content:keyword "*) out="$out、内容命中关键词" ;; esac
  case " $r " in *" content:value "*) out="$out、内容像真实凭据/连接串/应用入口" ;; esac
  case " $r " in *" readable "*) out="$out、当前用户可读" ;; esac
  out="${out#、}"
  [ -n "$p" ] && out="$out；已降权：${p# }"
  printf '%s' "$out"
}

filter_privesc_scored(){
  # summary 只保留能直接推进提权的文件证据；普通服务发现/默认配置不进主清单。
  # 允许条件：真实凭据/连接串、凭据/密钥类文件、.env、或应用数据库/脚本文件且内容命中凭据关键词。
  awk -F'|' '
    $3 ~ /content:value/ {print; next}
    $3 ~ /file:secret/ {print; next}
    $3 ~ /file:env/ {print; next}
    $3 ~ /path:data\/db/ && $3 ~ /file:db\/script/ && $3 ~ /content:keyword/ {print; next}
  '
}

format_scored_files(){
  awk -F'|' '{print $2 "|" $3 "|" $4}' | head -n 4 | while IFS='|' read -r file reason penalty; do
    [ -n "$file" ] || continue
    printf "  %s\n" "$file"
    printf "    命中原因：%s\n" "$(reason_to_cn "$reason" "$penalty")"
  done
}

profile_add(){
  local key="$1" title="$2" paths="$3" patterns="$4" grepkw="$5" reason_extra="$6"
  local existing="" scored="" topfiles="" p next
  for p in $paths; do
    [ -e "$p" ] && existing="$existing\n$p"
  done
  [ -n "$existing" ] || return 0
  scored="$(score_app_files "$paths" "$patterns" "$grepkw")"
  topfiles="$(printf '%s\n' "$scored" | format_scored_files)"
  [ -n "$topfiles" ] || return 0
  next="$(printf "# 识别到的重点目录：\n%s\n# 按证据评分排序的高价值文件（优先看前面的路径）：\n%s\n# 建议手工检查：\n# 1) 先看上面排序最高的文件\n# 2) 再搜索真实凭据/连接串，过滤文档和翻译噪音\ngrep -RniE '%s' %s 2>/dev/null | grep -Evi 'available-plugins|i18n|readme|changelog|documentation|example|sample' | head -n 80\nfind %s -writable -ls 2>/dev/null | head -n 50" "$(printf '%b\n' "$existing" | sed '/^$/d' | head -n 6)" "$topfiles" "$grepkw" "$paths" "$paths")"
  add_finding MED "$title" "当前用户/进程/路径命中服务画像；下面不是写死答案，而是按应用数据路径、文件名、内容有效性、可读性和模板降权规则评分得到的高价值文件。$reason_extra" "$next" "profile:$key"
}

check_service_profiles(){
  local u psout hit=0
  u="$(printf '%s' "$CURRENT_USER" | tr '[:upper:]' '[:lower:]')"
  psout="$(ps -eo user,comm,args --no-headers 2>/dev/null | tr '[:upper:]' '[:lower:]' | head -n 300 || true)"

  if [ "$u" = "openfire" ] || printf '%s\n' "$psout" | grep -q 'openfire'; then
    hit=1
    profile_add "openfire" "当前用户/进程疑似 OpenFire 服务" "/etc/openfire /var/lib/openfire /usr/share/openfire /opt/openfire /home/openfire" "-name openfire.xml -o -path '*/embedded-db/*' -o -name '*.script' -o -name '*.log' -o -name '*.properties' -o -name '*.xml' -o -name '*.db' -o -name '*.ini' -o -name '*.conf'" "password|passwd|pwd|admin|smtp|jdbc|secret|connection|database|username|root|token" "OpenFire 只是服务画像之一；重点文件由通用评分规则决定。"
  fi

  if [ "$u" = "tomcat" ] || printf '%s\n' "$psout" | grep -Eq 'tomcat|catalina'; then
    hit=1
    profile_add "tomcat" "当前用户/进程疑似 Tomcat 服务" "/etc/tomcat* /var/lib/tomcat* /usr/share/tomcat* /opt/tomcat* /home/tomcat" "-name tomcat-users.xml -o -name server.xml -o -name context.xml -o -name web.xml -o -name '*.war' -o -name '*.properties' -o -name '*.xml'" "password|passwd|pwd|manager|admin|jdbc|secret|connection|database" "Tomcat 常见重点：tomcat-users.xml、context.xml、server.xml、WEB-INF/web.xml、war。"
  fi

  if [ "$u" = "jenkins" ] || printf '%s\n' "$psout" | grep -q 'jenkins'; then
    hit=1
    profile_add "jenkins" "当前用户/进程疑似 Jenkins 服务" "/var/lib/jenkins /opt/jenkins /home/jenkins" "-name credentials.xml -o -name config.xml -o -name master.key -o -name hudson.util.Secret -o -name '*.xml' -o -name '*.properties'" "password|passwd|pwd|secret|token|credential|username|privateKey|api" "Jenkins 常见重点：credentials.xml、secrets/master.key、hudson.util.Secret、job config。"
  fi

  if [ "$u" = "git" ] || [ "$u" = "gitea" ] || printf '%s\n' "$psout" | grep -Eq 'gitea|gitlab'; then
    hit=1
    profile_add "git_services" "当前用户/进程疑似 Git/Gitea/GitLab 服务" "/etc/gitea /var/lib/gitea /opt/gitea /etc/gitlab /var/opt/gitlab /opt/gitlab /home/git" "-name app.ini -o -name gitea.db -o -name gitlab.rb -o -name database.yml -o -name secrets.yml -o -name config.toml -o -name '*.ini' -o -name '*.yml'" "password|passwd|pwd|secret|token|database|db_|internal_token|smtp|ldap" "Git 类服务常见重点：app.ini、database.yml、secrets.yml、gitlab.rb。"
  fi

  if [ "$u" = "mysql" ] || [ "$u" = "mariadb" ] || printf '%s\n' "$psout" | grep -Eq 'mysqld|mariadbd'; then
    hit=1
    profile_add "mysql" "当前用户/进程疑似 MySQL/MariaDB 服务" "/etc/mysql /var/lib/mysql /home/mysql /root" "-name my.cnf -o -name debian.cnf -o -name '.my.cnf' -o -name '*history' -o -name '*.cnf' -o -name '*.sql'" "password|passwd|pwd|user|client|mysqldump|secret" "数据库服务用户优先查 .my.cnf、debian.cnf、历史文件和备份。"
  fi

  if [ "$u" = "postgres" ] || printf '%s\n' "$psout" | grep -Eq 'postgres|postmaster'; then
    hit=1
    profile_add "postgres" "当前用户/进程疑似 PostgreSQL 服务" "/etc/postgresql /var/lib/postgresql /home/postgres" "-name pg_hba.conf -o -name postgresql.conf -o -name '.pgpass' -o -name '*.conf' -o -name '*.sql'" "password|passwd|pwd|md5|scram|trust|replication|connection" "Postgres 常见重点：.pgpass、pg_hba.conf、postgresql.conf、SQL 备份。"
  fi

  if [ "$u" = "redis" ] || printf '%s\n' "$psout" | grep -q 'redis'; then
    hit=1
    profile_add "redis" "当前用户/进程疑似 Redis 服务" "/etc/redis /var/lib/redis /home/redis" "-name redis.conf -o -name dump.rdb -o -name '*.conf'" "requirepass|masterauth|password|dir |dbfilename|appendonly" "Redis 常见重点：redis.conf、requirepass、dump.rdb、持久化目录。"
  fi

  if [ "$u" = "www-data" ] || [ "$u" = "apache" ] || [ "$u" = "nginx" ] || printf '%s\n' "$psout" | grep -Eq 'apache2|nginx|httpd|php-fpm'; then
    hit=1
    profile_add "web" "当前用户/进程疑似 Web 服务" "/var/www /srv/www /etc/nginx/sites-enabled /etc/nginx/sites-available /etc/nginx/conf.d /etc/apache2 /etc/nginx /home/www-data" "-name '.env' -o -name wp-config.php -o -name config.php -o -name config.inc.php -o -name database.php -o -name settings.php -o -name settings.py -o -name web.config -o -name '*.yml' -o -name '*.ini'" "password|passwd|pwd|db_pass|mysql|postgres|redis|connection|secret|token|APP_KEY" "Web 服务优先查 .env、CMS 配置、框架 settings、数据库连接串。"
  fi

  if printf '%s\n' "$psout" | grep -Eq 'node|npm|pm2'; then
    hit=1
    profile_add "node" "运行进程疑似 Node/PM2 应用" "/opt /srv /var/www /home /usr/local" "-name '.env' -o -name package.json -o -name ecosystem.config.js -o -name config.json -o -name '*.yml' -o -name '*.js'" "password|passwd|pwd|secret|token|DATABASE_URL|mongo|redis|mysql|postgres|api[_-]?key" "Node 应用常见重点：.env、ecosystem.config.js、config.json、DATABASE_URL。"
  fi

  # 如果已命中具体 Java 服务（例如 OpenFire/Tomcat/Jenkins），不再额外显示泛化 Java/Spring 模板。
  if [ "$hit" -eq 0 ] && printf '%s\n' "$psout" | grep -Eq 'java|spring|jar'; then
    hit=1
    profile_add "java" "运行进程疑似 Java/Spring 应用" "/opt /srv /var/www /home /usr/local /etc" "-name application.properties -o -name application.yml -o -name '*.properties' -o -name '*.yml' -o -name '*.xml' -o -name '*.jar'" "password|passwd|pwd|secret|token|jdbc|spring.datasource|connection|keystore|truststore" "Java/Spring 常见重点：application.properties/yml、jdbc、keystore、日志。"
  fi

  if [ "$hit" -eq 0 ] && ! echo "$u" | grep -Eq '^(root|kali|ubuntu|debian|user|admin|www-data)$'; then
    local roots="/etc /opt /var/lib /var/www /usr/local /home/$CURRENT_USER"
    local next="$(printf "env | sort\nps aux | grep -i '%s' | grep -v grep\nfind /etc /opt /var/lib /var/www /usr/local /home -iname '*%s*' 2>/dev/null | head -n 50\nfind %s -maxdepth 4 -type f \\( -name '.env' -o -name '*.conf' -o -name '*.xml' -o -name '*.properties' -o -name '*.yml' -o -name '*.ini' -o -name '*.script' -o -name '*.log' \\) 2>/dev/null | head -n 80" "$CURRENT_USER" "$CURRENT_USER" "$roots")"
    add_finding INFO "当前用户可能是服务账号：$CURRENT_USER" "未命中具体画像，但服务账号常在应用目录、配置文件、日志、数据库或插件目录中留下凭据/执行线索。" "$next" "profile:generic:$CURRENT_USER"
  fi
}

check_path(){
  local p bad=""
  IFS=':' read -ra parts <<< "$PATH"
  for p in "${parts[@]}"; do
    [ -z "$p" ] && bad="$bad\n空路径"
    [ "$p" = "." ] && bad="$bad\n."
    case "$p" in /tmp|/var/tmp|/dev/shm) bad="$bad\n$p";; esac
    is_writable "$p" && bad="$bad\n$p"
  done
  [ -n "$bad" ] && add_finding MED "PATH 中存在可疑或可写目录" "只有当 root 脚本/服务使用相对命令且继承该 PATH 时才可利用。" "$(printf "echo \"%s\"\nprintf '%s\n' '%s'" "$PATH" "可疑 PATH：" "$bad")" "path:risk"
}

check_nfs_container(){
  if grep -Rqs 'no_root_squash' /etc/exports /etc/exports.d 2>/dev/null; then
    add_finding HIGH "NFS no_root_squash 配置线索" "如果可从攻击机挂载该导出目录，可能通过 SUID 文件提权。" $'cat /etc/exports 2>/dev/null\nshowmount -e 127.0.0.1 2>/dev/null' "nfs:no_root_squash"
  fi
  if [ -f /.dockerenv ] || grep -qiE 'docker|lxc|kubepods' /proc/1/cgroup 2>/dev/null; then
    add_finding MED "疑似容器环境" "如果在容器内，优先检查挂载、capabilities、docker.sock、特权容器等逃逸条件。" $'cat /proc/1/cgroup\nmount | head -n 50\nls -la /var/run/docker.sock 2>/dev/null' "container:hint"
  fi
}

check_cve_backup(){
  # CVE 只做后备候选，不进主清单；默认给极简信息，full 展示更多。
  local sudo_v pkexec glibc kv
  kv="$(uname -r 2>/dev/null)"
  sudo_v="$(sudo -V 2>/dev/null | head -n 1 || true)"
  pkexec="$(command -v pkexec 2>/dev/null || true)"
  glibc="$(ldd --version 2>/dev/null | head -n 1 || true)"
  DETAILS+=("后备 CVE 候选（非主线）：\n系统：$OSREL\n内核：$kv\n$sudo_v\npkexec：$pkexec\nglibc：$glibc\n说明：发行版常回补补丁，只有常规提权路径无结果时再核对 CVE。")
}

run_checks(){
  check_root
  if [ "$(id -u 2>/dev/null)" = "0" ]; then
    return 0
  fi
  check_groups
  check_sudo
  check_suid
  check_caps
  check_sensitive_files
  check_cron
  check_user_owned_service_trees
  check_hijackable_bin_symlinks
  check_systemd
  check_path
  check_env_profile
  check_service_profiles
  check_creds_and_local_services
  check_nfs_container
  check_cve_backup
}

print_basic(){
  section "基础环境"
  echo "时间：$(date 2>/dev/null)"
  echo "主机名：$(hostname 2>/dev/null)"
  echo "当前用户：$CURRENT_USER"
  echo "用户 ID：$ID_OUT"
  echo "系统：$OSREL"
  echo "内核：$KERNEL"
}

print_details(){
  [ "$MODE" = "full" ] || return 0
  section "详细枚举（--full）"
  local d
  for d in "${DETAILS[@]}"; do
    printf '%b\n' "$d"
    echo
  done
  section "挂载与本地服务（--full）"
  mount 2>/dev/null | sed 's/^/  /' | head -n 120
  echo "--- ss/netstat ---"
  (ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null || true) | sed 's/^/  /' | head -n 80
}

banner
run_checks
print_summary
print_basic
print_details
section "结果汇总"
echo "高危发现：$HIGH"
echo "中危提示：$MED"
echo "信息提示：$INFO"
echo "建议流程：先验证上方重点；没有结果再跑 linpeas/lse/pspy；最后才看 CVE 候选。"
echo "注意：本脚本只枚举和提示，不自动提权。"
