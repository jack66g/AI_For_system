#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# occ_reach_probe.sh - 出厂 AI「沙箱可达面」实测探测（AIF-01）
#
# 干什么
#   把一份只读命令清单逐条放进 aik-sandbox 里执行，记录退出码、耗时、输出
#   字节数与输出首行，产出 TSV。用来回填/校正 audit_occ_capabilities.py 里
#   「沙箱内命令可达表」的静态推断（那张表的判定列原样带进来对照）。
#
# 调用方式与 occ 的 bash 工具逐字对齐
# （agent/ai/occ/occ_tools/sandbox.c:518-599；agent/ai/sandbox/aik-sandbox.c:3307-3340）：
#     aik-sandbox create <zone>
#     aik-sandbox run <zone> --rw-path <workdir> -- /bin/sh -c "cd <workdir> && { <cmd> ; }"
#     aik-sandbox destroy <zone>            （幂等；脚本退出时必做）
#   aik-sandbox 退出码：0 成功；1 用法；2 组装失败；127 exec 失败；其余是
#   沙箱内命令自己的退出码原样透传。
#
# 纪律
#   * 组装 namespace 需要特权：本脚本只认 euid 0，自己绝不调 sudo；非 root 退出 2。
#   * 清单里全是只读探测（写文件、发信号、可能伤到宿主的一律不收）。
#   * 工作目录缺省是 mktemp -d 的私有目录（不碰 /var/ai/work），退出即删。
#   * 不启停服务、不连外机、不读凭据文件。
#
# 用法
#   bash occ_reach_probe.sh --list                         只打印清单
#   bash occ_reach_probe.sh                               全量，TSV 打到标准输出
#   bash occ_reach_probe.sh --only "systemctl,ps,ip" --timeout 10 --out /tmp/reach.tsv
# 选项
#   --only a,b,c     只跑首 token 命中的条目
#   --timeout N      单条命令超时秒数（缺省 10；超时 SIGKILL 整个进程组）
#   --out FILE       TSV 输出文件（缺省标准输出）
#   --workdir DIR    挂进沙箱的读写工作目录（缺省 mktemp）
#   --sandbox-bin P  aik-sandbox 路径（缺省同 occ：OCC_SANDBOX_BIN →
#                    AIKERNEL_SANDBOX_BIN → /usr/local/bin/aik-sandbox）
#   --keep           退出时不销毁隔离区、不删工作目录；每条完整输出落
#                    <工作目录>.out/<序号>.txt（取证用）
# 退出码：0 跑完；1 沙箱不可用或建区失败；2 用法/权限错误。
#
# TSV 列：static_verdict  cmd  rc  seconds  out_bytes  occ_view  first_line
#   static_verdict  静态表的判定（ok/partial/no）；view = 脚本自带的视图探针
#   rc              aik-sandbox 透传的退出码；124/137 = 超时被杀
#   occ_view        occ 会怎么向模型呈现这一条：
#                     ok          rc=0（结果 + [exit=0]）
#                     tool_error  rc 不是 0/1/2（结果 + [exit=N]，工具 rc=0）
#                     sb_fail     rc=1 或 2
#   注意 occ_tools/sandbox.c:570-575 把 exit=1/2 一律报成「bash 沙箱执行失败」，
#   而沙箱内命令自己的退出码 1/2 也原样透传——两者在 occ 侧无法区分。
#
# 清单维护：改下面的 PROBE_LIST 即可。每条是「判定<TAB>命令」，判定取
# ok/partial/no（与 audit_occ_capabilities.py 的沙箱命令表同一口径）。
# 顺序执行，一区复用（create 一次、run 多次、destroy 一次）。
PROBE_LIST=(
	"view"$'\t'"ls -la /"
	"view"$'\t'"ls -la /etc"
	"view"$'\t'"ls -la /dev"
	"view"$'\t'"ls -ld /run /boot /var/log /var/lib/dpkg /etc/passwd /etc/systemd/system"
	"view"$'\t'"id"
	"view"$'\t'"grep -E '^(CapEff|CapBnd|NoNewPrivs):' /proc/self/status"
	"view"$'\t'"cat /proc/1/comm"
	"view"$'\t'"cat /proc/self/mountinfo"
	"view"$'\t'"hostname"
	"no"$'\t'"aa-complain --help"
	"no"$'\t'"aa-disable --help"
	"no"$'\t'"aa-enforce --help"
	"no"$'\t'"aa-status --help"
	"no"$'\t'"aik-upgrade status"
	"ok"$'\t'"aikctl policy get --json"
	"no"$'\t'"apparmor_status --help"
	"no"$'\t'"apt list --installed"
	"ok"$'\t'"arping -c 1 127.0.0.1"
	"no"$'\t'"blkid -o export"
	"no"$'\t'"bootctl status"
	"partial"$'\t'"cat /proc/meminfo"
	"no"$'\t'"cc --version"
	"no"$'\t'"conntrack -L"
	"no"$'\t'"crontab -l"
	"ok"$'\t'"ctstat"
	"ok"$'\t'"curl -s -m 5 http://127.0.0.1:8000/health"
	"ok"$'\t'"cut -d: -f1 /proc/meminfo"
	"partial"$'\t'"date +%s"
	"partial"$'\t'"df -P"
	"ok"$'\t'"dmesg --color=never"
	"no"$'\t'"dpkg-query -W"
	"no"$'\t'"dpkg-query -W"
	"no"$'\t'"dpkg-query -W"
	"no"$'\t'"dpkg-query -W"
	"no"$'\t'"du -x -d1 /var"
	"no"$'\t'"dumpe2fs -h /dev/sda1"
	"ok"$'\t'"echo ok"
	"no"$'\t'"ethtool eth0"
	"no"$'\t'"fdisk -l"
	"partial"$'\t'"find /sys/class/net -maxdepth 1"
	"partial"$'\t'"findmnt -J"
	"ok"$'\t'"free -b"
	"no"$'\t'"gcc --version"
	"no"$'\t'"getent passwd"
	"ok"$'\t'"grep -c Mem /proc/meminfo"
	"ok"$'\t'"head -n 5 /proc/meminfo"
	"partial"$'\t'"hostname"
	"no"$'\t'"hostnamectl"
	"no"$'\t'"id"
	"ok"$'\t'"ifconfig -a"
	"ok"$'\t'"ip -j addr"
	"no"$'\t'"journalctl -n 20 --no-pager"
	"no"$'\t'"kill -0 1"
	"no"$'\t'"last -n 5"
	"ok"$'\t'"lnstat -c 1"
	"no"$'\t'"localectl status"
	"no"$'\t'"loginctl list-sessions"
	"partial"$'\t'"ls /sys/class/net"
	"partial"$'\t'"lsattr /usr/local/bin/occ"
	"ok"$'\t'"lsblk -J"
	"ok"$'\t'"lscpu -J"
	"ok"$'\t'"lsipc"
	"ok"$'\t'"lslocks"
	"no"$'\t'"lslogins"
	"ok"$'\t'"lsmem"
	"no"$'\t'"lsns"
	"no"$'\t'"lvs --help"
	"no"$'\t'"mount"
	"ok"$'\t'"nc -z -w 2 127.0.0.1 22"
	"ok"$'\t'"netstat -tunl"
	"no"$'\t'"networkctl status"
	"no"$'\t'"nft list ruleset"
	"ok"$'\t'"nslookup 127.0.0.1"
	"ok"$'\t'"nstat -az"
	"ok"$'\t'"ollama list"
	"no"$'\t'"passwd -S root"
	"no"$'\t'"pgrep -a sshd"
	"no"$'\t'"pidof systemd"
	"ok"$'\t'"ping -c 2 127.0.0.1"
	"ok"$'\t'"printf ok"
	"no"$'\t'"ps -eo pid,ppid,stat,comm"
	"no"$'\t'"pvs --help"
	"ok"$'\t'"python3 -c 'print(1)'"
	"no"$'\t'"quota --help"
	"no"$'\t'"repquota --help"
	"no"$'\t'"resolvectl status"
	"ok"$'\t'"route -n"
	"ok"$'\t'"rtstat"
	"ok"$'\t'"sed -n 1,3p /proc/meminfo"
	"no"$'\t'"setquota --help"
	"partial"$'\t'"sha256sum /etc/aikernel/policy.conf"
	"ok"$'\t'"slabtop -o -s c"
	"no"$'\t'"smartctl -a /dev/sda"
	"ok"$'\t'"sort /proc/meminfo"
	"ok"$'\t'"ss -tunl"
	"no"$'\t'"sshd -T"
	"partial"$'\t'"stat /usr/local/bin/occ"
	"partial"$'\t'"strace -c true"
	"no"$'\t'"swapon --show"
	"ok"$'\t'"sysctl -a"
	"no"$'\t'"systemctl list-units --no-pager"
	"no"$'\t'"systemd-analyze time"
	"no"$'\t'"systemd-cgls --no-pager"
	"no"$'\t'"systemd-cgtop -n 1"
	"ok"$'\t'"systemd-detect-virt"
	"ok"$'\t'"tail -n 5 /proc/meminfo"
	"ok"$'\t'"tc -j qdisc show"
	"no"$'\t'"timedatectl show"
	"no"$'\t'"top -b -n 1"
	"ok"$'\t'"traceroute -n -m 5 127.0.0.1"
	"no"$'\t'"udevadm info /sys/class/net"
	"ok"$'\t'"uname -r"
	"ok"$'\t'"sort /proc/meminfo | uniq -c"
	"ok"$'\t'"uptime"
	"no"$'\t'"useradd -D"
	"no"$'\t'"vgs --help"
	"ok"$'\t'"vmstat 1 2"
	"ok"$'\t'"vmstat -d"
	"no"$'\t'"w -h"
	"ok"$'\t'"wc -l /proc/meminfo"
	"no"$'\t'"wdctl"
	"ok"$'\t'"wget -q -O - http://127.0.0.1:8000/health"
	"ok"$'\t'"whereis ls"
	"ok"$'\t'"which awk"
	"no"$'\t'"who"
)

# ---------------------------------------------------------------------------
# 以下为实现；清单在上面。
# ---------------------------------------------------------------------------
set -u

TIMEOUT=10
OUT=""
ONLY=""
WORKDIR=""
KEEP=0
LIST_ONLY=0
BIN="${OCC_SANDBOX_BIN:-${AIKERNEL_SANDBOX_BIN:-/usr/local/bin/aik-sandbox}}"

usage() {
	sed -n '/^# 用法/,/^# 退出码/p' "$0" | sed 's/^# \{0,1\}//' >&2
}

while [ $# -gt 0 ]; do
	case "$1" in
	--list) LIST_ONLY=1 ;;
	--only) ONLY="${2:-}"; shift ;;
	--timeout) TIMEOUT="${2:-}"; shift ;;
	--out) OUT="${2:-}"; shift ;;
	--workdir) WORKDIR="${2:-}"; shift ;;
	--sandbox-bin) BIN="${2:-}"; shift ;;
	--keep) KEEP=1 ;;
	-h|--help) usage; exit 0 ;;
	*)
		echo "occ_reach_probe: 未知参数：$1" >&2
		usage
		exit 2
		;;
	esac
	shift
done

if [ "$LIST_ONLY" = 1 ]; then
	for e in "${PROBE_LIST[@]}"; do
		printf '%s\t%s\n' "${e%%$'\t'*}" "${e#*$'\t'}"
	done
	exit 0
fi

case "$TIMEOUT" in
''|*[!0-9]*) echo "occ_reach_probe: --timeout 要正整数" >&2; exit 2 ;;
esac

if [ "$(id -u)" != 0 ]; then
	echo "occ_reach_probe: 需要 root（组装 namespace 需要特权）；本脚本不调 sudo，请以 root 身份运行" >&2
	exit 2
fi
if [ ! -x "$BIN" ]; then
	echo "occ_reach_probe: aik-sandbox 不存在或不可执行：$BIN" >&2
	exit 1
fi
# 与 occ 同款探测（occ_tools/sandbox.c:342-362）：--occ-probe 不是合法选项，
# aik-sandbox 打印用法并退出 1；用法文本里含 --rw-path 即表示支持。
if ! "$BIN" --occ-probe 2>&1 | grep -q -- '--rw-path'; then
	echo "occ_reach_probe: $BIN 版本过旧（不识别 --rw-path）" >&2
	exit 1
fi

ENVNOTE=""
for v in AIKERNEL_SANDBOX_NET AIKERNEL_SANDBOX_NO_CGROUP AIKERNEL_SANDBOX_BASE \
	AIKERNEL_SANDBOX_ARTIFACTS AIKERNEL_SANDBOX_CPUS AIKERNEL_SANDBOX_MEM_MB \
	AIKERNEL_SANDBOX_PIDS; do
	if [ -n "${!v:-}" ]; then
		ENVNOTE="${ENVNOTE}"$'\n'"# env $v=${!v}（会改变沙箱视图，对照静态表时请注意）"
	fi
done

MADE_WD=0
if [ -z "$WORKDIR" ]; then
	WORKDIR="$(mktemp -d /tmp/occ-reach-XXXXXXXX)" || exit 1
	MADE_WD=1
fi
mkdir -p "$WORKDIR" || exit 2
WORKDIR="$(cd "$WORKDIR" && pwd)" || exit 2
case "$WORKDIR" in
*[\'\\]*)
	echo "occ_reach_probe: 工作目录不能含单引号或反斜杠：$WORKDIR" >&2
	exit 2
	;;
esac

ZONE="occreach$$"                 # 区名规则 [A-Za-z0-9._-]，aik-sandbox.c:386-408
ZONE_CREATED=0

cleanup() {
	rc=$?
	if [ "$KEEP" != 1 ]; then
		if [ "$ZONE_CREATED" = 1 ]; then
			"$BIN" destroy "$ZONE" >/dev/null 2>&1 || \
				echo "occ_reach_probe: destroy $ZONE 失败，请手工检查：$BIN status" >&2
		fi
		if [ "$MADE_WD" = 1 ]; then
			rm -rf "$WORKDIR"
		fi
	fi
	exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# TSV 走 fd 3（文件或标准输出），日志走 stderr
if [ -n "$OUT" ]; then
	exec 3>"$OUT" || exit 2
else
	exec 3>&1
fi

{
	printf '# occ_reach_probe\t%s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')"
	printf '# host=%s\tkernel=%s\tuid=%s\n' "$(hostname)" "$(uname -r)" "$(id -u)"
	printf '# aik_sandbox=%s\tsize=%s\n' "$BIN" "$(stat -c %s "$BIN" 2>/dev/null)"
	printf '# zone=%s\tworkdir=%s\ttimeout=%ss\tonly=%s\n' "$ZONE" "$WORKDIR" "$TIMEOUT" "${ONLY:-all}"
	[ -n "$ENVNOTE" ] && printf '%s\n' "$ENVNOTE"
	printf '# columns: static_verdict cmd rc seconds out_bytes occ_view first_line\n'
	printf 'static_verdict\tcmd\trc\tseconds\tout_bytes\tocc_view\tfirst_line\n'
} >&3

echo "occ_reach_probe: 建区 $ZONE（工作目录 $WORKDIR）" >&2
if ! "$BIN" create "$ZONE" >/dev/null 2>&1; then
	echo "occ_reach_probe: aik-sandbox create $ZONE 失败" >&2
	"$BIN" destroy "$ZONE" >/dev/null 2>&1
	exit 1
fi
ZONE_CREATED=1

if [ "$KEEP" = 1 ]; then
	mkdir -p "$WORKDIR.out" || exit 2
fi

n=0
c_ok_rc0=0; c_ok_rcnz=0; c_partial_rc0=0; c_partial_rcnz=0
c_no_rc0=0; c_no_rcnz=0
for e in "${PROBE_LIST[@]}"; do
	static="${e%%$'\t'*}"
	cmd="${e#*$'\t'}"
	first="${cmd%% *}"
	if [ -n "$ONLY" ] && [ ",$ONLY," != *",$first,"* ]; then
		continue
	fi
	n=$((n + 1))
	t0=$(date +%s%N)
	out="$(timeout -s KILL "$TIMEOUT" "$BIN" run "$ZONE" --rw-path "$WORKDIR" -- \
		/bin/sh -c "cd '$WORKDIR' && { $cmd ; }" 2>&1)"
	rc=$?
	t1=$(date +%s%N)
	d=$(( (t1 - t0) / 1000000 ))
	secs=$(printf '%d.%03d' $((d / 1000)) $((d % 1000)))

	line="${out%%$'\n'*}"
	line="${line//$'\t'/ }"
	line="${line//$'\r'/}"
	if [ ${#line} -gt 200 ]; then
		line="${line:0:200}"
	fi
	case "$rc" in
	0) view="ok" ;;
	1|2) view="sb_fail" ;;
	*) view="tool_error" ;;
	esac
	case "$static" in
	ok)      if [ "$rc" = 0 ]; then c_ok_rc0=$((c_ok_rc0 + 1)); else c_ok_rcnz=$((c_ok_rcnz + 1)); fi ;;
	partial) if [ "$rc" = 0 ]; then c_partial_rc0=$((c_partial_rc0 + 1)); else c_partial_rcnz=$((c_partial_rcnz + 1)); fi ;;
	no)      if [ "$rc" = 0 ]; then c_no_rc0=$((c_no_rc0 + 1)); else c_no_rcnz=$((c_no_rcnz + 1)); fi ;;
	esac
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$static" "$cmd" "$rc" "$secs" \
		"${#out}" "$view" "$line" >&3
	if [ "$KEEP" = 1 ]; then
		{
			printf '$ %s\n[exit=%s]\n' "$cmd" "$rc"
			printf '%s\n' "$out"
		} >"$WORKDIR.out/$(printf '%03d' "$n").txt" 2>/dev/null
	fi
done

echo "occ_reach_probe: 完成 $n 条，隔离区 $ZONE 已销毁（--keep 时保留）" >&2
echo "occ_reach_probe: 静态表 × 实测（rc=0 / rc≠0）：ok $c_ok_rc0/$c_ok_rcnz  partial $c_partial_rc0/$c_partial_rcnz  no $c_no_rc0/$c_no_rcnz" >&2
echo "occ_reach_probe: 需要回看的是 ok 且 rc≠0（$c_ok_rcnz 条）与 no 且 rc=0（$c_no_rc0 条）" >&2
exit 0
