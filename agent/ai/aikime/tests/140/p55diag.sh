#!/bin/sh
# p55diag.sh — P-55 140 分诊轮：fbterm stderr 重定向取 aik-ime 协议日志
export AIK_IME_DATA=/root/rime-data
export AIK_IME_DEBUG=1
export LD_LIBRARY_PATH=/root/p55lib
exec >>/root/p55-diag.log 2>&1
set -x

rm -f /root/im.err /root/ime-out.txt
pkill -f 'fbterm -i /root/aik-ime' 2>/dev/null; sleep 1

# tty2 起 fbterm，stderr→/root/im.err（IM child 继承）
openvt -c 2 -s -- sh -c 'exec /usr/bin/fbterm -i /root/aik-ime -- sh -c "cat > /root/ime-out.txt" 2>/root/im.err' &
sleep 4
echo ====PROCS1====
ps w | grep -E 'aik-ime|fbterm' | grep -v grep
echo ====ACTIVE====
cat /sys/class/tty/tty0/active
echo ====IMELOG-1====
tail -5 /root/im.err 2>/dev/null

# Ctrl+Space
/root/aik-keys ctrl-space; sleep 2
echo ====PROCS2====
ps w | grep -E 'aik-ime' | grep -v grep
echo ====IMELOG-2====
tail -8 /root/im.err 2>/dev/null
/root/fbcat -s 716 768 -o /root/d-imon.ppm

# nihao
/root/aik-keys text "nihao"; sleep 1
echo ====IMELOG-3====
tail -8 /root/im.err 2>/dev/null
/root/fbcat -s 716 768 -o /root/d-preedit.ppm

# 全屏也抓一张（看 tty2 整屏态）
/root/fbcat -s 0 768 -o /root/d-full.ppm

# 空格+回车
/root/aik-keys text " "; sleep 2
/root/aik-keys enter; sleep 1
echo ====IMELOG-4====
tail -10 /root/im.err 2>/dev/null
echo ====OUT====
od -An -tx1 /root/ime-out.txt | head -2; wc -c /root/ime-out.txt

# 收尾
pkill -f 'fbterm -i /root/aik-ime'; sleep 1; chvt 1; sleep 1
cat /sys/class/tty/tty0/active
echo DIAG-DONE
