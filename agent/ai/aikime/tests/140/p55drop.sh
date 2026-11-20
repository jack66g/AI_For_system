#!/bin/sh
# p55drop.sh — 丢键分诊：激活后注入 abcdefgh 数到达键数
export AIK_IME_DATA=/root/rime-data
export AIK_IME_DEBUG=1
export LD_LIBRARY_PATH=/root/p55lib
exec >>/root/p55-drop.log 2>&1
set -x

pkill -f 'fbterm -i /root/aik-ime' 2>/dev/null; sleep 1
systemctl stop getty@tty2.service 2>/dev/null
systemctl stop getty@tty2 2>/dev/null
pkill -f 'agetty.*tty2' 2>/dev/null
sleep 1
ps w | grep tty2 | grep -v grep
rm -f /root/im2.err /root/ime-out.txt
openvt -c 2 -s -- sh -c 'exec /usr/bin/fbterm -i /root/aik-ime -- sh -c "cat > /root/ime-out.txt" 2>/root/im2.err' &
sleep 4

/root/aik-keys ctrl-space
sleep 3
/root/aik-keys text "abcdefgh"
sleep 2
echo ====COUNT====
grep -c 'rx SendKey' /root/im2.err
grep 'DrawText 0,713' /root/im2.err | tail -3

# 再来一轮验证可重复性（含空格提交）
/root/aik-keys text " "
sleep 2
/root/aik-keys enter
sleep 1
echo ====OUT====
wc -c /root/ime-out.txt; od -An -tx1 /root/ime-out.txt | head -2
grep -c 'rx SendKey' /root/im2.err

pkill -f 'fbterm -i /root/aik-ime'; sleep 1; chvt 1
echo DROP-DONE
