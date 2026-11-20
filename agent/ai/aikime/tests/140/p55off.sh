#!/bin/sh
# p55off.sh — 键路径分界：IM 不激活，直注 abcdefgh+回车给 cat
export LD_LIBRARY_PATH=/root/p55lib
exec >>/root/p55-off.log 2>&1
set -x

pkill -f 'fbterm -i /root/aik-ime' 2>/dev/null; sleep 1
systemctl stop getty@tty2.service 2>/dev/null; systemctl stop getty@tty2 2>/dev/null
pkill -f 'agetty.*tty2' 2>/dev/null; sleep 1
rm -f /root/tty2-off.txt
openvt -c 2 -s -- sh -c 'exec /usr/bin/fbterm -i /root/aik-ime -- sh -c "cat > /root/tty2-off.txt" 2>/dev/null' &
sleep 4
# 不按 Ctrl+Space：IM 未激活，键直透 tty2
/root/aik-keys text "abcdefgh"
sleep 1
/root/aik-keys enter
sleep 2
wc -c /root/tty2-off.txt
od -An -c /root/tty2-off.txt | head -2
pkill -f 'fbterm -i /root/aik-ime'; sleep 1; chvt 1
echo OFF-DONE
