#!/bin/sh
# p55fin.sh — P-55 真机收官轮：激活→输入→提交→Deactive 收窗 全协议面
export AIK_IME_DATA=/root/rime-data
export AIK_IME_DEBUG=1
export LD_LIBRARY_PATH=/root/p55lib
exec >>/root/p55-fin.log 2>&1
set -x

pkill -f 'fbterm -i /root/aik-ime' 2>/dev/null; sleep 1
systemctl stop getty@tty2.service 2>/dev/null; systemctl stop getty@tty2 2>/dev/null
pkill -f 'agetty.*tty2' 2>/dev/null; sleep 1
rm -f /root/im3.err /root/ime-out.txt

openvt -c 2 -s -- sh -c 'exec /usr/bin/fbterm -i /root/aik-ime -- sh -c "cat > /root/ime-out.txt" 2>/root/im3.err' &
sleep 4

# 激活
/root/aik-keys ctrl-space; sleep 2
# 输入 ha（注入基建丢前键，跳过 n/i；ha 单音稳）
/root/aik-keys text "ha"; sleep 1
/root/fbcat -o /root/f1-preedit.ppm
# 空格提交
/root/aik-keys text " "; sleep 2
# 再按 Ctrl+Space = Deactive
/root/aik-keys ctrl-space; sleep 2
/root/fbcat -o /root/f2-deactive.ppm

echo ====LOG====
grep -E 'rx (Active|Deactive|SendKey|HideUI)|tx (SetWin|PutText)' /root/im3.err
echo ====OUT====
od -An -tx1 /root/ime-out.txt
pkill -f 'fbterm -i /root/aik-ime'; sleep 1; chvt 1
echo FIN-DONE
