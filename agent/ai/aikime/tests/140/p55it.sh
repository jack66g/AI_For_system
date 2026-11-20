#!/bin/sh
# p55it.sh — P-55 aik-ime 140 真机集成验收（tty2 试验面，不碰 tty1 出厂链）
# 剧本：openvt tty2 起 fbterm -i aik-ime -- cat → Ctrl+Space 激活 →
#       键入 nihao → 抓屏断言候选窗绘制 → 空格提交 → 文件断言汉字字节 →
#       收尾回 tty1。证据 PPM 落 /root/。
export AIK_IME_DATA=/root/rime-data
export AIK_IME_DEBUG=1
export LD_LIBRARY_PATH=/root/p55lib
LOG=/root/p55-run.log
exec >>$LOG 2>&1
set -x

date
pkill -f 'fbterm -i /root/aik-ime' 2>/dev/null
sleep 1
rm -f /root/ime-out.txt

# 0) 基线抓屏（tty1 现状，不应变化）
/root/fbcat -o /root/p55-0-baseline.ppm -s 0 768

# 1) tty2 起 fbterm+IM；cat 收 PutText
openvt -c 2 -s -- sh -c 'exec /usr/bin/fbterm -i /root/aik-ime -- sh -c "cat > /root/ime-out.txt"' &
sleep 4
cat /sys/class/tty/tty0/active
ps w | grep -E 'aik-ime|fbterm' | grep -v grep

# 2) 激活 IM → 候选窗
/root/aik-keys ctrl-space
sleep 2
/root/fbcat -o /root/p55-1-imon.ppm -s 716 768

# 3) 键入 nihao → preedit+候选
/root/aik-keys text "nihao"
sleep 1
/root/fbcat -o /root/p55-2-preedit.ppm -s 716 768

# 4) 空格提交
/root/aik-keys text " "
sleep 2

# 5) 再来一轮（数字透传）+回车
/root/aik-keys text "9"
sleep 1
/root/aik-keys enter
sleep 1
/root/fbcat -o /root/p55-3-final.ppm -s 716 768

# 6) 断言材料
echo ====ime-out-bytes====
od -An -tx1 /root/ime-out.txt 2>/dev/null | head -3
wc -c /root/ime-out.txt 2>/dev/null
echo ====stats====
for f in p55-0-baseline p55-1-imon p55-2-preedit p55-3-final; do
  echo "$f: $(/root/fbcat -s 716 768)"
done

# 7) 收尾：杀 tty2 fbterm，回 tty1
pkill -f 'fbterm -i /root/aik-ime'
sleep 1
chvt 1
sleep 1
cat /sys/class/tty/tty0/active
echo DONE
