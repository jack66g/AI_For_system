#!/bin/bash
# 逐字符喂串口 FIFO(防 TCG 丢字): w6i-send.sh <fifo> <text> [delay_ms]
F="$1"; T="$2"; D="${3:-40}"
i=0
while [ "$i" -lt "${#T}" ]; do
  printf "%s" "${T:$i:1}" > "$F"
  sleep "0.$D"
  i=$(( i + 1 ))
done
printf "\r" > "$F"
