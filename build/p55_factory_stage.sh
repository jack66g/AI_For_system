#!/bin/bash
# p55_factory_stage.sh — P-55 factory 面组装（17.9 打版）
# 产物（全部进 factory 树=出厂即所装，ISO 断言 md5 直对 factory）：
#   factory/usr/local/bin/aik-ime          RPATH 版主件（-Wl,-rpath,
#                                           /usr/local/lib/aik-ime）
#   factory/usr/local/lib/aik-ime/*.so     9 件系统库随包（140 最小系统
#                                           无 yaml-cpp/boost/icu；SONAME
#                                           链+实体）
#   factory/usr/share/rime-data/           拼音数据（官方 yaml+essay.txt+
#                                           L1 预编 build/*.bin——nihao→
#                                           你好 字序已验）
#   factory/root/.fbtermrc                 input-method=aik-ime（Ctrl+Space）
# 用法：REPO=<工树或主仓路径> bash p55_factory_stage.sh
set -e
REPO="${REPO:-/home/jack66g/aikernel-repo-alpha11}"
POC=/home/jack66g/p55-poc
SYSL=/lib/x86_64-linux-gnu
F="$REPO/factory"

echo "== aik-ime =="
install -D -m 0755 "$REPO/agent/ai/aikime/aik-ime" \
	"$F/usr/local/bin/aik-ime"
md5sum "$F/usr/local/bin/aik-ime"

echo "== 随包 .so（实体+SONAME 链）=="
mkdir -p "$F/usr/local/lib/aik-ime"
declare -A SO=(
	[libyaml-cpp.so.0.7]=libyaml-cpp.so.0.7.0
	[libleveldb.so.1d]=libleveldb.so.1.23.0
	[libmarisa.so.0]=libmarisa.so.0.0.0
	[libopencc.so.1.1]=libopencc.so.1.1.3
	[libboost_regex.so.1.74.0]=libboost_regex.so.1.74.0
	[libicuuc.so.70]=libicuuc.so.70.1
	[libicui18n.so.70]=libicui18n.so.70.1
	[libicudata.so.70]=libicudata.so.70.1
	[libsnappy.so.1]=libsnappy.so.1.1.8
)
for soname in "${!SO[@]}"; do
	real="${SO[$soname]}"
	install -m 0644 "$SYSL/$real" "$F/usr/local/lib/aik-ime/$real"
	ln -sf "$real" "$F/usr/local/lib/aik-ime/$soname"
	ls -la "$F/usr/local/lib/aik-ime/$soname" | awk '{print $9, $10, $11}'
done

echo "== rime 数据（yaml+essay+预编 bin）=="
rm -rf "$F/usr/share/rime-data"
mkdir -p "$F/usr/share/rime-data"
cp -a "$POC/rime-data/." "$F/usr/share/rime-data/"
cat > "$F/usr/share/rime-data/SOURCE-NOTES.txt" << 'EOF'
AIKernel rime 数据来源（2026-11-20 组装，P-55）：
- schema/dict yaml：rime-luna-pinyin + rime-prelude（rime 官方仓，
  勘探棒 1.11.2 配套 clone）
- essay.txt：rime/rime-essay 官方仓（LGPL；语言模型词频——排序修复
  钥匙，实证 nihao→你好〔无 essay=生僻字〕）
- build/*.bin：L1 librime 1.11.2 静态构建自预编（BUILD_SHARED_LIBS=
  OFF 配方；预编后首启 0.17s 不重编）
- 用户词库目录：~/.config/aik-ime（首启自动创建）
EOF
du -sh "$F/usr/share/rime-data"

echo "== fbtermrc（出厂 IME 挂载）=="
mkdir -p "$F/root"
cat > "$F/root/.fbtermrc" << 'EOF'
# AIKernel 出厂（17.9 起）：fbterm IME 通道挂 aik-ime
# Ctrl+Space = 中/英输入切换（fbterm 自动绑定该 syskey）
input-method=aik-ime
EOF
cat "$F/root/.fbtermrc"

echo "== 断言 =="
file "$F/usr/local/bin/aik-ime" | grep -q 'ELF'
[ -f "$F/usr/share/rime-data/essay.txt" ]
[ -f "$F/usr/share/rime-data/build/luna_pinyin.prism.bin" ]
[ -f "$F/usr/share/rime-data/build/luna_pinyin.table.bin" ]
readelf -d "$F/usr/local/bin/aik-ime" | grep -q '/usr/local/lib/aik-ime'
echo "P55_FACTORY_STAGED"
