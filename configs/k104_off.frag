# K10.4 off 片：AIKernel 总关（叠加后 = /proc/ai 整树缺席）
--disable AIKERNEL
# 遗留六家族（agent/ai/Kconfig）不依赖总开关：AGENT 依赖 AI_AGENT，
# 其余五子依赖 AGENT——点名父符号即全家族级联（K10.4 矩阵实抓）
--disable AIKERNEL_AGENT
