# ORCH-E10 真模型调用记账（前半：真模型实战演练）

- 演练日：2026-11-15 ｜ 现场：L1（192.168.245.136）
- 模型：deepseek-flash（model.toml [default].model=cloud → [models.cloud]，经 t3-proxy 127.0.0.1:9443 → api.deepseek.com；model.toml 用户资产只读，key 不落任何日志/报告）
- 工作区：/tmp/e10ws ｜ DB：/tmp/e10ws/sessions.db ｜ env：OCC_SME=off OCC_ORCH_TOOLS=1 OCC_AC=off
- occ：~/aikernel-repo-alpha11/agent/ai/occ/occ（2026-11-15 06:08 构建现状，make 无需重编）
- 记账口径：一行=一次真模型 occ 进程调用（主会话一次 -p 起跑 / 一个子智能体 spawn 的一次 occ -p 运行）；该行 token 数=该次运行全部 LLM 请求 usage 总和（源=DB occ_message.usage_*，括注 assistant 消息数=LLM 请求数）。预算：进程调用 ≤12 次。
- 交叉核对：本账行数与 token 总额 ↔ /tmp/e10ws/sessions.db（occ_message.usage_in/out 求和、occ_toolcall 计数）逐笔对账，核对脚本 /tmp/e10ws/run/crosscheck.py。

| # | 时间 | 角色 | 会话/任务 | 模型 | tokens(in/out) | LLM请求数 | 目的 |
|---|------|------|-----------|------|----------------|-----------|------|
| 1 | 11-15 06:23 | 主（smoke） | ses_46ec7dbb…（无任务） | deepseek-flash | 2379/2 | 1 | 真模型链路冒烟：t3-proxy+provider+usage 记账管线验证（rc=0，finish=stop，回复「收到」） |
| 2 | 11-15 06:24 | 主#1（任务A首试） | ses_f5e09bf7…→tsk_14420e8e | deepseek-flash | 47722/4095 | 9 | 主会话起跑 A：spawn→wait→read→return(拒)。子报告含 GFM \|---\| 分隔行被 E4 误判数据行→机械判 fail→rework（产品 bug#1 现场） |
| 3 | 11-15 06:25 | 子（任务A首试） | ses_747a7552…（child） | deepseek-flash | 18728/1307 | 5 | 子智能体 A 首跑：edit README 追加 ORCH 节+glob 结果文件+write # VERDICT 报告（交付物真实，报告格式含分隔行） |
| 4 | 11-15 06:25 | 主#2（任务B首试） | ses_f5e09bf7…→tsk_6a0111d2 | deepseek-flash | 66059/2031 | 6 | 主会话续跑 B：spawn→wait→read→return(拒)。同 bug#1 致机械判 fail→rework；主模型诊断准确（指出 \|---\| 行被误判） |
| 5 | 11-15 06:26 | 子（任务B首试） | ses_43e9906d…（child） | deepseek-flash | 70791/3950 | 12 | 子智能体 B 首跑：glob/read 侦察 tree+实测构建（发现裸 make 失败 exit2）+write 报告+write tree-report.md（交付物真实） |
| 6 | 11-15 06:29 | 主#3（A2 腿） | ses_b06c5c6e…→tsk_3bbbd24c | deepseek-flash | 23495/1439 | 6 | 主会话 A2 腿：spawn→wait→read 后，自身 bash tail -c 子会话 jsonl 产生坏 UTF-8 毒化历史→下一请求 400（产品 bug#2 现场），末轮 400 零 token |
| 7 | 11-15 06:29 | 子（A2 子） | ses_6aaaac76…（child） | deepseek-flash | 0/0 | 0 | 子进程起跑 1.5s 即 llm 错误退出（exit=1，零 LLM 轮完成，session status=error）——零 token 行如实记 |
| 8 | 11-15 06:31 | 主#4（B2 腿） | ses_f26cebfe…→tsk_93ea38fb | deepseek-flash | 18141/1253 | 5 | 主会话 B2 腿：spawn→wait→read→return(拒)→rework 后，return 工具结果（整改词）含坏字节→续跑请求 400 死（bug#2 传导链：bash 坏字节→报告→整改词） |
| 9 | 11-15 06:31 | 子（B2 子） | ses_022224e5…（child） | deepseek-flash | 64030/3611 | 12 | 子智能体 B2：侦察+实测+write tree-report2.md+write 报告（交付物真实；其 bash 输出坏字节进工具结果，成为 bug#2 源头之一） |
| 10 | 11-15 06:40 | 主#5（M3：C 腿） | ses_9c659d00…→tsk_cee622c2 | deepseek-flash | 16195/950 | 4 | 主会话 M3：spawn C→wait→read→return(拒)→rework 落定；随后 read_result 工具结果（含 C1 报告文本）再现坏字节→续跑 400 死（bug#2 第三次，报告文件本身 UTF-8 合法——坏在工具结果→请求序列化段） |
| 11 | 11-15 06:41 | 子（C1） | ses_dc35b0b2…（child） | deepseek-flash | 34518/2081 | 8 | 子智能体 C1（坏任务书首跑）：重写 c_artifact.txt（74B/3 行真实交付）+write 报告——# VERDICT 表完美、md5 亲算 15539a24…如实 fail 行、无分隔行（真模型按格式令牌交付的正面实证） |

零模型脚注（不占行）：06:41 test_orch --e9-redrive 再派腿使用 dead_model.toml（127.0.0.1:1，零 provider 接触、零 token）spawn 子进程 ses_a4ba34f1… exit=1 5.6s——因 runner 轮询竞态误打在旧任务 tsk_93ea38fb 上（施工侧 bug，如实记）；该腿验证了 rework→再派→终局 collect→in_review 产品路径。

| 12 | 11-15 06:44 | 主#6（M4：AB 腿） | ses_7301833e…→tsk_fa1aa557 | deepseek-flash | 38775/1864 | 9 | 主会话 M4：spawn AB→wait→read→return(拒)。全程无 400（防毒纪律生效）；主模型亲抽交付物属实但结果文件为空（子漏写报告）→机械判 R-REPORT/R-HEADER fail→rework——判卷正确拒绝「报告缺失」 |
| 13 | 11-15 06:45 | 子（AB） | ses_9ce6e741…（child） | deepseek-flash | 100969/6429 | 12 | 子智能体 AB：侦察+write tree-report3.md（含 RECON）+复制/追加 write README2.md（3 处 TOKEN-A，两交付物真实完好）——但未把 # VERDICT 报告写入结果文件（0 字节），漏报告环节 |

## 总账（收工）

- **真模型调用进程（有 LLM 完成）恰 12 次 = 预算上限 12/12 满额，未超限**（行 1-6、8-13；行 7 为零 LLM 子进程行如实单列）。
- LLM 请求总数 89（主会话进程 40 + 子智能体进程 49，= DB occ_message assistant 行数）；tokens 合计 **in=501,802 / out=29,012**（源：/tmp/e10ws/sessions.db occ_message.usage_* 求和，全部 usage_est=0 即均为服务端真值）。
- 估算成本：按 deepseek-chat 牌价上界（$0.27/M in、$1.10/M out）约 **$0.17**；deepseek-flash 实际单价更低（以账单为准）。
- 另有零 provider 接触进程 2 个不占行：行 7 同款说明 + dead_model 再派腿（见脚注）。
- 交叉核对：见 /tmp/e10ws/verdict.md §记账核对（本账 13 行 ↔ DB 会话 13 个、usage 总额逐会话一致、occ_toolcall 60 行工具调用佐证）。


---

# ORCH-E10 复跑（修复波 62193c4 后真模型验收收口）

- 复跑日：2026-11-15 ｜ 现场：L1（192.168.245.136）｜ occ=62193c4 构建（make -j4 RC=0，二进制 11-15 07:26）
- 模型：deepseek-flash（缺省 ~/.aikernel/model.toml 只读，经复跑自建 t3-proxy 127.0.0.1:9443 → api.deepseek.com；key 零落日志）
- 工作区：/tmp/e10r ｜ DB：/tmp/e10r/sessions.db ｜ env：OCC_SME=off OCC_ORCH_TOOLS=1 OCC_AC=off ｜ 机读验收：/tmp/e10r/verdict2.md（27/30 断言过）
- 记账口径：同前半（一行=一次真模型 occ 进程调用）；预算 ≤8，实用 7（#8 留而未用），未超限。

| # | 时间 | 角色 | 会话/任务 | tokens(in/out) | LLM请求数 | 目的与结果 |
|---|------|------|-----------|----------------|-----------|-----------|
| 1 | 11-15 07:37 | 主（smoke） | ses_71b41d64…（无任务） | 2508/2 | 1 | 新建 t3-proxy 链路冒烟：rc=0，finish=stop，回复「收到」 |
| 2 | 11-15 07:37 | 主#1（AB 起跑） | ses_a7051f43…→tsk_24f7c2e0+tsk_d8038ad9 | 63535/2763 | 12 | A 双轮全流程（spawn→wait→read→return 拒→spawn+task_id 回炉→wait→read→再拒）+ 派发 B；**OCC_LOOP_MAX_STEPS=24 截断**于 B 收尾前（rc=0 finish=tool-calls） |
| 3 | 11-15 07:37 | 子（A1） | ses_eb243e64…（child） | 70964/2465 | 12 | README 追加真实达标（标题+TOKEN-A 在场）；**为找结果文件 bash 翻 DB/grep 场外脚本烧尽 24 步**，报告未写（虫R2 现场） |
| 4 | 11-15 07:38 | 子（A2 回炉） | ses_641a38c7…（child） | 88447/3044 | 12 | 同虫R2：交付在场、报告空，二度机械判 fail→rework 2/2 卡死（叠虫R1：brief rework_max=1 未生效，任务恒用缺省 2） |
| 5 | 11-15 07:38 | 子（B1） | ses_57094e13…（child） | 67353/3219 | 12 | tree-report.md（59 行含 RECON）真实交付；报告空（虫R2），机械判 R-REPORT/R-HEADER fail |
| 6 | 11-15 07:44 | 主#2（B 收口续跑） | ses_a7051f43…（--recover 续接） | 92867/2082 | 9 | B return 拒（如实）→ **spawn+task_id 回炉再派带 glob 发现教学** → wait→read→亲核→return pass=true→done（一次进程内闭环） |
| 7 | 11-15 07:45 | 子（B2 回炉） | ses_62beffbd…（child） | 22022/1227 | 5 | glob 教学生效：一次成型 # VERDICT 表（3 行机检令牌），机械判 pass n_hit=0，任务 **done+distill+子会话 archived** |

## 复跑总账

- 真模型进程调用 **7/8**（smoke 1 + 主 2 + 子 4），tokens **in=407,696 / out=14,802**（DB occ_message.usage_* 求和，usage_est 全 0 服务端真值），LLM 请求 63，工具调用留痕 65；成本上界（deepseek-chat 牌价）约 **$0.13**。
- 交叉核对：verdict2.md 27 断言内含逐项对账（会话 6=smoke+主+4子；主会话两进程拆行 63535+92867=156402 与库一致；tokens/请求全量对账一致）。
- 三任务终态：**B done 全链达成**（dispatch→result_file→result→verdict→rework→回炉 dispatch→result_file→result→verdict→done→distill+archived+budget 两轮基线）；**A 卡 rework 2/2**（交付物真实达标、二连拒+两轮整改词实证，因虫R1 未 escalate）；**C 未跑**（预算被虫R2 连锁耗尽，如实让位）。

## 复跑新虫清单（6 条，证据见 verdict2.md / DB / run/）

1. **R1（中危）spawn 丢弃 brief.rework_max**：occ_orch_spawn_opts 无该字段（orch.h:130-131 仅注释），tools.c task_spawn 解析后只进 brief_json 回显未传 C 路——occ_task 恒缺省 2。证据：A brief_json 尾 `"rework_max":1}` vs occ_task.rework_max=2。后果：A 二连拒后未升级。
2. **R2（高危）OCC_TASK_RESULT_FILE 沙箱内不可见**：修复波⑥渲染教子「写入环境变量 OCC_TASK_RESULT_FILE 指向的文件」，但 aik-sandbox bash 内该 env 为空——3 个子智能体全部无法定位结果文件（bash 翻 sessions.db/grep 场外脚本烧尽步数），报告恒空→机械判必 fail→回炉浪费。前半「AB 子漏写报告」疑同根因。workaround（本复跑 B2 实证）：brief context 教 glob 发现 /tmp/occ_orch_res_*。
3. **R3（设计缺口）OCC_LOOP_MAX_STEPS=24 静默截断**：loop.c:132 编译期常量；12 LLM 轮即止，rc=0、finish=tool-calls、会话 active。主可 --recover 续跑（本复跑已用），子无自动续跑——报告侧全灭的直接放大器。
4. **R4（低危）fileset 授权未强制**：子 write 出授权集外文件（/tmp/e10r/inspect2.py、inspect_tasks.py，已归档 run/child_droppings/）。
5. **R5（微小）orch.c OCC_TASK_ID env 注入块重复两遍**（约 L1015-1040，无害冗余）。
6. **R6（中危）distill 实体清单按字节截断破坏 UTF-8**：orch.c:1563 `"- %.160s\n"` 160 字节切片腰斩多字节字符且吞字节——B 任务 distill 事件 payload_json 落库即含 7 处非法 UTF-8（『：』EF BC 9A 截为 EF BC+\n 等）。严格解码方（本复跑 crosscheck 首读即炸）即断；修复波②净化只护请求出口，不护此写侧。

---

## C 终验（a85fb9a 修复波后 escalate 终迁移验收，2026-11-15 08:24-08:26）

- 现场：L1（192.168.245.136）｜ occ=a85fb9a 构建（make -j4 RC=0 无需重编；二进制 11-15 08:14 晚于全部源码 08:05-08:12）
- 工作区 /tmp/e10c ｜ DB /tmp/e10c/sessions.db ｜ env：OCC_SME=off OCC_ORCH_TOOLS=1 OCC_AC=off ｜ 机读验收 /tmp/e10c/verdict-c.md（**29/29 断言过**）
- 剧本：任务 C brief rework_max=1 + 故意坏验收哈希 md5:/tmp/e10c/c.txt=cbf945ff…（=md5("e10c-bad-acceptance")，对 TOKEN-C 不可达）→ 子两轮如实交付如实报真实哈希 → 两拒 → 回炉机会 1/1 用尽 → 自动 escalate
- 记账口径：同前（一行=一次真模型 occ 进程调用）；预算 ≤4，实用 **3**（主 1+子 2，主备用 1 次未用），未超限。

| # | 时间 | 角色 | 会话/任务 | tokens(in/out) | LLM请求数 | 目的与结果 |
|---|------|------|-----------|----------------|-----------|-----------|
| 1 | 11-15 08:24-08:25 | 主#1（C 全流程闭环） | ses_7b84d1d7…→tsk_f4ad1ea9 | 71120/3364 | 12 | 单进程跑完 spawn→wait→read→return 拒→rework→spawn+task_id 回炉→wait→read→再拒→escalate 确认+中文总结；finish=stop 未截断（R3 未复发），rc=0，墙钟 87 秒 |
| 2 | 11-15 08:24 | 子 C1（首交付） | ses_b3ef932c…（child） | 54695/2969 | 10 | 真改 c.txt=TOKEN-C（7B 无换行）+md5sum 亲算+# VERDICT 如实报 fail 行（真实哈希 abaa49bf…，不迎合坏哈希；R2 修复后子一步定位结果文件）→机械判 fail R-ROWPASS |
| 3 | 11-15 08:25 | 子 C2（回炉再交付） | ses_85f53701…（child） | 75420/4866 | 10 | 回炉两行表（md5+selfcheck）仍如实→机械判 fail R-ROWPASS+R-EVIDENCE→二拒→机会 1/1 用尽→**自动 escalated** |

### C 终验总账

- 真模型进程调用 **3/4**（主 1+子 2），tokens **in=201,235 / out=11,199**（DB occ_message.usage_* 求和，usage_est 全 0 服务端真值；t3-proxy 上游完成请求恰 32 与 DB assistant 行数严丝合缝），LLM 请求 32，工具调用留痕 32（主 11/C1 9/C2 12）；成本上界（deepseek-chat 牌价 $0.27/M in、$1.10/M out）≈ **$0.067**。
- 任务 tsk_f4ad1ea9…：终态 **escalated**（rework_max=1 全链传透生效；rework_count=2=fail 累计——第 1 次 fail 后机会 1/1 用尽进 rework，第 2 次 fail 超限升级）。事件序 dispatch→result_file→result→verdict→rework→dispatch→result_file→result→verdict→escalate 全链在库；两轮词齐备（rework_brief『验收不通过 第 1/1 次…剩余机会：0 次』+ escalate_brief『验收超限上抛（回炉 2/1 次已用尽）』）；交付物真实（/tmp/e10c/c.txt=TOKEN-C，md5=abaa49bf…≠坏哈希）。
- 三段累计（前半 12+复跑 7+C 终验 3=22 次）：tokens in 1,110,733 / out 55,013，成本上界合计 ≈ **$0.36**（E10 全程）。
