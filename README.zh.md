# dsh-kaspersky

一个 [DSH](https://github.com/deepseek-ai) 宿主插件：监听卡巴斯基，当杀软删除了 agent 刚写出的产物时，把报毒信息推送给 agent。

实时防护会在文件写入后几秒内删掉构建产物、测试样本或下载的二进制。agent 眼看着自己刚写的文件凭空消失——原因它观察不到——于是重新生成，循环往复。卡巴斯基不会告诉 harness 任何事。这个插件补上这段：

1. **监听卡巴斯基。** 轮询 `avp.com` 的查杀计数——这是该产品唯一不需要密码就能读到的信号。
2. **把报毒信息推送给 DSH。** 当 agent 最近写出的文件消失时，插件把消息推给 agent：列出所有消失的路径、计数变化、以及威胁报告的位置。
3. **提醒代码可能有恶意。** 消息中明确写出：刚才生成的代码可能包含恶意代码，先查源码再重新生成。

## 工作原理

两次轮询，一条消息。

```
avp.com STATISTICS File_Monitoring   →  "Total detected: 21"   ─┐
                                                                 ├─→ followup(agent)
工作区扫描（15 秒）                   →  build.exe 消失了        ─┘
```

* **计数**来自 `avp.com STATISTICS <profile>`：不需要登录，单调递增，两次轮询之间上升即代表杀软刚刚检出并处理了东西。
* **删除**来自账本：插件每次轮询遍历每个活动会话的工作目录，与上一次遍历做差。之前存在、现在没了、且写入时间在 `artifactMaxAgeMs` 之内的文件，就是被删掉的产物。
* **消息**通过 `agent.followup(...)` 投递（会唤醒 agent），且只推给工作目录覆盖了被删文件的 agent。

### 诚实规则

如果计数**没有**上升，消息会写明「删除原因未测量」，不会断言是卡巴斯基干的。一个在构建脚本清理目录时就大喊「杀软吃了你的文件」的插件，比没有插件更糟。标题随证据变化：

| 计数 | 标题 |
| --- | --- |
| 上升 | 卡巴斯基删除了刚生成的产物 |
| 未变化 | 工作区里有刚生成的产物消失了 |

### 受登录限制的部分

威胁**名称**只在 `avp.com REPORT <profile> /RA:<file>` 里，而该命令要求 `/login=` 与 `/password=`，没有凭据就拒绝写文件。配置了凭据，告警会指向报告文件；没配置，告警会说明名称未能获取。

## 安装

用插件管理器安装本 bundle（`install_bundle`，指向本目录的绝对路径），或把它作为 profile bundle 加入。清单是标准形式：

```yaml
# cordis.patch.yml
- insert:
    - id: kaspersky-guard
      name: dsh-kaspersky
      config: {}
```

所有配置项都可选。profile 级对该行的覆盖会**整体替换** `config` 对象，所以要保留的键必须一并写上。

| 键 | 默认值 | 含义 |
| --- | --- | --- |
| `avp` | `''` | 要运行的 `avp.com`。留空则在 `C:\Program Files*\Kaspersky Lab\Kaspersky *\` 下自动查找。 |
| `statisticsProfile` | `File_Monitoring` | 监听哪个防护组件的计数。 |
| `pollMs` | `15000` | 工作区扫描间隔。 |
| `timeoutMs` | `20000` | 单次 `avp.com` 调用的超时。 |
| `counterRefreshMs` | `300000` | 在没有文件消失时，多久刷新一次计数基线。 |
| `paths` | `[]` | 在「所有会话工作目录」之外额外监视的目录。 |
| `ignore` | `["node_modules", ".git"]` | 扫描时永不进入的目录名。 |
| `maxFiles` | `50000` | 每个工作区每次扫描最多记录的文件数。 |
| `artifactMaxAgeMs` | `7200000` | 只有在此时间窗内写过的文件才算「刚生成的产物」。 |
| `minAlertIntervalMs` | `30000` | 两条推送告警之间的最小间隔。 |
| `login` / `password` | `''` | `avp.com` 凭据，用于获取威胁名称。 |

插件还会往系统提示词里加一小段说明，让 agent 在触发之前就知道这道守卫存在。

## 验证

```console
$ npm test
```

测试覆盖：用实测的 `avp.com` 输出原文校验计数解析；用真实临时目录校验账本；两种计数结果下的消息文本；以及用替身 Cordis 上下文驱动 `apply()`——其中包括「被删产物确实送达 `agent.followup`」。最后一组是实机探针，未安装 `avp.com` 时自动跳过。

在 Windows 上的卡巴斯基 21.26（KAVKISKTS，中文版）实测：`avp.com STATUS` 与 `avp.com STATISTICS` 无需登录；`avp.com REPORT` 与 `avp.com TRACES` 会打印 `Login required:` 并要求凭据。该产品在 Windows 事件日志里没有卡巴斯基通道，`ProgramData\Kaspersky Lab\AVP*\Report\Database\reports.db` 又被自我保护挡住——这就是为什么用计数作为信号。

## 局限

* 靠轮询发现删除：在两次扫描之间被删掉又重建的文件看不见。`fs.watch` 在高负载下会丢事件，而遍历是确定性的。
* 账本只记录路径、大小和修改时间——从不读取文件内容。
* 没有凭据时，告警只能说明「检出了东西」，说不出「检出了什么」。
* 仅限 Windows、仅限 `avp.com`。其他杀软有自己的计数。

## 许可证

MIT
