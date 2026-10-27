---
name: nuclei-scan
description: nuclei 模板化漏洞扫描：13,000+ 模板覆盖 CVE/暴露面/配置缺陷/默认口令，Nday 与 1day 的主力检测手段
whenToUse: 漏洞发现阶段拿到存活资产清单后，做 Nday/1day 批量检测；或已知组件版本想快速确认是否有现成模板
role: vuln-scan
enabled: true
---

# nuclei（模板化漏洞检测）

`nuclei` 是漏洞发现阶段的**主力**：一条命令覆盖 CVE、暴露面、错误配置、默认口令、未授权访问。
本机模板库已就位（详见下方路径），**不要上网重新找 POC**。

## 本机二进制与模板

| 项 | 值 |
| --- | --- |
| 二进制 | `/usr/bin/nuclei`（v3.11.1） |
| 模板库 | `~/.local/nuclei-templates`（**13,742 个模板**） |
| 模板版本 | v10.4.9（更新于 2026-09-18） |
| 配置 | `~/.config/nuclei/config.yaml`、`.templates-config.json` |

模板分布（写报告时按类引用）：`http/` 11,364（其中 `http/cves` 4,320、`http/misconfiguration` 981、
`http/vulnerabilities` 961、`http/exposures` 707、`http/default-logins` 307）、`cloud/` 663、`file/` 447、
`network/` 282、`dast/` 251。

**更新模板**：`nuclei -update-templates`（频率不超过每周一次；更新后先跑 `-tl` 确认没坏）。

## 核心法则：精准打击 vs 盲目全量（为什么别人能打通而 Nuclei 0 命中？）

很多时候"别人脚本能利用成功，Nuclei 却一无所获"，根因有三：
1. **缺少 `-fr`（跟进重定向）**：目标常有 http→https、加斜杠或跳转登录页。未加 `-fr` 时 Nuclei 停在 301/302，响应与 Matcher 错位，直接判定不匹配；
2. **User-Agent 触发 WAF 阻断**：Nuclei 默认带 `Nuclei - Open-source...` 头，绝大多数国内 WAF / 宝塔 / 阿里云直接 403 阻断；
3. **全量盲轰导致 IP 被封**：对多目标直接跑几千个模板，瞬间发包数万，前 10 秒即触发频控拉黑，后续全部白跑。

**正解：指纹识别先行 → 定向模板投掷（Targeted Precision Scan）**。

## 必带的「黄金参数组合」

每次执行 nuclei，**必须带上以下五大保障参数**：
- `-fr` (`--follow-redirects`)：**必须带**。跟进 301/302，避免跳转导致 Matcher 假阴性；
- `-insecure`：忽略自签证书、域名与 SNI 不匹配错误；
- `-H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"`：伪装正常浏览器，规避 WAF 的 Scanner UA 拦截；
- `-mhe 30`：避免目标有少量 403/超时就被 nuclei 判定为 Dead Host 而跳过整站；
- `-include-rr` (`-irr`)：落库 JSONL 中包含完整请求与响应报文，供 `redteam_http_evidence_add` 直取。

## 推荐命令模版

```bash
# 1) 定向单模板验证（最精准！用于已知组件/CVE精确打击）
nuclei -u https://target.example.com \
  -t http/cves/2024/CVE-2024-xxxx.yaml \
  -fr -insecure \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36" \
  -v -jsonl -o runs/nuclei-hit.jsonl

# 2) 针对已知 CMS / 组件（如 WordPress 插件、Weblogic、Nacos）
nuclei -u https://target.example.com \
  -tags wordpress,wp-plugin \
  -severity critical,high,medium \
  -fr -insecure \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36" \
  -rl 20 -c 10 -mhe 30 -duc \
  -include-rr -jsonl -o runs/nuclei-wp.jsonl

# 3) 多目标存活 URL 批量排查（控制并发，避免打死）
nuclei -l runs/alive-urls.txt \
  -tags cve,exposure,default-login \
  -severity critical,high \
  -fr -insecure \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36" \
  -rl 25 -c 10 -timeout 8 -mhe 30 -duc \
  -include-rr -jsonl -o runs/nuclei-$(date +%m%d-%H%M).jsonl
```

## 关键参数速查表

| 参数 | 作用 | 必须性 | 说明 |
| --- | --- | --- | --- |
| `-fr` | 跟进 301/302 重定向 | **强制** | 消除 80% 的假阴性（漏报） |
| `-insecure` | 跳过 SSL 证书校验 | **强制** | 防止自签证书 / IP 访问直接失败 |
| `-H "User-Agent: ..."` | 浏览器 UA 伪装 | **强制** | 绕过 WAF 针对 nuclei 的指纹黑名单 |
| `-mhe 30` | 最大主机错误容忍 | **强烈推荐** | 默认错误 5 次就弃用主机，需放宽 |
| `-include-rr` | 结果带 HTTP 请求/响应 | **强烈推荐** | 自动产生落库所需 evidence |
| `-rl 20` | 限速每秒请求数 | 推荐 | 防 CC/WAF 自动封 IP |
| `-v` / `-debug` | 显示详细交互过程 | 调试必用 | 排查为什么没命中 |

## 与知识库的配合（先查再打，禁止重复劳动）

动手前先 `redteam_poc_search`（按 CVE / 组件 / 版本 / 正文特征）——它一次查两层：**本机 POC 知识库 + 本机 nuclei 模板库**。
命中就用 `redteam_poc_get` 取全文或直接 `nuclei -t <模板>`；两层都没有才上网找，最后才手搓。

验证有效的新模板/EXP 用 `redteam_poc_add` 回填知识库（带 `category` + `engagement` + `asset_target` + `verified` + `verified_note`，脱敏本次靶标信息）。

## 降噪与自保（重要）

1. **默认 ignore 已排除危险标签**：`~/.config/nuclei/.nuclei-ignore` 里默认忽略 `dos`、`local`、`fuzz`、`bruteforce`、`txt-service`——
   **不要为了"打得更全"去掉这些忽略项**，DoS 类模板会打死生产系统，直接毁掉演练。
2. **先探测后开火**：先用 `-severity critical,high` 跑一轮；命中后再对具体命中项深入，不要一上来全量。
3. **WAF/封禁处理**：被拦先降 `-rl` 到 5 并加 `--delay 1s`，换 UA（`-H "User-Agent: ..."`），
   必要时用技能 `cn-proxy-pool` 换出口；**同一目标累计被封 >3 次立刻放弃**（`redteam_asset_test` status=abandoned + blocked=true），转向下一个目标。
4. **生产系统避开业务高峰**：定时任务、批量任务类模板（如触发同步/重建索引的）先在测试/预发资产上验证。

## 输出与落库（强制）

跑完立刻落库，**不要攒到最后**：

1. 读 `runs/nuclei-*.jsonl`，逐条 `redteam_vuln_add`：
   - `title`（模板名 + 命中点）、`severity`、`cve`（模板带的 `classification.cve-id`）、`target`（**带端口**）、
     `evidence`（命中回显/响应特征/matched-at）、`confidence=confirmed`（nuclei 命中即为已确认存在于响应层面）、
     `gained`（通过它能拿到什么）、`agent=vuln-scan`。
2. **每条确认漏洞配一条 `redteam_http_evidence_add`**：请求行 + Host + 关键请求头 + 响应摘要（模板的 `curl-command` 字段可直接用）。
3. 每个关键动作 `redteam_chain_add`：`stage_code=recon` 或 `internet`，
   `tool` 写**实际命令原文**（例如 `nuclei -l runs/alive-urls.txt -severity critical,high -rl 50 -jsonl -o runs/nuclei-0918.jsonl`），
   `result` 写回显摘要（例如 `命中 3 条：CVE-2023-xxxx（critical）…`）。
4. 测完该资产立刻 `redteam_asset_test` 回写：`status`（testing/tested/no_surface/blocked）、`test`（追加式结论）、`surface`（还剩什么可测）。
5. **只记能得分的面**：与得分无关的信息泄露、版本暴露、CORS/CSRF、SSL 与响应头类问题**最多记一行排除结论**，不深挖、不重复跑。

## 常见坑

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 一条不命中 | 1. 目标发生 301/302 重定向未跟进<br>2. 默认 UA 被 WAF 拦截（403）<br>3. 模板 Matcher 过于严苛（如要求 200 但实际 500 仍利用成功）<br>4. 路径未对齐（如 WP 装在 /wp/ 下） | 1. 务必加 `-fr` 与浏览器 UA；<br>2. 用 `curl -v` 或 `nuclei -debug` 手工看实际 HTTP 返回；<br>3. 若确认漏洞存在但 Nuclei Matcher 不匹配，**果断切到 Python / curl 验证**；<br>4. 检查是否需指定子路径目标 `-u http://target/wp/`。 |
| 大量 `could not resolve` | URL 清单里有死链 | 先用 `pd-httpx` 过滤存活：`pd-httpx -l all.txt -o alive-urls.txt -silent` |
| 命中一堆 low/info | severity 没限 | 演练加 `-severity critical,high,medium` |
| 目标被打挂 | 并发过高 / 跑了 dos 模板 | 降 `-rl`/`-c`；确认 ignore 文件没被动过 |
| 内网目标打不到 | 没走隧道 | 加 `-proxy socks5://127.0.0.1:<suo5端口>`（技能 `suo5-tunnel`） |
