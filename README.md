# SuperMerge (Cloud Edition)

把多个免费节点订阅合并成一个 Clash Meta YAML，并用 **GitHub Actions 每 3 小时自动重建**，
手机/电脑直接拉公网链接即可，**完全不依赖本机电脑开机**。

## 手机怎么用
在手机 Clash（Clash for Android / OpenClash / Stash / Shadowrocket 等）里，
把下面任一链接作为「订阅链接」导入：

- 首选（jsDelivr CDN，国内相对稳）：
  `https://cdn.jsdelivr.net/gh/<你的用户名>/<仓库名>@main/SuperMerge.yaml`
- 备用（GitHub 原生 raw）：
  `https://raw.githubusercontent.com/<你的用户名>/<仓库名>/main/SuperMerge.yaml`

导入后，想刷新节点只需在 App 里点「更新订阅」即可，无需开电脑。
（若两个链接都被墙，再考虑加一层 Cloudflare Worker 反代，按需再加。）

> **客户端要求（重要）**：本配置含大量 `vless` 与 `hysteria2` 节点（实测 vless 约占 73%），
> **必须使用 Meta 内核（mihomo）客户端**：Clash Meta for Android (CMFA)、FlClash、
> Clash Verge Rev、OpenClash、Stash、Shadowrocket 等。
> **原版 Clash for Android（Dreamacro/kr328 旧内核）不支持 vless**，导入会直接报
> `unsupport proxy type: vless`。
> 换客户端是推荐做法；若坚持用旧内核，只能过滤出 `ss/ssr/vmess/trojan`（约 21% 节点）。

> jsDelivr 对分支引用有数小时缓存，构建后 workflow 会自动调用 purge 接口刷新，
> 因此手机拉到的始终是最新一版。若发现手机端仍是旧节点，手动访问一次
> `https://purge.jsdelivr.net/gh/<用户名>/<仓库名>@main/SuperMerge.yaml` 即可强刷。

## 文件说明
- `super_merge.py`：合并脚本（零第三方依赖），输出 `SuperMerge.yaml`
- `sources.txt`：订阅源列表，一行一个 URL，`#` 开头为注释
- `.github/workflows/build.yml`：定时构建 + 自动提交
- `publish.bat`：首次把仓库推送到 GitHub 的一键脚本

## 订阅源（17 个，2026-09-14 扩充）

筛选标准：**近 1 天内有推送**、**star 数达标（约 ≥900）**、**payload 为纯文本节点列表**。

| 仓库 | star | 更新频率 | 规模 |
|---|---|---|---|
| free-nodes/v2rayfree | 13.7k | 每日 | ~1600 |
| ermaozi/get_subscribe | 9.3k | 每日 | ~250 |
| free18/v2ray | 5.4k | 每日 | ~360 |
| mahdibland/V2RayAggregator | 4.0k | 每日 | ~4000 |
| peasoft/NoMoreWalls | 3.5k | 每日 | ~170 |
| Epodonios/v2ray-configs | 3.2k | 每 5 分钟 | 1000 分片 × 500 |
| Barabama/FreeNodes | 3.2k | 每日 | ~7000 |
| barry-far/V2ray-Config | 2.4k | 每 15 分钟 | ~7900 |
| snakem982/proxypool | 2.1k | 每日 | ~50 |
| roosterkid/openproxylist | 920 | 每小时 | ~150 |
| Pawdroid/Free-servers | 19.1k | 每 6 小时 | 核心源 |
| zhuhaiuk / 0xRadikal / Au1rxx | — | — | 核心源 |

被**排除**的仓库（原因已写在 `sources.txt` 注释里）：只发 Clash YAML 没有链接/base64
payload（free-nodes/clashfree、OpenRunner、Jsnzkpg）、payload 太小（awesome-vpn 仅 24 个）、
无 payload（hwanz）、仓库内带可执行文件（Leon406/SubCrawler，含 `.exe`/`.bat`/`.jar`）、
内容与已收录源完全重复（chengaopan，与 peasoft 逐字节相同）、
已停更（freefq、VPN-Subcription-Links、vxiaov、flik6 等）。

### 安全边界
- 每个源**只下载一个纯文本文件**（HTTPS GET），**不下载、不执行**仓库里的任何代码或脚本。
- 目录里即使含 `.sh`/`.exe`（如 mahdibland、snakem982）也不会被触发——我们只取其中的数据文件。
- 但请注意：**免费节点本质上不可信**，中间人可以观察你的流量。
  不要用它登录网银/邮箱/公司系统，敏感操作请走自己的可信线路。

## 首次发布（只需做一次）
1. 在 GitHub 注册账号（免费，邮箱即可）。
2. 新建一个 **空** 公开仓库（名字随意，如 `super-subscription`）。
3. 生成 PAT：GitHub → Settings → Developer settings → Personal access tokens →
   Tokens (classic) → Generate new token（**同时勾选 `repo` 和 `workflow`**）→ 复制令牌。
   （`workflow` 是必须的：只勾 `repo` 时推送 `.github/workflows/` 会被服务端拒绝。）
4. 编辑 `publish.bat`，把 `USER` / `REPO` / `TOKEN` 改成你自己的，双击运行。
   （TOKEN 用完可在第 3 步页面吊销，不影响已发布的仓库。）
5. 推送成功后，GitHub 会自动跑一次 Actions 生成 `SuperMerge.yaml`。

## 之后怎么维护
- **加/减订阅源**：直接改 `sources.txt`，提交到 GitHub，Actions 下次自动重建。
- **立刻刷新**：到仓库的 Actions 页面，手动 Run workflow（已开启 `workflow_dispatch`）。
- **频率**：默认每 3 小时一次；想改就编辑 `build.yml` 里的 cron。

> 🔴 **提交纪律（踩过坑，务必遵守）：`SuperMerge.yaml` 是机器人产出的文件，本地永远不要提交它。**
> 它每 3 小时就被 Actions 重写一次；本地那份一旦也被提交，两边版本必然对不上，
> 推送时就会卡在 `CONFLICT (content): Merge conflict in SuperMerge.yaml`。
> `publish.bat` 已经改成**只提交 `super_merge.py` / `sources.txt` / `README.md` /
> `.gitignore` / `build.yml`**，并用 `git reset --mixed origin/main` 把提交直接挂到远端最新
> 提交之上（而不是 `rebase`），因此冲突在机制上不可能再发生。
> 自己手动敲命令时，**不要用 `git add .` / `git add -A`**，要显式列出文件名。

## 本地测试
```
set SUPER_USE_PROXY=1        # 走本机 Clash 代理抓源（raw 被墙时）
python super_merge.py        # 生成 SuperMerge.yaml 到本目录
```

## 排错：手机报 `yaml: control characters are not allowed`

**原因**：某个节点字段里混入了 YAML 非法控制字符（C0 除 tab/LF/CR、C1 的
U+007F–U+009F、BOM、U+FFFE/FFFF）。桌面 Clash 解析宽松能忍，**安卓端严格、整份拒收**。
`super_merge.py` 的 `yaml_str()` 已统一清洗并在写文件前断言，正常不会再出现。

若仍报错，按顺序排查（多半是**缓存**，不是文件本身）：

1. **确认仓库产出是否干净**（`illegal` 必须为 0）：
   ```
   curl -s "https://raw.githubusercontent.com/<用户名>/<仓库名>/main/SuperMerge.yaml" -o a.yaml
   python -c "import yaml;yaml.safe_load(open('a.yaml',encoding='utf-8'));print('OK')"
   ```
2. **强刷 jsDelivr**：`https://purge.jsdelivr.net/gh/<用户名>/<仓库名>@main/SuperMerge.yaml`
3. **手机端删掉旧配置重新导入**（App 可能保留了上次失败/旧下载的副本）。
4. **换备用链接**：`raw.githubusercontent.com` 无 CDN 缓存，内容永远是最新的；
   jsDelivr 的多个 CDN 供应商（Cloudflare/Fastly/Gcore/Bunny）缓存相互独立，
   个别边缘节点最长可能滞后约 12 小时才自然过期。

> 诊断技巧：加 `?cb=时间戳` 只对同一个 URL 去重有用，**不能**用来绕过 CDN 缓存
> （实测 jsDelivr 的缓存键不含 query string）。
