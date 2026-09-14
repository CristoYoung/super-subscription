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

## 文件说明
- `super_merge.py`：合并脚本（零第三方依赖），输出 `SuperMerge.yaml`
- `sources.txt`：订阅源列表，一行一个 URL，`#` 开头为注释
- `.github/workflows/build.yml`：定时构建 + 自动提交
- `publish.bat`：首次把仓库推送到 GitHub 的一键脚本

## 首次发布（只需做一次）
1. 在 GitHub 注册账号（免费，邮箱即可）。
2. 新建一个 **空** 公开仓库（名字随意，如 `super-subscription`）。
3. 生成 PAT：GitHub → Settings → Developer settings → Personal access tokens →
   Tokens (classic) → Generate new token (勾选 `repo`) → 复制令牌。
4. 编辑 `publish.bat`，把 `USER` / `REPO` / `TOKEN` 改成你自己的，双击运行。
   （TOKEN 用完可在第 3 步页面吊销，不影响已发布的仓库。）
5. 推送成功后，GitHub 会自动跑一次 Actions 生成 `SuperMerge.yaml`。

## 之后怎么维护
- **加/减订阅源**：直接改 `sources.txt`，提交到 GitHub，Actions 下次自动重建。
- **立刻刷新**：到仓库的 Actions 页面，手动 Run workflow（已开启 `workflow_dispatch`）。
- **频率**：默认每 3 小时一次；想改就编辑 `build.yml` 里的 cron。

## 本地测试
```
set SUPER_USE_PROXY=1        # 走本机 Clash 代理抓源（raw 被墙时）
python super_merge.py        # 生成 SuperMerge.yaml 到本目录
```
