# dsh-plugin-sentinel 🔒

[![Awesome DSH Plugin](https://awesome-dsh-plugin.com/badge.svg)](https://awesome-dsh-plugin.com)

**DSH 插件安检机** — 给 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 装一台插件安检机：在安装任何社区插件**之前**做纯静态安全审计，输出按严重度排序的结构化风险报告。

> 官方文档对 GitHub 安装方式的警告原话：`prepare` 脚本授权是 *"permission to execute the package's code on your machine at install time, outside any sandbox the agent runs under"*。DSH 生态 24 小时收录 288+ 社区插件——这台安检机就是为了让"先过安检再安装"成为一句话的事。

## 安装

```sh
dsh plugin --profile <你的profile> add github:<你的fork>/dsh-plugin-sentinel
# 或本地安装
dsh plugin --profile <你的profile> add ./dsh-plugin-sentinel
```

装好后对 DSH 说：

- 「帮我装 github:xxx/yyy 这个插件」→ 模型会先调 `audit_plugin` 过安检，`block` 则拒绝安装并说明风险
- 「巡检我当前 profile 装过的插件安不安全」→ `audit_installed`

## 提供的工具

| 工具 | 用途 |
|---|---|
| `audit_plugin` | 审计一个插件目录或 `.tgz` 压缩包：安装期脚本、动态执行、凭据读取、网络外传、patch 层 `!!js` 表达式、静默禁用安全行、路径穿越、软链接… |
| `audit_installed` | 巡检 profile 内全部社区 bundle（官方 `@deepseek-ai/*` 内置包标记 trusted 跳过） |

结论分级：`pass`（通过）/ `review`（需人工审查）/ `block`（建议拒绝）。风险分权重 critical=10 / high=5 / medium=2 / low=1。

## 安全设计：安检机自身的攻击面为零

| 决策 | 理由 |
|---|---|
| **零 npm 依赖、零安装脚本、零构建** | `package.json` 没有 scripts、没有 dependencies；从 GitHub 安装**不需要** pnpm `allowBuilds` 授权，不存在安装期执行 |
| **原生 JSON-Schema ToolDefinition 注册**（MCP 工具同款路径） | 全部源码只 import Node 内置模块，不依赖任何运行时包 |
| **纯 JS tar 解析**（`node:zlib` + 手写 ustar/pax/GNU-longname） | `.tgz` 审计全程在内存完成，被审计的恶意代码**不落盘**；全程不用 `child_process` |
| **词法剥离扫描**：先剥注释/字符串再匹配危险 API；模板 `${}` 插值内的代码保留 | 字符串和注释里写着 `eval(` 不算证据（防误报）；藏在插值里的代码跑不掉（防漏报） |
| **组合规则** | `process.env` 读取 × 网络出站 = 凭据外传特征（critical）；编码载荷 × 动态执行（critical）；shell × 网络（critical） |

## 审计覆盖（v0.1 规则表）

- **package.json**：安装期 lifecycle 脚本（critical）、伪装插件、运行时依赖
- **JS/TS 源码**：`child_process`、`eval`/`new Function`/`vm`、网络出站、`process.env`、文件写入、动态 require、homedir 探测
- **字符串字面量**：敏感路径（`.ssh`/`.env`/云凭据/DSH credentials）、外部 URL、长编码载荷（混淆特征）
- **cordis.patch.yml**：`!!js` 配置表达式（加载期宿主执行，critical）、`disabled: true` 静默禁用 sandbox/approval/guard 行（critical）、重配置安全行（high）、伪装安全行 id（high）
- **tarball 结构**：路径穿越（critical）、软链接（high）、异常档案

## 局限（诚实地写）

- 词法扫描器不是完整 AST——针对**蓄意构造**的规避手法（如把代码藏进插值内的伪注释）可能漏报；它面向捕获真实世界的常见恶意模式，不承诺对抗性完备。规则表在 `src/rules.js`，欢迎补充。
- `review`/`block` 是"值得人看一眼/建议拒绝"，最终决定权在人。

## 开发

```sh
node --test test/*.test.js   # 27 个用例：扫描器/规则/解析器/tar/注册契约/端到端
```

MIT License.
