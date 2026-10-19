# Payloader Design Tokens 清单

> 来源：`src/styles/global.css`（前台唯一 token 源）。纪律：**全站颜色必须走 token，禁止硬编码色值**；半透明变体用 `color-mix(in srgb, <token> N%, transparent)`，不要再写 rgba 字面色。
> 2026-10-09 D1 重做：暗色从青灰调改为 GitHub Primer 风近黑三层，主 accent 由荧光青 `#42ced0` 收敛为科技蓝 `#4c8dff`（亮色 `#0969da`）。

## 背景层（三层近黑，层次=面板关系）

| Token | 暗色 | 亮色 | 用途 |
|-------|------|------|------|
| `--bg-primary` | `#0d1117` | `#f4f6f8` | 页面底 |
| `--bg-secondary` | `#11161d` | `#e9eef2` | 次层/代码块底 |
| `--bg-card` | `#161b22` | `#ffffff` | 卡片/面板 |
| `--bg-tertiary` | `#1c2128` | `#f6f9fc` | 嵌套/输入框底 |
| `--bg-hover` | `#212933` | `#eef3f8` | hover 态 |
| `--bg-active` | `#29323d` | `#e3ebf3` | active 态 |

## 主 accent（单一主色，克制点睛）

| Token | 暗色 | 亮色 | 用途 |
|-------|------|------|------|
| `--accent` | `#4c8dff` | `#0969da` | 链接/激活/主按钮/检索焦点 |
| `--accent-strong` | `#6ea4ff` | `#0550ae` | focus ring/hover 加深 |
| `--accent-contrast` | `#ffffff` | `#ffffff` | accent 实底上的文字 |
| `--accent-soft` | 14% mix | 10% mix | accent 半透明底（tab 激活/chips） |
| `--accent-border` | 45% mix | 40% mix | accent 系细边 |

## 文本三级（暗底实测对比：主 12.9:1 / 次 7.1:1 / 弱 4.9:1，全过 AA）

| Token | 暗色 | 亮色 | 用途 |
|-------|------|------|------|
| `--text-primary` | `#e6edf3` | `#1f242b` | 标题/正文 |
| `--text-secondary` | `#9da7b3` | `#4d5761` | 次级说明 |
| `--text-muted` | `#7d8b9b` | `#5a6672` | 弱化/标签/辅助 |
| `--text-tertiary` | =muted | =muted | 兼容别名 |

> 偏差记录：需求原值 `--text-muted: #6e7a89` 在卡片底 `#161b22` 上仅 3.9:1，不达 AA，提亮至 `#7d8b9b`（4.9:1），观感基本一致。

## 边框

| Token | 暗色 | 亮色 | 用途 |
|-------|------|------|------|
| `--border-color` | `rgba(240,246,252,0.1)` | `#d7dee6` | 常规边框 |
| `--border-strong` | `rgba(240,246,252,0.22)` | `#b3bfca` | 强边框/滚动条 |
| `--border-glow` | =accent-border | =accent-border | 兼容别名 |
| `--focus-ring` | =accent-strong | =accent-strong | 键盘焦点 |

## 严重度语义色阶（全站统一：卡片徽标/详情/后台共用）

| Token | 暗色 | 亮色 | 语义 |
|-------|------|------|------|
| `--sev-critical` | `#f85149` | `#cf222e` | 严重（红） |
| `--sev-high` | `#d29922` | `#bc4c00` | 高危（橙） |
| `--sev-medium` | `#e3b341` | `#9a6700` | 中危（黄） |
| `--sev-low` | `#539bf5` | `#0550ae` | 低危（蓝） |
| `--sev-*-bg` | 14% mix | 14% mix | 徽标半透明底 |

## EXP 来源色（同一形态不同色相）

| Token | 暗色 | 亮色 | 来源 |
|-------|------|------|------|
| （精选=accent 描边形态，用 accent 族） | | | curated |
| `--src-exploit-db` | `#539bf5` | `#0550ae` | Exploit-DB（蓝） |
| `--src-nuclei` | `#a371f7` | `#8250df` | Nuclei（紫） |
| `--src-gh-poc` | `#3fb950` | `#1a7f37` | GitHub PoC（绿） |
| `--src-metasploit` | `#56d4dd` | `#0997b3` | Metasploit（青/深蓝） |

## 状态色

| Token | 暗色 | 亮色 | 语义 |
|-------|------|------|------|
| `--state-success` | `#3fb950` | `#1a7f37` | 成功/复制完成 |
| `--state-warning` | `#d29922` | `#9a6700` | 警告 |
| `--state-danger` | `#f85149` | `#cf222e` | 错误/危险 |

## 代码高亮（bash/python/yaml/http 四语共用）

| Token | 暗色 | 亮色 | 语义 |
|-------|------|------|------|
| `--code-comment` | `#768390` | `#6e7781` | 注释 |
| `--code-string` | `#a5d6ff` | `#0a3069` | 字符串/URL |
| `--code-keyword` | `#ff7b72` | `#cf222e` | 关键字 |
| `--code-number` | `#79c0ff` | `#0550ae` | 数字 |
| `--code-function` | `#d2a8ff` | `#8250df` | 函数（预留） |
| `--code-meta` | `#ffa657` | `#bc4c00` | flag/变量/头名 |

## 阴影

| Token | 暗色 | 亮色 | 用途 |
|-------|------|------|------|
| `--shadow-card` | `0 4px 20px rgba(0,0,0,.5)` | `0 2px 12px rgba(23,32,42,.08)` | 卡片静态 |
| `--shadow-lift` | `0 6px 18px rgba(0,0,0,.42)` | `0 6px 16px rgba(23,32,42,.1)` | hover 上浮 |
| `--shadow-neon` | accent 22% glow | accent 16% glow | 焦点强调（克制） |

## 兼容桥（历史引用自动跟随新体系）

`--neon-cyan`→`--accent`、`--neon-purple`→`--src-nuclei`、`--neon-green`→`--state-success`、`--neon-red`→`--sev-critical`、`--neon-orange`→`#f0883e`、`--neon-yellow`→`--sev-medium`、`--neon-blue`→`--sev-low`、`--neon-pink` 保留原值。
**新代码一律用语义 token 正名，不再新增 `--neon-*` 引用。**

## Mantine 主题

`src/theme/mantineTheme.ts`：`accent` 十阶色板（index 3 = `#4c8dff`），`primaryColor: 'accent'`。Mantine 组件（Menu/SegmentedControl/notifications）自动协调。

## 管理后台（admin/admin.css，独立 token 域）

admin 不加载 global.css，token 自带于 `:root`（当前固定亮色）。accent 族已对齐前台亮色值（`#0969da`/`#0550ae`），severity/来源语义色同值定义。admin 暗色化属后续版本范围（P2 记录）。

## 颜色 audit 豁免记档（2026-10-09）

以下字面色为**中性系**（不随主题色相变化，属标准做法），审计豁免：

- 纯黑 alpha 阴影/遮罩：`rgba(0,0,0,…)`（--shadow-card/--shadow-lift 定义、header/syntax-modal/sidebar 的弹层遮罩、global 的移动端抽屉 backdrop）
- 纯黑 `#000`（ctf-forensics 一处画布背景）
- global.css `:root`/`[data-theme]` 定义区内的全部字面值 = token 定义本身

CTF 域信号色（红/绿/黄）已于本轮全部映射到 `--sev-*`/`--state-*`（color-mix 半透明变体），无残留。

## 断点阶梯记档（2026-10-09）

项目现有断点：1280 / 1180 / 1100 / 900 / **720**（EXP 筛选折叠）/ 680 / 640 / 520 / **400**（EXP 分页紧凑）/ 420 / 360 / 340。720 与 400 为本轮新增（exploit.css 专用），其余为存量；后续新增断点优先复用 680/360 阶梯。

## 已知遗留（P2 记账）

- `src/components/ctf/EntropyMapCard.tsx` canvas `fillStyle 'rgba(0,240,255,…)'`：canvas 无法直接消费 CSS var，需 getComputedStyle 解析，待专项。
- admin.css 侧栏暗底 `#4f96f4` 指示条：on-dark 变体，暗色化时统一处理。
- `--login-focus-green` 变量名与用途（装饰渐变）语义失真，待更名。
- Safari <16 的 `display:contents` 历史 a11y bug：目标基线 Chrome 111+，记账。
- 代码行号列 `flex: 0 0 3ch` 超 999 行会挤压，待专项。
