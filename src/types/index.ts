/** Bilingual text: either a plain string (treated as zh) or { zh, en } object */
export type I18nText = string | { zh: string; en: string };

export interface PayloadItem {
  id: string;
  name: I18nText;
  description: I18nText;
  category: I18nText;
  subCategory?: I18nText;
  tags: string[];
  prerequisites?: I18nText[];
  // P1-2 列表投影不含 execution（public-data 只发列表字段，详情按需拉取）：
  // 消费方必须做 undefined 兜底，详情级字段全部可选
  execution?: PayloadExecution[];
  analysis?: I18nText;
  opsecTips?: I18nText[];
  wafBypass?: PayloadExecution[];
  edrBypass?: PayloadExecution[];
  attackChain?: AttackChainStep[];
  references?: string[];
  tutorial?: TutorialContent;
  // 治理 M5：CVE/产品双通道预关联的 EXP 条目（≤3 条），详情页"相关 EXP"卡消费
  relatedExploits?: { id: string; name: string; source: string }[];
  // P1-2 首屏载荷瘦身：public-data 下发列表投影（详情级字段按需拉取），
  // commandCount/bypassCount 是搜索结果卡与详情模式切换需要的派生计数
  commandCount?: number;
  bypassCount?: number;
}

export interface PayloadExecution {
  title: I18nText;
  command: string;
  syntaxBreakdown?: SyntaxPart[];
  description?: I18nText;
  platform?: 'windows' | 'linux' | 'all';
  requiresAdmin?: boolean;
  /** 变体分类：bypass=真绕过，control=受控样例/基线对照（当前仅 wafBypass 域写入） */
  kind?: 'bypass' | 'control';
  /** 现代 WAF 有效性档位：A 普遍有效 / B 条件化 / C 教学价值需注明 */
  effectiveness?: 'A' | 'B' | 'C';
}

export interface SyntaxPart {
  part: string;
  explanation: I18nText;
  type?: 'command' | 'parameter' | 'value' | 'operator' | 'variable' | 'header' | 'technique' | 'format' | 'function' | 'keyword' | 'encoding' | 'method' | 'domain' | 'tag' | 'path' | 'json' | 'concept' | 'char' | 'tool-mode';
}

export interface AttackChainStep {
  title: I18nText;
  description: I18nText;
  payload?: string;
}

export interface TutorialContent {
  overview: I18nText;
  vulnerability: I18nText;
  exploitation: I18nText;
  mitigation: I18nText;
  difficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert';
}

export interface ToolCommand {
  id: string;
  name: I18nText;
  description: I18nText;
  category: I18nText;
  commands: ToolCommandItem[];
  installation?: I18nText;
  references?: string[];
  externalUrl?: string;
  systemLocked?: boolean;
}

export interface ToolCommandItem {
  name: I18nText;
  command: string;
  description: I18nText;
  syntaxBreakdown?: SyntaxPart[];
  examples?: I18nText[];
  platform?: 'windows' | 'linux' | 'all';
}

export interface ManagedCommand {
  id: string;
  name: I18nText;
  description: I18nText;
  command: string;
  platform: 'windows' | 'linux' | 'all';
  createdAt: string;
  updatedAt: string;
}

export interface ManagedToolCategory {
  id: string;
  name: I18nText;
  description?: I18nText;
  commands: ManagedCommand[];
  createdAt: string;
  updatedAt: string;
}

export interface SiteSettings {
  siteTitle: I18nText;
  siteSubtitle: I18nText;
  browserTitle: I18nText;
  logoIcon: string;
  logoUrl: string;
  projectUrl: string;
  xeyeEnabled: boolean;
  ctfEnabled: boolean;
}

export interface CheatJump {
  kind: 'payload' | 'tool';
  id: string;
}

export interface CheatEntry {
  id: string;
  title: { zh: string; en: string };
  summary: { zh: string; en: string };
  snippet?: string;
  tip?: { zh: string; en: string };
  jump?: CheatJump;
  // 解题动作序列（批次 B 动线扩展，可选）：一行一步一命令，如 ORDER BY 探列数→UNION 回显→查库→查表→查数据。
  steps?: { title: { zh: string; en: string }; snippet: string }[];
  // 一行一变体的绕过清单（可选）：空格/等号/分号等被过滤时的替代写法。
  variants?: string[];
}

export interface CheatSheet {
  entries: CheatEntry[];
}

export interface PublicData {
  settings: SiteSettings;
  payloads: PayloadItem[];
  tools: ToolCommand[];
  navigation: NavItem[];
  toolNavigation: NavItem[];
  // 内容性元数据（硬编码治理批）：默认全局变量与 CTF 速查由 DB 权威下发。
  globalVariables?: GlobalVariable[];
  ctfCheatsheets?: Record<string, CheatSheet>;
  exploits?: ExploitItem[];
  exploitNavigation?: NavItem[];
}

export interface PublicClientBuildItem {
  targetId?: string;
  platform: 'windows' | 'linux' | 'macos' | string;
  platformLabel: string;
  arch: string;
  archLabel: string;
  format: string;
  fileName: string;
  size: number;
  sha256: string;
  generatedAt: string;
  productName?: string;
  runtime?: string;
  distribution?: string;
  buildContractVersion?: number;
  codeSigningConfigured?: boolean;
  signingStatus?: 'configured' | 'unsigned' | string;
  mimeType?: string;
  downloadUrl: string;
  cpuFamily?: string;
  minOsVersion?: string;
  installType?: string;
  packageManager?: string;
  buildSource?: 'native-host' | 'official-shell' | string;
  shellVersion?: string;
  shellSha256?: string;
  performanceNotes?: string[];
  securityNotes?: string[];
  notes?: string[];
}

export interface PublicClientTargetInfo {
  id: string;
  platform: string;
  platformLabel: string;
  arch: string;
  archLabel: string;
  format: string;
  extension: string;
  recommended?: boolean;
  supported?: boolean;
  selectedByDefault?: boolean;
  reason?: string;
  cpuFamily?: string;
  minOsVersion?: string;
  installType?: string;
  packageManager?: string;
  requiresSigningNote?: string;
  source?: 'native-host' | 'official-shell' | 'unavailable' | string;
  shellVersion?: string;
  shellSigned?: boolean;
}

export interface PublicClientBuildInfo {
  available: boolean;
  latest: PublicClientBuildItem | null;
  offlineClient?: boolean;
  items?: PublicClientBuildItem[];
  generatedAt?: string;
  productName?: string;
  runtime?: string;
  distribution?: string;
  buildContractVersion?: number;
  codeSigningConfigured?: boolean;
  lastBuildFailed?: boolean;
  publicStats?: {
    payloads?: number;
    tools?: number;
    navigation?: number;
    toolNavigation?: number;
  };
  staleLatest?: {
    buildContractVersion?: number;
    runtime?: string;
    distribution?: string;
    generatedAt?: string;
  } | null;
  freshness?: {
    isCurrent: boolean;
    sourceCurrent: boolean;
    publicDataCurrent: boolean;
    reasons: string[];
    checkedAt: string;
  };
  targets?: PublicClientTargetInfo[];
  policies?: {
    performance?: Record<string, unknown>;
    security?: Record<string, unknown>;
  };
}

export interface NavItem {
  id: string;
  name: I18nText;
  icon?: string;
  children?: NavItem[];
  payloadId?: string;
  toolId?: string;
  exploitId?: string;
  /** EXP 分类树类型节点的全库入口标注（展示层注入，非库数据） */
  vulnType?: string;
}

export interface GlobalVariable {
  key: string;
  value: string;
  description: I18nText;
  group?: string;
}

export interface TreeNode {
  id: string;
  name: I18nText;
  children?: TreeNode[];
  isExpanded?: boolean;
  isSelected?: boolean;
  payloadId?: string;
  toolId?: string;
  exploitId?: string;
  icon?: string;
}

// ---- EXP 漏洞利用库（v2.0.2）：结构化字段机器可读优先，公开 API 与前端共用这份数据 ----

export interface ExploitVulnerabilityId {
  type: string;
  value: string;
}

export interface ExploitCodeSegment {
  title: string;
  language: string;
  code: string;
  description?: string;
}

// unknown = NVD 无评分且无官方模板档的诚实未评级态（不编造中危）
export type ExploitSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export interface ExploitItem {
  id: string;
  name: string;
  description: string;
  vulnType: string;
  affected: string;
  severity: ExploitSeverity;
  publishedAt: string;
  vulnerabilityIds: ExploitVulnerabilityId[];
  exploitCode: ExploitCodeSegment[];
  prerequisites: string;
  references: string[];
  tags: string[];
  attribution?: {
    source?: string;
    author?: string;
    license?: string;
  };
  /** 上游聚合来源标记（如 exploit-db）；缺省为精选/手工层 */
  source?: string;
  /** 上游主键（如 edb-12345），聚合管线幂等复用 */
  sourceRef?: string;
  /** 分类挂载路径（大类/类型/叶子 id） */
  treePath?: string;
  /** dedupe=canonical 聚合后该漏洞的来源总数（仅代表条目携带） */
  sourceCount?: number;
  /** 同 canonicalKey 的其他来源条目（/api/exploits/:id 详情接口附带，来源折叠区消费） */
  relatedSources?: { id: string; source: string }[];
}
