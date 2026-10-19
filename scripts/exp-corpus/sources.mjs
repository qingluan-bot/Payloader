// 聚合管线数据源常量（唯一事实源）：上游 URL 与列契约集中在此。
// 2026-09-27 取证：Exploit-DB 权威仓库 2022-11 起在 GitLab，GitHub 侧已归档死链，
// 任何新增 GitHub 路径都必须先取证（教训在案，勿凭记忆写 URL）。

export const EDB_CSV_URL = 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv';
// EDB 正文仓（codeload zip）：file 列即正文路径（exploits/...），含可直接执行脚本与 HTTP POC 正文
export const EDB_ZIP_URL = 'https://gitlab.com/exploit-database/exploitdb/-/archive/main/exploitdb-main.zip';

// Metasploit 官方 exploit 模块（codeload zip）：exploits/**/*.rb，msfconsole 直接 use 的高质量脚本
export const MSF_ZIP_URL = 'https://codeload.github.com/rapid7/metasploit-framework/zip/refs/heads/master';
export const MSF_MODULE_URL = modulePath => `https://github.com/rapid7/metasploit-framework/blob/master/${modulePath.replace(/^exploit\//, 'exploits/')}.rb`;
// 单条正文上限：超限截断入库（原文经 references 直达），防个别巨型文件撑爆 data 列
export const MAX_CODE_BYTES = 64 * 1024;

// files_exploits.csv 表头（2026-09-27 实测 17 列）；列数不符视为上游结构变化，管线显式报错
export const EDB_CSV_COLUMNS = [
  'id',
  'file',
  'description',
  'date_published',
  'author',
  'type',
  'platform',
  'port',
  'date_added',
  'date_updated',
  'verified',
  'codes',
  'tags',
  'aliases',
  'screenshot_url',
  'application_url',
  'source_url',
];

export const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
// 实证约束（2026-09-27）：121 天窗口 / resultsPerPage=2001 均 404 拒绝
export const NVD_MAX_WINDOW_DAYS = 120;
export const NVD_PAGE_SIZE = 2000;

// Nuclei Templates（第二聚合源，2026-09-27 纳入）：codeload zip 整仓下载（缓存复用，删缓存刷新）
export const NUCLEI_ZIP_URL = 'https://codeload.github.com/projectdiscovery/nuclei-templates/zip/refs/heads/main';
export const NUCLEI_RAW_URL = path => `https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/${path}`;
// 只收 CVE 检测与厂商漏洞两个目录（CVE N-day 主体 + 护网季国内厂商漏洞），跳过 misconfig/exposures 等噪音面
export const NUCLEI_INCLUDE_PREFIXES = ['/http/cves/', '/http/vulnerabilities/'];

// GitHub PoC 聚合源（第三聚合源，2026-09-27 纳入）：trickest/cve 数据集（MIT，每日更新，
// "almost every publicly available CVE PoC"）。codeload zip 整仓（数万 CVE md），十年窗口 = 2016 起
export const POCGH_ZIP_URL = 'https://codeload.github.com/trickest/cve/zip/refs/heads/main';
export const POCGH_BLACKLIST_URL = 'https://raw.githubusercontent.com/trickest/cve/main/blacklist.txt';
// 十年窗口：只解析 2016-2026 年目录的 CVE md（更早目录跳过，省下载后解析时间）
export const POCGH_MIN_YEAR = 2016;
export const POCGH_MD_PATTERN = /\/(20[01]\d|202[0-9])\/(CVE-\d{4}-\d{4,7})\.md$/;

export const OSV_QUERYBATCH_URL = 'https://api.osv.dev/v1/querybatch';
// CVE↔GHSA 互查通道：querybatch 不接受 CVE 主键（实测 400，2026-09-27），逐条 GET 可行；
// 官方 FAQ 明文当前无速率限制，管线仍限并发 + 失败阈值
export const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns';
export const OSV_CONCURRENCY = 8;

export const EDB_PAGE_URL = edbId => `https://www.exploit-db.com/exploits/${edbId}`;
export const EDB_FILE_URL = file => `https://gitlab.com/exploit-database/exploitdb/-/blob/main/${file}`;
export const NVD_CVE_URL = cve => `https://nvd.nist.gov/vuln/detail/${cve}`;
export const GHSA_URL = ghsa => `https://github.com/advisories/${ghsa}`;
