// 生成 v2.0.2 三库治理的 Payload overrides 文档（Lane C 产物合成器）。
// 从运行库快照各条目的 overrideContentFields 当前值，套用治理补丁
// （116 条 EN 描述重写 / 109 条 opsecTips·prerequisites 差异化 / 3 条版本边界标注），
// 合成 content-review/overrides-payload-gov-2026-09.json 并注册 manifest。
// 幂等可重放：补丁文件在 output/v202-governance/，脚本只依赖运行库与补丁。

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import * as sqlite from 'node:sqlite';

// node:sqlite 在 Windows 上打不开含非 ASCII 字符的绝对路径（errcode 14），
// 数据库一律用相对 cwd 的路径——本脚本必须从项目根运行（npm script 语义）。
const projectRoot = process.cwd();
const runtimeFile = resolve(projectRoot, 'data', 'payloader.sqlite');
const outputDir = resolve(projectRoot, 'output', 'v202-governance');
const reviewDir = resolve(projectRoot, 'content-review');
const outputFile = resolve(reviewDir, 'overrides-payload-gov-2026-09.json');
const manifestFile = resolve(reviewDir, 'manifest.json');
const GOVERNANCE_FILE = 'overrides-payload-gov-2026-09.json'; // manifest overrideFiles 模式约束 ^overrides-[a-z0-9-]+\.json$

const readJson = file => JSON.parse(readFileSync(file, 'utf8'));

const loadPatch = name => {
  const file = resolve(outputDir, name);
  return existsSync(file) ? readJson(file) : {};
};

const descA = loadPatch('desc-A.json');
const descB = loadPatch('desc-B.json');
const descC = loadPatch('desc-C.json');
const opsecA = loadPatch('opsec-A.json');
const opsecB = loadPatch('opsec-B.json');
const prereqFile = loadPatch('prereq-file.json');
const c2 = loadPatch('c2.json');

const descPatches = { ...descA, ...descB, ...descC };
const opsecPatches = { ...opsecA, ...opsecB };

const requiredFields = ['name', 'description', 'category', 'subCategory', 'tutorial', 'attackChain', 'references'];
const optionalFields = ['prerequisites', 'analysis', 'opsecTips', 'tags', 'wafBypass'];

const { DatabaseSync } = sqlite;
const { validatePayloadOverrideDocument } = await import(pathToFileURL(resolve(projectRoot, 'scripts', 'curate-payload-library.mjs')).href);
const database = new DatabaseSync(runtimeFile, { readOnly: true });
const rows = database.prepare('SELECT id, data FROM payloads').all();
const payloadsById = new Map(rows.map(row => [row.id, JSON.parse(row.data)]));

const patchIds = new Set([
  ...Object.keys(descPatches),
  ...Object.keys(opsecPatches),
  ...Object.keys(prereqFile),
  ...Object.keys(c2),
]);

const missing = [...patchIds].filter(id => !payloadsById.has(id));
if (missing.length) throw new Error(`补丁引用了库内不存在的 payload: ${missing.join(', ')}`);

const entries = [...patchIds].sort().map(id => {
  const source = payloadsById.get(id);
  const entry = { id };
  for (const field of [...requiredFields, 'review']) {
    if (source[field] !== undefined) entry[field] = structuredClone(source[field]);
  }
  // review 是策展文档侧字段，运行库 payload 不带（sanitize 剥离）；校验要求 decision 合法，补治理默认值
  if (!entry.review) entry.review = { decision: 'payload', rationale: 'v2.0.2 数据治理：描述/opsec/前置条件差异化重写' };
  for (const field of optionalFields) {
    if (source[field] !== undefined) entry[field] = structuredClone(source[field]);
  }

  if (descPatches[id]) {
    entry.description = {
      ...structuredClone(source.description),
      en: descPatches[id],
    };
  }
  if (c2[id]) {
    entry.description = {
      zh: `${entry.description.zh}${c2[id].descZhAppend}`,
      en: `${entry.description.en}${c2[id].descEnAppend ? ` ${c2[id].descEnAppend}` : ''}`,
    };
  }
  if (opsecPatches[id]) {
    if (!Array.isArray(entry.opsecTips) || !entry.opsecTips.length) {
      throw new Error(`${id}: opsecTips 补丁要求库内已有至少一条模板项`);
    }
    entry.opsecTips = [structuredClone(opsecPatches[id]), ...entry.opsecTips.slice(1)];
  }
  if (prereqFile[id]) {
    if (!Array.isArray(entry.prerequisites) || !entry.prerequisites.length) {
      throw new Error(`${id}: prerequisites 补丁要求库内已有至少一条模板项`);
    }
    entry.prerequisites = [structuredClone(prereqFile[id]), ...entry.prerequisites.slice(1)];
  }
  return entry;
});

const document = {
  schemaVersion: 1,
  contentStandard: 3, // 数字档位（2/3 合法，>=3 走 strict 12 字段比对）
  sourceIds: [...patchIds].sort(),
  entries,
};

// 自校验：对运行库 payload 全集跑官方校验器，0 错误才落盘
const payloadInput = rows.map(row => JSON.parse(row.data));
const errors = validatePayloadOverrideDocument(document, payloadInput, new Map());
if (errors.length) {
  const preview = errors.slice(0, 10).map(error => `${error.code}:${error.id}${error.detail ? ` (${error.detail})` : ''}`).join('\n');
  throw new Error(`overrides 文档校验失败 ${errors.length} 处:\n${preview}`);
}

writeFileSync(outputFile, JSON.stringify(document, null, 1));

const manifest = readJson(manifestFile);
if (!manifest.overrideFiles.includes(GOVERNANCE_FILE)) {
  manifest.overrideFiles.push(GOVERNANCE_FILE); // 置于数组末尾：同 id 多文档按声明顺序级联，治理批次最后声明最后胜出
  writeFileSync(manifestFile, JSON.stringify(manifest, null, 2));
}

const descCount = Object.keys(descPatches).length;
const opsecCount = Object.keys(opsecPatches).length;
const prereqCount = Object.keys(prereqFile).length;
const c2Count = Object.keys(c2).length;
console.log(`overrides-payload-gov-2026-09.json: ${entries.length} entries (desc ${descCount} / opsec ${opsecCount} / prereq ${prereqCount} / c2 ${c2Count}), 校验 0 错误, manifest 已注册`);
