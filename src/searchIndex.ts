import { getText } from './i18n';
import type { Language } from './i18n';
import type { ExploitItem, PayloadItem, ToolCommand } from './types';

export interface SearchIndex {
  payloadEntries: readonly SearchEntry[];
  toolEntries: readonly SearchEntry[];
  exploitEntries: readonly SearchEntry[];
}

export interface SearchMatches {
  payloadIds: ReadonlySet<string>;
  toolIds: ReadonlySet<string>;
  exploitIds: ReadonlySet<string>;
}

interface SearchEntry {
  id: string;
  text: string;
}

const searchableText = (values: Array<string | undefined>) => values
  .filter((value): value is string => Boolean(value))
  .join('\n')
  .toLowerCase();

const payloadSearchText = (payload: PayloadItem, language: Language, commandCorpusText = '') => searchableText([
  getText(payload.name, language),
  getText(payload.description, language),
  getText(payload.category, language),
  getText(payload.subCategory, language),
  ...payload.tags,
  ...(payload.prerequisites || []).map(item => getText(item, language)),
  // P1-2 列表投影不含 execution/wafBypass：命令文本来自延迟语料（payloadSearchCorpus），
  // 语料未到达时命令级搜索短暂回落为列表字段匹配，到达后自动补全
  ...commandCorpusText.split('\n').filter(Boolean),
]);

const toolSearchText = (tool: ToolCommand, language: Language) => searchableText([
  getText(tool.name, language),
  getText(tool.description, language),
  getText(tool.category, language),
  ...tool.commands.flatMap(command => [
    getText(command.name, language),
    getText(command.description, language),
    command.command,
  ]),
]);

// EXP 全文索引：编号/标题/产品/标签为检索主面（对应"按编号/产品一步命中"的用户路径）
const exploitSearchText = (exploit: ExploitItem) => searchableText([
  exploit.name,
  exploit.description,
  exploit.vulnType,
  exploit.affected,
  exploit.publishedAt,
  exploit.severity,
  ...exploit.vulnerabilityIds.flatMap(vid => [vid.type, vid.value]),
  ...exploit.tags,
  ...(exploit.exploitCode || []).map(segment => segment.title),
]);

const matchingIds = (entries: readonly SearchEntry[], normalizedQuery: string) => new Set(entries
  .filter(entry => entry.text.includes(normalizedQuery))
  .map(entry => entry.id));

export const buildSearchIndex = (
  payloads: PayloadItem[],
  tools: ToolCommand[],
  exploits: ExploitItem[],
  language: Language,
  payloadCommandCorpus: ReadonlyMap<string, string> = new Map(),
): SearchIndex => ({
  payloadEntries: payloads.map(payload => ({
    id: payload.id,
    text: payloadSearchText(payload, language, payloadCommandCorpus.get(payload.id) || ''),
  })),
  toolEntries: tools.map(tool => ({ id: tool.id, text: toolSearchText(tool, language) })),
  exploitEntries: exploits.map(exploit => ({ id: exploit.id, text: exploitSearchText(exploit) })),
});

export const matchSearchIndex = (index: SearchIndex, query: string): SearchMatches => {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    return { payloadIds: new Set(), toolIds: new Set(), exploitIds: new Set() };
  }

  return {
    payloadIds: matchingIds(index.payloadEntries, normalizedQuery),
    toolIds: matchingIds(index.toolEntries, normalizedQuery),
    exploitIds: matchingIds(index.exploitEntries, normalizedQuery),
  };
};
