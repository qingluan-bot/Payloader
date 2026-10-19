import { mkdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as sqlite from 'node:sqlite';
import {
  ensureDisplayTextObject,
  isObject,
  textValue,
} from './text-quality.mjs';
import {
  applyDataMigrations,
  excludedPublicToolIds,
  filterToolNavigation,
  initializeContentDatabase,
  isSystemNavigationNodeId,
  isSystemToolId,
  isXeyeEnabled,
  loadContentDataFromDatabase as _loadContentDataFromDatabase,
  loadDefaultDataFromSeedDb as _loadDefaultDataFromSeedDb,
  navigationTouchesSystemItem,
  prepareStoredPublicPayloadData,
  pruneSystemNavigationItem,
  readJsonMetadata,
  readMetadata,
  rowsToItems,
  runTransaction,
  seedIfNeeded,
  tableForResource,
  upsertItems,
  withProtectedSystemToolNavigation,
  withProtectedSystemTools,
  writeDefaultSeedDatabase as _writeDefaultSeedDatabase,
  writeMetadata,
  xeyeDisabledMetadataKey,
} from './migrations.mjs';
import {
  assertNoDemoPlaceholderContent,
  countResetState,
  createResetBackup,
  createResetImpact,
  executeImport,
  executeReset,
  makeSeedResetState,
  normalizeImportPackage,
  readResetState,
  validateResetTarget,
} from './import-export.mjs';
import { importSummary } from './import-template.mjs';

export { previewImportPackage } from './import-export.mjs';


export { curateSeedData, seedIncludedMigrationKeys } from './migrations.mjs';

export const loadDefaultDataFromSeedDb = (file = defaultSeedDbFile) => _loadDefaultDataFromSeedDb(file);
export const loadContentDataFromDatabase = (file = dbFile) => _loadContentDataFromDatabase(file);
export const loadDefaultData = async () => _loadDefaultDataFromSeedDb(defaultSeedDbFile);
export const writeDefaultSeedDatabase = (seedData, file = defaultSeedDbFile, source = 'database content seed') => enqueueMutation(() => _writeDefaultSeedDatabase(seedData, file, source));
import {
  defaultSettings,
  makeId,
  sanitizeExploit,
  sanitizeExploitNode,
  sanitizeNavItem,
  sanitizePayload,
  sanitizeSettings,
  sanitizeTool,
} from './sanitize.mjs';
import {
  invalidatePublicDataCache,
  readExploitCorpusCache,
  readPayloadFullCache,
  readPublicDataCache,
  withCacheInvalidation,
  writeExploitCorpusCache,
  writePayloadFullCache,
  writePublicDataCache,
} from './store-cache.mjs';

export { sanitizeExploit, sanitizeExploitNode, sanitizeNavItem, sanitizePayload, sanitizeSettings, sanitizeTool } from './sanitize.mjs';

export { createImportTemplate } from './import-template.mjs';

const { DatabaseSync } = sqlite;

const rootDir = fileURLToPath(new URL('..', import.meta.url));
const dataDir = resolve(process.env.PAYLOADER_DATA_DIR || join(rootDir, 'data'));
const dbFile = join(dataDir, 'payloader.sqlite');
const backupDir = join(dataDir, 'backups');
const defaultSeedDbFile = resolve(process.env.PAYLOADER_SEED_DB || join(rootDir, 'server', 'default-seed.sqlite'));

let db;
let dbInitialization;
let storeGeneration = 0;
let mutationQueue = Promise.resolve();
let storeTestHooks = {};

const now = () => new Date().toISOString();
const json = value => JSON.stringify(value ?? null);
const parseJson = value => {
  if (typeof value !== 'string' || value.length === 0) return null;
  return JSON.parse(value);
};




const protectedStoreError = message => {
  const error = new Error(message);
  error.status = 403;
  return error;
};

export const getDefaultSeedDbFile = () => defaultSeedDbFile;
export const getRuntimeDbFile = () => dbFile;

export const setStoreTestHooks = hooks => {
  const candidate = hooks && typeof hooks === 'object' ? hooks : {};
  storeTestHooks = {
    ...(typeof candidate.beforeInitializationPublish === 'function'
      ? { beforeInitializationPublish: candidate.beforeInitializationPublish }
      : {}),
    ...(typeof candidate.beforeResetBackup === 'function'
      ? { beforeResetBackup: candidate.beforeResetBackup }
      : {}),
  };
};

export const closeStore = () => {
  storeGeneration += 1;
  const initialized = Boolean(db);
  if (db) {
    db.close();
    db = undefined;
  }
  if (initialized || !dbInitialization) dbInitialization = undefined;
  invalidatePublicDataCache();
};

const enqueueMutation = work => {
  const operation = mutationQueue.then(work, work);
  mutationQueue = operation.then(() => undefined, () => undefined);
  return operation;
};



const initializeStore = async generation => {
  await mkdir(dataDir, { recursive: true });
  const candidate = new DatabaseSync(dbFile);
  try {
    candidate.exec('PRAGMA busy_timeout = 5000;');
    candidate.exec('PRAGMA journal_mode = WAL;');
    candidate.exec('PRAGMA synchronous = NORMAL;');
    candidate.exec('PRAGMA foreign_keys = ON;');
    initializeContentDatabase(candidate);
    await seedIfNeeded(candidate, { loadDefaults: loadDefaultData });
    await applyDataMigrations(candidate, { loadDefaults: loadDefaultData });
    if (typeof storeTestHooks.beforeInitializationPublish === 'function') {
      await storeTestHooks.beforeInitializationPublish();
    }
    if (generation !== storeGeneration) {
      const error = new Error('Store initialization was cancelled by closeStore().');
      error.code = 'ERR_STORE_INITIALIZATION_CANCELLED';
      throw error;
    }
    db = candidate;
    return candidate;
  } catch (error) {
    try {
      candidate.close();
    } catch {
      // Preserve the initialization error; the connection is already unusable.
    }
    throw error;
  }
};

const getDb = () => {
  if (!dbInitialization) {
    const pending = initializeStore(storeGeneration);
    dbInitialization = pending;
    pending.catch(() => {
      if (dbInitialization === pending) dbInitialization = undefined;
    });
  }
  return dbInitialization;
};

export const ensureStoreReady = async () => {
  await getDb();
  return true;
};


export const getMetadataValue = async (key, fallback = null) => {
  const database = await getDb();
  return readMetadata(database, key) ?? fallback;
};

export const setMetadataValue = withCacheInvalidation(async (key, value) => {
  return enqueueMutation(async () => {
    const database = await getDb();
    writeMetadata(database, key, String(value ?? ''));
    if (key === 'settings') invalidatePublicDataCache();
    return value;
  });
});
















export const getResetImpact = async value => {
  const target = validateResetTarget(value);
  const [database, defaults] = await Promise.all([getDb(), loadDefaultData()]);
  return createResetImpact(target, readResetState(database), makeSeedResetState(defaults));
};

export const createDataExportPackage = async () => {
  const database = await getDb();
  const state = readResetState(database);
  const summary = countResetState(state);
  return {
    format: 'payloader.export.v1',
    version: 1,
    generatedAt: now(),
    summary,
    data: {
      settings: state.settings,
      payloads: state.payloads,
      tools: state.tools,
      navigation: state.navigation,
      toolNavigation: state.toolNavigation,
      exploits: state.exploits,
      exploitNavigation: state.exploitNavigation,
    },
  };
};

export const resetDefaultData = withCacheInvalidation(value => {
  const target = validateResetTarget(value);
  return enqueueMutation(async () => {
    const [database, defaults] = await Promise.all([getDb(), loadDefaultData()]);
    const seedState = makeSeedResetState(defaults);
    const backup = await createResetBackup({ database, target, backupDir, beforeResetBackup: storeTestHooks.beforeResetBackup });
    const impact = createResetImpact(target, readResetState(database), seedState);
    executeReset({ database, target, seedState });

    const data = await getPublicData({ bypassCache: true });
    return {
      data,
      impact,
      before: impact.before,
      seed: impact.seed,
      delta: impact.delta,
      backup,
    };
  });
});

export const importDataPackage = withCacheInvalidation(async (value, options = {}) => {
  const normalized = normalizeImportPackage(value);
  assertNoDemoPlaceholderContent([
    ...normalized.payloads,
    ...normalized.tools,
    ...normalized.navigation,
    ...normalized.toolNavigation,
    ...normalized.exploits,
    ...normalized.exploitNavigation,
  ]);
  const mode = options.mode === 'replace' ? 'replace' : 'merge';
  return enqueueMutation(async () => {
    const database = await getDb();
    executeImport({ database, normalized, mode });

    return {
      mode,
      summary: importSummary(normalized),
      warnings: normalized.warnings,
      data: await getPublicData({ bypassCache: true }),
    };
  });
});

const assertMutableAdminItem = (resource, idOrItem) => {
  const id = isObject(idOrItem) ? idOrItem.id : idOrItem;
  if (resource === 'tools' && isSystemToolId(id)) {
    throw protectedStoreError('默认 XSS 平台入口不可编辑或移动，可在工具列表中删除。');
  }
  if (resource === 'navigation') {
    if (isSystemNavigationNodeId(id) || navigationTouchesSystemItem(idOrItem)) {
      throw protectedStoreError('系统内置 XSS 平台导航不可在后台编辑、移动或删除。');
    }
  }
};


const sanitizeGlobalVariables = value => {
  if (!Array.isArray(value)) return [];
  return value
    .filter(item => item && typeof item === 'object' && typeof item.key === 'string' && item.key.trim()
      && typeof item.value === 'string')
    .map(item => ({
      key: item.key,
      value: item.value,
      group: typeof item.group === 'string' ? item.group : 'general',
      description: item.description && typeof item.description === 'object'
        ? { zh: String(item.description.zh ?? ''), en: String(item.description.en ?? '') }
        : { zh: '', en: '' },
    }));
};

// 列表投影（P1-2 首屏载荷瘦身）：public-data 的 payloads 数组只保留列表 UI 与导航所需
// 字段，详情级大字段（wafBypass/tutorial/execution/attackChain/analysis/prerequisites/
// opsecTips/edrBypass/references）走 GET /api/payloads/:id/detail 按需下发。
// commandCount/bypassCount 是搜索结果卡与详情模式切换需要的计数派生字段。
const publicPayloadSummaryFields = (payload, execution, wafBypass) => ({
  id: payload.id,
  name: payload.name,
  description: payload.description,
  category: payload.category,
  ...(payload.subCategory ? { subCategory: payload.subCategory } : {}),
  tags: payload.tags,
  ...(payload.relatedExploits?.length ? { relatedExploits: payload.relatedExploits } : {}),
  commandCount: execution.length,
  bypassCount: wafBypass.length,
});

const projectPublicPayloadSummary = payload => publicPayloadSummaryFields(
  payload,
  Array.isArray(payload.execution) ? payload.execution : [],
  Array.isArray(payload.wafBypass) ? payload.wafBypass : [],
);

// 详情/离线快照/搜索语料的统一取数口：确保 getPublicData 已构建全量索引。
// 返回 Map（id → sanitize 后完整条目），与 publicDataCache 同生共死（同一失效路径）。
const ensurePayloadFullIndex = async () => {
  if (!readPayloadFullCache()) await getPublicData();
  return readPayloadFullCache();
};

// 详情端点数据源：完整条目（含全部详情级字段），与 public-data 列表投影同源同清洗管线。
export const getPayloadDetail = async payloadId => {
  const index = await ensurePayloadFullIndex();
  return index?.get(String(payloadId || '')) || null;
};

// 离线客户端快照数据源：全量条目数组（prepareElectronApp 写 payload-details.json）。
export const listPublicPayloadDetails = async () => {
  const index = await ensurePayloadFullIndex();
  return index ? [...index.values()] : [];
};

// 搜索语料（P1-2）：命令文本不进首屏 public-data（会顶爆 700KB gzip 闸），
// 由前端在空闲/首次搜索时延迟拉取并入索引，保证命令内容搜索行为不回归。
// 语料文本 = 命令标题（双语）+ 命令描述（双语）+ 命令原文 + 前置条件文本，
// 与原搜索索引对 execution/wafBypass/prerequisites 的覆盖面完全对齐。
const corpusI18nText = value => {
  if (!value) return [];
  if (typeof value === 'string') return value ? [value] : [];
  if (typeof value === 'object') return [value.zh, value.en].filter(Boolean);
  return [];
};

const corpusCommandText = commands => commands
  .flatMap(item => {
    if (!item || typeof item !== 'object') return [];
    return [
      ...corpusI18nText(item.title),
      ...corpusI18nText(item.description),
      ...(typeof item.command === 'string' && item.command ? [item.command] : []),
    ];
  })
  .filter(Boolean)
  .join('\n');

export const getPayloadSearchCorpus = async () => {
  const index = await ensurePayloadFullIndex();
  const entries = [];
  for (const payload of index?.values() || []) {
    const text = [
      corpusCommandText([
        ...(Array.isArray(payload.execution) ? payload.execution : []),
        ...(Array.isArray(payload.wafBypass) ? payload.wafBypass : []),
      ]),
      ...(Array.isArray(payload.prerequisites) ? payload.prerequisites.flatMap(corpusI18nText) : []),
    ].filter(Boolean).join('\n');
    if (text) entries.push({ id: payload.id, text });
  }
  return { version: 1, entries };
};

export const getPublicData = async ({ bypassCache = false } = {}) => {
  const cached = readPublicDataCache();
  if (cached && !bypassCache) return cached;
  const database = await getDb();
  const xeyeEnabled = isXeyeEnabled(database);
  const settings = {
    ...sanitizeSettings(readJsonMetadata(database, 'settings', defaultSettings)),
    xeyeEnabled,
  };
  const payloads = rowsToItems(database.prepare('SELECT data FROM payloads WHERE enabled = 1 ORDER BY sort_order, id').all());
  const tools = rowsToItems(database.prepare('SELECT data FROM tools WHERE enabled = 1 ORDER BY sort_order, id').all());
  const navigation = rowsToItems(database.prepare("SELECT tree FROM navigation_nodes WHERE enabled = 1 AND kind = 'payloads' ORDER BY sort_order, id").all());
  const toolNavigation = rowsToItems(database.prepare("SELECT tree FROM navigation_nodes WHERE enabled = 1 AND kind = 'tools' ORDER BY sort_order, id").all());
  const publicPayloadData = prepareStoredPublicPayloadData(payloads, navigation);
  const storedPublicTools = tools
    .filter(item => !excludedPublicToolIds.has(item.id))
    .map(item => sanitizeTool(item));
  const publicTools = xeyeEnabled ? withProtectedSystemTools(storedPublicTools) : storedPublicTools;
  const toolIds = new Set(publicTools.map(item => item.id));
  // EXP 公共面：仅 enabled 精选层条目（隐藏条目不进 public-data，也不进公开 API——不泄露存在性）；
  // 聚合层条目（带 source 来源标记）走 /api/exploits 分页检索，不进 public-data 快照，
  // 避免万级聚合索引撑爆前端初始载荷
  const exploits = rowsToItems(database.prepare('SELECT data FROM exploits WHERE enabled = 1 ORDER BY sort_order, id').all())
    .map(item => sanitizeExploit(item))
    .filter(item => !item.source || item.source === 'curated');
  const exploitNavigation = rowsToItems(database.prepare('SELECT tree FROM exploit_nodes WHERE enabled = 1 ORDER BY sort_order, id').all())
    .map(item => sanitizeExploitNode(item));
  // 全量索引先于列表投影落缓存：详情端点/搜索语料/离线快照都从它取完整条目
  const fullPayloadIndex = new Map(publicPayloadData.payloads.map(payload => [payload.id, payload]));
  writePayloadFullCache(fullPayloadIndex);
  return writePublicDataCache({
    settings,
    payloads: publicPayloadData.payloads.map(projectPublicPayloadSummary),
    tools: publicTools,
    // 内容性元数据（硬编码治理批）：默认全局变量与 CTF 速查由 DB 权威下发，前端不再硬编码。
    globalVariables: sanitizeGlobalVariables(readJsonMetadata(database, 'global_variables', null)),
    ctfCheatsheets: readJsonMetadata(database, 'ctf_cheatsheets', {}) || {},
    navigation: publicPayloadData.navigation,
    toolNavigation: filterToolNavigation(
      xeyeEnabled ? withProtectedSystemToolNavigation(toolNavigation) : toolNavigation,
      toolIds,
    ),
    exploits,
    exploitNavigation,
  });
};

export const getSettings = async () => {
  const database = await getDb();
  return {
    ...sanitizeSettings(readJsonMetadata(database, 'settings', defaultSettings)),
    xeyeEnabled: isXeyeEnabled(database),
  };
};

// EXP 全量公开面（精选层 + 聚合层，均 enabled）：/api/exploits 检索与 AI 渗透检索的数据源。
// 独立于 public-data 快照（只含精选层）——聚合层万级条目单独缓存，写路径经
// withCacheInvalidation 同步失效；隐藏条目两层都不出现，不泄露存在性。
export const listPublicExploits = async () => {
  const cached = readExploitCorpusCache();
  if (cached) return cached;
  const database = await getDb();
  const items = rowsToItems(database.prepare('SELECT data FROM exploits WHERE enabled = 1 ORDER BY sort_order, id').all())
    .map(item => sanitizeExploit(item));
  return writeExploitCorpusCache(items);
};

export const saveSettings = withCacheInvalidation(async value => {
  const settings = sanitizeSettings(value);
  return enqueueMutation(async () => {
    const database = await getDb();
    writeMetadata(database, 'settings', json(settings));
    writeMetadata(database, 'settings_updated_at', now());
    return { ...settings, xeyeEnabled: isXeyeEnabled(database) };
  });
});

export const listAdminItems = async resource => {
  const database = await getDb();
  if (resource === 'payloads') {
    return rowsToItems(database.prepare('SELECT data FROM payloads ORDER BY sort_order, id').all());
  }
  if (resource === 'tools') {
    const items = rowsToItems(database.prepare('SELECT data FROM tools ORDER BY sort_order, id').all())
      .filter(item => !isSystemToolId(item.id));
    return isXeyeEnabled(database) ? withProtectedSystemTools(items) : items;
  }
  if (resource === 'exploits') {
    // 后台列表含隐藏条目（enabled=false 标记），恢复语义依赖它；公共面只下发 enabled=1
    return database.prepare('SELECT data, enabled FROM exploits ORDER BY sort_order, id').all()
      .map(row => {
        const item = parseJson(row.data);
        return item ? { ...item, enabled: Boolean(row.enabled) } : null;
      })
      .filter(Boolean);
  }
  if (resource === 'exploit_navigation') {
    return database.prepare('SELECT id, tree, sort_order AS sortOrder, enabled FROM exploit_nodes ORDER BY sort_order, id')
      .all()
      .map(row => ({ ...parseJson(row.tree), enabled: Boolean(row.enabled), sortOrder: row.sortOrder }));
  }
  if (resource === 'navigation') {
    return database.prepare('SELECT id, tree, kind, sort_order AS sortOrder, enabled FROM navigation_nodes ORDER BY kind, sort_order, id')
      .all()
      .map(row => ({ ...parseJson(row.tree), kind: row.kind, enabled: Boolean(row.enabled), sortOrder: row.sortOrder }))
      .map(item => {
        const pruned = pruneSystemNavigationItem(item);
        return pruned ? { ...pruned, kind: item.kind, enabled: item.enabled, sortOrder: item.sortOrder } : null;
      })
      .filter(Boolean);
  }
  throw new Error(`Unsupported resource: ${resource}`);
};

export const listCustomPayloads = async () => {
  const database = await getDb();
  return rowsToItems(database.prepare(`
    SELECT data
    FROM payloads
    WHERE id LIKE 'custom-%'
      OR json_extract(data, '$.category.zh') = '自定义'
      OR json_extract(data, '$.category.en') = 'Custom'
    ORDER BY sort_order, id
  `).all());
};

const customContentDestinations = new Set(['payloads', 'tools']);

const customContentError = (status, message) => {
  const error = new Error(message);
  error.status = status;
  return error;
};

const requireCustomDestination = value => {
  const destination = String(value || '');
  if (!customContentDestinations.has(destination)) {
    throw customContentError(400, '自定义内容归属无效');
  }
  return destination;
};

const normalizeCustomContentInput = value => {
  const candidate = isObject(value) ? value : {};
  const title = String(candidate.title || '').trim();
  const content = String(candidate.content || '').trim();
  if (!title) throw customContentError(400, '请填写标题');
  if (!content) throw customContentError(400, '请填写内容');
  return {
    id: String(candidate.id || '').trim(),
    title,
    content,
    destination: requireCustomDestination(candidate.destination),
    sourceDestination: candidate.sourceDestination == null
      ? null
      : requireCustomDestination(candidate.sourceDestination),
  };
};

const isCustomContentItem = item => {
  const category = ensureDisplayTextObject(item?.category);
  return String(item?.id || '').startsWith('custom-')
    || category.zh === '自定义'
    || category.en === 'Custom';
};

const customContentView = (item, destination) => ({
  id: item.id,
  title: textValue(item.name).trim(),
  content: destination === 'tools'
    ? String(item.commands?.[0]?.command || '')
    : String(item.execution?.[0]?.command || ''),
  destination,
});

const customItemForDestination = ({ id, title, content, destination }) => (
  destination === 'tools'
    ? sanitizeTool({
        id,
        name: { zh: title, en: title },
        description: { zh: `自定义：${title}`, en: `Custom: ${title}` },
        category: { zh: '自定义', en: 'Custom' },
        commands: [{
          name: { zh: title, en: title },
          command: content,
          description: { zh: '自定义内容', en: 'Custom content' },
          platform: 'all',
        }],
        references: [],
      })
    : sanitizePayload({
        id,
        name: { zh: title, en: title },
        description: { zh: `自定义：${title}`, en: `Custom: ${title}` },
        category: { zh: '自定义', en: 'Custom' },
        tags: ['custom'],
        prerequisites: [],
        execution: [{
          title: { zh: title, en: title },
          command: content,
          description: { zh: '自定义内容', en: 'Custom content' },
          platform: 'all',
        }],
        wafBypass: [],
      })
);

export const listCustomContent = async () => {
  const database = await getDb();
  const payloads = rowsToItems(database.prepare('SELECT data FROM payloads ORDER BY sort_order, id').all())
    .filter(isCustomContentItem)
    .map(item => customContentView(item, 'payloads'));
  const tools = rowsToItems(database.prepare('SELECT data FROM tools ORDER BY sort_order, id').all())
    .filter(item => !isSystemToolId(item.id) && isCustomContentItem(item))
    .map(item => customContentView(item, 'tools'));
  return [...payloads, ...tools];
};

export const saveCustomContent = withCacheInvalidation(async value => {
  const input = normalizeCustomContentInput(value);
  const id = input.id || makeId('custom', input.title);
  const item = customItemForDestination({ ...input, id });
  assertMutableAdminItem(input.destination, item);
  assertNoDemoPlaceholderContent(item);

  return enqueueMutation(async () => {
    const database = await getDb();
    const source = input.sourceDestination || input.destination;
    const sourceTable = tableForResource(source).table;
    const targetTable = tableForResource(input.destination).table;
    const moving = source !== input.destination;
    const sourceRow = input.id
      ? database.prepare(`SELECT data FROM ${sourceTable} WHERE id = ?`).get(id)
      : null;
    const sourceItem = sourceRow ? parseJson(sourceRow.data) : null;
    if (input.id && (!sourceItem || !isCustomContentItem(sourceItem))) {
      throw customContentError(404, '自定义内容不存在');
    }
    if (moving && database.prepare(`SELECT id FROM ${targetTable} WHERE id = ?`).get(id)) {
      throw customContentError(409, '目标栏目已存在相同 ID 的内容');
    }

    runTransaction(database, () => {
      upsertItems(database, input.destination, [item]);
      if (moving) database.prepare(`DELETE FROM ${sourceTable} WHERE id = ?`).run(id);
    });
    return customContentView(item, input.destination);
  });
});

export const deleteCustomContent = withCacheInvalidation(async value => {
  const id = String(value?.id || '').trim();
  const destination = requireCustomDestination(value?.destination);
  if (!id) throw customContentError(400, '缺少自定义内容 ID');
  assertMutableAdminItem(destination, id);
  return enqueueMutation(async () => {
    const database = await getDb();
    const table = tableForResource(destination).table;
    const row = database.prepare(`SELECT data FROM ${table} WHERE id = ?`).get(id);
    const item = row ? parseJson(row.data) : null;
    if (!item || !isCustomContentItem(item)) {
      throw customContentError(404, '自定义内容不存在');
    }
    database.prepare(`DELETE FROM ${table} WHERE id = ?`).run(id);
    return { ok: true };
  });
});


export const saveAdminItem = withCacheInvalidation(async (resource, item) => {
  const { sanitizer } = tableForResource(resource);
  const normalized = sanitizer(item);
  assertMutableAdminItem(resource, normalized);
  assertNoDemoPlaceholderContent(normalized);
  return enqueueMutation(async () => {
    const database = await getDb();
    upsertItems(database, resource, [normalized], { trusted: true });
    return normalized;
  });
});

export const saveNavigationItem = withCacheInvalidation(async item => {
  const normalized = sanitizeNavItem(item);
  const kind = item.kind === 'tools' ? 'tools' : 'payloads';
  assertMutableAdminItem('navigation', { ...normalized, kind });
  return enqueueMutation(async () => {
    const database = await getDb();
    upsertItems(database, 'navigation', [normalized], { trusted: true, kind });
    return { ...normalized, kind };
  });
});

export const saveExploitNavigationItem = withCacheInvalidation(async item => {
  const normalized = sanitizeExploitNode(item);
  return enqueueMutation(async () => {
    const database = await getDb();
    upsertItems(database, 'exploit_navigation', [normalized], { trusted: true });
    return normalized;
  });
});

// 显式语义：删除系统内置 XSS 平台入口 = 禁用 Xeye 平台（写元数据开关，不删数据行）
export const disableXeye = withCacheInvalidation(() => enqueueMutation(async () => {
  const database = await getDb();
  writeMetadata(database, xeyeDisabledMetadataKey, '1');
  writeMetadata(database, `${xeyeDisabledMetadataKey}_at`, now());
  return { ok: true };
}));

export const deleteAdminItem = withCacheInvalidation(async (resource, id) => {
  if (!id) throw new Error('Missing id');
  if (resource === 'tools' && isSystemToolId(id)) {
    return disableXeye();
  }
  assertMutableAdminItem(resource, id);
  return enqueueMutation(async () => {
    const database = await getDb();
    if (resource === 'navigation') {
      database.prepare('DELETE FROM navigation_nodes WHERE id = ?').run(id);
      return;
    }
    // EXP 删除 = 隐藏（enabled=0）：对外一律 404 不泄露存在性，后台可恢复
    if (resource === 'exploits') {
      database.prepare('UPDATE exploits SET enabled = 0, updated_at = ? WHERE id = ?').run(now(), id);
      return;
    }
    const { table } = tableForResource(resource);
    database.prepare(`DELETE FROM ${table} WHERE id = ?`).run(id);
  });
});

export const restoreAdminItem = withCacheInvalidation(async (resource, id) => {
  if (!id) throw new Error('Missing id');
  if (resource !== 'exploits') throw new Error(`Unsupported restore resource: ${resource}`);
  return enqueueMutation(async () => {
    const database = await getDb();
    const result = database.prepare('UPDATE exploits SET enabled = 1, updated_at = ? WHERE id = ?').run(now(), id);
    if (Number(result.changes) === 0) throw new Error('EXP 不存在');
    return { ok: true };
  });
});

export const moveAdminItem = withCacheInvalidation(async (resource, id, direction) => {
  if (!id) throw new Error('Missing id');
  assertMutableAdminItem(resource, id);
  return enqueueMutation(async () => {
    const database = await getDb();
    const table = resource === 'navigation' ? 'navigation_nodes' : tableForResource(resource).table;
    const current = database.prepare(`SELECT id, sort_order, ${resource === 'navigation' ? 'kind' : "'all' AS kind"} FROM ${table} WHERE id = ?`).get(id);
    if (!current) return;
    const operator = direction === 'up' ? '<' : '>';
    const order = direction === 'up' ? 'DESC' : 'ASC';
    const kindClause = resource === 'navigation' ? 'AND kind = ?' : '';
    const args = resource === 'navigation' ? [current.sort_order, current.kind] : [current.sort_order];
    const other = database.prepare(`SELECT id, sort_order FROM ${table} WHERE sort_order ${operator} ? ${kindClause} ORDER BY sort_order ${order} LIMIT 1`).get(...args);
    if (!other) return;
    runTransaction(database, () => {
      database.prepare(`UPDATE ${table} SET sort_order = ? WHERE id = ?`).run(other.sort_order, current.id);
      database.prepare(`UPDATE ${table} SET sort_order = ? WHERE id = ?`).run(current.sort_order, other.id);
    });
  });
});

export const routeResource = path => {
  if (path.includes('/payloads')) return 'payloads';
  if (path.includes('/tools')) return 'tools';
  if (path.includes('/navigation')) return 'navigation';
  return null;
};
