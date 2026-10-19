// Minecraft Java 版 NBT（Named Binary Tag）解析引擎（杂项取证域，CTF 能力补强批次三 B3-5）。
// 格式出处：https://minecraft.wiki/w/NBT_format（Java 版大端口径）——13 种 tag（0-12）：
//   0 End / 1 Byte / 2 Short / 3 Int / 4 Long / 5 Float / 6 Double / 7 ByteArray / 8 String /
//   9 List / 10 Compound / 11 IntArray / 12 LongArray。
// 压缩自动判：1f 8b → gzip；0x78 且 (b0<<8|b1) % 31 == 0 → zlib；其余按裸 NBT。
// level.dat 摘要口径：种子优先 WorldGenSettings.seed（1.18+），回落 RandomSeed（旧存档）；
// DataVersion → 版本锚点表为 minecraft.wiki《Java Edition data values/Protocol and data versions》
// 核对值（1.16.5=2586 / 1.17.1=2730 / 1.18.2=2975 / 1.19=3105 / 1.19.2=3120 / 1.19.3=3218 /
// 1.19.4=3337 / 1.20.1=3465 / 1.20.4=3700 / 1.21=3953）；出生坐标字节全可打印 → 「可能坐标编码
// 字符」线索；非标准顶层字段（根 Compound 下 Data 之外的键）隐写高发位扫描。
// 防炸护栏：解析节点数 / 嵌套深度 / 解压后体积三重上限；ByteArray/List 长度负数或越界即抛。
// Compound 用 Object.create(null) 防原型污染（键名 "prototype"/"__proto__" 只当普通键）。
// Long/LongArray 一律 BigInt（种子常超 2^53）。测试权威向量见 tests/mcnbt.test.mjs（手工字节构造）。

export const NBT_MAX_NODES = 100000;
export const NBT_MAX_DEPTH = 128;
export const NBT_MAX_DECOMPRESSED = 64 * 1024 * 1024;

export const NBT_TAG_NAMES: Record<number, string> = {
  0: 'TAG_End',
  1: 'TAG_Byte',
  2: 'TAG_Short',
  3: 'TAG_Int',
  4: 'TAG_Long',
  5: 'TAG_Float',
  6: 'TAG_Double',
  7: 'TAG_Byte_Array',
  8: 'TAG_String',
  9: 'TAG_List',
  10: 'TAG_Compound',
  11: 'TAG_Int_Array',
  12: 'TAG_Long_Array',
};

// 值类型联合：number（Byte/Short/Int/Float/Double）| bigint（Long）| string | Uint8Array |
// NbtTag[]（List）| NbtCompound | Int32Array | bigint[]（LongArray）。
export type NbtCompound = Record<string, NbtTag>;

export interface NbtTag {
  type: number; // 0-12
  name: string;
  value: number | bigint | string | Uint8Array | NbtTag[] | NbtCompound | Int32Array | bigint[];
  elementType?: number; // List 专属：元素 tag 类型
}

export interface NbtParseResult {
  root: NbtCompound;
  rootName: string;
  compression: 'gzip' | 'zlib' | 'raw';
  byteLength: number; // 解析消费的字节数（解压后口径）
}

export interface NbtParseOptions {
  maxNodes?: number;
  maxDepth?: number;
  maxDecompressed?: number;
}

// ---- 解压（Node 22+/浏览器通用 DecompressionStream，与 apkParse.inflateRaw 同族）----

const decompressStream = async (bytes: Uint8Array, format: 'gzip' | 'deflate', maxOut: number): Promise<Uint8Array> => {
  const ds = new DecompressionStream(format);
  const writer = ds.writable.getWriter();
  const reader = ds.readable.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  const readAll = (async () => {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxOut) {
        void reader.cancel().catch(() => undefined);
        throw new Error(`NBT 解压后体积超过 ${maxOut} 字节上限，拒绝解析`);
      }
      chunks.push(value);
    }
  })();
  const writeDone = writer.write(new Uint8Array(bytes)).then(() => writer.close());
  await Promise.all([readAll, writeDone]);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

export type NbtCompression = 'gzip' | 'zlib' | 'raw';

// 压缩头判别：gzip 1f 8b / zlib 0x78 且校验和整除 / 裸 NBT（0x0A 根 Compound 起步）。
export const detectNbtCompression = (bytes: Uint8Array): NbtCompression => {
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) return 'gzip';
  if (bytes.length >= 2 && bytes[0] === 0x78 && ((bytes[0] << 8) | bytes[1]) % 31 === 0) return 'zlib';
  return 'raw';
};

// 自动解压：gzip/zlib 流解开，裸 NBT 原样返回。
export const decompressNbt = async (bytes: Uint8Array, options: NbtParseOptions = {}): Promise<{ data: Uint8Array; compression: NbtCompression }> => {
  const maxDecompressed = options.maxDecompressed ?? NBT_MAX_DECOMPRESSED;
  const compression = detectNbtCompression(bytes);
  if (compression === 'raw') return { data: bytes, compression };
  const data = await decompressStream(bytes, compression === 'gzip' ? 'gzip' : 'deflate', maxDecompressed);
  return { data, compression };
};

// ---- 字节读取器（大端）----

class NbtReader {
  private view: DataView;
  private position = 0;
  nodes = 0;
  private bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  remaining(): number {
    return this.bytes.length - this.position;
  }

  offset(): number {
    return this.position;
  }

  u8(): number {
    if (this.remaining() < 1) throw this.truncated(1);
    return this.bytes[this.position++];
  }

  i8(): number {
    if (this.remaining() < 1) throw this.truncated(1);
    return this.view.getInt8(this.position++);
  }

  i16(): number {
    if (this.remaining() < 2) throw this.truncated(2);
    const value = this.view.getInt16(this.position, false);
    this.position += 2;
    return value;
  }

  u16(): number {
    if (this.remaining() < 2) throw this.truncated(2);
    const value = this.view.getUint16(this.position, false);
    this.position += 2;
    return value;
  }

  i32(): number {
    if (this.remaining() < 4) throw this.truncated(4);
    const value = this.view.getInt32(this.position, false);
    this.position += 4;
    return value;
  }

  i64(): bigint {
    if (this.remaining() < 8) throw this.truncated(8);
    const value = this.view.getBigInt64(this.position, false);
    this.position += 8;
    return value;
  }

  f32(): number {
    if (this.remaining() < 4) throw this.truncated(4);
    const value = this.view.getFloat32(this.position, false);
    this.position += 4;
    return value;
  }

  f64(): number {
    if (this.remaining() < 8) throw this.truncated(8);
    const value = this.view.getFloat64(this.position, false);
    this.position += 8;
    return value;
  }

  slice(length: number): Uint8Array {
    if (length < 0 || length > this.remaining()) throw this.truncated(length);
    const out = this.bytes.slice(this.position, this.position + length);
    this.position += length;
    return out;
  }

  utf8(length: number): string {
    if (length < 0 || length > this.remaining()) throw this.truncated(length);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(this.bytes.subarray(this.position, this.position + length));
    this.position += length;
    return text;
  }

  truncated(need: number): Error {
    return new Error(`NBT 数据流在偏移 ${this.position} 处截断（还差 ${need} 字节，剩余 ${this.remaining()}）`);
  }
}

// ---- 解析主体 ----

const readStringPayload = (reader: NbtReader): string => {
  const length = reader.u16();
  return reader.utf8(length);
};

// 读单个 tag（不含 type/name 头，即载荷）；List 型在返回 tag 上带 elementType。
const readPayload = (reader: NbtReader, type: number, depth: number, options: Required<Pick<NbtParseOptions, 'maxNodes' | 'maxDepth'>>): NbtTag => {
  if (depth > options.maxDepth) throw new Error(`NBT 嵌套深度超过 ${options.maxDepth} 上限（疑似恶意构造）`);
  reader.nodes += 1;
  if (reader.nodes > options.maxNodes) throw new Error(`NBT 节点数超过 ${options.maxNodes} 上限（疑似恶意构造）`);
  if (type === 9) {
    // List：先读元素类型与长度，再逐元素读载荷（元素 tag 不带名字）。
    const elementType = reader.u8();
    const length = reader.i32();
    if (length < 0) throw new Error(`NBT List 长度为负（${length}），数据损坏`);
    if (length > 0 && elementType === 0) throw new Error('NBT List 元素类型为 TAG_End 但长度大于 0，数据损坏');
    const items: NbtTag[] = [];
    for (let index = 0; index < length; index += 1) {
      items.push(readPayload(reader, elementType, depth + 1, options));
    }
    return { type, name: '', value: items, elementType };
  }
  const value: NbtTag['value'] = (() => {
    switch (type) {
      case 1: return reader.i8();
      case 2: return reader.i16();
      case 3: return reader.i32();
      case 4: return reader.i64();
      case 5: return reader.f32();
      case 6: return reader.f64();
      case 7: {
        const length = reader.i32();
        if (length < 0) throw new Error(`NBT ByteArray 长度为负（${length}），数据损坏`);
        return reader.slice(length);
      }
      case 8: return readStringPayload(reader);
      case 10: {
        const compound: NbtCompound = Object.create(null);
        for (;;) {
          const childType = reader.u8();
          if (childType === 0) break; // TAG_End：Compound 收口
          if (childType > 12) throw new Error(`NBT tag 类型 ${childType} 越界（合法 0-12）`);
          const name = readStringPayload(reader);
          const child = readPayload(reader, childType, depth + 1, options);
          child.name = name;
          compound[name] = child;
        }
        return compound;
      }
      case 11: {
        const length = reader.i32();
        if (length < 0) throw new Error(`NBT IntArray 长度为负（${length}），数据损坏`);
        if (length > reader.remaining() / 4) throw new Error(`NBT IntArray 长度 ${length} 超过剩余字节可容纳范围，数据损坏`);
        const values = new Int32Array(length);
        for (let index = 0; index < length; index += 1) values[index] = reader.i32();
        return values;
      }
      case 12: {
        const length = reader.i32();
        if (length < 0) throw new Error(`NBT LongArray 长度为负（${length}），数据损坏`);
        if (length > reader.remaining() / 8) throw new Error(`NBT LongArray 长度 ${length} 超过剩余字节可容纳范围，数据损坏`);
        const values: bigint[] = [];
        for (let index = 0; index < length; index += 1) values.push(reader.i64());
        return values;
      }
      default:
        throw new Error(`NBT tag 类型 ${type} 越界（合法 0-12）`);
    }
  })();
  return { type, name: '', value };
};

// 解析已解压的裸 NBT 字节。Java 口径根节点必须为 Compound（type 10 + 命名）。
export const parseNbt = (bytes: Uint8Array, options: NbtParseOptions = {}): NbtParseResult => {
  const maxNodes = options.maxNodes ?? NBT_MAX_NODES;
  const maxDepth = options.maxDepth ?? NBT_MAX_DEPTH;
  const reader = new NbtReader(bytes);
  const rootType = reader.u8();
  if (rootType !== 10) {
    throw new Error(`NBT 根节点类型为 ${rootType}（${NBT_TAG_NAMES[rootType] ?? '未知'}），Java 口径必须是 TAG_Compound(10)`);
  }
  const rootName = readStringPayload(reader);
  const root = Object.create(null) as NbtCompound;
  for (;;) {
    const childType = reader.u8();
    if (childType === 0) break;
    if (childType > 12) throw new Error(`NBT tag 类型 ${childType} 越界（合法 0-12）`);
    const name = readStringPayload(reader);
    const child = readPayload(reader, childType, 1, { maxNodes, maxDepth });
    child.name = name;
    root[name] = child;
  }
  return { root, rootName, compression: 'raw', byteLength: reader.offset() };
};

// 自动判压 + 解压 + 解析一条龙。
export const parseNbtAuto = async (bytes: Uint8Array, options: NbtParseOptions = {}): Promise<NbtParseResult> => {
  const compression = detectNbtCompression(bytes);
  if (compression === 'raw') {
    const result = parseNbt(bytes, options);
    result.compression = 'raw';
    return result;
  }
  const { data } = await decompressNbt(bytes, options);
  const result = parseNbt(data, options);
  result.compression = compression;
  return result;
};

// ---- 路径查询（如 Data.Player.Inventory；List 用数字段下标）----

export const queryNbtPath = (root: NbtCompound, path: string): NbtTag => {
  const segments = path.split('.').filter(segment => segment.length > 0);
  let current: NbtTag = { type: 10, name: '', value: root };
  for (const segment of segments) {
    if (current.type === 10) {
      const compound = current.value as NbtCompound;
      const next = compound[segment];
      if (!next) {
        const keys = Object.keys(compound);
        throw new Error(`NBT 路径 "${path}" 在段 "${segment}" 处不存在（可用键：${keys.slice(0, 20).join(', ')}${keys.length > 20 ? ' …' : ''}）`);
      }
      current = next;
    } else if (current.type === 9) {
      const items = current.value as NbtTag[];
      const index = Number.parseInt(segment, 10);
      if (!Number.isInteger(index) || index < 0 || index >= items.length) {
        throw new Error(`NBT 路径 "${path}" 段 "${segment}" 不是合法 List 下标（长度 ${items.length}）`);
      }
      current = items[index];
    } else {
      throw new Error(`NBT 路径 "${path}" 在段 "${segment}" 处无法下钻：父节点是 ${NBT_TAG_NAMES[current.type]}（只有 Compound/List 可继续）`);
    }
  }
  return current;
};

// ---- 树缩进转储 ----

export interface NbtDumpOptions {
  path?: string; // 路径过滤：只转储该子树
  maxLines?: number; // 转储行数上限（默认 2000，超出截断标注）
  maxArrayPreview?: number; // ByteArray/IntArray/LongArray 预览元素数（默认 8）
}

const hexByte = (value: number): string => value.toString(16).padStart(2, '0');

const formatScalar = (tag: NbtTag): string => {
  if (tag.type === 4) return `${(tag.value as bigint).toString(10)}`;
  if (tag.type === 5 || tag.type === 6) return String(tag.value);
  if (tag.type === 8) return JSON.stringify(tag.value);
  if (tag.type === 1 || tag.type === 2 || tag.type === 3) return String(tag.value);
  return String(tag.value);
};

const formatArrayPreview = (tag: NbtTag, previewCount: number): string => {
  if (tag.type === 7) {
    const bytes = tag.value as Uint8Array;
    const head = Array.from(bytes.subarray(0, previewCount), hexByte).join(' ');
    return `[${bytes.length} 字节] ${head}${bytes.length > previewCount ? ' …' : ''}`;
  }
  if (tag.type === 11) {
    const values = tag.value as Int32Array;
    const head = Array.from(values.subarray(0, previewCount)).join(', ');
    return `[${values.length} 项] ${head}${values.length > previewCount ? ' …' : ''}`;
  }
  const values = tag.value as bigint[];
  const head = values.slice(0, previewCount).map(value => value.toString(10)).join(', ');
  return `[${values.length} 项] ${head}${values.length > previewCount ? ' …' : ''}`;
};

// 树缩进转储。LongArray/ByteArray 只显示前 previewCount 项防刷屏；行数超限截断。
export const dumpNbt = (root: NbtCompound, dumpOptions: NbtDumpOptions = {}): string => {
  const maxLines = dumpOptions.maxLines ?? 2000;
  const previewCount = dumpOptions.maxArrayPreview ?? 8;
  const target = dumpOptions.path ? queryNbtPath(root, dumpOptions.path) : { type: 10, name: '', value: root };
  const lines: string[] = [];
  let truncated = false;

  const walk = (tag: NbtTag, depth: number): void => {
    if (truncated) return;
    if (lines.length >= maxLines) {
      lines.push('…（转储行数达到上限，已截断；可用 path 参数缩小范围）');
      truncated = true;
      return;
    }
    const indent = '  '.repeat(depth);
    const label = tag.name ? `${tag.name}: ` : '';
    if (tag.type === 10) {
      const compound = tag.value as NbtCompound;
      const keys = Object.keys(compound);
      lines.push(`${indent}${label}${NBT_TAG_NAMES[10]}(${keys.length}) {`);
      for (const key of keys) walk(compound[key], depth + 1);
      lines.push(`${indent}}`);
    } else if (tag.type === 9) {
      const items = tag.value as NbtTag[];
      lines.push(`${indent}${label}${NBT_TAG_NAMES[9]}<${NBT_TAG_NAMES[tag.elementType ?? 0]}>(${items.length}) {`);
      for (const item of items) walk(item, depth + 1);
      lines.push(`${indent}}`);
    } else if (tag.type === 7 || tag.type === 11 || tag.type === 12) {
      lines.push(`${indent}${label}${NBT_TAG_NAMES[tag.type]} ${formatArrayPreview(tag, previewCount)}`);
    } else {
      lines.push(`${indent}${label}${NBT_TAG_NAMES[tag.type]}(${formatScalar(tag)})`);
    }
  };

  walk(target, 0);
  return lines.join('\n');
};

// ---- level.dat 摘要 ----

// DataVersion → 版本锚点（minecraft.wiki 核对值，见模块头）。
const DATA_VERSION_ANCHORS: ReadonlyArray<{ version: number; name: string }> = [
  { version: 2586, name: '1.16.5' },
  { version: 2730, name: '1.17.1' },
  { version: 2975, name: '1.18.2' },
  { version: 3105, name: '1.19' },
  { version: 3120, name: '1.19.2' },
  { version: 3218, name: '1.19.3' },
  { version: 3337, name: '1.19.4' },
  { version: 3465, name: '1.20.1' },
  { version: 3700, name: '1.20.4' },
  { version: 3953, name: '1.21' },
];

const dataVersionAnchor = (dataVersion: number): string => {
  const exact = DATA_VERSION_ANCHORS.find(entry => entry.version === dataVersion);
  if (exact) return exact.name;
  const below = [...DATA_VERSION_ANCHORS].reverse().find(entry => entry.version < dataVersion);
  if (!below) return `低于 ${DATA_VERSION_ANCHORS[0].name}（${DATA_VERSION_ANCHORS[0].version}）的旧版本`;
  return `介于 ${below.name}（${below.version}）与后续版本之间`;
};

// 常见 GameRules 默认值（不完全表：命中的比对，未命中的按「非常规（不在默认表）」高亮）。
const GAME_RULE_DEFAULTS: Record<string, string> = {
  announceAdvancements: 'true',
  commandBlockOutput: 'true',
  doDaylightCycle: 'true',
  doEntityDrops: 'true',
  doFireTick: 'true',
  doImmediateRespawn: 'false',
  doInsomnia: 'true',
  doLimitedCrafting: 'false',
  doMobLoot: 'true',
  doMobSpawning: 'true',
  doPatrolSpawning: 'true',
  doTileDrops: 'true',
  doTraderSpawning: 'true',
  doVinesSpread: 'true',
  doWeatherCycle: 'true',
  drownDamage: 'true',
  fallDamage: 'true',
  fireDamage: 'true',
  forgiveDeadPlayers: 'true',
  freezeDamage: 'true',
  keepInventory: 'false',
  maxCommandChainLength: '65536',
  maxEntityCramming: '24',
  mobGriefing: 'true',
  naturalRegeneration: 'true',
  playersSleepingPercentage: '100',
  randomTickSpeed: '3',
  reducedDebugInfo: 'false',
  sendCommandFeedback: 'true',
  showDeathMessages: 'true',
  spawnRadius: '10',
  spectatorsGenerateChunks: 'true',
  universalAngerChance: 'false',
};

export interface NbtGameRule {
  name: string;
  value: string;
  unusual: boolean; // 与常见默认不同或不在默认表（CTF 出题人改规则的落点）
}

export interface NbtLevelSummary {
  seed: bigint | null;
  seedSource: 'WorldGenSettings.seed' | 'RandomSeed' | null;
  spawn: { x: number | null; y: number | null; z: number | null };
  dataVersion: number | null;
  dataVersionAnchor: string | null;
  versionName: string | null; // Version.Name（如 "1.20.1"）
  gameRules: NbtGameRule[];
  asciiHints: string[]; // 出生坐标字节可打印 ASCII 的编码字符线索
  topLevelExtra: string[]; // 根 Compound 下 Data 之外的非标准顶层字段
  notes: string[];
}

// 4 字节坐标的可打印 ASCII 检查（大端/小端两读法，命中即提示）。
const coordinateAsciiHint = (value: number): string | null => {
  const bigEndian = [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
  const littleEndian = [...bigEndian].reverse();
  const printable = (list: number[]): boolean => list.every(byte => byte >= 0x20 && byte <= 0x7e);
  const toText = (list: number[]): string => Array.from(list, byte => String.fromCharCode(byte)).join('');
  if (printable(bigEndian)) return toText(bigEndian);
  if (printable(littleEndian)) return toText(littleEndian);
  return null;
};

const asCompound = (tag: NbtTag | undefined): NbtCompound | null => (tag && tag.type === 10 ? (tag.value as NbtCompound) : null);
const asInt = (tag: NbtTag | undefined): number | null => (tag && tag.type === 3 && typeof tag.value === 'number' ? tag.value : null);
const asLong = (tag: NbtTag | undefined): bigint | null => {
  if (!tag) return null;
  if (tag.type === 4 && typeof tag.value === 'bigint') return tag.value;
  if (tag.type === 3 && typeof tag.value === 'number') return BigInt(tag.value);
  return null;
};

// level.dat 摘要：种子/出生点/GameRules（非常规高亮）/DataVersion 锚点/坐标编码线索/非标准顶层字段。
export const levelDatSummary = (root: NbtCompound): NbtLevelSummary => {
  const notes: string[] = [];
  const data = asCompound(root.Data);
  if (!data) throw new Error('level.dat 结构异常：根 Compound 下没有 Data Compound（不是标准 level.dat）');

  const worldGen = asCompound(data.WorldGenSettings);
  let seed = asLong(worldGen?.seed);
  let seedSource: NbtLevelSummary['seedSource'] = worldGen?.seed !== undefined ? 'WorldGenSettings.seed' : null;
  if (seed === null) {
    seed = asLong(data.RandomSeed);
    seedSource = data.RandomSeed !== undefined ? 'RandomSeed' : null;
  }
  if (seed === null) notes.push('未找到 WorldGenSettings.seed 或 RandomSeed，无法确定世界种子');

  const spawn = { x: asInt(data.SpawnX), y: asInt(data.SpawnY), z: asInt(data.SpawnZ) };

  const dataVersion = asInt(data.DataVersion);
  const versionCompound = asCompound(data.Version);
  const versionName = versionCompound && typeof versionCompound.Name?.value === 'string' ? versionCompound.Name.value : null;

  const gameRules: NbtGameRule[] = [];
  const rules = asCompound(data.GameRules);
  if (rules) {
    for (const name of Object.keys(rules)) {
      const tag = rules[name];
      const value = typeof tag.value === 'string' || typeof tag.value === 'number' ? String(tag.value) : JSON.stringify(tag.value);
      const expected = GAME_RULE_DEFAULTS[name];
      gameRules.push({ name, value, unusual: expected === undefined || expected !== value });
    }
    gameRules.sort((left, right) => Number(right.unusual) - Number(left.unusual) || left.name.localeCompare(right.name));
  } else {
    notes.push('该存档没有 GameRules Compound');
  }

  const asciiHints: string[] = [];
  for (const [axis, value] of [['X', spawn.x], ['Y', spawn.y], ['Z', spawn.z]] as const) {
    if (value === null) continue;
    const text = coordinateAsciiHint(value);
    if (text) asciiHints.push(`Spawn${axis}=${value} 的 4 字节编码为可打印 ASCII "${text}"，可能是坐标编码字符（flag 藏点）`);
  }

  const topLevelExtra = Object.keys(root).filter(key => key !== 'Data');
  if (topLevelExtra.length > 0) notes.push(`根 Compound 存在非标准顶层字段：${topLevelExtra.join(', ')}（标准 level.dat 根下只有 Data，隐写/隐藏数据高发位）`);

  return {
    seed,
    seedSource,
    spawn,
    dataVersion,
    dataVersionAnchor: dataVersion !== null ? dataVersionAnchor(dataVersion) : null,
    versionName,
    gameRules,
    asciiHints,
    topLevelExtra,
    notes,
  };
};
