// OLE/CFB 复合文档只读提取引擎（文件取证域 B2-11）：512B 头 → DIFAT → FAT 链 → 目录红黑树
// → <4096B 流走 MiniFAT（Root Entry mini 流）→ storage/stream 树列出与流字节导出。
// 格式规范：[MS-CFB]（Compound File Binary File Format），v3 扇区 512B / v4 扇区 4096B，
// mini 扇区恒 64B，mini 流截断阈值 4096B。目录项 128B 定长：名称 UTF-16LE(64B)、objectType
// (0=unknown/1=storage/2=stream/5=root)、left/right sibling 与 child 扇区号、起始扇区、大小。
// FAT 特殊值：0xFFFFFFFE=ENDOFCHAIN、0xFFFFFFFF=FREESECT、0xFFFFFFFD=FATSECT、
// 0xFFFFFFFC=DIFSECT；DIFAT 首入门 109 项在头内，其余经 DIFAT 扇区链（每扇区 127 项 + 1 下一指针）。
// 安全红线：只读解析与导出，绝不执行宏/外链；检测到加密迹象（WordDocument FibBase fEncrypted、
// Excel FILEPASS 记录、EncryptedPackage 流）时给出提示。
// 对拍锚点：Python olefile 读出流字节逐位（SHA-256）比对 + 手工构造最小 CFB 双验证，
// 见 tests/ole-extract.test.mjs。
export const MAX_OLE_STREAM_BYTES = 32 * 1024 * 1024;
const ENDOFCHAIN = 0xfffffffe;
// FREESECT(0xFFFFFFFF)/FATSECT/DIFSECT 等保留值（[MS-CFB] 2.3）统一按 >=0xFFFFFFFC
// 视为"非数据扇区/空指针"处理。
const isReservedValue = (value: number): boolean => value >= 0xfffffffc;
const isNoStreamValue = isReservedValue;

export interface OleEntry {
  // 以 '/' 分隔的完整路径（根下的 "Workbook"、嵌套的 "WordDocument/1Table" 风格用 storage 前缀）。
  path: string;
  name: string;
  type: 'root' | 'storage' | 'stream' | 'unknown';
  size: number;
  clsidHex: string | null;
}

export interface OleStreamData {
  path: string;
  bytes: Uint8Array;
}

export interface OleParseResult {
  ok: boolean;
  version: 3 | 4 | null;
  sectorSize: number;
  entries: OleEntry[];
  // 已导出的流字节（≤ maxStreamBytes 的流；超限流只列条目并在 notes 说明）。
  streams: OleStreamData[];
  failure: string | null;
  notes: string[];
  // 加密迹象提示（命中即提示，不影响结构解析）。
  encryptedHints: string[];
}

const u16 = (bytes: Uint8Array, offset: number): number => bytes[offset] | (bytes[offset + 1] << 8);
const u32 = (bytes: Uint8Array, offset: number): number =>
  (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | ((bytes[offset + 3] << 24) >>> 0)) >>> 0;

const FAT_CHAIN_GUARD = 1 << 22; // FAT 链最大步数（环保护）

// 沿 FAT 链收集扇区号（带环保护，越界/环即停并报告）。
const walkChain = (
  fat: Uint32Array,
  start: number,
  onSector: (sector: number) => void,
  problems: string[],
): number => {
  let sector = start;
  let steps = 0;
  while (sector !== ENDOFCHAIN && steps < FAT_CHAIN_GUARD) {
    if (sector >= fat.length) {
      problems.push(`FAT 链引用越界扇区 ${sector}（链头 ${start}），数据可能损坏，已截断`);
      return steps;
    }
    onSector(sector);
    steps += 1;
    sector = fat[sector];
  }
  if (steps >= FAT_CHAIN_GUARD) {
    problems.push(`FAT 链超过步数上限（链头 ${start}），疑似环引用，已截断`);
  }
  return steps;
};

// 读取一个"普通扇区流"的全部字节（扇区号链 → 拼接字节）。
const readSectorStream = (
  bytes: Uint8Array,
  fat: Uint32Array,
  start: number,
  sectorSize: number,
  size: number,
  problems: string[],
): Uint8Array => {
  const parts: Uint8Array[] = [];
  let collected = 0;
  walkChain(fat, start, sector => {
    if (collected >= size) return;
    const base = (sector + 1) * sectorSize;
    if (base + sectorSize > bytes.length) {
      if (problems.length < 8) problems.push(`扇区 ${sector} 越过文件尾，流数据被截断`);
      collected = size; // 停止继续收集
      return;
    }
    const take = Math.min(sectorSize, size - collected);
    parts.push(bytes.slice(base, base + take));
    collected += take;
  }, problems);
  const out = new Uint8Array(Math.min(collected, size));
  let offset = 0;
  for (const part of parts) {
    const take = Math.min(part.length, out.length - offset);
    if (take <= 0) break;
    out.set(part.subarray(0, take), offset);
    offset += take;
  }
  return out;
};

const isOle = (bytes: Uint8Array): boolean =>
  bytes.length >= 8 &&
  bytes[0] === 0xd0 && bytes[1] === 0xcf && bytes[2] === 0x11 && bytes[3] === 0xe0 &&
  bytes[4] === 0xa1 && bytes[5] === 0xb1 && bytes[6] === 0x1a && bytes[7] === 0xe1;

// 加密迹象检测（启发式，只提示不阻断）：
// - WordDocument 流 FibBase offset 0x0A bit8 (0x0100) = fEncrypted（[MS-DOC] 2.5.11 FibBase）；
// - Workbook/Book 流头部出现 FILEPASS 记录（id 0x0042，[MS-XLS]）；
// - 名为 EncryptedPackage 的流（[MS-OFFCRYPTO] 的 OLE 包装壳）。
const collectEncryptedHints = (streams: OleStreamData[], encryptedHints: string[]): void => {
  for (const stream of streams) {
    const base = stream.path.split('/').pop() ?? stream.path;
    if (/^WordDocument$/i.test(base) && stream.bytes.length >= 12) {
      const flags = u16(stream.bytes, 0x0a);
      if ((flags & 0x0100) !== 0) encryptedHints.push(`WordDocument 的 FibBase 标志位含 fEncrypted（0x${flags.toString(16)}）：该文档正文已加密（Word 二进制加密），流内容不是可读文档结构`);
    }
    if (/^(Workbook|Book)$/i.test(base) && stream.bytes.length >= 8) {
      const bofId = u16(stream.bytes, 0);
      const passId = u16(stream.bytes, 4);
      if (bofId === 0x0809 && passId === 0x0042) {
        encryptedHints.push('Workbook 流在 BOF 后紧跟 FILEPASS 记录（0x0042）：该 Excel 工作簿已加密');
      } else if (passId === 0x0042) {
        encryptedHints.push('Workbook 流出现 FILEPASS 记录（0x0042）：该 Excel 工作簿可能已加密');
      }
    }
  }
  for (const entry of streams) {
    if (/EncryptedPackage/i.test(entry.path)) {
      encryptedHints.push('存在 EncryptedPackage 流：这是 [MS-OFFCRYPTO] 加密 OOXML 的 OLE 包装壳，正文需按加密包解析');
    }
  }
};

// 主入口：解析 CFB 并导出全部流。options.maxStreamBytes 限制单流导出上限（默认 32MB，
// 超限流只列条目）。
export const parseOle = (bytes: Uint8Array, options?: { maxStreamBytes?: number }): OleParseResult => {
  const notes: string[] = [];
  const problems: string[] = [];
  const encryptedHints: string[] = [];
  const entries: OleEntry[] = [];
  const streams: OleStreamData[] = [];
  const result: OleParseResult = {
    ok: false,
    version: null,
    sectorSize: 0,
    entries,
    streams,
    failure: null,
    notes,
    encryptedHints,
  };
  const maxStreamBytes = options?.maxStreamBytes ?? MAX_OLE_STREAM_BYTES;

  if (!isOle(bytes)) {
    result.failure = '不是 OLE/CFB 复合文档（缺少 D0 CF 11 E0 A1 B1 1A E1 魔数）';
    return result;
  }
  if (bytes.length < 512) {
    result.failure = '文件不足 512B，装不下完整 CFB 头';
    return result;
  }
  const major = u16(bytes, 26);
  const sectorShift = u16(bytes, 30);
  const miniSectorShift = u16(bytes, 32);
  if ((major !== 3 && major !== 4) || sectorShift < 6 || sectorShift > 20) {
    result.failure = `CFB 版本字段异常（major=${major}, sectorShift=${sectorShift}），无法解析`;
    return result;
  }
  const sectorSize = 1 << sectorShift;
  const miniSectorSize = 1 << miniSectorShift;
  result.version = major as 3 | 4;
  result.sectorSize = sectorSize;
  if (major === 3 && sectorSize !== 512) notes.push(`v3 文档扇区大小为 ${sectorSize}B（规范建议 512B）`);
  const firstDirSector = u32(bytes, 48);
  const miniStreamCutoff = u32(bytes, 56);
  const firstMiniFatSector = u32(bytes, 60);
  const numMiniFatSectors = u32(bytes, 64);
  const firstDifatSector = u32(bytes, 68);
  const numDifatSectors = u32(bytes, 72);
  if (miniStreamCutoff !== 4096) notes.push(`mini 流阈值 ${miniStreamCutoff} 非 4096（规范默认值），按文件声明处理`);

  const sectorAt = (sector: number): Uint8Array => {
    const base = (sector + 1) * sectorSize;
    return bytes.slice(base, base + sectorSize);
  };

  // ---- DIFAT：头内 109 项 + DIFAT 扇区链 ----
  const fatSectorIds: number[] = [];
  for (let index = 0; index < 109; index += 1) {
    const value = u32(bytes, 76 + index * 4);
    if (!isNoStreamValue(value)) fatSectorIds.push(value);
  }
  let difatSector = firstDifatSector;
  let difatSteps = 0;
  const seenDifat = new Set<number>();
  while (!isNoStreamValue(difatSector) && difatSteps < FAT_CHAIN_GUARD) {
    if (seenDifat.has(difatSector)) {
      problems.push(`DIFAT 扇区环引用（扇区 ${difatSector}），停止扩展`);
      break;
    }
    seenDifat.add(difatSector);
    const base = (difatSector + 1) * sectorSize;
    if (base + sectorSize > bytes.length) {
      problems.push(`DIFAT 扇区 ${difatSector} 越过文件尾，FAT 列表可能不完整`);
      break;
    }
    const sectorData = sectorAt(difatSector);
    const perSector = sectorSize / 4 - 1; // 每扇区最后一项是下一 DIFAT 扇区指针
    for (let index = 0; index < perSector; index += 1) {
      const value = u32(sectorData, index * 4);
      if (!isNoStreamValue(value)) fatSectorIds.push(value);
    }
    difatSector = u32(sectorData, sectorSize - 4);
    difatSteps += 1;
  }
  if (difatSteps >= FAT_CHAIN_GUARD) problems.push('DIFAT 链超过步数上限，疑似环引用');
  if (numDifatSectors > 0 && seenDifat.size < numDifatSectors) {
    notes.push(`头声明的 DIFAT 扇区数 ${numDifatSectors} 与实际遍历 ${seenDifat.size} 不一致（可能文件被截断）`);
  }

  // ---- FAT：按扇区号表拼出全 FAT ----
  const fat = new Uint32Array(fatSectorIds.length * (sectorSize / 4));
  let fatFilled = 0;
  for (const sector of fatSectorIds) {
    const base = (sector + 1) * sectorSize;
    if (base + sectorSize > bytes.length) {
      problems.push(`FAT 扇区 ${sector} 越过文件尾，FAT 不完整`);
      continue;
    }
    const sectorData = sectorAt(sector);
    const perSector = sectorSize / 4;
    for (let index = 0; index < perSector && fatFilled < fat.length; index += 1) {
      fat[fatFilled + index] = u32(sectorData, index * 4);
    }
    fatFilled += perSector;
  }
  const fatTrimmed = fat.subarray(0, fatFilled);

  // ---- MiniFAT ----
  let miniFat = new Uint32Array(0);
  if (firstMiniFatSector !== ENDOFCHAIN && numMiniFatSectors > 0) {
    const miniParts: Uint8Array[] = [];
    walkChain(fatTrimmed, firstMiniFatSector, sector => {
      const base = (sector + 1) * sectorSize;
      if (base + sectorSize <= bytes.length) miniParts.push(bytes.slice(base, base + sectorSize));
    }, problems);
    const miniBytes = miniParts.reduce((sum, part) => sum + part.length, 0);
    const miniView = new Uint32Array(Math.floor(miniBytes / 4));
    let offset = 0;
    for (const part of miniParts) {
      const view = new DataView(part.buffer, part.byteOffset, part.byteLength);
      const count = Math.floor(part.length / 4);
      for (let index = 0; index < count; index += 1) miniView[offset / 4 + index] = view.getUint32(index * 4, true);
      offset += part.length;
    }
    miniFat = miniView;
  }

  // ---- 目录（Root Entry 所在扇区链拼成目录扇区池）----
  const dirParts: Uint8Array[] = [];
  walkChain(fatTrimmed, firstDirSector, sector => {
    const base = (sector + 1) * sectorSize;
    if (base + sectorSize <= bytes.length) dirParts.push(bytes.slice(base, base + sectorSize));
  }, problems);
  if (dirParts.length === 0) {
    result.failure = '目录扇区链为空或越过文件尾，无法枚举条目';
    result.notes.push(...problems);
    return result;
  }
  const dirAt = (index: number): { buffer: Uint8Array; offset: number } | null => {
    let remaining = index * 128;
    for (const part of dirParts) {
      if (remaining + 128 <= part.length) return { buffer: part, offset: remaining };
      remaining -= part.length;
    }
    return null;
  };

  const readEntry = (index: number) => {
    const slot = dirAt(index);
    if (!slot) return null;
    const { buffer, offset } = slot;
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const nameLen = u16(buffer, offset + 64);
    const chars = Math.max(0, Math.min(32, (nameLen - 1) >> 1)); // nameLen 含结尾 NUL
    let name = '';
    for (let charIndex = 0; charIndex < chars; charIndex += 1) name += String.fromCharCode(view.getUint16(offset + charIndex * 2, true));
    const objectType = buffer[offset + 66];
    const left = u32(buffer, offset + 68);
    const right = u32(buffer, offset + 72);
    const child = u32(buffer, offset + 76);
    const clsid = buffer.slice(offset + 80, offset + 96);
    const startSector = u32(buffer, offset + 116);
    const sizeLow = u32(buffer, offset + 120);
    const sizeHigh = u32(buffer, offset + 124); // v4 的 64 位大小高 32 位（>4GB 流不导出，给出提示）
    return { name, objectType, left, right, child, startSector, size: sizeLow + sizeHigh * 4294967296, clsid };
  };

  // ---- Root Entry mini 流（mini 扇区池）----
  const root = readEntry(0);
  if (!root || root.objectType !== 5) {
    result.failure = '目录第 0 项不是 Root Entry，目录结构损坏';
    result.notes.push(...problems);
    return result;
  }
  let miniStream: Uint8Array = new Uint8Array(0);
  if (root.startSector !== ENDOFCHAIN) {
    const miniParts: Uint8Array[] = [];
    let collected = 0;
    walkChain(fatTrimmed, root.startSector, sector => {
      if (collected >= MAX_OLE_STREAM_BYTES) return;
      const base = (sector + 1) * sectorSize;
      if (base + sectorSize <= bytes.length) {
        miniParts.push(bytes.slice(base, base + sectorSize));
        collected += sectorSize;
      }
    }, problems);
    miniStream = miniParts.length === 1 ? miniParts[0] : (() => {
      const out = new Uint8Array(miniParts.reduce((sum, part) => sum + part.length, 0));
      let offset = 0;
      for (const part of miniParts) {
        out.set(part, offset);
        offset += part.length;
      }
      return out;
    })();
  }

  const readMiniStream = (start: number, size: number, problems2: string[]): Uint8Array => {
    const parts: Uint8Array[] = [];
    let collected = 0;
    walkChain(miniFat, start, miniSector => {
      if (collected >= size) return;
      const base = miniSector * miniSectorSize;
      if (base + miniSectorSize > miniStream.length) {
        if (problems2.length < 8) problems2.push(`mini 扇区 ${miniSector} 越过 Root mini 流尾，流被截断`);
        collected = size;
        return;
      }
      const take = Math.min(miniSectorSize, size - collected);
      parts.push(miniStream.slice(base, base + take));
      collected += take;
    }, problems2);
    const out = new Uint8Array(Math.min(collected, size));
    let offset = 0;
    for (const part of parts) {
      const take = Math.min(part.length, out.length - offset);
      if (take <= 0) break;
      out.set(part.subarray(0, take), offset);
      offset += take;
    }
    return out;
  };

  const readStreamBytes = (entry: ReturnType<typeof readEntry>, path: string): { bytes: Uint8Array | null; note?: string } => {
    if (!entry || entry.size === 0) return { bytes: new Uint8Array(0) };
    if (entry.size < miniStreamCutoff) {
      return { bytes: readMiniStream(entry.startSector, entry.size, problems) };
    }
    if (entry.size > maxStreamBytes) {
      return { bytes: null, note: `流 ${path} 大小 ${entry.size}B 超过单流导出上限 ${maxStreamBytes}B，只列条目不导出` };
    }
    return { bytes: readSectorStream(bytes, fatTrimmed, entry.startSector, sectorSize, entry.size, problems) };
  };

  // ---- 红黑树遍历（按 left/right/child 指针，带环保护）----
  // NOSTREAM = 0xFFFFFFFF（部分实现用 ENDOFCHAIN 0xFFFFFFFE），四种保留值一律视为空指针。
  const isNoStream = (value: number): boolean => value >= 0xfffffffc;
  const visitedNodes = new Set<number>();
  const emitEntry = (index: number, parentPath: string, depth: number): void => {
    if (depth > 32) return; // 深度保护（环保护在 walkTree 中做）
    const entry = readEntry(index);
    if (!entry) return;
    if (entry.objectType !== 1 && entry.objectType !== 2 && entry.objectType !== 5) return; // unknown 跳过
    const type: OleEntry['type'] = entry.objectType === 5 ? 'root' : entry.objectType === 1 ? 'storage' : 'stream';
    const path = type === 'root' ? '/' : `${parentPath === '/' ? '' : parentPath}/${entry.name}`;
    entries.push({
      path,
      name: entry.name,
      type,
      size: type === 'stream' ? entry.size : 0,
      clsidHex: entry.clsid.every(value => value === 0) ? null : Array.from(entry.clsid).map(value => value.toString(16).padStart(2, '0')).join(''),
    });
    if (type === 'stream') {
      const { bytes: streamBytes, note } = readStreamBytes(entry, path);
      if (streamBytes) streams.push({ path, bytes: streamBytes });
      if (note) notes.push(note);
    }
    if (type === 'root' || type === 'storage') {
      walkTree(entry.child, path, depth + 1); // storage 的子树
    }
  };
  const walkTree = (nodeIndex: number, parentPath: string, depth: number): void => {
    if (isNoStream(nodeIndex)) return;
    if (depth > 32 || visitedNodes.has(nodeIndex)) {
      if (visitedNodes.has(nodeIndex)) problems.push(`目录树存在环引用（节点 ${nodeIndex}），该分支跳过`);
      return;
    }
    visitedNodes.add(nodeIndex);
    const entry = readEntry(nodeIndex);
    if (!entry) return;
    walkTree(entry.left, parentPath, depth + 1);
    emitEntry(nodeIndex, parentPath, depth);
    walkTree(entry.right, parentPath, depth + 1);
  };
  // Root Entry（目录第 0 项）本身不入树，显式发出后遍历其 child 红黑树。
  entries.push({ path: '/', name: 'Root Entry', type: 'root', size: 0, clsidHex: root.clsid.every(value => value === 0) ? null : Array.from(root.clsid).map(value => value.toString(16).padStart(2, '0')).join('') });
  if (root.child !== undefined) walkTree(root.child, '/', 0);

  if (visitedNodes.size === 0) notes.push('Root Entry 没有 child 指针：文档只有根节点，没有可列的 storage/stream');

  collectEncryptedHints(streams, encryptedHints);
  result.notes.push(...problems);
  result.ok = true;
  return result;
};
