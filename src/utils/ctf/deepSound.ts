// DeepSound 音频隐写提取引擎（音频域 B2-7）：RIFF/WAV 载体 → 样本低位流滑动扫描 →
// DSCF/DSC2 头解析 → 按模式低位提取 → DSSF 记录链解析 → 可选 AES-256-ECB 解密。
// 格式口径（对官方 DeepSound 工具实机逆向核实，2026-10，GitHub Jpinsoft/DeepSound v2.0/v2.3
// 官方产物逐字节验证，另与 openwall/john deepsound2john.py 公开口径交叉比对）：
// - 样本流 S = data chunk 内每个音频采样"最低有效字节"按帧序排列（16bit 取偶数索引字节，
//   8/24/32bit 取每样本首字节）；立体声两通道按帧交织视为同一条流（实测噪声载体 L/R 交替携带
//   同一数据流的相邻字节）。
// - 头部恒以 mode-4 口径（字节 i = (S[2i]&0x0F)<<4 | (S[2i+1]&0x0F)）编码在前 6 字节：
//   [0..3]='DSCF'（2.0）/ 'DSC2'（2.1+，"more secured format + unicode password"）；
//   [4]=mode：2=LowQuality（每样本藏全 8bit，逐样本连续）/ 4=NormalQuality（每样本低 4 位，
//   两样本拼一字节）/ 8=HiQuality（每样本低 2 位，四样本拼一字节）；[5]=AES 加密标志(0/1)。
//   头部 6 字节占样本 0..11；数据区从样本 12 起，加密时字节 6..25 另存 20B 口令摘要
//   （实测派生算法带盐，非裸 SHA-1/SHA-256，仅作展示），密文从样本 52 起。
// - 记录链（明文或解密后）：'DSSF'(4) + 文件名(20B，零截断) + 大端 uint32 长度(4) +
//   4 字节零 = 32B 记录头；随后为文件内容并补零对齐到 4 字节；以长度 0 的空记录收尾。
// - 加密：AES-256-ECB 无填充，明文零补齐到块边界。DSC2 密钥 = SHA-256(UTF-16LE(口令))
//   （实测 v2.3 载体解密命中）；DSCF 依次尝试 ASCII 口令右补零 32B（任务口径）与
//   SHA-1(口令) 右补零 32B（openwall/john #3195 口径）；实测 v2.0 加密载体的派生带盐，
//   两条口径都无法解开官方 2.0 加密样本——如实拒绝并说明。
// - 对拍锚点：官方工具生成的真实载体（无密码 mode2/4/8 + DSC2 密码档全通过本引擎提取），
//   见 tests/deepsound.test.mjs 与 tests/fixtures/deepsound/。
// 只读实现；非 DSC 载体明确报"未发现 DeepSound 头"。
import { ecb } from '@noble/ciphers/aes.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { parseWav } from './audioStego';

export const MAX_DS_CARRIER_SAMPLES = 1 << 26;
const MAX_SCAN_START = 1 << 16; // 头部滑动扫描的样本上限（嵌入起点不必对齐，但总在浅层）
const MAX_TOTAL_PLAINTEXT = 32 * 1024 * 1024;

export interface DeepSoundFileInfo {
  fileName: string;
  size: number;
  bytes: Uint8Array;
}

export interface DeepSoundResult {
  found: boolean;
  marker: 'DSCF' | 'DSC2' | null;
  // 嵌入起点（样本流内偏移；头部恒按 mode-4 编码）。
  startSample: number | null;
  mode: 2 | 4 | 8 | null;
  modeName: string;
  encrypted: boolean;
  // 加密头里的 20B 口令摘要（hex）。实测派生带盐，仅作指纹展示，不用于解密。
  passwordDigest: string | null;
  files: DeepSoundFileInfo[];
  // 显式失败原因（错密码 / 记录链损坏等），永远不静默。
  failure: string | null;
  notes: string[];
}

const toHex = (bytes: Uint8Array): string => {
  let out = '';
  for (let index = 0; index < bytes.length; index += 1) out += bytes[index].toString(16).padStart(2, '0');
  return out;
};

const MODE_NAMES: Record<number, string> = { 2: 'low（每样本 8 位）', 4: 'normal（每样本 4 位）', 8: 'high（每样本 2 位）' };

// data chunk 定位（复用 audioStego.parseWav 校验 PCM 合法性，自己按 RIFF 规范再定位 data
// 的绝对偏移——parseWav 不暴露偏移，包装不改原文件）。
const locateDataChunk = (bytes: Uint8Array): number => {
  let pos = 12;
  while (pos + 8 <= bytes.length) {
    const id = String.fromCharCode(bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]);
    const size = bytes[pos + 4] | (bytes[pos + 5] << 8) | (bytes[pos + 6] << 16) | ((bytes[pos + 7] << 24) >>> 0);
    const bodyStart = pos + 8;
    if (id === 'data') return bodyStart;
    pos = bodyStart + size + (size & 1);
  }
  throw new Error('RIFF 中没有 data chunk，无法扫描 DeepSound 载体');
};

// 样本最低有效字节流：16bit 取偶数索引字节，8bit 全字节，24/32bit 取每样本首字节（LE 最低位）。
const buildSampleStream = (bytes: Uint8Array, dataOffset: number, bitsPerSample: number): Uint8Array => {
  const stride = bitsPerSample >> 3;
  const avail = bytes.length - dataOffset;
  const count = Math.floor(avail / stride);
  if (count <= 0) throw new Error('data chunk 为空，无法扫描 DeepSound 载体');
  const capped = Math.min(count, MAX_DS_CARRIER_SAMPLES);
  const out = new Uint8Array(capped);
  for (let index = 0; index < capped; index += 1) out[index] = bytes[dataOffset + index * stride];
  return out;
};

// mode-4 口径解码：字节 i = (S[2i]&15)<<4 | (S[2i+1]&15)（头部恒用此口径）。
const decodeMode4 = (stream: Uint8Array, start: number, count: number): Uint8Array => {
  const out = new Uint8Array(count);
  for (let index = 0; index < count; index += 1) {
    out[index] = ((stream[start + 2 * index] & 0x0f) << 4) | (stream[start + 2 * index + 1] & 0x0f);
  }
  return out;
};

// 数据区按实际模式解码。start 为样本流内起始（数据首字节所在样本）。
const decodeData = (stream: Uint8Array, start: number, mode: number, maxBytes: number): Uint8Array => {
  if (mode === 2) {
    // 每样本藏全 8bit：逐样本连续取整字节。
    const take = Math.min(maxBytes, stream.length - start);
    return stream.slice(start, start + take);
  }
  if (mode === 4) return decodeMode4(stream, start, Math.min(maxBytes, (stream.length - start) >> 1));
  // mode 8：四样本低 2 位 MSB-first 拼一字节。
  const count = Math.min(maxBytes, (stream.length - start) >> 2);
  const out = new Uint8Array(count);
  for (let index = 0; index < count; index += 1) {
    const base = start + 4 * index;
    out[index] = ((stream[base] & 3) << 6) | ((stream[base + 1] & 3) << 4) | ((stream[base + 2] & 3) << 2) | (stream[base + 3] & 3);
  }
  return out;
};

// AES-256-ECB 无填充解密（逐 16B 块，密文尾部不足一块的零尾巴丢弃）。
const aesEcbDecryptBlocks = (key: Uint8Array, data: Uint8Array): Uint8Array => {
  const blocks = Math.floor(data.length / 16);
  if (blocks < 1) return new Uint8Array(0);
  return ecb(key, { disablePadding: true }).decrypt(data.subarray(0, blocks * 16));
};

// UTF-16LE 编码（TextEncoder 无 utf-16le 支持，手工展开）。
const utf16le = (text: string): Uint8Array => {
  const out = new Uint8Array(text.length * 2);
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    out[index * 2] = code & 0xff;
    out[index * 2 + 1] = (code >> 8) & 0xff;
  }
  return out;
};

// 各 marker 的候选 AES-256 密钥（按优先级）。
const deriveKeys = (marker: 'DSCF' | 'DSC2', password: string): Uint8Array[] => {
  if (marker === 'DSC2') {
    // v2.1+ 实测口径：SHA-256(UTF-16LE(口令))。
    return [sha256(utf16le(password))];
  }
  // v2.0：任务口径 ASCII 口令右补零 32B 优先，john #3195 口径 SHA-1(口令) 右补零兜底。
  const ascii = new Uint8Array(32);
  ascii.set(new TextEncoder().encode(password).subarray(0, 32), 0);
  const sha1Key = new Uint8Array(32);
  sha1Key.set(sha1(new TextEncoder().encode(password)), 0);
  return [ascii, sha1Key];
};

// 记录链解析：32B 记录头（DSSF + 20B 文件名 + BE uint32 长度 + 4B 零），内容后补零到
// 4 字节对齐（实测补齐量 = 4 - 长度%4，长度恰为 4 的倍数时补 4 字节，实测 len=24 补 4、
// len=26 补 2）；长度 0 的空记录为链尾。2.0 加密载体的链尾是「DSSF + 零填充」而非完整
// 空记录——遇到 DSSF 后字段为垃圾时按链尾处理。
const parseRecordChain = (data: Uint8Array, notes: string[], maxTotal: number): DeepSoundFileInfo[] => {
  const files: DeepSoundFileInfo[] = [];
  let pos = 0;
  let total = 0;
  while (pos + 32 <= data.length && files.length < 256) {
    if (data[pos] !== 0x44 || data[pos + 1] !== 0x53 || data[pos + 2] !== 0x53 || data[pos + 3] !== 0x46) {
      if (files.length === 0) throw new Error('记录链起点没有 DSSF 标记（解密结果不是合法的 DeepSound 记录链）');
      notes.push(`记录链在偏移 ${pos} 处丢失 DSSF 标记，提取提前结束（已解出 ${files.length} 个文件）`);
      break;
    }
    let nameEnd = pos + 4;
    while (nameEnd < pos + 24 && data[nameEnd] !== 0) nameEnd += 1;
    const fileName = new TextDecoder('latin1').decode(data.slice(pos + 4, nameEnd));
    const length = ((data[pos + 24] << 24) | (data[pos + 25] << 16) | (data[pos + 26] << 8) | data[pos + 27]) >>> 0;
    if (length === 0) break; // 空记录 = 链尾
    if (pos + 32 + length > data.length) {
      if (files.length === 0) {
        throw new Error(`首个记录「${fileName}」声明 ${length}B 超过解密数据量 ${Math.max(0, data.length - pos - 32)}B：不是合法记录链`);
      }
      notes.push(`链尾记录字段为填充垃圾（官方 2.0 加密档链尾即「DSSF+零填充」），按 ${files.length} 个文件收尾`);
      break;
    }
    total += length;
    if (total > maxTotal) {
      notes.push(`累计明文超过上限，只提取前 ${files.length} 个文件`);
      break;
    }
    files.push({ fileName, size: length, bytes: data.slice(pos + 32, pos + 32 + length) });
    const contentEnd = pos + 32 + length;
    pos = contentEnd + (4 - (length % 4)); // 内容补零到 4 字节对齐（最少补 1 字节，实测口径）
  }
  return files;
};

// 主入口：从 WAV 载体提取 DeepSound 隐藏文件。options.password 提供口令（加密载体必填）。
export const extractDeepSound = (bytes: Uint8Array, options?: { password?: string }): DeepSoundResult => {
  const notes: string[] = [];
  const result: DeepSoundResult = {
    found: false,
    marker: null,
    startSample: null,
    mode: null,
    modeName: '',
    encrypted: false,
    passwordDigest: null,
    files: [],
    failure: null,
    notes,
  };
  const wav = parseWav(bytes); // 复用 audioStego 的 PCM 校验（非 PCM 抛中文错误）
  const dataOffset = locateDataChunk(bytes);
  const stream = buildSampleStream(bytes, dataOffset, wav.info.bitsPerSample);

  // 头部滑动扫描：起点不必对齐，恒按 mode-4 口径解 6 字节头判 DSCF/DSC2。
  let header: { start: number; marker: 'DSCF' | 'DSC2'; mode: number; encrypted: boolean; digest: Uint8Array | null } | null = null;
  const scanLimit = Math.min(MAX_SCAN_START, stream.length - 104);
  for (let start = 0; start <= scanLimit; start += 1) {
    const head = decodeMode4(stream, start, 6);
    if (head[0] !== 0x44 || head[1] !== 0x53 || head[2] !== 0x43) continue;
    const marker: 'DSCF' | 'DSC2' | null = head[3] === 0x46 ? 'DSCF' : head[3] === 0x32 ? 'DSC2' : null;
    if (!marker) continue;
    const mode = head[4];
    const encrypted = head[5] === 1;
    if (mode !== 2 && mode !== 4 && mode !== 8) {
      notes.push(`样本 ${start} 处发现 ${marker} 标记但 mode=${mode} 不是 2/4/8，跳过`);
      continue;
    }
    let digest: Uint8Array | null = null;
    if (encrypted) {
      if (start + 52 > stream.length) {
        notes.push(`${marker} 标记后样本不足，无法读取 20B 口令摘要`);
        continue;
      }
      digest = decodeMode4(stream, start + 12, 20); // 头字节 6..25 = 样本 12..31（20B 摘要）
    }
    header = { start, marker, mode, encrypted, digest };
    break;
  }
  if (!header) {
    result.failure = '未发现 DeepSound 头（DSCF/DSC2 标记扫描无命中）：不是 DeepSound 2.x 载体';
    return result;
  }
  result.found = true;
  result.marker = header.marker;
  result.startSample = header.start;
  result.mode = header.mode as 2 | 4 | 8;
  result.modeName = MODE_NAMES[header.mode] ?? `mode ${header.mode}`;
  result.encrypted = header.encrypted;
  result.passwordDigest = header.digest ? toHex(header.digest) : null;
  if (header.start !== 0) notes.push(`嵌入起点在样本 ${header.start}（非零偏移，头部按 mode-4 口径对齐扫描命中）`);

  const dataStart = header.encrypted ? header.start + 52 : header.start + 12;
  if (!header.encrypted) {
    const data = decodeData(stream, dataStart, header.mode, MAX_TOTAL_PLAINTEXT);
    result.files = parseRecordChain(data, notes, MAX_TOTAL_PLAINTEXT);
    if (result.files.length === 0) {
      result.failure = result.failure ?? '记录链为空：载体头部存在但未解出任何文件';
    }
    return result;
  }

  // 加密载体：没有口令直接显式拒绝。
  const password = options?.password;
  if (password === undefined || password === '') {
    result.failure = '载体已 AES-256 加密（AES 标志=1），需要提供口令才能解密记录链';
    return result;
  }
  const candidates = deriveKeys(header.marker, password);
  for (const [keyIndex, key] of candidates.entries()) {
    const data = decodeData(stream, dataStart, header.mode, MAX_TOTAL_PLAINTEXT);
    const plain = aesEcbDecryptBlocks(key, data);
    try {
      const files = parseRecordChain(plain, notes, MAX_TOTAL_PLAINTEXT);
      result.files = files;
      if (keyIndex > 0) notes.push(`按第 ${keyIndex + 1} 候选密钥派生解密成功`);
      return result;
    } catch {
      notes.push(`候选密钥 #${keyIndex + 1} 解密后不是 DSSF 记录链`);
    }
  }
  result.files = [];
  result.failure = '解密失败：所有候选密钥（' + (header.marker === 'DSC2' ? 'SHA-256(UTF-16LE)' : 'ASCII 补零 / SHA-1 补零') + '）解出的数据都不是 DSSF 记录链——口令错误或该载体的密钥派生为带盐变体（实测官方 2.0 加密档的摘要字段不等于 SHA-1(口令) 的任何常见编码），已显式拒绝，不输出伪造明文';
  return result;
};
