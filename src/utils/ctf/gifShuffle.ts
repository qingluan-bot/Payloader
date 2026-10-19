// GIF 调色板排序隐写 gifshuffle 解码档（杂项取证域，CTF 能力补强批次三 B3-6）。
// 算法出处：Matthew Kwan gifshuffle 2.0（Debian 源码包 encode.c/gifshuffle.1，darkside.com.au）：
//  1. 取色表中「唯一色」按槽位顺序（重复色剔除，不参与编码）；
//  2. 唯一色按 RGB 值（r<<16|g<<8|b）排序得秩（无口令口径；2.0 带口令时按加密哈希排序，本档不支持）；
//  3. 阶乘进制还原大整数 m：pos[rank]=槽位，m = ((0·n + pos[0])·(n-1) + pos[1])·… （i=0..n-2 乘 n-i），
//     内层对未处理秩做「大于当前槽位则减一」的删除补偿（与原实现 ci_array 内层循环一致）；
//  4. 位流：m 的二进制最高位是哨兵 1（消息为空时 m=1），其余位按追加序（LSB 先出）拼回字节，
//     每字节 MSB 在前（原实现 character_encode 以 (c & (128>>i)) 逐位输出）；
//  5. 容量锚点：256 唯一色 = bitLength(256!-1) - 1 = 1683 位（210 字节）。
// 本档边界：仅无口令、无压缩（-C/-p 均关闭）的 gifshuffle 数据；提取字节可打印率过低时提示
// 「该样本可能带加密/压缩层，当前不支持」。2.0 无口令时 v1/v2 排序一致，天然兼容两版。
// 色表变化判定：LZW 像素解码仅用于第一帧一致性体检与局部色表存在性提示（gifshuffle 只编码
// 全局色表排列，帧级局部色表意味着色表变化，提取口径以全局色表为准）。复用 gifInspect 导出面。
// 测试权威向量：tests/gif-shuffle.test.mjs（阶乘进制手算对拍 + 测试侧独立实现编码器交叉验证）。

import { decodeGifFrame, inspectGif } from './gifInspect';
import type { GifInspectResult } from './gifInspect';

export interface GifShuffleResult {
  uniqueColors: number; // 唯一色数 n（容量由 n! 决定）
  permutationNumber: string; // 阶乘进制还原的大整数（十进制字符串，BigInt）
  bitLength: number; // 含哨兵位的总位数
  capacityBits: number; // 净容量 = bitLength(n!-1) - 1
  bytes: Uint8Array; // 提取的原始消息字节
  text: string; // 消息文本（UTF-8 优先，失败回落 latin1）
  printableRatio: number; // 可打印率 0-1
  notes: string[]; // 局部色表/加密压缩层提示等
}

// bitLength(n! - 1)：BigInt 逐乘累积（n ≤ 256 时毫秒级）。
const factorialBitLength = (n: number): number => {
  let factorial = 1n;
  for (let index = 2; index <= n; index += 1) factorial *= BigInt(index);
  return (factorial - 1n).toString(2).length;
};

// gifshuffle 容量：n 唯一色的净容量位数（哨兵占 1 位）。n < 2 时无存储空间。
export const gifShuffleCapacityBits = (uniqueColors: number): number => {
  if (!Number.isInteger(uniqueColors) || uniqueColors < 0) throw new Error(`唯一色数非法：${uniqueColors}`);
  if (uniqueColors < 2) return 0;
  return factorialBitLength(uniqueColors) - 1;
};

// 色表（RGB 三元组平铺）→ 阶乘进制大整数。唯一色按槽位顺序收集，按 24bit RGB 值定秩。
export const permutationNumberFromColorTable = (palette: Uint8Array): { value: bigint; uniqueCount: number; slotRanks: number[] } => {
  if (palette.length < 3 || palette.length % 3 !== 0) {
    throw new Error(`色表字节数 ${palette.length} 不是 3 的倍数，无法按 RGB 三元组解析`);
  }
  const slotValues: number[] = [];
  const seen = new Set<number>();
  for (let slot = 0; slot < palette.length / 3; slot += 1) {
    const value = (palette[slot * 3] << 16) | (palette[slot * 3 + 1] << 8) | palette[slot * 3 + 2];
    if (seen.has(value)) continue; // 重复色不参与编码（gifshuffle unique_colours 口径）
    seen.add(value);
    slotValues.push(value);
  }
  const n = slotValues.length;
  if (n < 2) {
    throw new Error(`色表只有 ${n} 个唯一色，gifshuffle 无存储空间（至少需要 2 个唯一色）`);
  }
  // 秩：按 RGB 值升序的位置。
  const sorted = [...slotValues].sort((left, right) => left - right);
  const slotRanks = slotValues.map(value => sorted.indexOf(value));
  // pos[rank] = 槽位；Horner 乘 (n-i) 累加，内层对未处理秩做删除补偿。
  const positions = new Array<number>(n);
  for (let slot = 0; slot < n; slot += 1) positions[slotRanks[slot]] = slot;
  let value = 0n;
  for (let rank = 0; rank < n - 1; rank += 1) {
    const position = positions[rank];
    value *= BigInt(n - rank);
    value += BigInt(position);
    for (let rest = rank + 1; rest < n; rest += 1) {
      if (positions[rest] > position) positions[rest] -= 1;
    }
  }
  return { value, uniqueCount: n, slotRanks };
};

// 大整数 → 消息字节：最高位的 1 是哨兵，其余位按追加序（LSB 先出）8 位拼字节（MSB 在前）。
export const messageFromPermutationNumber = (value: bigint): { bytes: Uint8Array; sentinelBitIndex: number; remainderBits: number } => {
  if (value < 0n) throw new Error('排列数不能为负');
  const bitLength = value === 0n ? 0 : value.toString(2).length;
  const sentinelBitIndex = bitLength === 0 ? -1 : bitLength - 1; // 哨兵即最高位（m≥1 恒有）
  const messageBits = Math.max(0, sentinelBitIndex); // 哨兵之下的位数
  const wholeBytes = Math.floor(messageBits / 8);
  const bytes = new Uint8Array(wholeBytes);
  for (let index = 0; index < messageBits; index += 1) {
    if ((value >> BigInt(index)) & 1n) {
      bytes[index >> 3] |= 0x80 >> (index & 7); // 追加序 → 每字节 MSB 在前
    }
  }
  return { bytes, sentinelBitIndex, remainderBits: messageBits - wholeBytes * 8 };
};

const bytesToText = (bytes: Uint8Array): string => {
  const utf8 = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  return utf8.includes('\uFFFD') ? Array.from(bytes, byte => String.fromCharCode(byte)).join('') : utf8;
};

const printableRatioOf = (text: string): number => {
  if (!text.length) return 0;
  let printable = 0;
  for (const char of text) {
    const code = char.charCodeAt(0);
    if ((code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13) printable += 1;
  }
  return printable / text.length;
};

// 主入口：GIF 字节 → gifshuffle 解码档结果。只读输入，同步，无口令无压缩口径。
export const decodeGifShuffle = (bytes: Uint8Array): GifShuffleResult => {
  const inspected: GifInspectResult = inspectGif(bytes);
  const notes: string[] = [];

  // 目标色表：优先全局色表；无全局时回落第一帧局部色表（并提示口径）。
  const firstLocal = inspected.frames.map(frame => frame.localColorTable).find(table => table && table.length >= 3) ?? null;
  const palette = inspected.globalColorTable ?? firstLocal;
  if (!palette) throw new Error('该 GIF 无全局色表且帧无局部色表，gifshuffle 无从提取');
  if (!inspected.globalColorTable && firstLocal) {
    notes.push('无全局色表，按第一帧局部色表提取（非 gifshuffle 常规载体，结果需人工复核）');
  }

  // 色表变化判定：帧级局部色表意味着色表切换，gifshuffle 原版只编码全局色表。
  const localTableFrames = inspected.frames.filter(frame => frame.localColorTable && frame.localColorTable.length >= 3).length;
  if (localTableFrames > 0) {
    notes.push(`${localTableFrames} 帧携带局部色表（色表变化）：gifshuffle 只编码全局色表排列，本结果以全局色表为准`);
  }
  // 第一帧 LZW 像素解码体检：验证色表不是摆设（解码失败不阻断提取，仅记录线索）。
  if (inspected.frames.length > 0) {
    try {
      decodeGifFrame(bytes, inspected.frames[0], inspected.globalColorTable);
    } catch (error) {
      notes.push(`第一帧像素解码失败（${error instanceof Error ? error.message : String(error)}），色表与像素索引可能被篡改`);
    }
  }

  const { value, uniqueCount } = permutationNumberFromColorTable(palette);
  const capacityBits = gifShuffleCapacityBits(uniqueCount);
  const { bytes: message, sentinelBitIndex, remainderBits } = messageFromPermutationNumber(value);
  if (value === 0n || sentinelBitIndex <= 0) {
    notes.push('排列数为 0 或仅含哨兵位：未嵌入消息（或载体是未做 gifshuffle 的普通 GIF）');
  }
  if (remainderBits > 0 && message.length > 0) {
    notes.push(`位流尾部 ${remainderBits} 位不足一个字节，按填充丢弃`);
  }

  const text = bytesToText(message);
  const printableRatio = printableRatioOf(text);
  if (message.length > 0 && printableRatio < 0.5) {
    notes.push('提取字节可打印率过低：该样本带加密/压缩层（gifshuffle -p 口令或 -C 压缩），当前仅支持无口令无压缩档，不支持解密解压');
  }
  if (capacityBits > 0 && message.length * 8 > capacityBits) {
    notes.push('提取位数超过理论容量（异常载体），结果不可信');
  }

  return {
    uniqueColors: uniqueCount,
    permutationNumber: value.toString(10),
    bitLength: value === 0n ? 0 : value.toString(2).length,
    capacityBits,
    bytes: message,
    text,
    printableRatio,
    notes,
  };
};
