// zsteg 式位平面全组合自动扫描引擎（misc 域图片隐写命中）：在 通道组 × bit × 字节内位序 ×
// 像素序 × 行序 × 每采样位宽 的全部组合上提取字节流并评分（zlib/gzip 魔数、flag 正则、
// 可打印率、base64），只返回带命中理由的组合，按 score 降序截 maxHits。提取语义以
// imagePlanes.extractLsbBytes 为基准（行序 + MSB-first + 单通道 + topdown + 1bit），命中该
// 基准的组合直接复用原函数避免行为漂移；其余变体是本文件受控扩展：
// - lsbFirst：字节内低位在前（第 1 个采样位落 b0）；
// - column：先固定 x 遍历 y；
// - rowOrder='bottomup'：像素行自底向上取（BMP 文件扫描线是自底向上存储，zsteg 对 BMP
//   按文件原始行序处理——canvas 解码语义丢掉了这维，BUG#6/打野真题的修复面）；
// - bitsPerSample∈{2,4}：每样本取 bitsPerSample 个最低位、高位在前拼流（zsteg -b 2/4 型
//   嵌入；10_lsb_png 真题口径 (bit1<<1|bit0) MSB-first），bit 维度恒为 1（LSB 基准）。
// 组合规模：1bit=576、2bit/4bit 各 72，总 720 次提取；每次提取受 maxBytes 窗口约束，
// 实测 4096² 图全扫秒级内。纯函数、只读输入、无 Canvas/DOM 依赖，可在 node 测试。
import { bytesToPreviewText, extractLsbBytes } from './imagePlanes';
import type { RgbaChannel } from './imagePlanes';

export type RowOrder = 'topdown' | 'bottomup';
export type BitsPerSample = 1 | 2 | 4;

export interface BitPlaneHit {
  channel: string;
  // 1..8，1=LSB（zsteg b1 命名习惯；内部换算为 imagePlanes 的 0 起始 bit 下标）。
  // bitsPerSample>1 时恒为 1（多位采样从 LSB 起取）。
  bit: number;
  // 每样本采样位宽（1=单 bit 位平面；2/4=zsteg -b 2/4 型多位采样）。
  bitsPerSample: BitsPerSample;
  lsbFirst: boolean;
  pixelOrder: 'row' | 'column';
  rowOrder: RowOrder;
  score: number;
  reasons: string[];
  preview: string;
  byteCount: number;
}

export interface BitPlaneScanOptions {
  // 单组合提取字节上限（评分窗口），默认 256（zsteg -a 惯例）。
  maxBytes?: number;
  // 返回命中数上限，默认 20。
  maxHits?: number;
}

// 通道组按 zsteg 命名习惯：rgb/rgba/bgr/bgra 是"每像素内按该序连续取字节"的打包序；
// all 与 rgba 字节序相同（r,g,b,a），仅命名并存，命中时会并列出现。
const CHANNEL_GROUPS: Array<{ name: string; channels: RgbaChannel[] }> = [
  { name: 'r', channels: [0] },
  { name: 'g', channels: [1] },
  { name: 'b', channels: [2] },
  { name: 'a', channels: [3] },
  { name: 'rgb', channels: [0, 1, 2] },
  { name: 'bgr', channels: [2, 1, 0] },
  { name: 'rgba', channels: [0, 1, 2, 3] },
  { name: 'bgra', channels: [2, 1, 0, 3] },
  { name: 'all', channels: [0, 1, 2, 3] },
];

// 排序兜底的通道名次序（同分时按 r→g→b→a→rgb→bgr→rgba→bgra→all 稳定输出）。
const CHANNEL_RANK: Record<string, number> = {
  r: 0, g: 1, b: 2, a: 3, rgb: 4, bgr: 5, rgba: 6, bgra: 7, all: 8,
};

// flag 正则按工具箱常用赛题前缀维护（i 大小写不敏感）。通用分支的花括号内容限定可打印
// 字符：真实 flag 必为可打印串，而全组合扫描下不限定的 [^}]{3,} 会贪婪吞掉
// 控制字符造成成片误报（实测纯随机图即触发），故收紧到 [ -~]。
const FLAG_PATTERN = /(flag|ctf|key|ctfshow|NSSCTF|DASCTF|BaseCTF|wanictf)\{|[A-Za-z0-9_]{2,}\{[ -~]{3,}\}/i;

// 单组合提取：bitIndex 为 0 起始（0=LSB）。像素定位按 pixelOrder 展开采样序，再按
// rowOrder 做行翻转（bottomup = 第 1 个采样来自最后一行，即 BMP 文件扫描线序）。
const extractComboBytes = (
  rgba: ArrayLike<number>,
  width: number,
  height: number,
  channels: RgbaChannel[],
  bitIndex: number,
  lsbFirst: boolean,
  pixelOrder: 'row' | 'column',
  rowOrder: RowOrder,
  bitsPerSample: BitsPerSample,
  maxBytes: number,
): Uint8Array => {
  const pixels = Math.min(Math.floor(rgba.length / 4), width * height);
  // 与 extractLsbBytes 完全同语义的组合（单通道 + 行序 + topdown + MSB-first + 1bit）直接复用原函数。
  if (channels.length === 1 && !lsbFirst && pixelOrder === 'row' && rowOrder === 'topdown' && bitsPerSample === 1) {
    return extractLsbBytes(rgba, { channel: channels[0], bit: bitIndex, maxBytes });
  }
  const samples = Math.min(pixels * channels.length, Math.floor((maxBytes * 8) / bitsPerSample));
  const out = new Uint8Array(Math.ceil((samples * bitsPerSample) / 8));
  let byte = 0;
  let filled = 0;
  let written = 0;
  for (let sample = 0; sample < samples; sample += 1) {
    const ordinal = Math.floor(sample / channels.length);
    const channel = channels[sample % channels.length];
    const x = pixelOrder === 'row' ? ordinal % width : Math.floor(ordinal / height);
    const yTop = pixelOrder === 'row' ? Math.floor(ordinal / width) : ordinal % height;
    const y = rowOrder === 'bottomup' ? height - 1 - yTop : yTop;
    const value = rgba[(y * width + x) * 4 + channel];
    // 每样本按 高位→低位 出 bitsPerSample 个位（多位采样 MSB-of-pair 在前）。
    for (let offset = bitsPerSample - 1; offset >= 0; offset -= 1) {
      const bit = value & (1 << (bitIndex + offset)) ? 1 : 0;
      byte = lsbFirst ? byte | (bit << filled) : (byte << 1) | bit;
      filled += 1;
      if (filled === 8) {
        out[written] = byte;
        written += 1;
        byte = 0;
        filled = 0;
      }
    }
  }
  if (filled > 0) out[written] = lsbFirst ? byte : byte << (8 - filled);
  return out;
};

const isPrintableByte = (code: number): boolean =>
  (code >= 0x20 && code <= 0x7e) || code === 0x09 || code === 0x0a || code === 0x0d;

const isBase64Byte = (code: number): boolean =>
  (code >= 0x41 && code <= 0x5a)
  || (code >= 0x61 && code <= 0x7a)
  || (code >= 0x30 && code <= 0x39)
  || code === 0x2b || code === 0x2f || code === 0x3d;

// 评分：强 100 / 中 60 / 弱 30，理由可叠加；纯噪声返回空 reasons（调用方据此丢弃）。
// 可打印口径与 bytesToPreviewText 一致（0x20-0x7e + \t\n\r），避免预览与评分打架。
const evaluateBytes = (bytes: Uint8Array): { score: number; reasons: string[] } => {
  const reasons: string[] = [];
  let score = 0;
  if (bytes.length >= 2) {
    const head = bytes[0] * 0x100 + bytes[1];
    if (head === 0x7801 || head === 0x789c || head === 0x78da || head === 0x1f8b) {
      reasons.push('zlib/gzip 魔数');
      score += 100;
    }
  }
  let text = '';
  for (let index = 0; index < bytes.length; index += 1) text += String.fromCharCode(bytes[index]);
  if (FLAG_PATTERN.test(text)) {
    reasons.push('flag 格式');
    score += 100;
  }
  if (bytes.length >= 16) {
    let printable = 0;
    let base64 = true;
    for (let index = 0; index < bytes.length; index += 1) {
      if (isPrintableByte(bytes[index])) printable += 1;
      if (!isBase64Byte(bytes[index])) base64 = false;
    }
    if (printable / bytes.length >= 0.9) {
      reasons.push('高可打印率');
      score += 60;
    }
    if (base64) {
      reasons.push('疑似 base64');
      score += 30;
    }
  }
  return { score, reasons };
};

// 多位采样档位：1bit 全 bit 面 1..8；2/4bit 只从 LSB 起取（zsteg -b 2/4 语义，
// 真题锚点即 bit1..bit0）。组合规模 = 9 通道 × (8×1bit + 1×2bit + 1×4bit) × 2 位序 ×
// 2 像素序 × 2 行序 = 720。
const SAMPLE_WIDTHS: BitsPerSample[] = [1, 2, 4];

// 全组合扫描主入口。
export const scanBitPlanes = (
  rgba: ArrayLike<number>,
  width: number,
  height: number,
  options?: BitPlaneScanOptions,
): BitPlaneHit[] => {
  const maxBytes = options?.maxBytes ?? 256;
  const maxHits = options?.maxHits ?? 20;
  if (rgba.length < 4 || width <= 0 || height <= 0) return [];
  const hits: BitPlaneHit[] = [];
  for (const group of CHANNEL_GROUPS) {
    for (const bitsPerSample of SAMPLE_WIDTHS) {
      // 1bit 扫全 8 个位面；多位采样固定 bit=1（LSB 基准，zsteg b2/b4 语义）。
      const bitRange: number[] = bitsPerSample === 1 ? [1, 2, 3, 4, 5, 6, 7, 8] : [1];
      for (const bit of bitRange) {
        for (const lsbFirst of [false, true]) {
          for (const pixelOrder of ['row', 'column'] as const) {
            for (const rowOrder of ['topdown', 'bottomup'] as const) {
              const bytes = extractComboBytes(
                rgba, width, height, group.channels, bit - 1, lsbFirst, pixelOrder, rowOrder, bitsPerSample, maxBytes,
              );
              const verdict = evaluateBytes(bytes);
              if (verdict.reasons.length === 0) continue;
              hits.push({
                channel: group.name,
                bit,
                bitsPerSample,
                lsbFirst,
                pixelOrder,
                rowOrder,
                score: verdict.score,
                reasons: verdict.reasons,
                preview: bytesToPreviewText(bytes),
                byteCount: bytes.length,
              });
            }
          }
        }
      }
    }
  }
  hits.sort((left, right) =>
    right.score - left.score
    || CHANNEL_RANK[left.channel] - CHANNEL_RANK[right.channel]
    || left.bit - right.bit
    || left.bitsPerSample - right.bitsPerSample
    || Number(left.lsbFirst) - Number(right.lsbFirst)
    || Number(left.pixelOrder === 'column') - Number(right.pixelOrder === 'column')
    || Number(left.rowOrder === 'bottomup') - Number(right.rowOrder === 'bottomup'));
  return hits.slice(0, maxHits);
};
