// F5 隐写提取器（批次 SI·A 线收尾件）：Westfeld F5 Extract.java 语义——按 F5Random
// 派生的置乱序遍历 MCU 交织展平的全部 DCT 系数（块内 natural order，含 DC），跳过
// 每块 DC 与收缩产生的 0 系数；前 32 个可用位 LSB-first 组成长度头并去白噪（小端
// 4 字节，pad 按 Java 带符号 byte 符号扩展后再移位异或），头部高字节算术移位 %32
// 是矩阵编码参数 k、低 23 位是声明载荷长度；k>0 时正文按矩阵解码：每 2^k-1 个可用
// 系数为一块，块内 LSB 为 1 的 code（1..n）异或出 k 位段，k 位段 LSB-first 逐位落入
// 字节累加器（Java：extractedByte |= ((hash>>i)&1) << availBits++）；k=0 时每个可用
// 系数直嵌 1 bit（同样 LSB-first）。每输出字节再与 PRNG 字节异或去白噪。
// 布局适配：vendor 解码器按标准之字表落系数，而 F5（ortega/jpeg-6b 系）块内 55/62
// 两槽为历史互换序——消费前对每块做 55↔62 交换得到 jpeg-6b 布局（outguess 同源同
// 处理；jsteg Go 版用标准序，不受影响）。真实工具黄金向量：Westfeld 原版 Java F5
// 产物（tests/fixtures/f5-real-westfeld.jpg，口令 Password123）。
// PRNG 消耗序必须与嵌入端逐拍一致，任何一处错位都会整体雪崩：
// Permutation 构造（coeff.length 次 getNextValue，每次 4 字节）→ 头部去白噪 4 字节
// → 每输出字节 1 字节。
import { F5Permutation, F5Random } from './f5Crypto';
import { readJpegCoefficients } from './jpegCoeffs';

export interface F5ExtractResult {
  data: Uint8Array;
  k: number;
  declaredLength: number;
  usableCoefficients: number;
}

// jpeg-6b 布局适配：F5/outguess 的原版工具链（jpeg-6b jpeg_natural_order 尾部 55/62
// 历史互换）与本仓 vendor 解码器的标准之字表在块内 55/62 两槽错位，逐块交换即对齐。
// 交换以整块（64 系数）为单位，尾部不足一块的余数不动（真实 JPEG 系数总数恒为 64 的
// 整数倍；该约束只防非系数流误用）
const swapLegacySlots55And62 = (coeff: Int32Array): void => {
  for (let base = 0; base + 64 <= coeff.length; base += 64) {
    const slot55 = coeff[base + 55];
    coeff[base + 55] = coeff[base + 62];
    coeff[base + 62] = slot55;
  }
};

// 口令 → 字节用 Latin-1：对齐 Java 口令的 8 位缺省编码与本仓 jphs 线约定；
// F5 载荷口令事实标准是 ASCII，此时与 UTF-8 等价
const passwordBytes = (password: string): Uint8Array => {
  const bytes = new Uint8Array(password.length);
  for (let index = 0; index < password.length; index += 1) {
    bytes[index] = password.charCodeAt(index) & 0xff;
  }
  return bytes;
};

// 可用位读取约定（Extract.java 的正负分支）：正系数取物理 LSB、负系数取反——
// F5 嵌入端按 |c|±1 翻转，双端共用同一读位函数才能维持块 hash 一致
const bitOf = (coefficient: number): number =>
  coefficient > 0 ? coefficient & 1 : 1 - (coefficient & 1);

export const f5ExtractFromCoefficients = (
  inputCoefficients: Int32Array,
  password: string,
): F5ExtractResult => {
  // 防御性拷贝后做 jpeg-6b 布局适配：不改动调用方传入的系数数组
  const coeff = Int32Array.from(inputCoefficients);
  swapLegacySlots55And62(coeff);
  const random = new F5Random(passwordBytes(password));
  const permutation = new F5Permutation(coeff.length, random);

  // 可用系数总数（非 DC、非 0）：容量上限校验与结果字段共用
  let usableCoefficients = 0;
  for (let index = 0; index < coeff.length; index += 1) {
    if (index % 64 !== 0 && coeff[index] !== 0) usableCoefficients += 1;
  }

  // 头 32 位：与正文共用同一条可用系数流（跳 DC 与 0），LSB-first 累位
  let header = 0;
  let headerBits = 0;
  let cursor = 0;
  while (headerBits < 32) {
    if (cursor >= coeff.length) {
      throw new Error('系数容量不足：可用系数不够拼出 32 位长度头');
    }
    const index = permutation.getShuffled(cursor);
    cursor += 1;
    if (index % 64 === 0 || coeff[index] === 0) continue;
    header |= bitOf(coeff[index]) << headerBits;
    headerBits += 1;
  }
  // 去白噪：Permutation 构造后的前 4 个 PRNG 字节，小端异或。Java getNextByte 返回带
  // 符号 byte，负字节左移会把高位翻成 1——先 (b<<24)>>24 符号扩展再移位（与 Java
  // int 运算逐位一致），末端 |0 收敛回带符号 int32
  header = (header
    ^ ((random.getNextByte() << 24) >> 24)
    ^ (((random.getNextByte() << 24) >> 24) << 8)
    ^ (((random.getNextByte() << 24) >> 24) << 16)
    ^ (((random.getNextByte() << 24) >> 24) << 24)) | 0;
  // Java 算术移位语义（header 为负时 >>> 与 >> 结果不同），负数取模保留符号亦同 Java
  const k = (header >> 24) % 32;
  const declaredLength = header & 0x007fffff;
  const n = (1 << k) - 1;
  // 容量防线：任何 F5 载荷每字节至多消耗 8 个可用系数（k=0 恰 1 位/系数；k>0 时
  // n=k 位段占 n>1 个系数，位密度 <1）——超出即口令错误或非 F5 载荷。不用嵌入端
  // capacity 公式（floor((usable-32)/n)×k）：嵌入收缩会减少可用系数，对真实载荷会误杀
  if (declaredLength <= 0 || declaredLength * 8 > usableCoefficients - 32) {
    throw new Error(
      `口令错误或非 F5 载荷：头部长度字段解码为 ${declaredLength} 字节，超出系数可用容量`,
    );
  }

  const output = new Uint8Array(declaredLength);
  let outputIndex = 0;
  // LSB-first 位累加器（Java Extract.java：extractedByte |= bit << availableExtractedBits++），
  // 凑满 8 位即与 PRNG 字节异或去白噪落一个输出字节；载荷凑齐后段内剩余位丢弃
  // （Java 的 break extractingLoop 同语义）
  let extractedByte = 0;
  let availBits = 0;
  const pushBit = (bit: number): void => {
    if (outputIndex >= declaredLength) return;
    extractedByte |= bit << availBits;
    availBits += 1;
    if (availBits === 8) {
      output[outputIndex] = (extractedByte ^ random.getNextByte()) & 0xff;
      outputIndex += 1;
      extractedByte = 0;
      availBits = 0;
    }
  };

  // 单一遍历循环：块状态（hash/code）作为循环携带变量，k=0 走逐位直嵌分支
  let hash = 0;
  let code = 0;
  while (outputIndex < declaredLength) {
    if (cursor >= coeff.length) {
      throw new Error('系数耗尽仍未凑齐头部声明的载荷长度（口令错误或非 F5 载荷）');
    }
    const index = permutation.getShuffled(cursor);
    cursor += 1;
    if (index % 64 === 0 || coeff[index] === 0) continue;
    if (n === 0) {
      pushBit(bitOf(coeff[index]));
      continue;
    }
    code += 1;
    if (bitOf(coeff[index]) === 1) hash ^= code;
    if (code === n) {
      // k 位段 LSB-first 逐位入累加器（Java：for i<k，extractedByte |= ((hash>>i)&1)<<availBits++）
      for (let bitIndex = 0; bitIndex < k; bitIndex += 1) {
        pushBit((hash >> bitIndex) & 1);
      }
      hash = 0;
      code = 0;
    }
  }
  return { data: output, k, declaredLength, usableCoefficients };
};

export const f5Extract = (jpegBytes: Uint8Array, password: string): F5ExtractResult =>
  f5ExtractFromCoefficients(readJpegCoefficients(jpegBytes).mcuOrderCoefficients, password);
