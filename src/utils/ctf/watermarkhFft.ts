// WaterMarkH 频域隐形水印（批次 B3·E 线）：单图幅度谱提取。算法口径与 WaterMarkH 1.2.0.0
// 样本输出对拍的复刻实现（Henglie/EBCTFCodeBox src/core/watermarkhFft.js 的常数逐项核对，
// 该实现宣称与原 exe 输出 FFT 相位约定误差 ≤1e-15；原 exe 为闭源 Windows 程序）：
//   提取：幅度谱 = |DFT(通道/256)| × 256/√N × 增益（截断取整、饱和 0..255）。等价写法是
//         |ifft|·(N/√N)·256·增益——乘 N/√N 与除 √N 是同一件事，勿少一个 √N 因子。
//   嵌入（原软件行为，供造样本/互测）：图案 W = 黑底白字再中心对称镜像，**直接当作频谱**
//         叠加：S = conj(FFT(x/256))/√N + α·W/256（α=强度/500，默认 0.1），
//         输出像素 = trunc(clamp(|FFT(S)|·256/√N))。像素归一化除以 256（不是 255）。
//   原软件行为照抄：通道顺序无关（三通道叠同一图案，取模对共轭不变），alpha 不参与运算；
//   FFT 要求两方向都是 2 的幂，非 2 幂自动缩放并提示。
//   提取增强（原软件只支持手动增益）：自动增益（99.5 分位归 240）、去背景分位数拉伸
//   （0.60→0.995）、压制镜像副本（max(0, v−180°旋转副本)——中心对称图案的文字与其
//   180° 副本在频谱图上重叠，相减后小字更易辨认）。
// FFT 复用 src/utils/ctf/fft.ts（numpy 语义、已对拍 1e-12）。纯函数零 DOM，node 可单测。
import { fft2d } from './fft';
import type { RgbaImage } from './imageOps';

export const WATERMARKH_DEFAULT_GAIN = 10; // 原软件「亮度/5」的默认档
export const WATERMARKH_MAX_PIXELS = 1_000_000; // FFT 主线程同步运算预算（与 blindWatermark.ts 同口径）
const AUTOGAIN_TARGET = 240; // 99.5 分位归一点

export const watermarkhIsPowerOfTwo = (value: number): boolean => value > 0 && (value & (value - 1)) === 0;

// 最近 2 的幂（原软件几何方案一）：2^round(log2 v)
const nearestPowerOfTwo = (value: number): number => 2 ** Math.round(Math.log2(value));

const truncClamp255 = (value: number): number => {
  const truncated = Math.trunc(value);
  return truncated < 0 ? 0 : truncated > 255 ? 255 : truncated;
};

// 单通道通道缓冲提取（0..255 原值，归一化在各算法入口统一做）
const channelOf = (image: RgbaImage, channel: number): Float64Array => {
  const { width, height, data } = image;
  const out = new Float64Array(width * height);
  for (let index = 0; index < width * height; index += 1) {
    out[index] = data[index * 4 + channel];
  }
  return out;
};

// 提取单通道幅度谱：|fft2d(channel/256)| × 256/√N × gain，截断饱和，返回 0..255。
// 入参为 0..255 原始像素（归一化除以 256 在此统一做——不是除以 255，原软件口径）。
export const watermarkhExtractChannel = (channel: Float64Array, width: number, height: number, gain: number): Uint8ClampedArray => {
  const n = width * height;
  const scale = 256 / Math.sqrt(n);
  const im = new Float64Array(n);
  const re = new Float64Array(n);
  for (let index = 0; index < n; index += 1) re[index] = channel[index] / 256;
  const spectrum = fft2d(re, im, width, height);
  const out = new Uint8ClampedArray(n);
  for (let index = 0; index < n; index += 1) {
    const magnitude = Math.sqrt(spectrum.re[index] * spectrum.re[index] + spectrum.im[index] * spectrum.im[index]);
    out[index] = truncClamp255(magnitude * scale * gain);
  }
  return out;
};

// 自动增益（原软件「亮度」的手动档替代）：R 通道幅度谱（无增益）的 99.5 分位归 240。
// 增益上限 10000、下限 0.5（EBCTFCodeBox 复刻口径）。
export const watermarkhAutoGain = (image: RgbaImage): number => {
  const { width, height } = image;
  const n = width * height;
  const scale = 256 / Math.sqrt(n);
  const im = new Float64Array(n);
  const re = channelOf(image, 0);
  for (let index = 0; index < n; index += 1) re[index] /= 256;
  const spectrum = fft2d(re, im, width, height);
  const values = new Float64Array(n);
  for (let index = 0; index < n; index += 1) {
    const magnitude = Math.sqrt(spectrum.re[index] * spectrum.re[index] + spectrum.im[index] * spectrum.im[index]);
    values[index] = magnitude * scale;
  }
  const sorted = Float64Array.from(values).sort();
  const p995 = sorted[Math.floor(n * 0.995)] || 1;
  return Math.max(0.5, Math.min(10000, AUTOGAIN_TARGET / p995));
};

// 压制镜像副本：max(0, v − 180°旋转副本)。中心对称图案的文字与其旋转副本在幅度谱图上
// 常重叠，逐点相减削掉共有成分（旋转映射 (y,x) → (h−1−y, w−1−x)，与原软件增强版一致）。
export const watermarkhSuppressMirror = (spec: RgbaImage): RgbaImage => {
  const { width, height, data } = spec;
  const out = new Uint8ClampedArray(width * height * 4);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const source = (y * width + x) * 4;
      const mirror = ((height - 1 - y) * width + (width - 1 - x)) * 4;
      for (let channel = 0; channel < 3; channel += 1) {
        out[source + channel] = Math.max(0, data[source + channel] - data[mirror + channel]);
      }
      out[source + 3] = 255;
    }
  }
  return { data: out, width, height };
};

// 去背景归一化：按分位数拉伸（默认 0.60→0.995）。直方图取 R 通道，a/b 作用于全部三通道
// （EBCTFCodeBox 复刻口径：spec[i*4] 统计、三通道同 a/b）。
export const watermarkhNormalize = (spec: RgbaImage, lo = 0.6, hi = 0.995): RgbaImage => {
  const { width, height, data } = spec;
  const n = width * height;
  const histogram = new Uint32Array(256);
  for (let index = 0; index < n; index += 1) histogram[data[index * 4]] += 1;
  const pick = (fraction: number): number => {
    const target = fraction * n;
    let accumulated = 0;
    for (let value = 0; value < 256; value += 1) {
      accumulated += histogram[value];
      if (accumulated >= target) return value;
    }
    return 255;
  };
  const low = pick(lo);
  const high = Math.max(low + 1, pick(hi));
  const out = new Uint8ClampedArray(data.length);
  for (let index = 0; index < data.length; index += 1) {
    out[index] = index % 4 === 3 ? 255 : truncClamp255(((data[index] - low) * 255) / (high - low));
  }
  return { data: out, width, height };
};

export interface WatermarkhExtractOptions {
  gain?: number; // 手动增益（默认 10）
  autoGain?: boolean; // 自动增益（99.5 分位归 240），与手动增益互斥、优先生效
  suppressMirror?: boolean; // 压制镜像副本
  normalize?: boolean; // 去背景分位数拉伸
}

export interface WatermarkhExtractResult {
  image: RgbaImage; // 幅度谱图（三通道各自的谱，文字靠人眼判读）
  gain: number; // 实际使用的增益
  notes: string[]; // 非 2 幂缩放提示等
}

// 非两幂尺寸最近邻缩放（确定性、不引入插值涂抹）。缩放只服务「FFT 要求 2 幂」这一硬约束，
// 若样本原本是 2 幂尺寸后被人改过，用户应自行缩回原尺寸提取——notes 里给出提示。
const scaleNearestToPot = (image: RgbaImage, targetWidth: number, targetHeight: number): RgbaImage => {
  const { width, height, data } = image;
  const out = new Uint8ClampedArray(targetWidth * targetHeight * 4);
  for (let y = 0; y < targetHeight; y += 1) {
    const sourceY = Math.min(height - 1, Math.floor((y * height) / targetHeight));
    for (let x = 0; x < targetWidth; x += 1) {
      const sourceX = Math.min(width - 1, Math.floor((x * width) / targetWidth));
      const source = (sourceY * width + sourceX) * 4;
      const target = (y * targetWidth + x) * 4;
      out[target] = data[source];
      out[target + 1] = data[source + 1];
      out[target + 2] = data[source + 2];
      out[target + 3] = data[source + 3];
    }
  }
  return { data: out, width: targetWidth, height: targetHeight };
};

export const watermarkhExtract = (image: RgbaImage, options: WatermarkhExtractOptions = {}): WatermarkhExtractResult => {
  const notes: string[] = [];
  let work = image;
  if (!watermarkhIsPowerOfTwo(image.width) || !watermarkhIsPowerOfTwo(image.height)) {
    const targetWidth = nearestPowerOfTwo(image.width);
    const targetHeight = nearestPowerOfTwo(image.height);
    if (targetWidth * targetHeight > WATERMARKH_MAX_PIXELS) {
      throw new Error(`图像缩放到 2 幂尺寸后为 ${targetWidth}×${targetHeight}，超过 ${WATERMARKH_MAX_PIXELS} 像素上限：请先手动缩小到 2 的幂尺寸再提取`);
    }
    work = scaleNearestToPot(image, targetWidth, targetHeight);
    notes.push(
      `宽高需为 2 的幂：已按最近邻缩放 ${image.width}×${image.height} → ${targetWidth}×${targetHeight}；` +
      '若样本原为 2 幂尺寸，建议手动缩回原尺寸再提取（缩放会破坏频域结构）',
    );
  }
  const { width, height } = work;
  const gain = options.autoGain ? watermarkhAutoGain(work) : options.gain ?? WATERMARKH_DEFAULT_GAIN;
  const specData = new Uint8ClampedArray(width * height * 4);
  for (let channel = 0; channel < 3; channel += 1) {
    const values = watermarkhExtractChannel(channelOf(work, channel), width, height, gain);
    for (let index = 0; index < width * height; index += 1) {
      specData[index * 4 + channel] = values[index];
    }
  }
  for (let index = 0; index < width * height; index += 1) specData[index * 4 + 3] = 255;
  let result: RgbaImage = { data: specData, width, height };
  if (options.suppressMirror) {
    result = watermarkhSuppressMirror(result);
    notes.push('已压制镜像副本（max(0, v−旋转180°副本)）');
  }
  if (options.normalize) {
    result = watermarkhNormalize(result);
    notes.push('已按分位数拉伸去背景（0.60→0.995）');
  }
  return { image: result, gain, notes };
};

// ==================== 兼容原软件的嵌入（造样本 / 互测用） ====================

// 原软件图案的像素级中心对称镜像 p[N−1−i] = p[i]（M96 行为，就地修改并返回）
export const watermarkhMirrorPattern = (pattern: Uint8Array | number[]): Uint8Array => {
  const out = Uint8Array.from(pattern);
  const n = out.length;
  for (let i = 0; i < Math.floor(n / 2); i += 1) out[n - 1 - i] = out[i];
  return out;
};

export interface WatermarkhEmbedOptions {
  alpha?: number; // 强度系数（原软件「强度/500」，默认 50 → 0.1）
}

// 单图频域嵌入（原软件口径）：图案直接当作频谱叠加，输出像素 = trunc(clamp(|FFT(S)|·256/√N))，
// S = conj(FFT(x/256))/√N + α·pattern/256。pattern 为长度 w·h 的 0..255 灰度图案
// （黑底白字 + watermarkhMirrorPattern 中心对称）。三通道叠同一图案，alpha 原样保留。
export const watermarkhEmbed = (image: RgbaImage, pattern: ArrayLike<number>, options: WatermarkhEmbedOptions = {}): RgbaImage => {
  const { width, height, data } = image;
  if (!watermarkhIsPowerOfTwo(width) || !watermarkhIsPowerOfTwo(height)) {
    throw new Error(`WaterMarkH 嵌入要求宽高为 2 的幂（当前 ${width}×${height}）`);
  }
  if (width * height > WATERMARKH_MAX_PIXELS) {
    throw new Error(`图像 ${width}×${height} 超过 ${WATERMARKH_MAX_PIXELS} 像素上限：请先缩小图片`);
  }
  if (pattern.length !== width * height) {
    throw new Error(`图案长度 ${pattern.length} 与画布 ${width * height} 不一致`);
  }
  const n = width * height;
  const alpha = options.alpha ?? 0.1;
  const sqrtN = Math.sqrt(n);
  const out = new Uint8ClampedArray(data.length);
  for (let channel = 0; channel < 3; channel += 1) {
    const re = new Float64Array(n);
    const im = new Float64Array(n);
    for (let index = 0; index < n; index += 1) re[index] = data[index * 4 + channel] / 256;
    const spectrum = fft2d(re, im, width, height);
    // S = conj(F)/√N + α·pattern/256
    for (let index = 0; index < n; index += 1) {
      spectrum.re[index] = spectrum.re[index] / sqrtN + (alpha * pattern[index]) / 256;
      spectrum.im[index] = -spectrum.im[index] / sqrtN;
    }
    const composed = fft2d(spectrum.re, spectrum.im, width, height);
    const scale = 256 / sqrtN;
    for (let index = 0; index < n; index += 1) {
      const magnitude = Math.sqrt(composed.re[index] * composed.re[index] + composed.im[index] * composed.im[index]);
      out[index * 4 + channel] = truncClamp255(magnitude * scale);
    }
  }
  for (let index = 0; index < n; index += 1) out[index * 4 + 3] = data[index * 4 + 3];
  return { data: out, width, height };
};
