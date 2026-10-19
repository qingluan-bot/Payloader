// DWT-DCT-SVD 真盲水印（批次 B3·E 线）：guofei9987/blind_watermark 0.4.4 兼容口径（兼容性声明，
// 算法本体为学术界的 DWT-DCT-SVD 嵌入方案：Haar 一级小波取 cA 低频 → 4×4 块正交 DCT-II →
// 块内置乱 → 奇异值量化）。与现有 blindWatermark.ts（chishaxie FFT 双图半盲方案）互补：
// 本方案单图真盲——提取只需水印图本身 + 水印位长/wmShape，不需要原图。
// 逐段行为对齐本机安装的 blind_watermark/bwm_core.py + blind_watermark.py（源码已全文核对，
// 互通验证见 tests/blind-watermark-dwtsvd.test.mjs）：
//   读图 → float → cv2 BGR2YUV(BT.601) → 底/右补黑边偶数化 → pywt dwt2('haar') 取 cA（正交归一：
//   2×2 块内 (a+b+c+d)/2 等四式）→ 4×4 分块 → cv2.dct（正交 DCT-II）→ flatten 后按
//   RandomState(password_img) 的第 i 行 random((n,16)).argsort(axis=1) 置乱 → numpy svd →
//   s[0]=(⌊s[0]/d1⌋+1/4+w/2)·d1、s[1]=(⌊s[1]/d2⌋+1/4+w/2)·d2 → 逆链回写；提取同路径取
//   (s[0]%d1>d1/2)、(s[1]%d2>d2/2)，i%wm_size 循环冗余 + 3 通道平均，文本模式 kmeans 二分阈值。
// 文本位流：bin(int(utf8.hex(),16))[2:]（无长度头、丢前导零——与库一致，勿"修正"成定长），
// 并用 RandomState(password_wm).shuffle 置乱；解密用同一置换的 fancy-index 反演。
// 数值锚点（本机 numpy 2.5.4 / Python 3.14 实测）：RandomState(0).random 前 3 位
// 0.5488135039273248 / 0.7151893663724195 / 0.6027633760716439；RandomState(1) 洗牌 arange(8)
// → [7,2,1,6,0,4,3,5]；cv2.dct(arange(16)/7) 首元 4.285714149475098。
import type { RgbaImage } from './imageOps';

export interface DwtSvdOptions {
  passwordImg?: number; // 频域分块置乱种子（库默认 1）
  passwordWm?: number; // 水印位流置乱种子（库默认 1）
  d1?: number; // s[0] 量化步长（库默认 36）
  d2?: number; // s[1] 量化步长（库默认 20；0 表示只用 s[0]，库 fast 模式）
}

export const DWT_SVD_DEFAULT_PASSWORD_IMG = 1;
export const DWT_SVD_DEFAULT_PASSWORD_WM = 1;
export const DWT_SVD_DEFAULT_D1 = 36;
export const DWT_SVD_DEFAULT_D2 = 20;
// 单线程同步运算预算（与 blindWatermark.ts 同族理由：防止页面冻结）
export const DWT_SVD_MAX_PIXELS = 4_000_000;

// ==================== numpy RandomState 复刻 ====================
// pyRandom.ts 复刻的是 CPython random 模块（init_by_array 播种 + getrandbits 拒绝采样洗牌），
// 而 blind_watermark 用的是 numpy legacy RandomState：播种走 init_genrand（mt[0]=seed，
// mt[i]=1812433253·(mt[i-1]^(mt[i-1]>>30))+i），洗牌走 random_interval（全 1 位掩码拒绝采样，
// numpy/random/src/distributions/distributions.c——与 CPython _randbelow 不同算法），取
// double 走 rk_double 53 位拼接。pyRandom.ts 不含这些语义且本批次禁止改动，故在此实现。
// 逐位锚点（本机 numpy 实测，见测试）：rk_double / shuffle / argsort 三族全部对齐。
const MT_SIZE = 624;
const MT_MATRIX_A = 0x9908b0df;
const MT_UPPER = 0x80000000;
const MT_LOWER = 0x7fffffff;

export class NumpyRandomState {
  private mt = new Uint32Array(MT_SIZE);
  private pos = MT_SIZE;

  // numpy mt19937_seed：等价 MT19937 参考 init_genrand(seed & 0xffffffff)
  constructor(seed: number) {
    if (!Number.isInteger(seed) || seed < 0 || seed > 0xffffffff) {
      throw new Error(`RandomState 种子必须为 0..2^32-1 的整数，当前 ${seed}`);
    }
    let value = seed >>> 0;
    this.mt[0] = value;
    for (let i = 1; i < MT_SIZE; i += 1) {
      value = (Math.imul(value ^ (value >>> 30), 1812433253) + i) >>> 0;
      this.mt[i] = value;
    }
    this.pos = MT_SIZE;
  }

  // 块生成（twist）+ tempering 后的 32 位输出
  nextUint32(): number {
    if (this.pos >= MT_SIZE) {
      for (let i = 0; i < MT_SIZE; i += 1) {
        const y = (this.mt[i] & MT_UPPER) | (this.mt[(i + 1) % MT_SIZE] & MT_LOWER);
        this.mt[i] = (this.mt[(i + 397) % MT_SIZE] ^ (y >>> 1) ^ (y & 1 ? MT_MATRIX_A : 0)) >>> 0;
      }
      this.pos = 0;
    }
    let y = this.mt[this.pos];
    this.pos += 1;
    y ^= y >>> 11;
    y = (y ^ ((y << 7) & 0x9d2c5680)) >>> 0;
    y = (y ^ ((y << 15) & 0xefc60000)) >>> 0;
    y = y ^ (y >>> 18);
    return y >>> 0;
  }

  // rk_double：两个 32 位输出拼 53 位（(a>>5)·2^26 + (b>>6)）/ 2^53
  nextDouble(): number {
    const a = this.nextUint32() >>> 5; // 高 27 位
    const b = this.nextUint32() >>> 6; // 高 26 位
    return (a * 67108864 + b) / 9007199254740992;
  }

  // numpy random_interval(max)：全 1 位掩码 + 拒绝采样；max===0 时不消耗随机数（流位置敏感）
  randomInterval(max: number): number {
    if (max === 0) return 0;
    let mask = max;
    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;
    mask |= mask >> 8;
    mask |= mask >> 16;
    for (;;) {
      const value = this.nextUint32() & mask;
      if (value <= max) return value;
    }
  }

  // numpy RandomState.shuffle（1-D fast path）：Fisher–Yates 降序，j=random_interval(i)
  shuffleInPlace<T>(items: T[]): T[] {
    for (let i = items.length - 1; i > 0; i -= 1) {
      const j = this.randomInterval(i);
      const temp = items[i];
      items[i] = items[j];
      items[j] = temp;
    }
    return items;
  }
}

// RandomState(seed).random((rows,16)).argsort(axis=1) 的逐行复刻：每行 = 该块内置乱置换。
// 16 个随机 double 互异（概率 1−O(16²/2^53)）时结果与 numpy 默认 quicksort 唯一一致，
// 故用稳定排序即可。
const blockShufflers = (seed: number, blockNum: number): number[][] => {
  const random = new NumpyRandomState(seed);
  const shufflers: number[][] = [];
  for (let block = 0; block < blockNum; block += 1) {
    const row = new Array<number>(16);
    for (let i = 0; i < 16; i += 1) row[i] = random.nextDouble();
    const order = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    order.sort((left, right) => row[left] - row[right]);
    shufflers.push(order);
  }
  return shufflers;
};

// password_wm 置乱序列：RandomState(password_wm).shuffle(arange(n))，返回洗牌后的数组
// （order[i] = 原第 order[i] 位被换到第 i 位）
const wmShuffleOrder = (seed: number, size: number): number[] =>
  new NumpyRandomState(seed).shuffleInPlace(Array.from({ length: size }, (_, index) => index));

// ==================== 文本位流（库兼容口径） ====================

// 库 read_wm(mode='str')：bits = bin(int(text.utf8.hex(),16))[2:]（大端、无长度头、丢前导零）
export const encodeTextBits = (text: string): number[] => {
  const bytes = new TextEncoder().encode(text);
  if (bytes.length === 0) throw new Error('水印文本为空：库口径下空文本无法编码（int(hex) 非法）');
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  const bits = BigInt(`0x${hex}`).toString(2);
  return Array.from(bits, (char) => (char === '1' ? 1 : 0));
};

// 库 extract(mode='str') 末段：''.join(bit>=0.5) → int(bits,2) → hex → utf-8。
// 差异说明：库的 bytes.fromhex 要求偶长 hex（奇长直接抛 ValueError），此处补前导 0 兜底；
// 常规可打印文本两者输出逐字节一致。
export const decodeTextBits = (values: ArrayLike<number>): string => {
  if (values.length === 0) throw new Error('水印位流为空');
  let bits = '';
  for (let i = 0; i < values.length; i += 1) bits += values[i] >= 0.5 ? '1' : '0';
  let hex = BigInt(`0b${bits}`).toString(16);
  if (hex.length % 2 === 1) hex = `0${hex}`;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
};

// ==================== 小波 / DCT / SVD 数值核 ====================

// BT.601 YUV（cv2.COLOR_BGR2YUV 文档系数；float 通道，无 128 偏移）
const rgbToYuv = (r: number, g: number, b: number): [number, number, number] => [
  0.299 * r + 0.587 * g + 0.114 * b,
  -0.147 * r - 0.289 * g + 0.436 * b,
  0.615 * r - 0.515 * g - 0.1 * b,
];
// 逆变换（前向矩阵逆的解析形式：B=Y+2.032U、R=Y+1.140V、G 由 Y 消元）
const yuvToRgb = (y: number, u: number, v: number): [number, number, number] => {
  const r = y + 1.14 * v;
  const b = y + 2.032 * u;
  const g = (y - 0.114 * b - 0.299 * r) / 0.587;
  return [r, g, b];
};

// cv2.imwrite 的 float→uint8 舍入：cvRound = 银行家舍入 + 饱和（探针实测 0.5→0、1.5→2、2.5→2、3.5→4）
export const toByte = (value: number): number => {
  const floor = Math.floor(value);
  const diff = value - floor;
  let rounded: number;
  if (diff < 0.5) rounded = floor;
  else if (diff > 0.5) rounded = floor + 1;
  else rounded = floor % 2 === 0 ? floor : floor + 1;
  return Math.max(0, Math.min(255, rounded));
};

// pywt dwt2('haar') 正交归一口径的 2×2 块四式（与 pywt 数值对拍一致）。导出供测试对拍。
export const haarForward = (
  input: Float64Array,
  width: number,
  ca: Float64Array,
  ch: Float64Array,
  cv: Float64Array,
  cd: Float64Array,
): void => {
  const halfWidth = width / 2;
  const rows = input.length / width;
  for (let cy = 0; cy < rows / 2; cy += 1) {
    for (let cx = 0; cx < halfWidth; cx += 1) {
      const a = input[cy * 2 * width + cx * 2];
      const b = input[cy * 2 * width + cx * 2 + 1];
      const c = input[(cy * 2 + 1) * width + cx * 2];
      const d = input[(cy * 2 + 1) * width + cx * 2 + 1];
      const index = cy * halfWidth + cx;
      ca[index] = (a + b + c + d) / 2;
      ch[index] = (a + b - c - d) / 2;
      cv[index] = (a - b + c - d) / 2;
      cd[index] = (a - b - c + d) / 2;
    }
  }
};

// 4×4 正交 DCT-II（cv2.dct 口径：α(0)=1/2、α(>0)=√2/2；核 cos((2y+1)uπ/2N)=cos(·π/8)）。
// 踩坑记录：核频率写成 π/16 会让整条链路产出垃圾位且 u=0 锚点照样通过（cos(0)=1），必须用
// 全量 16 值对拍。cos 表预计算，导出供测试对拍。
const DCT4_COS = (() => {
  const table = new Float64Array(16); // table[y*4+u] = cos((2y+1)uπ/8)
  for (let y = 0; y < 4; y += 1) {
    for (let u = 0; u < 4; u += 1) table[y * 4 + u] = Math.cos(((2 * y + 1) * u * Math.PI) / 8);
  }
  return table;
})();
const DCT4_ALPHA = [0.5, Math.SQRT1_2, Math.SQRT1_2, Math.SQRT1_2];

// 导出供测试对拍 cv2.dct 锚点
export const dct4 = (block: Float64Array, out: Float64Array): void => {
  for (let u = 0; u < 4; u += 1) {
    for (let v = 0; v < 4; v += 1) {
      let sum = 0;
      for (let y = 0; y < 4; y += 1) {
        const cosU = DCT4_COS[y * 4 + u];
        for (let x = 0; x < 4; x += 1) {
          sum += block[y * 4 + x] * cosU * DCT4_COS[x * 4 + v];
        }
      }
      out[u * 4 + v] = DCT4_ALPHA[u] * DCT4_ALPHA[v] * sum;
    }
  }
};

// 导出供测试对拍 cv2.idct 锚点
export const idct4 = (block: Float64Array, out: Float64Array): void => {
  for (let y = 0; y < 4; y += 1) {
    for (let x = 0; x < 4; x += 1) {
      let sum = 0;
      for (let u = 0; u < 4; u += 1) {
        const cosU = DCT4_COS[y * 4 + u] * DCT4_ALPHA[u];
        for (let v = 0; v < 4; v += 1) {
          sum += cosU * DCT4_ALPHA[v] * block[u * 4 + v] * DCT4_COS[x * 4 + v];
        }
      }
      out[y * 4 + x] = sum;
    }
  }
};

// 单边 Jacobi（Hestenes）SVD，4×4。奇异值唯一且降序（与 numpy LAPACK 口径一致），重构
// U·diag(s)·Vᵀ 对任意合法分解逐值相同（符号/子空间旋转在求和中抵消），量化嵌入只依赖 s[0..1]。
export const svd4 = (a: Float64Array): { u: Float64Array; s: Float64Array; vh: Float64Array } => {
  const u = Float64Array.from(a); // 列向量被逐步正交化
  const v = new Float64Array(16);
  v[0] = 1; v[5] = 1; v[10] = 1; v[15] = 1;
  for (let sweep = 0; sweep < 30; sweep += 1) {
    let rotated = false;
    for (let p = 0; p < 3; p += 1) {
      for (let q = p + 1; q < 4; q += 1) {
        let alpha = 0;
        let beta = 0;
        let gamma = 0;
        for (let i = 0; i < 4; i += 1) {
          const ap = u[i * 4 + p];
          const aq = u[i * 4 + q];
          alpha += ap * ap;
          beta += aq * aq;
          gamma += ap * aq;
        }
        if (Math.abs(gamma) <= 1e-15 * Math.sqrt(alpha * beta)) continue;
        rotated = true;
        const zeta = (beta - alpha) / (2 * gamma);
        const t = Math.sign(zeta) / (Math.abs(zeta) + Math.sqrt(1 + zeta * zeta));
        const c = 1 / Math.sqrt(1 + t * t);
        const s = c * t;
        for (let i = 0; i < 4; i += 1) {
          const ap = u[i * 4 + p];
          const aq = u[i * 4 + q];
          u[i * 4 + p] = c * ap - s * aq;
          u[i * 4 + q] = s * ap + c * aq;
          const vp = v[i * 4 + p];
          const vq = v[i * 4 + q];
          v[i * 4 + p] = c * vp - s * vq;
          v[i * 4 + q] = s * vp + c * vq;
        }
      }
    }
    if (!rotated) break;
  }
  const norms = new Float64Array(4);
  for (let j = 0; j < 4; j += 1) {
    let norm = 0;
    for (let i = 0; i < 4; i += 1) norm += u[i * 4 + j] * u[i * 4 + j];
    norms[j] = Math.sqrt(norm);
  }
  const order = [0, 1, 2, 3].sort((left, right) => norms[right] - norms[left]);
  const su = new Float64Array(16);
  const sv = new Float64Array(16);
  const ss = new Float64Array(4);
  for (let j = 0; j < 4; j += 1) {
    const source = order[j];
    ss[j] = norms[source];
    const norm = norms[source];
    for (let i = 0; i < 4; i += 1) {
      // U 列 = 正交化后的列 / 奇异值；V 列是 Givens 旋转累积产物、本就单位正交，不可除 norm。
      // 零奇异值列的 U/V 无定义（任意正交补），回退单位向量——重构仍精确。
      su[i * 4 + j] = norm > 0 ? u[i * 4 + source] / norm : i === j ? 1 : 0;
      sv[j * 4 + i] = v[i * 4 + source];
    }
  }
  return { u: su, s: ss, vh: sv };
};

// ==================== 嵌入 / 提取主链 ====================

interface PreparedChannels {
  ca: Float64Array[]; // 每通道 cA 低频（halfWidth·halfHeight 行主序）
  ch: Float64Array[];
  cv: Float64Array[];
  cd: Float64Array[];
  halfWidth: number;
  blockRows: number;
  blockCols: number;
}

const resolveOptions = (options: DwtSvdOptions = {}): Required<DwtSvdOptions> => ({
  passwordImg: options.passwordImg ?? DWT_SVD_DEFAULT_PASSWORD_IMG,
  passwordWm: options.passwordWm ?? DWT_SVD_DEFAULT_PASSWORD_WM,
  d1: options.d1 ?? DWT_SVD_DEFAULT_D1,
  d2: options.d2 ?? DWT_SVD_DEFAULT_D2,
});

// 公共前处理：YUV + 底/右补黑边偶数化 + Haar 一级 + cA（与库 read_img_arr 逐段对应）
const prepareChannels = (image: RgbaImage): PreparedChannels => {
  const { width, height, data } = image;
  if (width * height > DWT_SVD_MAX_PIXELS) {
    throw new Error(`图像 ${width}×${height} 超过 DWT-SVD 盲水印 ${DWT_SVD_MAX_PIXELS} 像素上限，请先缩小图片`);
  }
  const evenWidth = width + (width % 2);
  const evenHeight = height + (height % 2);
  const halfWidth = evenWidth / 2;
  const planeSize = halfWidth * (evenHeight / 2);
  const ca: Float64Array[] = [];
  const ch: Float64Array[] = [];
  const cv: Float64Array[] = [];
  const cd: Float64Array[] = [];
  const plane = new Float64Array(evenWidth * evenHeight); // 补边恒 0（与库 BORDER_CONSTANT value=0 一致）
  for (let channel = 0; channel < 3; channel += 1) {
    for (let y = 0; y < height; y += 1) {
      for (let x = 0; x < width; x += 1) {
        const base = (y * width + x) * 4;
        const [yy, uu, vv] = rgbToYuv(data[base], data[base + 1], data[base + 2]);
        plane[y * evenWidth + x] = channel === 0 ? yy : channel === 1 ? uu : vv;
      }
    }
    const cA = new Float64Array(planeSize);
    const cH = new Float64Array(planeSize);
    const cV = new Float64Array(planeSize);
    const cD = new Float64Array(planeSize);
    haarForward(plane, evenWidth, cA, cH, cV, cD);
    ca.push(cA);
    ch.push(cH);
    cv.push(cV);
    cd.push(cD);
  }
  return {
    ca,
    ch,
    cv,
    cd,
    halfWidth,
    blockRows: Math.floor(evenHeight / 2 / 4),
    blockCols: Math.floor(halfWidth / 4),
  };
};

// cA 的 (bi,bj) 块 ↔ 行主序 16 元组
const readBlock = (ca: Float64Array, caWidth: number, bi: number, bj: number, out: Float64Array): void => {
  for (let y = 0; y < 4; y += 1) {
    const row = (bi * 4 + y) * caWidth + bj * 4;
    for (let x = 0; x < 4; x += 1) out[y * 4 + x] = ca[row + x];
  }
};
const writeBlock = (ca: Float64Array, caWidth: number, bi: number, bj: number, block: Float64Array): void => {
  for (let y = 0; y < 4; y += 1) {
    const row = (bi * 4 + y) * caWidth + bj * 4;
    for (let x = 0; x < 4; x += 1) ca[row + x] = block[y * 4 + x];
  }
};

export interface DwtSvdEmbedResult {
  image: RgbaImage;
  wmBitCount: number; // 文本 = 位流长度；图片 = wm 像素数
  wmShape: [number, number]; // [高, 宽]（文本为 [1, 位长] 口径，提取时用位长）
  blockNum: number; // 可嵌入块数（wm_size 必须小于它）
}

const assertWmFits = (wmSize: number, blockNum: number): void => {
  if (wmSize >= blockNum) {
    throw new Error(`可嵌入块数 ${blockNum} 不足以容纳 ${wmSize} 位水印（库断言 wm_size < block_num）：请加大图片或缩短水印`);
  }
};

const embedWithBits = (image: RgbaImage, wmBits: number[], options: DwtSvdOptions): DwtSvdEmbedResult => {
  const resolved = resolveOptions(options);
  const prepared = prepareChannels(image);
  const blockNum = prepared.blockRows * prepared.blockCols;
  assertWmFits(wmBits.length, blockNum);
  // 水印置乱（库 read_wm：RandomState(password_wm).shuffle(wm_bit)，in-place）
  const order = wmShuffleOrder(resolved.passwordWm, wmBits.length);
  const shuffled = order.map((originalIndex) => wmBits[originalIndex]);
  const shufflers = blockShufflers(resolved.passwordImg, blockNum);
  const wmSize = wmBits.length;

  // 内层热循环的缓冲区全部外提（75 万块 × 3 通道场景下逐块分配代价不可接受）
  const block = new Float64Array(16);
  const freq = new Float64Array(16);
  const scrambled = new Float64Array(16);
  const modified = new Float64Array(16);
  const restored = new Float64Array(16);
  const spatial = new Float64Array(16);
  for (let channel = 0; channel < 3; channel += 1) {
    const cA = prepared.ca[channel];
    let index = 0;
    for (let bi = 0; bi < prepared.blockRows; bi += 1) {
      for (let bj = 0; bj < prepared.blockCols; bj += 1) {
        const shuffler = shufflers[index];
        const wm = shuffled[index % wmSize];
        readBlock(cA, prepared.halfWidth, bi, bj, block);
        dct4(block, freq);
        // 置乱 → SVD → 量化 → 逆 SVD → 逆置乱（等价库 block_add_wm_slow）
        for (let p = 0; p < 16; p += 1) scrambled[p] = freq[shuffler[p]];
        const { u, s, vh } = svd4(scrambled);
        s[0] = (Math.floor(s[0] / resolved.d1) + 0.25 + 0.5 * wm) * resolved.d1;
        if (resolved.d2 !== 0) s[1] = (Math.floor(s[1] / resolved.d2) + 0.25 + 0.5 * wm) * resolved.d2;
        // M = U·diag(s)·Vᵀ
        for (let p = 0; p < 4; p += 1) {
          for (let q = 0; q < 4; q += 1) {
            let sum = 0;
            for (let k = 0; k < 4; k += 1) sum += u[p * 4 + k] * s[k] * vh[k * 4 + q];
            modified[p * 4 + q] = sum;
          }
        }
        for (let p = 0; p < 16; p += 1) restored[shuffler[p]] = modified[p];
        idct4(restored, spatial);
        writeBlock(cA, prepared.halfWidth, bi, bj, spatial);
        index += 1;
      }
    }
  }

  // idwt（逐像素四式）+ 裁剪 + YUV2BGR + 银行家舍入（库的 np.clip 在浮点域，等价吸收在饱和里）
  const pixels = new Uint8ClampedArray(image.width * image.height * 4);
  for (let y = 0; y < image.height; y += 1) {
    for (let x = 0; x < image.width; x += 1) {
      const cy = y >> 1;
      const cx = x >> 1;
      const offset = (y % 2) * 2 + (x % 2);
      const index = cy * prepared.halfWidth + cx;
      const values: number[] = [0, 0, 0];
      for (let channel = 0; channel < 3; channel += 1) {
        const a = prepared.ca[channel][index];
        const h = prepared.ch[channel][index];
        const v = prepared.cv[channel][index];
        const d = prepared.cd[channel][index];
        values[channel] =
          offset === 0 ? (a + h + v + d) / 2
            : offset === 1 ? (a + h - v - d) / 2
              : offset === 2 ? (a - h + v - d) / 2
                : (a - h - v + d) / 2;
      }
      const [r, g, b] = yuvToRgb(values[0], values[1], values[2]);
      const base = (y * image.width + x) * 4;
      pixels[base] = toByte(r);
      pixels[base + 1] = toByte(g);
      pixels[base + 2] = toByte(b);
      pixels[base + 3] = image.data[base + 3];
    }
  }
  return {
    image: { data: pixels, width: image.width, height: image.height },
    wmBitCount: wmBits.length,
    wmShape: wmBits.length > 0 ? [1, wmBits.length] : [0, 0],
    blockNum,
  };
};

// 文本嵌入（库 read_wm(text, 'str') 口径：位流无长度头 + password_wm 洗牌）
export const dwtSvdEmbedText = (image: RgbaImage, text: string, options: DwtSvdOptions = {}): DwtSvdEmbedResult =>
  embedWithBits(image, encodeTextBits(text), options);

// 图片嵌入（库 read_wm(file, 'img') 口径：灰度 luma > 128 → bit）
export const dwtSvdEmbedImage = (image: RgbaImage, watermark: RgbaImage, options: DwtSvdOptions = {}): DwtSvdEmbedResult => {
  const bits: number[] = [];
  for (let index = 0; index < watermark.width * watermark.height; index += 1) {
    const base = index * 4;
    const luma = 0.299 * watermark.data[base] + 0.587 * watermark.data[base + 1] + 0.114 * watermark.data[base + 2];
    bits.push(luma > 128 ? 1 : 0);
  }
  const result = embedWithBits(image, bits, options);
  result.wmShape = [watermark.height, watermark.width];
  return result;
};

// 提取原始块位：每块一值（d2 非零时两比特加权 0/0.25/0.75/1），三通道分开记录。
// 行主序 [channel][blockIndex]，blockIndex = bi·blockCols + bj。
export const dwtSvdExtractRaw = (image: RgbaImage, options: DwtSvdOptions = {}): number[][] => {
  const resolved = resolveOptions(options);
  const prepared = prepareChannels(image);
  const blockNum = prepared.blockRows * prepared.blockCols;
  const shufflers = blockShufflers(resolved.passwordImg, blockNum);
  const blockBits: number[][] = [[], [], []];
  const block = new Float64Array(16);
  const freq = new Float64Array(16);
  const scrambled = new Float64Array(16);
  for (let channel = 0; channel < 3; channel += 1) {
    const cA = prepared.ca[channel];
    let index = 0;
    for (let bi = 0; bi < prepared.blockRows; bi += 1) {
      for (let bj = 0; bj < prepared.blockCols; bj += 1) {
        const shuffler = shufflers[index];
        readBlock(cA, prepared.halfWidth, bi, bj, block);
        dct4(block, freq);
        for (let p = 0; p < 16; p += 1) scrambled[p] = freq[shuffler[p]];
        const { s } = svd4(scrambled);
        let wm = s[0] % resolved.d1 > resolved.d1 / 2 ? 1 : 0;
        if (resolved.d2 !== 0) {
          const tmp = s[1] % resolved.d2 > resolved.d2 / 2 ? 1 : 0;
          wm = (wm * 3 + tmp) / 4;
        }
        blockBits[channel].push(wm);
        index += 1;
      }
    }
  }
  return blockBits;
};

// 库 extract_avg：i % wm_size 循环冗余 + 3 通道全平均 → wmAvg[i] ∈ [0,1]（越接近 0/1 越可信）
const averageBySize = (blockBits: number[][], blockNum: number, wmSize: number): number[] => {
  const avg = new Array<number>(wmSize).fill(0);
  for (let i = 0; i < wmSize; i += 1) {
    let sum = 0;
    let count = 0;
    for (let channel = 0; channel < 3; channel += 1) {
      const bits = blockBits[channel];
      for (let position = i; position < blockNum; position += wmSize) {
        sum += bits[position];
        count += 1;
      }
    }
    avg[i] = count > 0 ? sum / count : 0;
  }
  return avg;
};

// extract_decrypt：σ = shuffle(arange)；out[σ[i]] = avg[i]（fancy-index 反演）
const decrypt = (avg: number[], passwordWm: number): number[] => {
  const order = wmShuffleOrder(passwordWm, avg.length);
  const decrypted = new Array<number>(avg.length).fill(0);
  for (let i = 0; i < avg.length; i += 1) decrypted[order[i]] = avg[i];
  return decrypted;
};

// 提取并按位长对齐（不含二值化，返回可信度 avg）
export const dwtSvdExtractAvg = (image: RgbaImage, wmSize: number, options: DwtSvdOptions = {}): number[] => {
  if (!Number.isInteger(wmSize) || wmSize <= 0) throw new Error(`水印位长必须为正整数，当前 ${wmSize}`);
  const resolved = resolveOptions(options);
  const blockBits = dwtSvdExtractRaw(image, options);
  const blockNum = blockBits[0].length;
  return decrypt(averageBySize(blockBits, blockNum, wmSize), resolved.passwordWm);
};

// 库 one_dim_kmeans 逐行复刻（含空类 NaN 语义：阈值变 NaN 后所有比较为 False → 全 0）
const kmeansBinarize = (inputs: number[]): boolean[] => {
  let min = Infinity;
  let max = -Infinity;
  for (const value of inputs) {
    if (value < min) min = value;
    if (value > max) max = value;
  }
  let center0 = min;
  let center1 = max;
  let threshold = 0;
  for (let iteration = 0; iteration < 300; iteration += 1) {
    threshold = (center0 + center1) / 2;
    let lowSum = 0;
    let lowCount = 0;
    let highSum = 0;
    let highCount = 0;
    for (const value of inputs) {
      if (value > threshold) {
        highSum += value;
        highCount += 1;
      } else {
        lowSum += value;
        lowCount += 1;
      }
    }
    center0 = lowCount > 0 ? lowSum / lowCount : NaN;
    center1 = highCount > 0 ? highSum / highCount : NaN;
    if (Math.abs((center0 + center1) / 2 - threshold) < 1e-6) {
      threshold = (center0 + center1) / 2;
      break;
    }
  }
  return inputs.map((value) => value > threshold);
};

// 文本提取（需知道嵌入时的位长，即库的 wm_shape=wm_bit.shape；不知位长用 dwtSvdExtractTextAuto）
export const dwtSvdExtractText = (image: RgbaImage, wmBitCount: number, options: DwtSvdOptions = {}): string => {
  const avg = dwtSvdExtractAvg(image, wmBitCount, options);
  const bits = kmeansBinarize(avg);
  return decodeTextBits(bits.map((flag) => (flag ? 1 : 0)));
};

// 可读性评分：可打印 ASCII / CJK / 全角占比（自动扫描的判停依据）
const printableRatio = (text: string): number => {
  const chars = [...text];
  if (chars.length === 0) return 0;
  let printable = 0;
  for (const char of chars) {
    const code = char.codePointAt(0) ?? 0;
    if ((code >= 0x20 && code <= 0x7e) || (code >= 0x3000 && code <= 0x9fff) || (code >= 0xff00 && code <= 0xffef)) {
      printable += 1;
    }
  }
  return printable / chars.length;
};

export interface DwtSvdAutoTextResult {
  text: string;
  wmBitCount: number;
  candidates: number; // 扫过的候选数
}

// 自动文本提取：库要求调用方提供 wm_shape（位长）是硬伤，CTF 实战场景不知道位长。
// 从小到大扫描候选位长 W，两级判据：
//   1. 位置信度：真实 W 处每个位由大量同值块样本支撑（i 与 i+kW 落在同一位），avg 强烈极化
//      （|avg−0.5|≥0.25 的位占比 ≈1）；错误 W 处不同位混采、avg 拥挤 0.5 附近（实测占比 0）。
//   2. 可读性：按 0.5 阈值二值化（可信嵌入下等价 kmeans）解码 UTF-8，可打印占比 ≥0.9 且无
//      替换符。升序扫描取最小命中（2N、3N 也通过但 N 先到）。
// 复杂度：块位提取一次 O(blockNum)，每个候选 O(blockNum + W)。
export const dwtSvdExtractTextAuto = (
  image: RgbaImage,
  options: DwtSvdOptions & { minBits?: number; maxBits?: number; minPrintableRatio?: number; minConfidenceFraction?: number } = {},
): DwtSvdAutoTextResult => {
  const resolved = resolveOptions(options);
  const blockBits = dwtSvdExtractRaw(image, options);
  const blockNum = blockBits[0].length;
  const minBits = Math.max(4, options.minBits ?? 4);
  const maxBits = Math.min(options.maxBits ?? 4096, blockNum - 1);
  if (minBits > maxBits) throw new Error(`图像块数（${blockNum}）太少，无法自动扫描文本位长`);
  const minPrintable = options.minPrintableRatio ?? 0.9;
  const minConfidence = options.minConfidenceFraction ?? 0.9;
  let candidates = 0;
  for (let size = minBits; size <= maxBits; size += 1) {
    candidates += 1;
    const avg = decrypt(averageBySize(blockBits, blockNum, size), resolved.passwordWm);
    let confident = 0;
    for (const value of avg) {
      if (Math.abs(value - 0.5) >= 0.25) confident += 1;
    }
    if (confident / size < minConfidence) continue;
    const bits = avg.map((value) => (value >= 0.5 ? 1 : 0));
    let text: string;
    try {
      text = decodeTextBits(bits);
    } catch {
      continue;
    }
    if (text.includes('\uFFFD')) continue; // UTF-8 解码失败的替换符
    if (printableRatio(text) < minPrintable) continue;
    return { text, wmBitCount: size, candidates };
  }
  throw new Error(`自动扫描 ${candidates} 个候选位长（${minBits}..${maxBits}）未找到可读文本：请确认这是 guofei9987 版 DWT-SVD 盲水印图，或手动指定位长`);
};

// 图片提取（需 wmShape；返回 255·wm 灰度图，与库 out_wm_name 输出一致）
export const dwtSvdExtractImage = (
  image: RgbaImage,
  wmShape: { width: number; height: number },
  options: DwtSvdOptions = {},
): RgbaImage => {
  const wmSize = wmShape.width * wmShape.height;
  const avg = dwtSvdExtractAvg(image, wmSize, options);
  const pixels = new Uint8ClampedArray(wmSize * 4);
  for (let index = 0; index < wmSize; index += 1) {
    const value = toByte(255 * avg[index]);
    pixels[index * 4] = value;
    pixels[index * 4 + 1] = value;
    pixels[index * 4 + 2] = value;
    pixels[index * 4 + 3] = 255;
  }
  return { data: pixels, width: wmShape.width, height: wmShape.height };
};
