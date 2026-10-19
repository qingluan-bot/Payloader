// 音频信号处理纯函数引擎（misc 域音频隐写四件套）：WAV 解析 / LSB 提取 / DTMF 解码 /
// 摩尔斯音频识别 / 频谱矩阵。全部只读输入、零浏览器依赖（FFT 自写迭代 Cooley-Tukey），
// 可在 node --test 直接跑。mp3/flac/ogg 等压缩格式解码由组件层 decodeAudioData 负责，
// 解出样本后转 Float64 走同一套接口。
// dtmfDecode/morseDecodeAudio/computeSpectrogram 均按单声道设计：多通道 WAV 由调用方
// 先取第一通道再传入（mono 分析足够，LSB 才需要逐通道区分）。

// 交织样本总数上限（内存红线：≈3 分钟 48kHz 立体声；超出后 parseWav 截断解码，
// info 的 frames/dataBytes 按截断后计，避免百 MB 级 Float64Array）。
export const MAX_WAV_SAMPLES = 1 << 24;

export interface WavInfo {
  sampleRate: number;
  channels: number;
  bitsPerSample: number;
  dataBytes: number;
  frames: number;
  formatTag: number;
}

export interface DecodedWav {
  info: WavInfo;
  samples: Float64Array; // 归一到 [-1,1]，多通道按帧交织保留（L,R,L,R,...）
}

const ascii4 = (bytes: Uint8Array, offset: number): string => {
  let out = '';
  for (let index = 0; index < 4; index += 1) out += String.fromCharCode(bytes[offset + index]);
  return out;
};

const u16le = (bytes: Uint8Array, offset: number): number =>
  bytes[offset] | (bytes[offset + 1] << 8);

const u32le = (bytes: Uint8Array, offset: number): number =>
  (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;

// RIFF/WAVE 解析：只认 PCM（formatTag=1）与 WAVE_FORMAT_EXTENSIBLE(0xFFFE) 的 PCM 基础子格式，
// 其余编码（a-law/μ-law/ADPCM 等）抛中文错误提示走组件层 decodeAudioData。
export const parseWav = (bytes: Uint8Array): DecodedWav => {
  if (bytes.length < 12 || ascii4(bytes, 0) !== 'RIFF' || ascii4(bytes, 8) !== 'WAVE') {
    throw new Error('不是有效 WAV 文件（缺少 RIFF/WAVE 头），压缩音频请走组件层 decodeAudioData 解码');
  }
  let fmtTag = -1;
  let channels = 0;
  let sampleRate = 0;
  let bits = 0;
  let dataOffset = -1;
  let dataEnd = -1;
  let pos = 12;
  while (pos + 8 <= bytes.length) {
    const id = ascii4(bytes, pos);
    const size = u32le(bytes, pos + 4);
    const bodyStart = pos + 8;
    const bodyEnd = Math.min(bodyStart + size, bytes.length); // chunk 声称尺寸越过文件尾时按实际截住
    if (id === 'fmt ' && fmtTag === -1) {
      if (bodyEnd - bodyStart < 16) throw new Error('fmt chunk 残缺，无法解析 WAV 参数');
      fmtTag = u16le(bytes, bodyStart);
      if (fmtTag === 0xfffe) {
        // WAVE_FORMAT_EXTENSIBLE：基础子格式在 subFormat GUID 的 data1 低 16 位（fmt 偏移 24）
        if (bodyEnd - bodyStart < 40) throw new Error('WAVE_FORMAT_EXTENSIBLE 的 fmt chunk 残缺');
        fmtTag = u16le(bytes, bodyStart + 24);
      }
      channels = u16le(bytes, bodyStart + 2);
      sampleRate = u32le(bytes, bodyStart + 4);
      bits = u16le(bytes, bodyStart + 14);
    } else if (id === 'data' && dataOffset === -1) {
      dataOffset = bodyStart;
      dataEnd = bodyEnd;
    }
    pos = bodyStart + size + (size & 1); // RIFF chunk 按 2 字节对齐补偶
  }
  if (fmtTag === -1) throw new Error('缺少 fmt chunk，无法解析 WAV 参数');
  if (fmtTag !== 1) {
    throw new Error(`不支持的 WAV 编码 formatTag=${fmtTag}（仅 PCM 8/16/24/32bit），请走组件层 decodeAudioData 解码`);
  }
  if (channels < 1) throw new Error(`无效声道数 ${channels}`);
  if (sampleRate < 1) throw new Error(`无效采样率 ${sampleRate}`);
  if (bits !== 8 && bits !== 16 && bits !== 24 && bits !== 32) {
    throw new Error(`不支持的 PCM 位深 ${bits}bit（仅 8/16/24/32）`);
  }
  const bytesPerSample = bits >> 3;
  const blockAlign = channels * bytesPerSample;
  let frames = Math.floor((dataEnd - dataOffset) / blockAlign);
  if (frames * channels > MAX_WAV_SAMPLES) frames = Math.floor(MAX_WAV_SAMPLES / channels);
  if (frames < 1) throw new Error('data chunk 为空或不足一帧，无可分析样本');
  const samples = new Float64Array(frames * channels);
  const scale = bits === 8 ? 0x80 : bits === 16 ? 0x8000 : bits === 24 ? 0x800000 : 0x80000000;
  let out = 0;
  for (let frame = 0; frame < frames; frame += 1) {
    for (let channel = 0; channel < channels; channel += 1) {
      const base = dataOffset + (frame * channels + channel) * bytesPerSample;
      let value: number;
      if (bits === 8) value = bytes[base] - 0x80; // 8bit PCM 无符号
      else if (bits === 16) value = ((bytes[base] | (bytes[base + 1] << 8)) << 16) >> 16;
      else if (bits === 24) {
        value = bytes[base] | (bytes[base + 1] << 8) | (bytes[base + 2] << 16);
        if (value & 0x800000) value -= 0x1000000; // 24bit 手工符号扩展
      } else {
        value = (bytes[base] | (bytes[base + 1] << 8) | (bytes[base + 2] << 16) | (bytes[base + 3] << 24)) | 0;
      }
      samples[out] = value / scale;
      out += 1;
    }
  }
  return {
    info: { sampleRate, channels, bitsPerSample: bits, dataBytes: frames * blockAlign, frames, formatTag: fmtTag },
    samples,
  };
};

// WAV 重编码：归一化 Float64 样本（parseWav 同口径，[-1,1]、按帧交织）按 info 编回标准
// 44 字节头 RIFF PCM WAV（fmt/data 尺寸手写，formatTag 恒 1——extensible 输入已被 parseWav
// 归一成基础 PCM，不必保留外壳）。量化用 round，2 的幂分母下与 parseWav 精确互逆（位不丢）；
// 值域钳位防浮点越界写坏位流。位深仅收 parseWav 覆盖的 8/16/24/32，范围外抛错拒编。
export const encodeWav = (samples: Float64Array, info: WavInfo): Uint8Array => {
  const { sampleRate, channels, bitsPerSample: bits } = info;
  if (sampleRate < 1) throw new Error(`无效采样率 ${sampleRate}，无法编码 WAV`);
  if (channels < 1) throw new Error(`无效声道数 ${channels}，无法编码 WAV`);
  if (bits !== 8 && bits !== 16 && bits !== 24 && bits !== 32) {
    throw new Error(`不支持的 PCM 位深 ${bits}bit（仅 8/16/24/32，压缩格式样本请走组件层自行编码）`);
  }
  const frames = Math.floor(samples.length / channels);
  if (frames < 1) throw new Error('样本数不足一帧，无法编码 WAV');
  const bytesPerSample = bits >> 3;
  const blockAlign = channels * bytesPerSample;
  const dataBytes = frames * blockAlign;
  const out = new Uint8Array(44 + dataBytes);
  const view = new DataView(out.buffer);
  const writeAscii4 = (offset: number, text: string) => {
    for (let index = 0; index < 4; index += 1) out[offset + index] = text.charCodeAt(index);
  };
  writeAscii4(0, 'RIFF');
  view.setUint32(4, 36 + dataBytes, true);
  writeAscii4(8, 'WAVE');
  writeAscii4(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true); // PCM
  view.setUint16(22, channels, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * blockAlign, true); // byteRate
  view.setUint16(32, blockAlign, true);
  view.setUint16(34, bits, true);
  writeAscii4(36, 'data');
  view.setUint32(40, dataBytes, true);
  const scale = bits === 8 ? 0x80 : bits === 16 ? 0x8000 : bits === 24 ? 0x800000 : 0x80000000;
  const maxInt = bits === 8 ? 0x7f : bits === 16 ? 0x7fff : bits === 24 ? 0x7fffff : 0x7fffffff;
  for (let index = 0; index < frames * channels; index += 1) {
    const raw = Math.round(samples[index] * scale);
    // 8bit 无符号（+0x80 偏移），16/24/32 补码；钳位后再经 uint32 补码解释逐字节小端写出
    const integer = bits === 8
      ? Math.min(maxInt, Math.max(-0x80, raw)) + 0x80
      : Math.min(maxInt, Math.max(-maxInt - 1, raw));
    const value = integer >>> 0;
    const base = 44 + index * bytesPerSample;
    for (let byte = 0; byte < bytesPerSample; byte += 1) out[base + byte] = (value >>> (8 * byte)) & 0xff;
  }
  return out;
};

// WAV 倒放：帧粒度整段换位（交织样本按帧反转，等价于每通道各自时间反转且帧内通道次序
// 不乱）后按原参数重编码。位数/格式覆盖与 parseWav 一致，非 PCM 的中文错误直接上抛。
export const reverseWav = (bytes: Uint8Array): Uint8Array => {
  const wav = parseWav(bytes);
  const { channels, frames } = wav.info;
  const samples = wav.samples;
  const reversed = new Float64Array(samples.length);
  for (let frame = 0; frame < frames; frame += 1) {
    const source = (frames - 1 - frame) * channels;
    const target = frame * channels;
    for (let channel = 0; channel < channels; channel += 1) reversed[target + channel] = samples[source + channel];
  }
  return encodeWav(reversed, wav.info);
};

// ============================================================================
// PCM 波形变换四档（声道差 / 一阶差分 / 波形反相 / 阈值位流）。
// 统一整数口径：样本先还原到"居中有符号域"——8bit 无符号 PCM 减 0x80 得 [-128,127]，
// 16/24/32bit 取补码精确值；变换全部在整数域做，wrap 用 ((x+2^(b-1)) mod 2^b) − 2^(b-1)
// （即补码定点溢出语义，与 sox/audacity 的 Delta/Invert 一致）。变换产物经归一化
// Float64 走 encodeWav 重编码——parseWav 的 scale 是 2 的幂，整数 ↔ 归一化严格互逆，位不丢。
// 用途：声道差/差分把"藏在立体声平衡或低幅抖动里"的信号抬到可见；反相用于消去背景
// （L+(−L) 抵消人声）与 invert-round-trip 校验；阈值位流把方波音频还原成原始比特流。
// ============================================================================

// 归一化样本 → 居中整数（精确：scale 为 2 的幂，乘回无舍入）。
const wavCenteredIntegers = (samples: Float64Array, bits: number): Int32Array => {
  const scale = bits === 8 ? 0x80 : bits === 16 ? 0x8000 : bits === 24 ? 0x800000 : 0x80000000;
  const out = new Int32Array(samples.length);
  for (let index = 0; index < samples.length; index += 1) out[index] = Math.round(samples[index] * scale);
  return out;
};

// wrap 到居中有符号域：[-2^(b-1), 2^(b-1)-1]（8bit 居中域与补码域同 wrap 规则）。
const wrapSignedCentered = (value: number, bits: number): number => {
  const half = 2 ** (bits - 1);
  const modulus = 2 ** bits;
  return (((value + half) % modulus) + modulus) % modulus - half;
};

// 变换后居中整数 → 归一化样本（encodeWav 输入口径）。
const centeredToNormalized = (integers: Int32Array, bits: number): Float64Array => {
  const scale = bits === 8 ? 0x80 : bits === 16 ? 0x8000 : bits === 24 ? 0x800000 : 0x80000000;
  const out = new Float64Array(integers.length);
  for (let index = 0; index < integers.length; index += 1) out[index] = integers[index] / scale;
  return out;
};

export interface ChannelDiffResult {
  // 32bit 单声道 WAV（L−R 逐帧差，保留原采样率）。
  wav: Uint8Array;
  // 宽域差值超出 int32 被饱和钳位的样本数（8/16bit 输入恒为 0，32bit 满幅对冲时出现）。
  clamped: number;
}

// 声道差：Float64 宽域逐帧 L−R（int 精确），输出 32bit 单声道 WAV + 饱和计数。
// 多于 2 声道的输入取前两声道（L/R 惯例）；mono 拒绝。
export const channelDiffWav = (bytes: Uint8Array): ChannelDiffResult => {
  const wav = parseWav(bytes);
  const { channels, frames } = wav.info;
  if (channels < 2) throw new Error(`声道差需要至少 2 个声道（收到 ${channels} 声道，mono 输入拒绝）`);
  const centered = wavCenteredIntegers(wav.samples, wav.info.bitsPerSample);
  const diff = new Int32Array(frames);
  let clamped = 0;
  for (let frame = 0; frame < frames; frame += 1) {
    const wide = centered[frame * channels] - centered[frame * channels + 1];
    if (wide > 0x7fffffff || wide < -0x80000000) {
      diff[frame] = wide > 0 ? 0x7fffffff : -0x80000000;
      clamped += 1;
    } else {
      diff[frame] = wide;
    }
  }
  const wavOut = encodeWav(centeredToNormalized(diff, 32), {
    sampleRate: wav.info.sampleRate, channels: 1, bitsPerSample: 32, dataBytes: frames * 4, frames, formatTag: 1,
  });
  return { wav: wavOut, clamped };
};

// 一阶差分：逐通道 wrap 差分 d[i]=x[i]−x[i−1]（d[0]=x[0]），输出同位深/声道 WAV。
// 直流偏置被差掉，突变量被放大——隐藏在"幅度缓慢变化"里的信号一眼可见。
export const deltaWav = (bytes: Uint8Array): Uint8Array => {
  const wav = parseWav(bytes);
  const { channels, frames, bitsPerSample: bits } = wav.info;
  const centered = wavCenteredIntegers(wav.samples, bits);
  const out = new Int32Array(centered.length);
  for (let channel = 0; channel < channels; channel += 1) {
    let previous = centered[channel];
    out[channel] = previous;
    for (let frame = 1; frame < frames; frame += 1) {
      const current = centered[frame * channels + channel];
      out[frame * channels + channel] = wrapSignedCentered(current - previous, bits);
      previous = current;
    }
  }
  return encodeWav(centeredToNormalized(out, bits), { ...wav.info });
};

// 波形反相：逐样本 wrap 取负 −x（8bit 等价 (256−v)&255）。反相 + 反相 = 原样（自逆），
// 可用于与已知背景轨对消（相加即差）提取隐藏信号。
export const invertWav = (bytes: Uint8Array): Uint8Array => {
  const wav = parseWav(bytes);
  const { bitsPerSample: bits } = wav.info;
  const centered = wavCenteredIntegers(wav.samples, bits);
  const out = new Int32Array(centered.length);
  for (let index = 0; index < centered.length; index += 1) out[index] = wrapSignedCentered(-centered[index], bits);
  return encodeWav(centeredToNormalized(out, bits), { ...wav.info });
};

export interface ThresholdOptions {
  // 整数域阈值：8bit 居中域 [-128,127]，16/24/32bit 补码值。窗口 max 严格大于阈值记 1。
  threshold: number;
  // 分窗大小（帧数），默认 1 = 逐样本。窗口 max 严格大于 T → 该窗 1。
  window?: number;
  // 分析声道，默认 0（第一声道）。
  channel?: number;
  // 游程记录上限（防超长音频撑爆返回值），默认 4096。
  maxRuns?: number;
}

export interface ThresholdRun {
  value: 0 | 1;
  length: number;
}

export interface ThresholdBitstreamResult {
  // LSB-first 打包的位流（bit i = 字节 i>>3 的第 i&7 位）。
  bytes: Uint8Array;
  totalBits: number;
  ones: number;
  // 交替游程段（1/0 交替的长度序列），超过 maxRuns 截断并置 runsTruncated。
  runs: ThresholdRun[];
  runsTruncated: boolean;
  // 因分窗丢弃的尾部样本数（不足一窗）。
  droppedTailSamples: number;
}

// 阈值位流：逐样本（或分窗取 max）严格大于阈值 → 1，LSB-first 打包成字节流 + 游程统计。
// 游程长度分布直接暴露方波波特率（常见 1:1 / 1:3 占空比），用于还原串口/曼彻斯特原始位流。
export const extractThresholdBitstream = (wav: DecodedWav, options: ThresholdOptions): ThresholdBitstreamResult => {
  const { channels, bitsPerSample: bits, frames } = wav.info;
  const window = options.window ?? 1;
  const maxRuns = options.maxRuns ?? 4096;
  if (!Number.isFinite(options.threshold)) throw new Error(`阈值必须为有限整数（收到 ${options.threshold}）`);
  if (window < 1 || !Number.isInteger(window)) throw new Error(`窗宽必须为 ≥1 的整数（收到 ${options.window}）`);
  if (options.channel !== undefined && (options.channel < 0 || options.channel >= channels)) {
    throw new Error(`通道 ${options.channel} 越界（该文件共 ${channels} 个声道）`);
  }
  const channel = options.channel ?? 0;
  const centered = wavCenteredIntegers(wav.samples, bits);
  const bitCount = Math.floor(frames / window);
  const droppedTailSamples = frames - bitCount * window;
  const bytesOut = new Uint8Array(Math.ceil(bitCount / 8));
  const runs: ThresholdRun[] = [];
  let runsTruncated = false;
  let ones = 0;
  let currentRunValue: 0 | 1 | null = null;
  let currentRunLength = 0;
  const pushRun = (value: 0 | 1, length: number) => {
    if (runs.length >= maxRuns) {
      runsTruncated = true;
      return;
    }
    runs.push({ value, length });
  };
  for (let bitIndex = 0; bitIndex < bitCount; bitIndex += 1) {
    let max = -Infinity;
    const start = bitIndex * window;
    for (let offset = 0; offset < window; offset += 1) {
      const value = centered[(start + offset) * channels + channel];
      if (value > max) max = value;
    }
    const bit: 0 | 1 = max > options.threshold ? 1 : 0;
    if (bit === 1) ones += 1;
    bytesOut[bitIndex >> 3] |= bit << (bitIndex & 7);
    if (bit === currentRunValue) {
      currentRunLength += 1;
    } else {
      if (currentRunValue !== null) pushRun(currentRunValue, currentRunLength);
      currentRunValue = bit;
      currentRunLength = 1;
    }
  }
  if (currentRunValue !== null) pushRun(currentRunValue, currentRunLength);
  return { bytes: bytesOut, totalBits: bitCount, ones, runs, runsTruncated, droppedTailSamples };
};

export interface LsbOptions {
  channel: number;
  bit: number;
  // 单次提取字节上限（红线 64KB，避免巨音频全量提取卡 UI）。
  maxBytes?: number;
}

// WAV LSB 提取：指定通道指定位平面，按帧序（音频的"行序"）采样，MSB-first 组字节
// （与图片域 extractLsbBytes 同一口径）。样本先还原回整数再取位——归一化 Float64 与
// 整数在 2 的幂分母下精确互转，位信息不丢失。
export const extractWavLsb = (wav: DecodedWav, options: LsbOptions): Uint8Array => {
  const { channels, bitsPerSample: bits, frames } = wav.info;
  if (options.channel < 0 || options.channel >= channels) {
    throw new Error(`通道 ${options.channel} 越界（该文件共 ${channels} 个声道）`);
  }
  if (options.bit < 0 || options.bit >= bits) {
    throw new Error(`位平面 ${options.bit} 超出 ${bits}bit 样本范围`);
  }
  const maxBytes = options.maxBytes ?? 64 * 1024;
  const count = Math.min(frames, maxBytes * 8);
  const scale = bits === 8 ? 0x80 : bits === 16 ? 0x8000 : bits === 24 ? 0x800000 : 0x80000000;
  const mask = 1 << options.bit;
  const out = new Uint8Array(Math.ceil(count / 8));
  let byte = 0;
  let filled = 0;
  let written = 0;
  for (let frame = 0; frame < count; frame += 1) {
    const sample = wav.samples[frame * channels + options.channel];
    const integer = bits === 8 ? Math.round(sample * scale) + 0x80 : Math.round(sample * scale);
    byte = (byte << 1) | ((integer & mask) === 0 ? 0 : 1);
    filled += 1;
    if (filled === 8) {
      out[written] = byte;
      written += 1;
      byte = 0;
      filled = 0;
    }
  }
  if (filled > 0) out[written] = byte << (8 - filled);
  return out;
};

// ITU Q.23 DTMF 频率表（Goertzel 逐频检测，无需 FFT）。
const DTMF_LOW = [697, 770, 852, 941];
const DTMF_HIGH = [1209, 1336, 1477, 1633];
const DTMF_KEYS = [
  ['1', '2', '3', 'A'],
  ['4', '5', '6', 'B'],
  ['7', '8', '9', 'C'],
  ['*', '0', '#', 'D'],
];

// DTMF 解码：25ms 帧窗 + 10ms 步进；帧 RMS 做自适应静音门（全局长峰值 RMS 的 8%），
// 过门帧对 8 个频率跑 Goertzel 取双频，组内最优/次优功率比 ≥1.25 且双频功率占帧能量
// ≥30% 才判有效（压制跨键混叠帧与噪声误报）；连续同键 ≥2 帧记一次按键，容忍 1 帧毛刺断裂。
export const dtmfDecode = (samples: Float64Array, sampleRate: number): string => {
  if (samples.length === 0 || sampleRate < 1) return '';
  const frameLen = Math.max(64, Math.round(sampleRate * 0.025)); // 最短可分辨低频组 73Hz 间距
  const hop = Math.max(1, Math.round(sampleRate * 0.01));
  const frameCount = Math.floor((samples.length - frameLen) / hop) + 1;
  if (frameCount < 1) return '';
  const rms = new Float64Array(frameCount);
  let maxRms = 0;
  for (let frame = 0; frame < frameCount; frame += 1) {
    const start = frame * hop;
    let acc = 0;
    for (let index = 0; index < frameLen; index += 1) {
      const value = samples[start + index];
      acc += value * value;
    }
    rms[frame] = Math.sqrt(acc / frameLen);
    if (rms[frame] > maxRms) maxRms = rms[frame];
  }
  if (maxRms < 1e-6) return ''; // 全零静音
  const gate = maxRms * 0.08;
  const coeffs = new Float64Array(8);
  for (let index = 0; index < 8; index += 1) {
    const freq = index < 4 ? DTMF_LOW[index] : DTMF_HIGH[index - 4];
    coeffs[index] = (2 * Math.cos((2 * Math.PI * freq) / sampleRate));
  }
  const power = new Float64Array(8);
  const detected: string[] = new Array<string>(frameCount).fill('');
  for (let frame = 0; frame < frameCount; frame += 1) {
    if (rms[frame] < gate) continue;
    const start = frame * hop;
    for (let index = 0; index < 8; index += 1) {
      const coeff = coeffs[index];
      let s1 = 0;
      let s2 = 0;
      for (let i = 0; i < frameLen; i += 1) {
        const s = samples[start + i] + coeff * s1 - s2;
        s2 = s1;
        s1 = s;
      }
      power[index] = s1 * s1 + s2 * s2 - coeff * s1 * s2;
    }
    let lowBest = 0;
    let lowSecond = 0;
    let lowIndex = 0;
    for (let index = 0; index < 4; index += 1) {
      if (power[index] > lowBest) {
        lowSecond = lowBest;
        lowBest = power[index];
        lowIndex = index;
      } else if (power[index] > lowSecond) {
        lowSecond = power[index];
      }
    }
    let highBest = 0;
    let highSecond = 0;
    let highIndex = 4;
    for (let index = 4; index < 8; index += 1) {
      if (power[index] > highBest) {
        highSecond = highBest;
        highBest = power[index];
        highIndex = index;
      } else if (power[index] > highSecond) {
        highSecond = power[index];
      }
    }
    // 双频能量门（量纲对齐）：Goertzel power 是未归一 |X(f)|² ≈ 能量×N/2，乘 2/N 归一后
    // 才与帧能量 rms²×frameLen 同量纲可比（纯音时两者相等）；否则 0.3 阈值等效噪声容忍百倍于信号。
    const energy = rms[frame] * rms[frame] * frameLen;
    if (lowBest > lowSecond * 1.25 && highBest > highSecond * 1.25 && ((lowBest + highBest) * 2) / frameLen > 0.3 * energy) {
      detected[frame] = DTMF_KEYS[lowIndex][highIndex - 4];
    }
  }
  // 按帧折叠成按键序列：同键连续段（容忍 1 帧断裂）计一次，最短 2 帧防单帧噪声
  let result = '';
  let index = 0;
  while (index < frameCount) {
    const key = detected[index];
    if (key === '') {
      index += 1;
      continue;
    }
    let run = 0;
    let gap = 0;
    let cursor = index;
    while (cursor < frameCount) {
      if (detected[cursor] === key) {
        run += 1;
        gap = 0;
        cursor += 1;
      } else if (detected[cursor] === '' && gap === 0) {
        gap = 1;
        cursor += 1;
      } else {
        break;
      }
    }
    if (run >= 2) result += key;
    index = cursor;
  }
  return result;
};

// 国际摩尔斯电码表（含常见标点；未收录序列输出 ? 便于人工核对 timeline）。
const MORSE_TABLE: Record<string, string> = {
  '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G',
  '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N',
  '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
  '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z',
  '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4', '.....': '5',
  '-....': '6', '--...': '7', '---..': '8', '----.': '9',
  '.-.-.-': '.', '--..--': ',', '..--..': '?', '-..-.': '/', '-....-': '-', '-.--.': '(',
  '-.--.-': ')', '.----.': "'", '---...': ':', '-.-.-.': ';', '-...-': '=', '.-.-.': '+',
  '..--.-': '_', '.-..-.': '"', '...-..-': '$', '.--.-.': '@',
};

// 摩尔斯音频识别：5ms 能量窗 1ms 步进做包络检波（整流+低通的等价离散实现），
// 峰谷中点自适应阈值二值化 → 交替电平段；最短有效 on 段自适应出 1 单位（点），
// on >2 单位判划，间隔 <2 单位为元素内、2~5 单位为字母间隔、≥5 单位为词间隔。
export const morseDecodeAudio = (samples: Float64Array, sampleRate: number): { text: string; timeline: string } => {
  if (samples.length === 0 || sampleRate < 1) return { text: '', timeline: '' };
  const winLen = Math.max(1, Math.round(sampleRate * 0.005));
  const hop = Math.max(1, Math.round(sampleRate * 0.001));
  const frameCount = Math.max(1, Math.floor((samples.length - winLen) / hop) + 1);
  const env = new Float64Array(frameCount);
  let peak = 0;
  let floorLevel = Infinity;
  for (let frame = 0; frame < frameCount; frame += 1) {
    const start = frame * hop;
    const end = Math.min(start + winLen, samples.length);
    let acc = 0;
    for (let index = start; index < end; index += 1) acc += samples[index] * samples[index];
    env[frame] = Math.sqrt(acc / Math.max(1, end - start));
    if (env[frame] > peak) peak = env[frame];
    if (env[frame] < floorLevel) floorLevel = env[frame];
  }
  if (peak < 1e-6 || peak - floorLevel < 1e-6) return { text: '', timeline: '' }; // 全零/直流静音
  const threshold = floorLevel + (peak - floorLevel) * 0.5;
  const runs: Array<{ on: boolean; len: number }> = [];
  let level = env[0] > threshold;
  let len = 1;
  for (let frame = 1; frame < frameCount; frame += 1) {
    const on = env[frame] > threshold;
    if (on === level) {
      len += 1;
    } else {
      runs.push({ on: level, len });
      level = on;
      len = 1;
    }
  }
  runs.push({ on: level, len });
  // 折叠成有效脉冲与脉冲间隔（<3 窗口的 on 段视为边沿毛刺丢弃，两侧 off 顺延合并）
  const pulses: number[] = [];
  const gaps: number[] = [];
  let pendingOff = 0;
  for (const run of runs) {
    if (run.on) {
      if (run.len >= 3) {
        pulses.push(run.len);
        gaps.push(pendingOff);
        pendingOff = 0;
      }
    } else {
      pendingOff += run.len;
    }
  }
  if (pulses.length === 0) return { text: '', timeline: '' };
  gaps.shift(); // 首脉冲前的静音无意义
  let unit = Infinity;
  for (const pulse of pulses) if (pulse < unit) unit = pulse;
  const parts: string[] = []; // timeline 片段：摩尔斯字母与词分隔 '/'
  let letter = '';
  for (let index = 0; index < pulses.length; index += 1) {
    letter += pulses[index] > unit * 2 ? '-' : '.';
    const gap = index + 1 < pulses.length ? gaps[index] : 0; // 尾脉冲后无间隔概念，不发分隔
    if (gap >= unit * 5) {
      parts.push(letter, '/');
      letter = '';
    } else if (gap >= unit * 2) {
      parts.push(letter);
      letter = '';
    }
  }
  if (letter !== '') parts.push(letter);
  const timeline = parts.join(' ');
  const words: string[] = [];
  let word = '';
  for (const part of parts) {
    if (part === '/') {
      if (word !== '') {
        words.push(word);
        word = '';
      }
    } else {
      word += MORSE_TABLE[part] ?? '?';
    }
  }
  if (word !== '') words.push(word);
  return { text: words.join(' '), timeline };
};

export interface SpectrogramOptions {
  fftSize?: number;
  hop?: number;
  maxFrames?: number;
}

export interface SpectrogramResult {
  matrix: Float64Array; // 行主序 frames×bins，值域 [0,1]（全局峰值=1，-96dB=0）
  bins: number;
  frames: number;
  maxFreq: number;
}

// 迭代 radix-2 Cooley-Tukey FFT：位反转置换 + 蝶形，原位变换（长度须为 2 的幂）。
const fftRadix2 = (re: Float64Array, im: Float64Array): void => {
  const n = re.length;
  for (let i = 1, j = 0; i < n; i += 1) {
    let bit = n >> 1;
    for (; (j & bit) !== 0; bit >>= 1) j ^= bit;
    j |= bit;
    if (i < j) {
      const swapRe = re[i];
      re[i] = re[j];
      re[j] = swapRe;
      const swapIm = im[i];
      im[i] = im[j];
      im[j] = swapIm;
    }
  }
  for (let len = 2; len <= n; len <<= 1) {
    const angle = (-2 * Math.PI) / len;
    const wRe = Math.cos(angle);
    const wIm = Math.sin(angle);
    const half = len >> 1;
    for (let base = 0; base < n; base += len) {
      let curRe = 1;
      let curIm = 0;
      for (let k = 0; k < half; k += 1) {
        const i0 = base + k;
        const i1 = i0 + half;
        const vRe = re[i1] * curRe - im[i1] * curIm;
        const vIm = re[i1] * curIm + im[i1] * curRe;
        re[i1] = re[i0] - vRe;
        im[i1] = im[i0] - vIm;
        re[i0] += vRe;
        im[i0] += vIm;
        const nextRe = curRe * wRe - curIm * wIm;
        curIm = curRe * wIm + curIm * wRe;
        curRe = nextRe;
      }
    }
  }
};

// 频谱矩阵：Hann 加窗分帧 → FFT → 取 [0, fs/2] 幅度谱，全局峰值 dB 归一映射到 [0,1]
// （96dB 动态范围，看 SSTV/隐藏文本类特征够用）。fftSize 默认 1024、hop=fftSize/4、
// maxFrames 默认 600 控内存（600×513 double ≈ 2.5MB）：超长音频只取前 maxFrames 帧不全量扫。
export const computeSpectrogram = (
  samples: Float64Array,
  sampleRate: number,
  options?: SpectrogramOptions,
): SpectrogramResult => {
  const fftSize = options?.fftSize ?? 1024;
  const hop = options?.hop ?? fftSize >> 2;
  const maxFrames = options?.maxFrames ?? 600;
  if (sampleRate < 1) throw new Error(`无效采样率 ${sampleRate}`);
  if (fftSize < 16 || (fftSize & (fftSize - 1)) !== 0) {
    throw new Error(`fftSize 必须为 ≥16 的 2 的幂（收到 ${fftSize}）`);
  }
  if (hop < 1) throw new Error(`hop 必须 ≥1（收到 ${hop}）`);
  const bins = (fftSize >> 1) + 1;
  if (samples.length === 0) {
    return { matrix: new Float64Array(0), bins, frames: 0, maxFreq: sampleRate / 2 };
  }
  const frameCount = Math.min(
    maxFrames,
    samples.length >= fftSize ? Math.floor((samples.length - fftSize) / hop) + 1 : 1, // 短音频零填补一帧
  );
  const window = new Float64Array(fftSize);
  for (let index = 0; index < fftSize; index += 1) {
    window[index] = 0.5 - 0.5 * Math.cos((2 * Math.PI * index) / fftSize); // 周期 Hann（DFT 口径）
  }
  const re = new Float64Array(fftSize);
  const im = new Float64Array(fftSize);
  const matrix = new Float64Array(frameCount * bins);
  let maxMag = 0;
  for (let frame = 0; frame < frameCount; frame += 1) {
    const start = frame * hop;
    for (let index = 0; index < fftSize; index += 1) {
      const raw = start + index < samples.length ? samples[start + index] : 0;
      re[index] = raw * window[index];
      im[index] = 0;
    }
    fftRadix2(re, im);
    const row = frame * bins;
    for (let bin = 0; bin < bins; bin += 1) {
      const mag = Math.sqrt(re[bin] * re[bin] + im[bin] * im[bin]);
      matrix[row + bin] = mag;
      if (mag > maxMag) maxMag = mag;
    }
  }
  if (maxMag < 1e-12) return { matrix, bins, frames: frameCount, maxFreq: sampleRate / 2 }; // 全零样本保持全 0
  for (let index = 0; index < matrix.length; index += 1) {
    const db = Math.max(-96, 20 * Math.log10(matrix[index] / maxMag)); // log10(0)=-Infinity，钳到下界
    matrix[index] = (db + 96) / 96;
  }
  return { matrix, bins, frames: frameCount, maxFreq: sampleRate / 2 };
};


// ============================================================================
// 频谱文字解码（G-2 Hear-with-your-Eyes 级自动链）：频谱图里"画出来"的文字自动识别。
// 链路：行能量找文本频带 → 带内二值化 → 列投影分割字形 → 归一化 + 盒式模糊 → 与内嵌
// 7×10 粗黑字形模板（hex 字符集 + 'l' + ':'，覆盖 "flag" 前缀与 hex 载荷）做归一化
// 互相关 → 逐字符取最优；多频带画同一段文字时按位票选共识（作者常把文字画两遍防单
// 带遮挡）。识别形态：文字以"笔画横跨一段频带"的字形绘出（非频带组合编码），本质是
// 16+2 类小字符集 OCR，模板匹配即可靠覆盖。
// 另附 renderSpectrogramPng：纯 JS 灰度 PNG 导出（deflate stored 块 + 自算 CRC32/
// Adler32，零依赖同步实现，node/浏览器通用），自动识别供人工复核的兜底导出件。
// ============================================================================

// ---- 内嵌字形模板（7×10，'#'=墨）：中性粗黑无衬线风格，锚定 hex 小字符集频谱字 ----
// 字形模板（14×20，# = 墨）：粗黑 condensed 无衬线体在频谱分辨率下的实测字形——
// 频谱画字类生成器（逆 STFT 文字入谱）多用此类字体，模板按该风格标定，与引擎的
// 归一化网格（14×20）同规格，normalize 仅剩盒式模糊。
const GLYPH_FONT: Record<string, string[]> = {
  '0': ['.##########...', '.############.', '##############', '#####....#####', '####......####', '###.......####', '###.......####', '###.......####', '###.......####', '####......####', '####......####', '#####....#####', '######...#####', '##############', '.############.', '.##########...', '.############.', '.############.', '.############.', '.############.'],
  '1': ['..########....', '.#########....', '##########....', '##########....', '##########....', '##...#####....', '.....#####....', '.....#####....', '.....#####....', '.....#####....', '.....#####....', '.....#####....', '.....#####....', '.....#####....', '.....#####....', '.....#####....', '.....#####....', '....######....', '##############', '##############'],
  '2': ['#############.', '#####..#######', '####....######', '........######', '.........#####', '.........#####', '.........#####', '........######', '........######', '........######', '........#####.', '.......#####..', '......######..', '......#####...', '.....#####....', '...######.....', '..######......', '.#######......', '##############', '##############'],
  '3': ['##############', '##############', '#####..#######', '####....######', '........######', '........######', '........######', '........######', '.......#######', '...##########.', '..##########..', '..###########.', '..############', '......########', '........######', '.........#####', '###......#####', '##############', '##############', '##############'],
  '4': ['......######..', '......######..', '.....#######..', '.....#######..', '....########..', '....########..', '....########..', '...#########..', '...#########..', '..##########..', '..####..####..', '.#####..####..', '#####...####..', '#####..#####..', '##############', '##############', '##############', '.......######.', '........####..', '........####..'],
  '5': ['##############', '##############', '######........', '######........', '######........', '######........', '######........', '######........', '###########...', '#############.', '##############', '##############', '.#############', '........######', '.........#####', '.........#####', '###.....######', '##############', '##############', '##############'],
  '6': ['..#####....#..', '..#####.......', '..####........', '.#####........', '#####.........', '#####.........', '#####.........', '#####.........', '#####.........', '###########...', '#############.', '##############', '#####....#####', '#####....#####', '#####.....####', '#####.....####', '#####....#####', '######..######', '.############.', '..##########..'],
  '7': ['##############', '##############', '........######', '........######', '........######', '........######', '.......#######', '.......#######', '......#######.', '......#######.', '......#######.', '.....#######..', '.....#######..', '....########..', '....#######...', '...########...', '...#######....', '..########....', '..#######.....', '..######......'],
  '8': ['##############', '##############', '######..######', '######..######', '######..######', '######..######', '######..######', '##############', '##############', '.############.', '.############.', '..###########.', '##############', '##############', '##############', '######...#####', '######...#####', '##############', '##############', '##############'],
  '9': ['.#####..#####.', '######..######', '#####....#####', '#####....#####', '#####....#####', '#####.....####', '#####.....####', '#####.....####', '#####.....####', '#####.....####', '######...#####', '.#############', '..############', '...###########', '.........#####', '.........#####', '.........#####', '.......######.', '############..', '###########...'],
  a: ['..###########.', '.############.', '##############', '##############', '##############', '######..######', '#####...######', '.###.....#####', '.........#####', '....##########', '..############', '.#############', '##############', '##############', '#######..#####', '######...#####', '######.#######', '##############', '##############', '##############'],
  b: ['#####.........', '#####.........', '#####.........', '#####.........', '###########...', '############..', '#############.', '##############', '##############', '##############', '######..######', '######...#####', '#####....#####', '#####....#####', '#####....#####', '######...#####', '######..######', '##############', '##############', '##############'],
  c: ['.....#######..', '....#########.', '...###########', '..############', '..############', '.######...####', '.######....###', '######........', '######........', '######........', '######........', '######........', '######........', '######........', '######........', '######........', '#######....###', '.#############', '..############', '...###########'],
  d: ['.........#####', '.........#####', '.........#####', '.........#####', '....##########', '..############', '.#############', '.#############', '##############', '##############', '######..######', '######...#####', '#####....#####', '#####....#####', '#####....#####', '#####....#####', '######..######', '##############', '##############', '.#############'],
  e: ['...#########..', '...#########..', '..###########.', '.#############', '.#############', '######..######', '######...#####', '#####....#####', '#####....#####', '##############', '##############', '##############', '##############', '##############', '#####.........', '#####.........', '######....####', '##############', '.#############', '..############'],
  f: ['...######.....', '...######.....', '...######.....', '...######.....', '...######.....', '##############', '##############', '##############', '##########.###', '...######.....', '...######.....', '...######.....', '...######.....', '...######.....', '...######.....', '...######.....', '...######.....', '...######.....', '...######.....', '...######.....'],
  l: ['##############', '.#############', '##############', '##############', '.#############', '##############', '##############', '.#############', '##############', '##############', '.#############', '##############', '##############', '.#############', '##############', '##############', '.#############', '##############', '##############', '.#############'],
  ':': ['#############.', '##############', '##############', '##############', '##############', '#############.', '.###########..', '..............', '..............', '..............', '..............', '..............', '..............', '..............', '..............', '..............', '#############.', '##############', '##############', '##############'],
  g: ['..###########.', '.############.', '##############', '##############', '#####..#######', '####....######', '####.....#####', '####......####', '####......####', '####.....#####', '####....######', '#####..#######', '#############.', '.###########..', '#######.......', '#######.......', '#######.......', '#######.......', '.#######......', '.#############'],
};
export const SPECTRO_TEXT_CHARSET = Object.keys(GLYPH_FONT).sort().join('');

// 字形位图归一化：任意二值位图缩放到固定网格（盒式均值 → 灰度），再做半径 1 盒式模糊
// （抵消笔画粗细差异，让细模板与粗字形的相关结构对齐）。
const normalizeGlyphBitmap = (on: Uint8Array, w: number, h: number, gw: number, gh: number): Float64Array => {
  const grid = new Float64Array(gw * gh);
  for (let gy = 0; gy < gh; gy += 1) {
    const y0 = Math.floor((gy * h) / gh);
    const y1 = Math.max(y0 + 1, Math.floor(((gy + 1) * h) / gh));
    for (let gx = 0; gx < gw; gx += 1) {
      const x0 = Math.floor((gx * w) / gw);
      const x1 = Math.max(x0 + 1, Math.floor(((gx + 1) * w) / gw));
      let sum = 0;
      for (let y = y0; y < y1; y += 1) {
        for (let x = x0; x < x1; x += 1) sum += on[y * w + x];
      }
      grid[gy * gw + gx] = sum / ((x1 - x0) * (y1 - y0));
    }
  }
  return boxBlur(grid, gw, gh);
};

const boxBlur = (grid: Float64Array, w: number, h: number): Float64Array => {
  const out = new Float64Array(w * h);
  for (let y = 0; y < h; y += 1) {
    for (let x = 0; x < w; x += 1) {
      let sum = 0;
      let count = 0;
      for (let dy = -1; dy <= 1; dy += 1) {
        for (let dx = -1; dx <= 1; dx += 1) {
          const nx = x + dx;
          const ny = y + dy;
          if (nx < 0 || ny < 0 || nx >= w || ny >= h) continue;
          sum += grid[ny * w + nx];
          count += 1;
        }
      }
      out[y * w + x] = sum / count;
    }
  }
  return out;
};

// 模板库（模块加载时构建一次）：14×20 网格 + 均值中心化，供互相关比对。
const GLYPH_GRID_W = 14;
const GLYPH_GRID_H = 20;
const GLYPH_TEMPLATES: Array<{ char: string; grid: Float64Array; mean: number }> = Object.entries(GLYPH_FONT).map(([char, rows]) => {
  const w = rows[0].length;
  const on = new Uint8Array(w * rows.length);
  for (let y = 0; y < rows.length; y += 1) {
    for (let x = 0; x < w; x += 1) on[y * w + x] = rows[y][x] === '#' ? 1 : 0;
  }
  const grid = normalizeGlyphBitmap(on, w, rows.length, GLYPH_GRID_W, GLYPH_GRID_H);
  let mean = 0;
  for (let i = 0; i < grid.length; i += 1) mean += grid[i];
  mean /= grid.length;
  return { char, grid, mean };
});

// 归一化互相关（零均值点积 / 各自模长），返回 [-1,1]。
const nccScore = (left: Float64Array, leftMean: number, right: Float64Array, rightMean: number): number => {
  let dot = 0;
  let normLeft = 0;
  let normRight = 0;
  for (let i = 0; i < left.length; i += 1) {
    const a = left[i] - leftMean;
    const b = right[i] - rightMean;
    dot += a * b;
    normLeft += a * a;
    normRight += b * b;
  }
  if (normLeft < 1e-9 || normRight < 1e-9) return 0;
  return dot / Math.sqrt(normLeft * normRight);
};

export interface SpectrogramTextResult {
  // 各文本频带识别出的字符串（按频带从低到高）。
  bandTexts: string[];
  // 多频带按位票选共识（长度一致时逐位取多数；否则取最长的带文本）。
  consensus: string | null;
  // 共识文本每字符的模板相关分（-1..1）。
  charScores: number[];
  // "flag: <hex>" / "flag <hex>" 形态的共识包装成 flag{hex} 候选。
  flagCandidates: string[];
  notes: string[];
}

export interface SpectrogramTextOptions {
  fftSize?: number;
  hop?: number;
  maxFrames?: number;
  // 带内形状二值化阈值（相对全谱峰值归一值）。默认 0.45——绘字频谱的笔画内部
  // 强度有起伏，阈值取高会把实心字形削成碎片骨架。
  threshold?: number;
  // 字母边界检测阈值（需显著高于形状阈值：笔画峰值稳定饱和，带内噪声 ≤0.6）。
  // 默认 0.68。
  boundaryThreshold?: number;
}

// 频谱文字解码主入口。samples 为单声道（多通道 WAV 由调用方先取第一通道）。
export const decodeSpectrogramText = (
  samples: Float64Array,
  sampleRate: number,
  options?: SpectrogramTextOptions,
): SpectrogramTextResult => {
  const notes: string[] = [];
  const spec = computeSpectrogram(samples, sampleRate, {
    fftSize: options?.fftSize ?? 2048,
    hop: options?.hop ?? 256,
    maxFrames: options?.maxFrames ?? 2400,
  });
  if (spec.frames < 40) {
    return { bandTexts: [], consensus: null, charScores: [], flagCandidates: [], notes: ['音频过短，频谱帧不足'] };
  }
  const threshold = options?.threshold ?? 0.62;
  const boundaryThreshold = options?.boundaryThreshold ?? 0.68;
  const { bins, frames, matrix } = spec;

  // 文本频带检测：行强能量占比 > 10% 的连续 bin 区段（字高不足 40 bin 的丢弃）。
  const rowFrac = new Float64Array(bins);
  for (let b = 0; b < bins; b += 1) {
    let count = 0;
    for (let f = 0; f < frames; f += 1) {
      if (matrix[f * bins + b] > boundaryThreshold) count += 1;
    }
    rowFrac[b] = count / frames;
  }
  const bands: Array<[number, number]> = [];
  let bandStart = -1;
  for (let b = 0; b < bins; b += 1) {
    const on = rowFrac[b] > 0.1;
    if (on && bandStart < 0) bandStart = b;
    if (!on && bandStart >= 0) {
      if (b - bandStart >= 40) bands.push([bandStart, b - 1]);
      bandStart = -1;
    }
  }
  if (bandStart >= 0 && bins - bandStart >= 40) bands.push([bandStart, bins - 1]);
  if (bands.length === 0) {
    return { bandTexts: [], consensus: null, charScores: [], flagCandidates: [], notes: ['未检出文本频带（画字特征不足）'] };
  }

  const bandTexts: string[] = [];
  const bandScores: number[][] = [];
  for (const [b0, b1] of bands) {
    const bandH = b1 - b0 + 1;
    // 带内双阈值：低阈值取字形实心形状（笔画内部强度有起伏，高阈值会削成碎片骨架），
    // 高阈值取列剖面定位字母边界（笔画峰值饱和、带内噪声显著更低，边界干净）。
    const on = new Uint8Array(frames * bandH);
    const colCount = new Int32Array(frames);
    for (let f = 0; f < frames; f += 1) {
      for (let b = 0; b < bandH; b += 1) {
        if (matrix[f * bins + b0 + b] > threshold) on[f * bandH + b] = 1;
      }
    }
    for (let f = 0; f < frames; f += 1) {
      for (let b = 0; b < bandH; b += 1) {
        if (matrix[f * bins + b0 + b] > boundaryThreshold) colCount[f] += 1;
      }
    }
    // 列剖面分割：colCount 从 <2 跳升 ≥2 即字母起点，降回 <2 持续 ≥4 帧收尾
    // （边界阈值下空隙列归零干净；字母间偶尔的 2-3 计数毛刺不足以开新段）。
    const glyphs: Array<[number, number]> = [];
    let glyphStart = -1;
    let gap = 0;
    for (let f = 0; f < frames; f += 1) {
      if (colCount[f] >= 2) {
        if (glyphStart < 0) glyphStart = f;
        gap = 0;
      } else if (glyphStart >= 0) {
        gap += 1;
        if (gap >= 2) {
          glyphs.push([glyphStart, f - gap]);
          glyphStart = -1;
        }
      }
    }
    if (glyphStart >= 0) glyphs.push([glyphStart, frames - 1]);
    // 窄段（<6 帧）视为笔画间噪声丢弃
    const kept = glyphs.filter(([gs, ge]) => ge - gs + 1 >= 6);
    if (kept.length < 2) {
      notes.push(`频带 ${b0}-${b1}: 仅分割出 ${kept.length} 个字形，放弃该带`);
      continue;
    }
    let text = '';
    const scores: number[] = [];
    for (const [gs, ge] of kept) {
      const w = ge - gs + 1;
      // 字形高度收紧：取带内实际有墨的行范围（去上下空白/邻字干扰）
      let top = -1;
      let bottom = -1;
      for (let b = 0; b < bandH; b += 1) {
        let has = false;
        for (let f = gs; f <= ge; f += 1) {
          if (on[f * bandH + b]) {
            has = true;
            break;
          }
        }
        if (has) {
          if (top < 0) top = b;
          bottom = b;
        }
      }
      if (top < 0 || bottom - top < 8) continue;
      const h = bottom - top + 1;
      // 垂直翻转取字：频谱 bin 沿频率升序排列，画字音频的文本以"低频在下"为正立方向
      // （生成器把文字画上图像后逐频率逆变换，图像行首在低频端），裁剪按 bin 降序读行，
      // 使字形与模板的自然方向一致。
      const onCrop = new Uint8Array(w * h);
      for (let b = 0; b < h; b += 1) {
        for (let f = 0; f < w; f += 1) onCrop[b * w + f] = on[(gs + f) * bandH + bottom - b];
      }
      const grid = normalizeGlyphBitmap(onCrop, w, h, GLYPH_GRID_W, GLYPH_GRID_H);
      let mean = 0;
      for (let i = 0; i < grid.length; i += 1) mean += grid[i];
      mean /= grid.length;
      let bestChar = '?';
      let bestScore = -2;
      for (const tpl of GLYPH_TEMPLATES) {
        const score = nccScore(grid, mean, tpl.grid, tpl.mean);
        if (score > bestScore) {
          bestScore = score;
          bestChar = tpl.char;
        }
      }
      text += bestChar;
      scores.push(bestScore);
    }
    bandTexts.push(text);
    bandScores.push(scores);
  }
  if (bandTexts.length === 0) {
    return { bandTexts: [], consensus: null, charScores: [], flagCandidates: [], notes };
  }
  // 多带共识：长度一致逐位取多数（同票取低带），否则取最长带文本。
  let consensus: string | null = null;
  let charScores: number[] = [];
  if (bandTexts.length >= 2 && new Set(bandTexts.map(text => text.length)).size === 1) {
    let agreed = 0;
    consensus = '';
    for (let i = 0; i < bandTexts[0].length; i += 1) {
      const votes = new Map<string, number>();
      for (const text of bandTexts) votes.set(text[i], (votes.get(text[i]) ?? 0) + 1);
      let bestChar = bandTexts[0][i];
      let bestVotes = 0;
      for (const [char, count] of votes) {
        if (count > bestVotes) {
          bestVotes = count;
          bestChar = char;
        }
      }
      consensus += bestChar;
      if (bestVotes === bandTexts.length) agreed += 1;
    }
    if (agreed === consensus.length) notes.push(`${bandTexts.length} 个频带逐位全票一致`);
    else notes.push(`${bandTexts.length} 个频带逐位共识：${agreed}/${consensus.length} 位全票`);
    charScores = bandScores[0];
  } else {
    let longest = bandTexts[0];
    for (const text of bandTexts) if (text.length > longest.length) longest = text;
    consensus = longest;
    charScores = bandScores[bandTexts.indexOf(consensus)] ?? [];
    if (bandTexts.length >= 2) notes.push('各频带识别长度不一致，取最长带文本');
  }
  // flag 包装："flag: <hex>" / "flag <hex>" → flag{hex}
  const flagCandidates: string[] = [];
  const source = consensus ?? '';
  const match = /^flag\s*[:=]?\s*([0-9a-fA-F]{8,})\s*$/i.exec(source);
  if (match) flagCandidates.push(`flag{${match[1].toLowerCase()}}`);
  return { bandTexts, consensus, charScores, flagCandidates, notes };
};

// ---- 纯 JS 灰度 PNG 导出（deflate stored 块，零依赖同步实现） ----

const PNG_CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return table;
})();

const pngCrc32 = (bytes: Uint8Array): number => {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) c = PNG_CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};

const pngAdler32 = (bytes: Uint8Array): number => {
  let a = 1;
  let b = 0;
  for (let i = 0; i < bytes.length; i += 1) {
    a = (a + bytes[i]) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
};

const pngChunk = (type: string, data: Uint8Array): Uint8Array => {
  const out = new Uint8Array(12 + data.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, data.length);
  for (let i = 0; i < 4; i += 1) out[4 + i] = type.charCodeAt(i);
  out.set(data, 8);
  view.setUint32(8 + data.length, pngCrc32(out.subarray(4, 8 + data.length)));
  return out;
};

// zlib 流（stored 块版）：2B 头 + 若干 ≤65535 的非压缩块 + adler32。
const zlibStore = (raw: Uint8Array): Uint8Array => {
  const blockCount = Math.max(1, Math.ceil(raw.length / 65535));
  const out = new Uint8Array(2 + raw.length + blockCount * 5 + 4);
  out[0] = 0x78;
  out[1] = 0x01;
  let pos = 2;
  let offset = 0;
  for (let block = 0; block < blockCount; block += 1) {
    const len = Math.min(65535, raw.length - offset);
    out[pos] = block === blockCount - 1 ? 1 : 0;
    out[pos + 1] = len & 0xff;
    out[pos + 2] = (len >> 8) & 0xff;
    out[pos + 3] = (~len) & 0xff;
    out[pos + 4] = ((~len) >> 8) & 0xff;
    out.set(raw.subarray(offset, offset + len), pos + 5);
    pos += 5 + len;
    offset += len;
  }
  const view = new DataView(out.buffer);
  view.setUint32(pos, pngAdler32(raw));
  return out;
};

const concatUint8 = (parts: Uint8Array[]): Uint8Array => {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

export interface SpectrogramPngOptions {
  // 只渲染 [binStart, binEnd] 区段（缺省全谱）；低频在下。
  binStart?: number;
  binEnd?: number;
  // 对比度增益（归一值乘 gain 后钳到 1，再反相成灰度）。默认 1。
  gain?: number;
}

// 频谱矩阵 → 灰度 PNG（8bit grayscale，低频在下，黑=强）。纯 JS 同步实现。
export const renderSpectrogramPng = (spec: SpectrogramResult, options?: SpectrogramPngOptions): Uint8Array => {
  const binStart = options?.binStart ?? 0;
  const binEnd = Math.min(spec.bins - 1, options?.binEnd ?? spec.bins - 1);
  const gain = options?.gain ?? 1;
  const width = spec.frames;
  const height = binEnd - binStart + 1;
  if (width < 1 || height < 1) throw new Error(`频谱尺寸异常 ${width}×${height}，无法导出 PNG`);
  const stride = width + 1; // 每行前置 filter byte 0
  const raw = new Uint8Array(stride * height);
  for (let row = 0; row < height; row += 1) {
    const bin = binStart + row; // 行 0 = 最低 bin（低频在下）
    const line = (height - 1 - row) * stride;
    raw[line] = 0;
    for (let f = 0; f < width; f += 1) {
      const v = Math.max(0, Math.min(1, spec.matrix[f * spec.bins + bin] * gain));
      raw[line + 1 + f] = Math.round(255 * (1 - v));
    }
  }
  const ihdr = new Uint8Array(13);
  const view = new DataView(ihdr.buffer);
  view.setUint32(0, width);
  view.setUint32(4, height);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 0; // color type: grayscale
  const signature = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return concatUint8([
    signature,
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlibStore(raw)),
    pngChunk('IEND', new Uint8Array(0)),
  ]);
};
