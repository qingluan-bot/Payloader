// PCM 波形变换四档测试（B2-8）：声道差 / 一阶差分 / 波形反相 / 阈值位流。
// 期望值三重来源：①手算逐样本断言；②Python wave+numpy 独立实现生成的黄金向量
// （gen 脚本经 wave 模块真实容器读写往返验证，值嵌入下方 GOLDEN 常量）；
// ③不变量断言（invert 自逆往返、delta 可逆性、游程守恒）。
// 加载方式统一走 tests/helpers/compileTsModule.mjs；沙箱红线：引擎产物断言前 Array.from 转主 realm。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const {
  parseWav, channelDiffWav, deltaWav, invertWav, extractThresholdBitstream,
} = loadModule(path.join(projectRoot, 'src', 'utils', 'ctf', 'audioStego.ts'));

// ---- 测试工厂（与 audio-stego.test.mjs 同款手写 WAV 头）----

const buildWav = ({ sampleRate = 8000, channels = 1, bits = 16, samplesInt }) => {
  if (samplesInt.length % channels !== 0) throw new Error('样本数必须是通道数整数倍');
  const frames = samplesInt.length / channels;
  const bytesPerSample = bits / 8;
  const blockAlign = channels * bytesPerSample;
  const dataLen = frames * blockAlign;
  const header = Buffer.alloc(44);
  header.write('RIFF', 0, 'latin1');
  header.writeUInt32LE(36 + dataLen, 4);
  header.write('WAVE', 8, 'latin1');
  header.write('fmt ', 12, 'latin1');
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(1, 20);
  header.writeUInt16LE(channels, 22);
  header.writeUInt32LE(sampleRate, 24);
  header.writeUInt32LE(sampleRate * blockAlign, 28);
  header.writeUInt16LE(blockAlign, 32);
  header.writeUInt16LE(bits, 34);
  header.write('data', 36, 'latin1');
  header.writeUInt32LE(dataLen, 40);
  const data = Buffer.alloc(dataLen);
  for (let index = 0; index < samplesInt.length; index += 1) {
    const value = samplesInt[index] >>> 0; // 8bit 存储域为 u8；16/24/32 为补码按位写
    const offset = index * bytesPerSample;
    for (let byte = 0; byte < bytesPerSample; byte += 1) data[offset + byte] = (value >>> (8 * byte)) & 0xff;
  }
  return new Uint8Array(Buffer.concat([header, data]));
};

// 解析产物归一化样本 → 居中整数（parseWav scale 是 2 的幂，精确还原）。
const centeredInts = (parsed, bits) => {
  const scale = bits === 8 ? 0x80 : bits === 16 ? 0x8000 : bits === 24 ? 0x800000 : 0x80000000;
  return Array.from(parsed.samples, value => Math.round(value * scale));
};

// ---- Python wave+numpy 黄金向量（独立权威，生成脚本见报告；值经手算复核）----
// 期望域说明：chdiff 为 32bit 居中整数；invert/delta 为输入位深的居中整数；
// threshold8.threshold perSample.ints 为 8bit 存储域 u8（引擎输出 WAV 回读后的存储字节）。
const GOLDEN = {
  // stereo_{bits}.wav：L=[...], R=[...]（生成侧经 wave 写入→读回往返验证；期望为交织域）
  stereo: [
    { bits: 8, inputInts: [0, 200, 255, 1, 128, 254, 64, 129],
      chdiff: { ints: [-200, 254, -126, -65], clamped: 0 },
      invertInts: [-128, -72, -127, 127, 0, -126, 64, -1],
      deltaInts: [-128, 72, -1, 57, -127, -3, -64, -125] },
    { bits: 16, inputInts: [32767, -32768, -32768, 32767, 0, 1, -1, -2],
      chdiff: { ints: [65535, -65535, -1, 1], clamped: 0 },
      invertInts: [-32767, -32768, -32768, -32767, 0, -1, 1, 2],
      deltaInts: [32767, -32768, 1, -1, -32768, -32766, -1, -3] },
    { bits: 24, inputInts: [8388607, -8388608, -8388608, 8388607, 0, 1, -1, -2],
      chdiff: { ints: [16777215, -16777215, -1, 1], clamped: 0 },
      invertInts: [-8388607, -8388608, -8388608, -8388607, 0, -1, 1, 2],
      deltaInts: [8388607, -8388608, 1, -1, -8388608, -8388606, -1, -3] },
    { bits: 32, inputInts: [2147483647, -2147483648, -2147483648, 2147483647, 0, 1, -1, -2],
      chdiff: { ints: [2147483647, -2147483648, -1, 1], clamped: 2 },
      invertInts: [-2147483647, -2147483648, -2147483648, -2147483647, 0, -1, 1, 2],
      deltaInts: [2147483647, -2147483648, 1, -1, -2147483648, -2147483646, -1, -3] },
  ],
  mono16Delta: { bits: 16, inputInts: [32767, -32768, 32767, -1, 0], ints: [32767, 1, -1, -32768, 1] },
  mono8Invert: { bits: 8, inputInts: [0, 1, 127, 128, 129, 254, 255] }, // 期望见各断言（(256−v)&255）
  threshold16: { bits: 16, inputInts: [100, -200, 20000, 16000, 16001, -5, 0, 7, -7, 32000, 1, -1],
    perSample: { threshold: 0, window: 1, packed: '9d06', totalBits: 12, ones: 7,
      runs: [[1, 1], [0, 1], [1, 3], [0, 2], [1, 1], [0, 1], [1, 2], [0, 1]] },
    window3: { threshold: 16000, window: 3, packed: '0b', totalBits: 4, ones: 3,
      runs: [[1, 2], [0, 1], [1, 1]] } },
  threshold8: { bits: 8, inputInts: [128, 129, 127, 0, 255, 128, 200, 55],
    perSample: { threshold: -1, window: 1, packed: '73', totalBits: 8, ones: 5,
      runs: [[1, 2], [0, 2], [1, 3], [0, 1]] } },
};

const toHex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');

// ---- chdiff 声道差 ----

test('channelDiffWav 手算 16bit：宽域 L−R 输出 32bit mono，逐样本与手算一致', () => {
  const input = buildWav({ channels: 2, bits: 16, samplesInt: [1000, -400, -2000, 500, 0, 32767, -32768, -32768] });
  const { wav, clamped } = channelDiffWav(input);
  const parsed = parseWav(wav);
  assert.equal(parsed.info.bitsPerSample, 32);
  assert.equal(parsed.info.channels, 1);
  assert.equal(parsed.info.frames, 4);
  assert.equal(parsed.info.sampleRate, 8000);
  assert.deepEqual(Array.from(parsed.samples), [1400 / 2147483648, -2500 / 2147483648, -32767 / 2147483648, 0 / 2147483648]);
  assert.equal(clamped, 0);
});

test('channelDiffWav 32bit 满幅对冲：2 个样本饱和钳位到 int32 边界（黄金向量）', () => {
  const golden = GOLDEN.stereo.find(caseRow => caseRow.bits === 32);
  const { wav, clamped } = channelDiffWav(buildWav({ channels: 2, bits: 32, samplesInt: golden.inputInts }));
  assert.equal(clamped, golden.chdiff.clamped);
  assert.deepEqual(centeredInts(parseWav(wav), 32), golden.chdiff.ints);
});

for (const golden of GOLDEN.stereo.filter(caseRow => caseRow.bits !== 32)) {
  test(`channelDiffWav ${golden.bits}bit 立体声：numpy/wave 黄金向量逐样本一致`, () => {
    const { wav, clamped } = channelDiffWav(buildWav({ channels: 2, bits: golden.bits, samplesInt: golden.inputInts }));
    assert.equal(clamped, golden.chdiff.clamped);
    assert.deepEqual(centeredInts(parseWav(wav), 32), golden.chdiff.ints);
  });
}

test('channelDiffWav mono 输入拒绝（中文错误）', () => {
  assert.throws(() => channelDiffWav(buildWav({ channels: 1, bits: 16, samplesInt: [1, 2, 3] })), /声道/);
});

// ---- delta 一阶差分 ----

test('deltaWav 手算 mono 16bit：d[0]=x[0]，wrap 差分含 32767→-32768 边界', () => {
  const golden = GOLDEN.mono16Delta;
  const wav = deltaWav(buildWav({ channels: 1, bits: 16, samplesInt: golden.inputInts }));
  assert.deepEqual(centeredInts(parseWav(wav), 16), golden.ints);
});

test('deltaWav 立体声逐通道独立差分（黄金向量 16bit，交织域）', () => {
  const golden = GOLDEN.stereo.find(caseRow => caseRow.bits === 16);
  const wav = deltaWav(buildWav({ channels: 2, bits: 16, samplesInt: golden.inputInts }));
  assert.deepEqual(centeredInts(parseWav(wav), 16), golden.deltaInts);
  // L 通道子序列 = Python deltaLeft 黄金向量 [32767,1,-32768,-1]
  const leftChannel = golden.deltaInts.filter((_, index) => index % 2 === 0);
  assert.deepEqual(leftChannel, [32767, 1, -32768, -1]);
});

test('deltaWav 与手算一致：交织输出保持帧次序，8bit 居中域 wrap', () => {
  // 8bit 存储 [0, 200, 255, 1] → 居中 [-128, 72, 127, -127] → 差分 [-128, -128+200=72... ]
  // d[0]=-128；d[1]=72-(-128)=200→wrap8(200)=200-256=-56；d[2]=127-72=55；d[3]=-127-127=-254→wrap8(−254)=2
  const wav = deltaWav(buildWav({ channels: 1, bits: 8, samplesInt: [0, 200, 255, 1] }));
  assert.deepEqual(centeredInts(parseWav(wav), 8), [-128, -56, 55, 2]);
});

// ---- invert 波形反相 ----

test('invertWav 8bit：存储域 (256−v)&255，居中域 wrap 取负（黄金向量）', () => {
  const golden = GOLDEN.mono8Invert;
  const wav = invertWav(buildWav({ channels: 1, bits: 8, samplesInt: golden.inputInts }));
  // 存储 [0,1,127,128,129,254,255] → (256−v)&255 = [0,255,129,128,127,2,1] → 居中 [-128,127,1,0,-1,-126,-127]
  assert.deepEqual(centeredInts(parseWav(wav), 8), [-128, 127, 1, 0, -1, -126, -127]);
});

test('invertWav invert+invert 逐字节往返还原（8/16/24/32 全位宽）', () => {
  for (const golden of GOLDEN.stereo) {
    const original = buildWav({ channels: 2, bits: golden.bits, samplesInt: golden.inputInts });
    const twice = invertWav(invertWav(original));
    assert.deepEqual(Array.from(twice), Array.from(original), `${golden.bits}bit 反相往返`);
  }
});

for (const golden of GOLDEN.stereo) {
  test(`invertWav ${golden.bits}bit 立体声：numpy 黄金向量逐样本一致`, () => {
    const wav = invertWav(buildWav({ channels: 2, bits: golden.bits, samplesInt: golden.inputInts }));
    assert.deepEqual(centeredInts(parseWav(wav), golden.bits), golden.invertInts);
  });
}

test('invertWav 保留头参数（采样率/声道/位深不变）', () => {
  const wav = invertWav(buildWav({ sampleRate: 44100, channels: 2, bits: 16, samplesInt: [1, -1, 2, -2] }));
  const info = parseWav(wav).info;
  assert.equal(info.sampleRate, 44100);
  assert.equal(info.channels, 2);
  assert.equal(info.bitsPerSample, 16);
  assert.equal(info.frames, 2);
});

// ---- threshold 阈值位流 ----

test('extractThresholdBitstream 手算+黄金向量：逐样本 T=0（16bit）', () => {
  const golden = GOLDEN.threshold16;
  const wav = { info: { sampleRate: 8000, channels: 1, bitsPerSample: 16, dataBytes: 0, frames: golden.inputInts.length, formatTag: 1 },
    samples: Float64Array.from(golden.inputInts, value => value / 32768) };
  const result = extractThresholdBitstream(wav, { threshold: 0 });
  assert.equal(toHex(result.bytes), golden.perSample.packed);
  assert.equal(result.totalBits, golden.perSample.totalBits);
  assert.equal(result.ones, golden.perSample.ones);
  assert.deepEqual(Array.from(result.runs, run => [run.value, run.length]), golden.perSample.runs);
  assert.equal(result.runsTruncated, false);
  assert.equal(result.droppedTailSamples, 0);
});

test('extractThresholdBitstream 分窗 window=3 T=16000：窗口 max 严格大于阈值（黄金向量）', () => {
  const golden = GOLDEN.threshold16;
  const wav = { info: { sampleRate: 8000, channels: 1, bitsPerSample: 16, dataBytes: 0, frames: golden.inputInts.length, formatTag: 1 },
    samples: Float64Array.from(golden.inputInts, value => value / 32768) };
  const result = extractThresholdBitstream(wav, { threshold: 16000, window: 3 });
  assert.equal(toHex(result.bytes), golden.window3.packed);
  assert.equal(result.totalBits, golden.window3.totalBits);
  assert.equal(result.ones, golden.window3.ones);
  assert.deepEqual(Array.from(result.runs, run => [run.value, run.length]), golden.window3.runs);
  assert.equal(result.droppedTailSamples, 0); // 12 = 4 窗 × 3，无尾丢弃
});

test('extractThresholdBitstream 8bit T=-1：居中域阈值生效（黄金向量）', () => {
  const golden = GOLDEN.threshold8;
  const wav = { info: { sampleRate: 8000, channels: 1, bitsPerSample: 8, dataBytes: 0, frames: golden.inputInts.length, formatTag: 1 },
    samples: Float64Array.from(golden.inputInts, value => (value - 128) / 128) };
  const result = extractThresholdBitstream(wav, { threshold: -1 });
  assert.equal(toHex(result.bytes), golden.perSample.packed);
  assert.equal(result.ones, golden.perSample.ones);
  assert.deepEqual(Array.from(result.runs, run => [run.value, run.length]), golden.perSample.runs);
});

test('extractThresholdBitstream 游程守恒：Σ 段长 = 总位数，首尾值与位流一致', () => {
  const wav = { info: { sampleRate: 8000, channels: 1, bitsPerSample: 16, dataBytes: 0, frames: 10, formatTag: 1 },
    samples: Float64Array.from([5, -5, 5, -5, 5, 5, -5, -5, 5, -5], value => value / 32768) };
  const result = extractThresholdBitstream(wav, { threshold: 0 });
  const totalRunLength = result.runs.reduce((sum, run) => sum + run.length, 0);
  assert.equal(totalRunLength, result.totalBits);
  assert.equal(result.totalBits, 10);
  // 位流 1,0,1,0,1,1,0,0,1,0 → LSB-first：byte0 = 1+4+16+32 = 0x35；bit8=1 → byte1 bit0 = 0x01
  assert.equal(toHex(result.bytes), '3501');
});

test('extractThresholdBitstream 分窗尾样本丢弃计数与 maxRuns 截断标记', () => {
  const samples = [1, -1, 1, -1, 1, -1, 1];
  const wav = { info: { sampleRate: 8000, channels: 1, bitsPerSample: 16, dataBytes: 0, frames: samples.length, formatTag: 1 },
    samples: Float64Array.from(samples, value => value / 32768) };
  const dropped = extractThresholdBitstream(wav, { threshold: 0, window: 3 });
  assert.equal(dropped.totalBits, 2);
  assert.equal(dropped.droppedTailSamples, 1);
  const capped = extractThresholdBitstream(wav, { threshold: 0, maxRuns: 2 });
  assert.equal(capped.runsTruncated, true);
  assert.equal(capped.runs.length, 2);
});

test('extractThresholdBitstream 声道选择与越界拒绝、非法窗宽拒绝', () => {
  const frames = 4;
  const samples = new Float64Array(frames * 2);
  for (let frame = 0; frame < frames; frame += 1) {
    samples[frame * 2] = frame < 2 ? 1 : -1; // L
    samples[frame * 2 + 1] = frame < 2 ? -1 : 1; // R（与 L 反相 → 位流互补）
  }
  const wav = { info: { sampleRate: 8000, channels: 2, bitsPerSample: 16, dataBytes: 0, frames, formatTag: 1 }, samples };
  const left = extractThresholdBitstream(wav, { threshold: 0, channel: 0 });
  const right = extractThresholdBitstream(wav, { threshold: 0, channel: 1 });
  assert.equal(toHex(left.bytes), '03'); // 1,1,0,0
  assert.equal(toHex(right.bytes), '0c'); // 0,0,1,1
  assert.throws(() => extractThresholdBitstream(wav, { threshold: 0, channel: 2 }), /通道/);
  assert.throws(() => extractThresholdBitstream(wav, { threshold: 0, window: 0 }), /窗宽/);
  assert.throws(() => extractThresholdBitstream(wav, { threshold: Number.NaN }), /阈值/);
});

test('decodeAudioCard 集成口径：parseWav→threshold 位流可还原藏入方波 flag（LSB-first）', () => {
  // 方波音频：样本 >0 编码位 1（占 2 帧）——'OK' 的 LSB-first 位流 = 'O'=0x4F 位序 1,1,1,1,0,0,1,0
  const bits = [];
  for (const ch of 'OK') for (let bit = 0; bit < 8; bit += 1) bits.push((ch.charCodeAt(0) >> bit) & 1);
  const samples = [];
  for (const bit of bits) for (let i = 0; i < 2; i += 1) samples.push(bit ? 20000 : -20000);
  const decoded = parseWav(buildWav({ channels: 1, bits: 16, samplesInt: samples }));
  const result = extractThresholdBitstream(decoded, { threshold: 0, window: 2 });
  const text = Array.from(result.bytes.subarray(0, 2), byte => String.fromCharCode(byte)).join('');
  assert.equal(text, 'OK');
});
