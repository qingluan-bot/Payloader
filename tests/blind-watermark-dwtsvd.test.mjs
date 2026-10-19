// DWT-DCT-SVD 真盲水印测试（批次 B3·E 线）：guofei9987/blind_watermark 0.4.4 兼容口径。
// 向量与对拍锚点全部独立权威：
//   · NumpyRandomState：本机 numpy 2.5.4 / Python 3.14 实测（rk_double 全精度、shuffle 排列、
//     argsort 行、init_genrand(5489) 的 MT19937 经典首输出 3499211612）。
//   · haar：pywt dwt2('haar') 数值（正交归一）；dct/idct：cv2.dct 全 16 值（float32 基准容差 1e-6）；
//     svd：numpy.linalg.svd 奇异值 + 重构不变量。
//   · 互通：本机安装 blind_watermark 时做双向对拍（库嵌→TS 提 / TS 嵌→库提 / 图片模式），
//     未安装则跳过该项（纯 TS 闭环与全部锚点不受影响）。
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import zlib from 'node:zlib';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const mod = loadModule(path.join(srcDir, 'utils', 'ctf', 'blindWatermarkDwtSvd.ts'));

// ---- 工具：程序化造图 / PNG 编解码（测试自含，不复用浏览器 API） ----

const noiseImage = (width, height, seed) => {
  const data = new Uint8ClampedArray(width * height * 4);
  let state = seed;
  const rand = () => {
    state = (state * 1103515245 + 12345) % 2147483648;
    return Math.floor((state / 2147483648) * 256);
  };
  for (let index = 0; index < width * height; index += 1) {
    data[index * 4] = rand();
    data[index * 4 + 1] = rand();
    data[index * 4 + 2] = rand();
    data[index * 4 + 3] = 255;
  }
  return { data, width, height };
};

const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();
const crc32 = (buffer) => {
  let c = 0xffffffff;
  for (const byte of buffer) c = crcTable[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
const pngChunk = (type, data) => {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, 'ascii');
  Buffer.from(data).copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
};
// 最小 PNG 编码：8bit RGBA、每行 filter 0（None）
const pngEncode = (image) => {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(image.width, 0);
  ihdr.writeUInt32BE(image.height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const raw = Buffer.alloc(image.height * (image.width * 4 + 1));
  for (let y = 0; y < image.height; y += 1) {
    const rowStart = y * (image.width * 4 + 1);
    raw[rowStart] = 0;
    for (let x = 0; x < image.width * 4; x += 1) {
      raw[rowStart + 1 + x] = image.data[y * image.width * 4 + x];
    }
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlib.deflateSync(raw, { level: 6 })),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
};
// 最小 PNG 解码：8bit 灰度/RGB/RGBA，filter 0..4 全解（filter byte 每行一个，见 AGENTS.md 坑）
const pngDecode = (bytes) => {
  let offset = 8;
  let width = 0;
  let height = 0;
  let colorType = 0;
  const idat = [];
  while (offset + 8 <= bytes.length) {
    const view = new DataView(bytes.buffer, bytes.byteOffset + offset, 8);
    const length = view.getUint32(0);
    const type = Buffer.from(bytes.subarray(offset + 4, offset + 8)).toString('ascii');
    const data = bytes.subarray(offset + 8, offset + 8 + length);
    if (type === 'IHDR') {
      const header = new DataView(bytes.buffer, bytes.byteOffset + offset + 8, 13);
      width = header.getUint32(0);
      height = header.getUint32(4);
      colorType = bytes[offset + 17];
    } else if (type === 'IDAT') {
      idat.push(Buffer.from(data));
    }
    offset += 12 + length;
  }
  const channels = { 0: 1, 2: 3, 6: 4 }[colorType];
  if (channels === undefined) throw new Error(`不支持 colorType ${colorType}`);
  const raw = zlib.inflateSync(Buffer.concat(idat));
  const stride = width * channels;
  const pixels = new Uint8Array(height * stride);
  const previous = new Uint8Array(stride);
  for (let y = 0; y < height; y += 1) {
    const filter = raw[y * (stride + 1)];
    const line = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    const current = pixels.subarray(y * stride, (y + 1) * stride);
    for (let x = 0; x < stride; x += 1) {
      const left = x >= channels ? current[x - channels] : 0;
      const up = previous[x];
      const upperLeft = x >= channels ? previous[x - channels] : 0;
      let value = line[x];
      if (filter === 1) value += left;
      else if (filter === 2) value += up;
      else if (filter === 3) value += (left + up) >> 1;
      else if (filter === 4) {
        const p = left + up - upperLeft;
        const pa = Math.abs(p - left);
        const pb = Math.abs(p - up);
        const pc = Math.abs(p - upperLeft);
        value += pa <= pb && pa <= pc ? left : pb <= pc ? up : upperLeft;
      }
      current[x] = value & 0xff;
    }
    previous.set(current);
  }
  const data = new Uint8ClampedArray(width * height * 4);
  for (let index = 0; index < width * height; index += 1) {
    if (channels === 4) data.set(pixels.subarray(index * 4, index * 4 + 4), index * 4);
    else if (channels === 3) {
      data[index * 4] = pixels[index * 3];
      data[index * 4 + 1] = pixels[index * 3 + 1];
      data[index * 4 + 2] = pixels[index * 3 + 2];
      data[index * 4 + 3] = 255;
    } else {
      const value = pixels[index * channels];
      data[index * 4] = value;
      data[index * 4 + 1] = value;
      data[index * 4 + 2] = value;
      data[index * 4 + 3] = 255;
    }
  }
  return { data, width, height };
};

// ---- NumpyRandomState（numpy legacy RandomState 语义） ----

test('NumpyRandomState：rk_double 与 numpy 逐位一致（seed 0/1/5 全精度锚点）', () => {
  const anchors = {
    0: [0.5488135039273248, 0.7151893663724195, 0.6027633760716439, 0.5448831829968969, 0.4236547993389047, 0.6458941130666561],
    1: [0.417022004702574, 0.7203244934421581, 0.00011437481734488664, 0.30233257263183977, 0.14675589081711304, 0.0923385947687978],
    5: [0.22199317108973948, 0.8707323061773764, 0.20671915533942642, 0.9186109079379216, 0.48841118879482914, 0.6117438629026457],
  };
  for (const [seed, expected] of Object.entries(anchors)) {
    const random = new mod.NumpyRandomState(Number(seed));
    const got = Array.from({ length: expected.length }, () => random.nextDouble());
    assert.deepEqual(got, expected, `seed=${seed}`);
  }
});

test('NumpyRandomState：init_genrand(5489) 首输出 = MT19937 经典向量 3499211612；shuffle 与 numpy 逐位一致', () => {
  // MT19937 标准测试向量（与 pyRandom.ts 注释同源；init_genrand 直播种路径）
  const classic = new mod.NumpyRandomState(5489);
  assert.equal(classic.nextUint32(), 3499211612);
  // 本机 numpy 实测排列（RandomState(seed).shuffle(arange(n))）
  const cases = [
    { seed: 0, n: 4, expected: [2, 3, 1, 0] },
    { seed: 0, n: 8, expected: [6, 2, 1, 7, 3, 0, 5, 4] },
    { seed: 0, n: 16, expected: [1, 6, 8, 9, 13, 4, 2, 14, 10, 7, 15, 11, 3, 0, 5, 12] },
    { seed: 1, n: 8, expected: [7, 2, 1, 6, 0, 4, 3, 5] },
    { seed: 1, n: 23, expected: [20, 17, 3, 13, 19, 16, 10, 4, 2, 18, 6, 7, 1, 14, 0, 15, 22, 21, 9, 8, 12, 11, 5] },
    { seed: 5, n: 23, expected: [19, 2, 18, 17, 20, 22, 13, 10, 5, 1, 21, 12, 0, 11, 7, 4, 8, 9, 16, 6, 15, 14, 3] },
  ];
  for (const { seed, n, expected } of cases) {
    const shuffled = new mod.NumpyRandomState(seed).shuffleInPlace(Array.from({ length: n }, (_, index) => index));
    assert.deepEqual(shuffled, expected, `seed=${seed} n=${n}`);
  }
  // max=0 不消耗随机数（流位置敏感，numpy random_interval 语义）
  const probe = new mod.NumpyRandomState(1);
  assert.equal(probe.randomInterval(0), 0);
  assert.equal(probe.nextDouble(), 0.417022004702574);
  // argsort 行（password_img 置乱行）：RandomState(1).random((4,16)).argsort(axis=1) 第 1 行
  const random = new mod.NumpyRandomState(1);
  const row = Array.from({ length: 16 }, () => random.nextDouble());
  const order = Array.from({ length: 16 }, (_, index) => index).sort((left, right) => row[left] - row[right]);
  assert.deepEqual(order, [2, 14, 5, 4, 6, 12, 3, 7, 8, 0, 10, 9, 15, 11, 1, 13]);
  // 种子校验
  assert.throws(() => new mod.NumpyRandomState(-1), /0\.\.2\^32-1/);
  assert.throws(() => new mod.NumpyRandomState(1.5), /0\.\.2\^32-1/);
});

// ---- 数值核：haar / dct / idct / svd ----

test('haarForward：pywt dwt2(haar) 正交归一锚点（含 4×4 全四式）', () => {
  // pywt dwt2(np.arange(16).reshape(4,4)*3, 'haar') 实测
  const input = new Float64Array([0, 3, 6, 9, 12, 15, 18, 21, 24, 27, 30, 33, 36, 39, 42, 45]);
  const ca = new Float64Array(4);
  const ch = new Float64Array(4);
  const cv = new Float64Array(4);
  const cd = new Float64Array(4);
  mod.haarForward(input, 4, ca, ch, cv, cd);
  assert.deepEqual(Array.from(ca), [15, 27, 63, 75]);
  for (let index = 0; index < 4; index += 1) assert.ok(Math.abs(ch[index] + 12) < 1e-6, `cH[${index}]`);
  for (let index = 0; index < 4; index += 1) assert.ok(Math.abs(cv[index] + 3) < 1e-6, `cV[${index}]`);
  for (let index = 0; index < 4; index += 1) assert.equal(cd[index], 0);
  // 2×2 最小例：[[0,3],[12,15]] → ca=15, ch=−12, cv=−3, cd=0
  const small = new Float64Array([0, 3, 12, 15]);
  const ca2 = new Float64Array(1);
  const ch2 = new Float64Array(1);
  const cv2 = new Float64Array(1);
  const cd2 = new Float64Array(1);
  mod.haarForward(small, 2, ca2, ch2, cv2, cd2);
  assert.equal(ca2[0], 15);
  assert.equal(ch2[0], -12);
  assert.equal(cv2[0], -3);
  assert.equal(cd2[0], 0);
});

test('dct4/idct4：cv2.dct 全 16 值对拍（float32 基准容差 1e-6）+ 正逆往返机器精度', () => {
  const block = new Float64Array(16);
  for (let index = 0; index < 16; index += 1) block[index] = index / 7;
  const out = new Float64Array(16);
  mod.dct4(block, out);
  // 本机 cv2.dct(np.arange(16).reshape(4,4)/7) 实测（float32，容差 1e-6 吸收其量化噪声）
  const expected = [4.285714149, -0.637269258, 0, -0.045289263, -2.549077272, 0, 0, 0, 0, 0, 0, 0, -0.181157216, 0, 0, 0];
  for (let index = 0; index < 16; index += 1) {
    assert.ok(Math.abs(out[index] - expected[index]) < 1e-6, `dct[${index}] got ${out[index]}`);
  }
  const restored = new Float64Array(16);
  mod.idct4(out, restored);
  for (let index = 0; index < 16; index += 1) {
    assert.ok(Math.abs(restored[index] - block[index]) < 1e-12, `roundtrip[${index}]`);
  }
});

test('svd4：奇异值降序与 numpy 一致、重构不变量、正交性', () => {
  // 本机 numpy.linalg.svd(float64) 实测奇异值
  const matrix = new Float64Array([7, 2.5, -1, 3, 0.5, -3, 4, 1.5, 2, 1, -2.5, 0, 1, 4, 0.5, -1.5]);
  const { u, s, vh } = mod.svd4(matrix);
  const expectedS = [8.733126551766585, 5.881155327858475, 3.5065745185056865, 0.590294660824624];
  for (let index = 0; index < 4; index += 1) {
    assert.ok(Math.abs(s[index] - expectedS[index]) < 1e-9, `s[${index}] got ${s[index]}`);
  }
  // 重构 A = U·diag(s)·Vᵀ（任意合法分解逐值相同的数学性质，Jacobi 与 LAPACK 符号差异抵消）
  for (let p = 0; p < 4; p += 1) {
    for (let q = 0; q < 4; q += 1) {
      let sum = 0;
      for (let k = 0; k < 4; k += 1) sum += u[p * 4 + k] * s[k] * vh[k * 4 + q];
      assert.ok(Math.abs(sum - matrix[p * 4 + q]) < 1e-9, `recon[${p}][${q}]`);
    }
  }
  // U/V 正交性（列各自 O(1)）
  for (let p = 0; p < 4; p += 1) {
    for (let q = p; q < 4; q += 1) {
      let dotU = 0;
      let dotV = 0;
      for (let i = 0; i < 4; i += 1) {
        dotU += u[i * 4 + p] * u[i * 4 + q];
        dotV += vh[p * 4 + i] * vh[q * 4 + i];
      }
      assert.ok(Math.abs(dotU - (p === q ? 1 : 0)) < 1e-9, `U orth ${p},${q}`);
      assert.ok(Math.abs(dotV - (p === q ? 1 : 0)) < 1e-9, `V orth ${p},${q}`);
    }
  }
  // 对角阵：奇异值降序排列还原
  const diagonal = mod.svd4(new Float64Array([3, 0, 0, 0, 0, 4, 0, 0, 0, 0, 2, 0, 0, 0, 0, 1]));
  assert.deepEqual(Array.from(diagonal.s), [4, 3, 2, 1]);
});

// ---- toByte：cv2.imwrite 银行家舍入 + 饱和（本机 cv2 实测） ----

test('toByte：银行家舍入与饱和（cv2.imwrite float→uint8 口径）', () => {
  assert.equal(mod.toByte(0.5), 0);
  assert.equal(mod.toByte(1.5), 2);
  assert.equal(mod.toByte(2.5), 2);
  assert.equal(mod.toByte(3.5), 4);
  assert.equal(mod.toByte(-0.5), 0);
  assert.equal(mod.toByte(100.5), 100);
  assert.equal(mod.toByte(254.5), 254);
  assert.equal(mod.toByte(255.4), 255);
  assert.equal(mod.toByte(256), 255);
  assert.equal(mod.toByte(-3), 0);
  assert.equal(mod.toByte(42.4), 42);
  assert.equal(mod.toByte(42.6), 43);
});

// ---- 文本位流（库 bin(int(utf8.hex(),16))[2:] 口径） ----

test('encodeTextBits/decodeTextBits：库口径（无长度头、丢前导零）+ 往返 + 空文本报错', () => {
  // 沙箱跨 realm 数组：主 realm Array.from 转换后再断言（见 AGENTS.md 坑）
  assert.deepEqual(Array.from(mod.encodeTextBits('A')), [1, 0, 0, 0, 0, 0, 1]); // 0x41 = 0b1000001（7 位，丢前导 0）
  assert.deepEqual(Array.from(mod.encodeTextBits(' ')), [1, 0, 0, 0, 0, 0]); // 0x20 → 6 位
  const bits = mod.encodeTextBits('@guofei9987 open source!');
  assert.equal(bits.length, 191); // 本机 Python bin(int(hex,16)) 实测
  assert.equal(bits.slice(0, 8).join(''), '10000000'); // '@'=0x40 → 1000000 + 'g' 首位 1
  // 往返（decode 按库口径 int(bits,2)→hex→utf-8）
  assert.equal(mod.decodeTextBits(bits), '@guofei9987 open source!');
  assert.equal(mod.decodeTextBits(mod.encodeTextBits('flag{dwt_svd_ok}')), 'flag{dwt_svd_ok}');
  assert.equal(mod.decodeTextBits(mod.encodeTextBits('盲水印')), '盲水印');
  assert.throws(() => mod.encodeTextBits(''), /空文本/);
  assert.throws(() => mod.decodeTextBits([]), /空/);
});

// ---- 嵌入 / 提取闭环（纯 TS） ----

test('DWT-SVD：文本嵌入→指定位长提取一致，auto 提取命中同位长，原图不被修改', () => {
  const carrier = noiseImage(96, 64, 2026);
  const original = Uint8ClampedArray.from(carrier.data);
  const result = mod.dwtSvdEmbedText(carrier, 'CTF{dwt_svd}');
  assert.equal(result.wmBitCount, mod.encodeTextBits('CTF{dwt_svd}').length);
  assert.equal(result.blockNum, 12 * 8);
  assert.deepEqual(Array.from(carrier.data), Array.from(original), '嵌入不得修改输入图');
  const extracted = mod.dwtSvdExtractText(result.image, result.wmBitCount);
  assert.equal(extracted, 'CTF{dwt_svd}');
  const auto = mod.dwtSvdExtractTextAuto(result.image);
  assert.equal(auto.text, 'CTF{dwt_svd}');
  assert.equal(auto.wmBitCount, result.wmBitCount);
  // 比特容忍度：avg 全部强极化（可信嵌入下 0/1 清晰可分）
  const avg = mod.dwtSvdExtractAvg(result.image, result.wmBitCount);
  for (const value of avg) assert.ok(value < 0.25 || value > 0.75, `avg 极化 ${value}`);
});

test('DWT-SVD：图片水印嵌入→提取还原（>128 灰度阈值位图）', () => {
  // 256 块承载 72 位 = 3.5 个循环（每位 ~10 样本），贴近真实嵌入冗余度
  const carrier = noiseImage(128, 128, 99);
  const wmWidth = 12;
  const wmHeight = 6;
  const watermark = { data: new Uint8ClampedArray(wmWidth * wmHeight * 4), width: wmWidth, height: wmHeight };
  for (let y = 0; y < wmHeight; y += 1) {
    for (let x = 0; x < wmWidth; x += 1) {
      const value = y >= 1 && y < 5 && x >= 3 && x < 9 ? 255 : 0;
      watermark.data[(y * wmWidth + x) * 4] = value;
      watermark.data[(y * wmWidth + x) * 4 + 1] = value;
      watermark.data[(y * wmWidth + x) * 4 + 2] = value;
      watermark.data[(y * wmWidth + x) * 4 + 3] = 255;
    }
  }
  const result = mod.dwtSvdEmbedImage(carrier, watermark);
  assert.equal(result.wmBitCount, wmWidth * wmHeight);
  assert.deepEqual(Array.from(result.wmShape), [wmHeight, wmWidth]);
  const extracted = mod.dwtSvdExtractImage(result.image, { width: wmWidth, height: wmHeight });
  for (let y = 0; y < wmHeight; y += 1) {
    for (let x = 0; x < wmWidth; x += 1) {
      const expected = y >= 1 && y < 5 && x >= 3 && x < 9 ? 255 : 0;
      const value = extracted.data[(y * wmWidth + x) * 4];
      // 位判定级断言（库口径 wm>128 → bit）：可信嵌入下判位必须一致
      assert.equal(value > 128, expected === 255, `wm[${y},${x}] got ${value} expect ${expected}`);
    }
  }
});

test('DWT-SVD：password 与 d2 参数变体闭环（库全部可调参数）', () => {
  const carrier = noiseImage(80, 80, 7);
  for (const options of [
    { passwordImg: 7, passwordWm: 3 },
    { d2: 0 }, // 库 fast 模式：只用 s[0]
    { d1: 20, d2: 10 },
  ]) {
    const result = mod.dwtSvdEmbedText(carrier, 'variant-ok', options);
    assert.equal(mod.dwtSvdExtractText(result.image, result.wmBitCount, options), 'variant-ok', JSON.stringify(options));
  }
});

test('DWT-SVD：块数不足报错、超像素预算报错、auto 扫描空间不足报错', () => {
  const tiny = noiseImage(36, 24, 1); // ca 18×12 → 块 4×3=12
  // 'A' 7 位 < 12 可嵌；15 位（'ok'）与更长文本必超
  assert.throws(() => mod.dwtSvdEmbedText(tiny, 'ok'), /不足以容纳/);
  assert.throws(() => mod.dwtSvdEmbedText(tiny, 'way too long for this tiny image'), /不足以容纳/);
  assert.ok(mod.dwtSvdEmbedText(tiny, 'A').wmBitCount === 7);
  const huge = { data: new Uint8ClampedArray(4_000_001 * 4), width: 2001, height: 2000 };
  assert.throws(() => mod.dwtSvdEmbedText(huge, 'x'), /像素上限/);
  const small = noiseImage(36, 24, 2); // 12 块 → maxBits = 11，扫不到可读文本
  assert.throws(() => mod.dwtSvdExtractTextAuto(small), /未找到可读文本/);
  assert.throws(() => mod.dwtSvdExtractText(noiseImage(64, 64, 3), 0), /正整数/);
});

// ---- blind_watermark 库双向互通（本机未安装则跳过） ----

// Python 侧脚本：造噪声载体 + 库嵌文本/图片水印；或读 TS 嵌 PNG 用库提取。
// 关键口径与库源码一致：password_wm=1、password_img=1；文本模式 wm_shape=(1, bit_count)。
const PY_INTEROP_SCRIPT = `# -*- coding: utf-8 -*-
import sys
import numpy as np
import cv2
from blind_watermark import WaterMark

mode, work = sys.argv[1], sys.argv[2]
if mode == 'embed':
    carrier = np.random.RandomState(7).randint(0, 256, (480, 640, 3), dtype=np.uint8)
    cv2.imwrite(work + '/carrier.png', carrier)
    text = '@guofei9987 open source!'
    bwm = WaterMark(password_wm=1, password_img=1)
    bwm.read_img(work + '/carrier.png')
    bwm.read_wm(text, mode='str')
    bwm.embed(work + '/py_embed.png', compression_ratio=None)
    with open(work + '/bit_count.txt', 'w') as f:
        f.write(str(bwm.wm_bit.size))
    wm_img = np.zeros((32, 32), dtype=np.uint8)
    wm_img[8:24, 8:24] = 255
    cv2.imwrite(work + '/wm_img.png', wm_img)
    bwm2 = WaterMark(password_wm=1, password_img=1)
    bwm2.read_img(work + '/carrier.png')
    bwm2.read_wm(work + '/wm_img.png', mode='img')
    bwm2.embed(work + '/py_embed_img.png', compression_ratio=None)
    print('embedded')
elif mode == 'extract':
    # TS 嵌入的文本自带位长（与 embed 阶段库嵌文本的 191 不同），从独立文件读
    with open(work + '/ts_bit_count.txt') as f:
        ts_count = int(f.read().strip())
    bwm = WaterMark(password_wm=1, password_img=1)
    text = bwm.extract(work + '/ts_embed.png', wm_shape=(1, ts_count), mode='str')
    with open(work + '/extract_out.txt', 'w', encoding='utf-8') as f:
        f.write(text)
    bwm3 = WaterMark(password_wm=1, password_img=1)
    back = bwm3.extract(work + '/ts_embed_img.png', wm_shape=(32, 32), out_wm_name=work + '/wm_back.png', mode='img')
    print('extracted')
`;

let pythonAvailable = false;
try {
  execFileSync('py', ['-c', 'import blind_watermark'], { stdio: 'pipe' });
  pythonAvailable = true;
} catch {
  pythonAvailable = false;
}

test('blind_watermark 互通：库嵌→TS 提（文本逐位一致 + auto 命中 + 图片模式还原）', { skip: pythonAvailable ? false : '本机未安装 blind_watermark' }, () => {
  const work = mkdtempSync(path.join(tmpdir(), 'bwm-interop-'));
  try {
    writeFileSync(path.join(work, 'probe.py'), PY_INTEROP_SCRIPT);
    execFileSync('py', [path.join(work, 'probe.py'), 'embed', work], { stdio: 'pipe', timeout: 300000 });
    const bitCount = Number(readFileSync(path.join(work, 'bit_count.txt'), 'utf8').trim());
    assert.equal(bitCount, 191);

    const pyEmbedded = pngDecode(new Uint8Array(readFileSync(path.join(work, 'py_embed.png'))));
    assert.equal(pyEmbedded.width, 640);
    const text = mod.dwtSvdExtractText(pyEmbedded, bitCount);
    assert.equal(text, '@guofei9987 open source!', '库嵌文本必须被 TS 逐位提取');
    const auto = mod.dwtSvdExtractTextAuto(pyEmbedded);
    assert.equal(auto.text, '@guofei9987 open source!', 'auto 扫描必须命中真实位长');
    assert.equal(auto.wmBitCount, 191);

    // 图片模式：库嵌 32×32 方块 → TS extractImage 还原（中心亮、边缘暗）
    const pyEmbedImg = pngDecode(new Uint8Array(readFileSync(path.join(work, 'py_embed_img.png'))));
    const wmBack = mod.dwtSvdExtractImage(pyEmbedImg, { width: 32, height: 32 });
    let brightCenter = 0;
    let darkBorder = 0;
    for (let y = 0; y < 32; y += 1) {
      for (let x = 0; x < 32; x += 1) {
        const value = wmBack.data[(y * 32 + x) * 4];
        if (y >= 8 && y < 24 && x >= 8 && x < 24 ? value > 128 : false) brightCenter += 1;
        if ((y < 8 || y >= 24 || x < 8 || x >= 24) && value < 128) darkBorder += 1;
      }
    }
    assert.equal(brightCenter, 256);
    assert.equal(darkBorder, 768);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test('blind_watermark 互通：TS 嵌→库提（文本 + 图片模式，库读 TS 产 PNG）', { skip: pythonAvailable ? false : '本机未安装 blind_watermark' }, () => {
  const work = mkdtempSync(path.join(tmpdir(), 'bwm-interop-'));
  try {
    writeFileSync(path.join(work, 'probe.py'), PY_INTEROP_SCRIPT);
    execFileSync('py', [path.join(work, 'probe.py'), 'embed', work], { stdio: 'pipe', timeout: 300000 });
    const carrier = pngDecode(new Uint8Array(readFileSync(path.join(work, 'carrier.png'))));

    const textResult = mod.dwtSvdEmbedText(carrier, 'payloader lane E');
    writeFileSync(path.join(work, 'ts_embed.png'), pngEncode(textResult.image));
    writeFileSync(path.join(work, 'ts_bit_count.txt'), String(textResult.wmBitCount));
    const wmImage = { data: new Uint8ClampedArray(32 * 32 * 4), width: 32, height: 32 };
    for (let index = 0; index < 32 * 32; index += 1) {
      const value = index % 32 >= 8 && index % 32 < 24 && Math.floor(index / 32) >= 8 && Math.floor(index / 32) < 24 ? 255 : 0;
      wmImage.data[index * 4] = value;
      wmImage.data[index * 4 + 1] = value;
      wmImage.data[index * 4 + 2] = value;
      wmImage.data[index * 4 + 3] = 255;
    }
    const imgResult = mod.dwtSvdEmbedImage(carrier, wmImage);
    writeFileSync(path.join(work, 'ts_embed_img.png'), pngEncode(imgResult.image));

    execFileSync('py', [path.join(work, 'probe.py'), 'extract', work], { stdio: 'pipe', timeout: 300000 });
    const extracted = readFileSync(path.join(work, 'extract_out.txt'), 'utf8');
    assert.equal(extracted, 'payloader lane E', '库必须从 TS 嵌图逐位提取出原文本');

    // 库回的图片水印（wm_back.png 255·wm）与 TS 侧 extractImage 一致（>128 判位）
    const libBack = pngDecode(new Uint8Array(readFileSync(path.join(work, 'wm_back.png'))));
    const tsBack = mod.dwtSvdExtractImage(imgResult.image, { width: 32, height: 32 });
    let agree = 0;
    for (let index = 0; index < 32 * 32; index += 1) {
      const libBit = libBack.data[index * 4] > 128 ? 1 : 0;
      const tsBit = tsBack.data[index * 4] > 128 ? 1 : 0;
      if (libBit === tsBit) agree += 1;
    }
    assert.ok(agree >= (32 * 32) * 0.98, `库/TS 图片水印判位一致率 ${agree}/1024`);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});
