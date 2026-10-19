// 位平面全组合扫描引擎测试：R/LSB flag、B/LSB zlib 魔数、列序可打印、rgb 打包序、
// lsbFirst 位序变体、与 extractLsbBytes 语义一致性、排序/maxHits、退化输入。
// 测试向量全部程序化构造（无外部 fixture），加载统一走 tests/helpers/compileTsModule.mjs。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import zlib from 'node:zlib';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { scanBitPlanes } = loadModule(path.join(srcDir, 'utils', 'ctf', 'bitPlaneScan.ts'));
const { extractLsbBytes, bytesToPreviewText } = loadModule(path.join(srcDir, 'utils', 'ctf', 'imagePlanes.ts'));

// ---- 测试工厂 ----

const makePrng = seed => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
};

const makeRgba = (width, height, prng) => {
  const rgba = new Uint8Array(width * height * 4);
  for (let index = 0; index < rgba.length; index += 1) rgba[index] = Math.floor(prng() * 256);
  for (let pixel = 0; pixel < width * height; pixel += 1) rgba[pixel * 4 + 3] = 255;
  return rgba;
};

// 嵌入是扫描提取的写侧镜像：按 通道组序 × 像素序 展开采样位，写进指定位平面（LSB）。
const embedBits = (rgba, width, height, channels, messageBytes, { lsbFirst = false, column = false } = {}) => {
  const bits = [];
  for (const byte of messageBytes) {
    for (let shift = 0; shift < 8; shift += 1) bits.push((byte >> (lsbFirst ? shift : 7 - shift)) & 1);
  }
  for (let sample = 0; sample < bits.length; sample += 1) {
    const ordinal = Math.floor(sample / channels.length);
    const channel = channels[sample % channels.length];
    const pixel = column
      ? Math.floor(ordinal / height) + (ordinal % height) * width
      : ordinal;
    const index = pixel * 4 + channel;
    rgba[index] = (rgba[index] & 0xfe) | bits[sample];
  }
  return rgba;
};

const textBytes = text => Array.from(Buffer.from(text, 'latin1'));
const repeatTo = (text, length) => text.repeat(Math.ceil(length / text.length)).slice(0, length);

const SIZE = 64;

// ---- 用例 1：R 通道 LSB 行序 MSB-first 藏 flag，应排 #1 ----

test('scanBitPlanes R/LSB/行序/MSB-first 藏 flag：#1 命中且 reasons 含 flag 格式', () => {
  const rgba = makeRgba(SIZE, SIZE, makePrng(0x5eed0001));
  embedBits(rgba, SIZE, SIZE, [0], textBytes('flag{zsteg_scan_hit}'));
  const hits = scanBitPlanes(rgba, SIZE, SIZE);
  assert.ok(hits.length >= 1, `应有命中，实际 ${hits.length}`);
  const top = hits[0];
  assert.equal(top.channel, 'r');
  assert.equal(top.bit, 1);
  assert.equal(top.lsbFirst, false);
  assert.equal(top.pixelOrder, 'row');
  assert.ok(top.reasons.includes('flag 格式'), `reasons=${JSON.stringify(top.reasons)}`);
  assert.equal(top.score, 100);
  assert.ok(top.preview.includes('flag{zsteg_scan_hit}'), `preview=${top.preview.slice(0, 40)}`);
  assert.equal(top.byteCount, 256, '64x64 单通道可提取 512 字节，默认窗口截 256');
});

// ---- 用例 2：B 通道 LSB 藏 zlib 头 ----

test('scanBitPlanes B/LSB 藏 78 9C：zlib 魔数命中', () => {
  const prng = makePrng(0x5eed0002);
  const payload = [0x78, 0x9c];
  for (let index = 0; index < 254; index += 1) payload.push(Math.floor(prng() * 256));
  const rgba = makeRgba(SIZE, SIZE, makePrng(0x5eed0003));
  embedBits(rgba, SIZE, SIZE, [2], payload);
  const hits = scanBitPlanes(rgba, SIZE, SIZE);
  const zlibHit = hits.find(hit =>
    hit.channel === 'b' && hit.bit === 1 && !hit.lsbFirst && hit.pixelOrder === 'row');
  assert.ok(zlibHit, `应命中 b/1/msb/row，实际 hits=${JSON.stringify(hits.map(h => `${h.channel}/${h.bit}/${h.pixelOrder}`))}`);
  assert.ok(zlibHit.reasons.includes('zlib/gzip 魔数'));
  assert.equal(zlibHit.score, 100);
  assert.ok(zlibHit.preview.startsWith('x\\x9c'), `preview=${zlibHit.preview.slice(0, 12)}`);
});

// ---- 用例 3：列序藏长可打印文本 ----

test('scanBitPlanes R/LSB 列序藏 256 字节文本：column 组合高可打印命中', () => {
  const secret = repeatTo('column order walks pixels top to bottom before shifting right. ', 256);
  const rgba = makeRgba(SIZE, SIZE, makePrng(0x5eed0004));
  embedBits(rgba, SIZE, SIZE, [0], textBytes(secret), { column: true });
  const hits = scanBitPlanes(rgba, SIZE, SIZE);
  const columnHit = hits.find(hit =>
    hit.channel === 'r' && hit.bit === 1 && hit.pixelOrder === 'column' && !hit.lsbFirst);
  assert.ok(columnHit, `应命中 r/1/msb/column，实际 ${JSON.stringify(hits.map(h => `${h.channel}/${h.pixelOrder}`))}`);
  assert.ok(columnHit.reasons.includes('高可打印率'));
  assert.ok(columnHit.preview.includes('column order walks'), `preview=${columnHit.preview.slice(0, 40)}`);
});

// ---- 用例 4：全随机图无强命中 ----

test('scanBitPlanes 全随机图：无 zlib/flag 强命中', () => {
  for (const seed of [0x5eed0005, 0xfeedbeef, 0xc0ffee42]) {
    const rgba = makeRgba(SIZE, SIZE, makePrng(seed));
    const hits = scanBitPlanes(rgba, SIZE, SIZE);
    for (const hit of hits) {
      assert.ok(!hit.reasons.includes('zlib/gzip 魔数'), `误报 zlib: ${hit.channel}/${hit.bit} seed=${seed}`);
      assert.ok(!hit.reasons.includes('flag 格式'), `误报 flag: ${hit.channel}/${hit.bit} seed=${seed}`);
      assert.ok(hit.score <= 90, `随机图不应出现强命中: ${hit.channel}/${hit.bit} score=${hit.score}`);
    }
  }
});

// ---- 用例 5：rgb 打包序（每像素 r,g,b 连续）藏文本 ----

test('scanBitPlanes rgb 打包序藏文本：rgb 组合命中且 bgr 读不出', () => {
  const secret = repeatTo('rgb packing hides three chars per pixel in a row. ', 256);
  const rgba = makeRgba(SIZE, SIZE, makePrng(0x5eed0006));
  embedBits(rgba, SIZE, SIZE, [0, 1, 2], textBytes(secret));
  const hits = scanBitPlanes(rgba, SIZE, SIZE);
  const rgbHit = hits.find(hit =>
    hit.channel === 'rgb' && hit.bit === 1 && hit.pixelOrder === 'row' && !hit.lsbFirst);
  assert.ok(rgbHit, `应命中 rgb/1/msb/row，实际 ${JSON.stringify(hits.map(h => h.channel))}`);
  assert.ok(rgbHit.reasons.includes('高可打印率'));
  assert.ok(rgbHit.preview.includes('rgb packing hides'), `preview=${rgbHit.preview.slice(0, 40)}`);
  const bgrLeak = hits.find(hit => hit.channel === 'bgr' && hit.preview.includes('rgb packing hides'));
  assert.equal(bgrLeak, undefined, 'bgr 反序读取不应还原出明文');
});

// ---- 用例 6：lsbFirst 字节内位序变体 ----

test('scanBitPlanes R/LSB lsbFirst 位序藏文本：lsbFirst=true 组合命中', () => {
  const secret = repeatTo('lsb first packs bits from b0 within each byte. ', 256);
  const rgba = makeRgba(SIZE, SIZE, makePrng(0x5eed0007));
  embedBits(rgba, SIZE, SIZE, [0], textBytes(secret), { lsbFirst: true });
  const hits = scanBitPlanes(rgba, SIZE, SIZE);
  const lsbHit = hits.find(hit =>
    hit.channel === 'r' && hit.bit === 1 && hit.lsbFirst && hit.pixelOrder === 'row');
  assert.ok(lsbHit, `应命中 r/1/lsb/row，实际 ${JSON.stringify(hits.map(h => `${h.channel}/${h.lsbFirst}`))}`);
  assert.ok(lsbHit.reasons.includes('高可打印率'));
  assert.ok(lsbHit.preview.includes('lsb first packs'), `preview=${lsbHit.preview.slice(0, 40)}`);
});

// ---- 用例 7：与 extractLsbBytes 语义一致性 ----

test('scanBitPlanes 基准组合输出与 extractLsbBytes 语义一致', () => {
  const secret = repeatTo('baseline semantics must stay aligned. ', 256);
  const rgba = makeRgba(SIZE, SIZE, makePrng(0x5eed0008));
  embedBits(rgba, SIZE, SIZE, [0], textBytes(secret));
  const hits = scanBitPlanes(rgba, SIZE, SIZE);
  const baseline = hits.find(hit =>
    hit.channel === 'r' && hit.bit === 1 && !hit.lsbFirst && hit.pixelOrder === 'row');
  assert.ok(baseline);
  const reference = bytesToPreviewText(extractLsbBytes(rgba, { channel: 0, bit: 0, maxBytes: 256 }));
  assert.equal(baseline.preview, reference);
});

// ---- 用例 8：同分排序（通道序 tie-break）与 maxHits 截断、字段域 ----
// 注：flag 正则的通用分支（word{3+}）会对文本位平面的串扰噪声产生同分误报，
// 全局前三名因此不稳定；同分 tie-break 的可判定形式是 r(0) 与 g(1) 之间无通道可插队。

test('scanBitPlanes 同分通道序 tie-break + maxHits 截断 + 字段域校验', () => {
  const secret = 'flag{tie_break_order_check}';
  const rgba = makeRgba(SIZE, SIZE, makePrng(0x5eed0009));
  embedBits(rgba, SIZE, SIZE, [0], textBytes(secret));
  embedBits(rgba, SIZE, SIZE, [1], textBytes(secret));
  const full = scanBitPlanes(rgba, SIZE, SIZE);
  assert.ok(full.length >= 2);
  const channelNames = new Set(['r', 'g', 'b', 'a', 'rgb', 'bgr', 'rgba', 'bgra', 'all']);
  for (const hit of full) {
    assert.ok(channelNames.has(hit.channel), `未知通道名 ${hit.channel}`);
    assert.ok(hit.bit >= 1 && hit.bit <= 8);
    assert.ok(hit.pixelOrder === 'row' || hit.pixelOrder === 'column');
    assert.ok(typeof hit.lsbFirst === 'boolean');
    assert.ok(Array.isArray(hit.reasons) && hit.reasons.length >= 1);
    assert.ok(hit.preview.length > 0);
    assert.ok(hit.byteCount >= 1 && hit.byteCount <= 256);
  }
  for (let index = 1; index < full.length; index += 1) {
    assert.ok(full[index - 1].score >= full[index].score, 'score 应降序');
  }
  const rHit = full.find(hit =>
    hit.channel === 'r' && hit.bit === 1 && !hit.lsbFirst && hit.pixelOrder === 'row');
  const gHit = full.find(hit =>
    hit.channel === 'g' && hit.bit === 1 && !hit.lsbFirst && hit.pixelOrder === 'row');
  assert.ok(rHit && gHit, 'r/g 同藏 flag 文本均应命中');
  assert.equal(rHit.score, 100);
  assert.equal(gHit.score, 100);
  // 同分 100 时按通道序 tie-break：r(0) 必为全局第一，且排在 g(1) 之前
  // （其余 r 变体的通用分支误报同属 rank 0，只可能插在 r 与 g 之间，不影响两条断言）
  assert.ok(full[0] === rHit, `全局第一应为 r，实际 ${full[0].channel}/${full[0].score}`);
  assert.ok(full.indexOf(rHit) < full.indexOf(gHit), '同分时 r 应排在 g 前');
  const capped = scanBitPlanes(rgba, SIZE, SIZE, { maxHits: 1 });
  assert.equal(capped.length, 1);
  assert.equal(capped[0].channel, 'r');
});

// ---- 用例 9：退化输入不崩溃（沙箱数组勿用 deepStrictEqual，见 AGENTS.md 踩坑） ----

test('scanBitPlanes 退化输入：空图/越界尺寸返回空数组不崩溃', () => {
  assert.equal(scanBitPlanes(new Uint8Array(0), 0, 0).length, 0);
  assert.equal(scanBitPlanes(new Uint8Array(16), 2, 2).length, 0);
  assert.equal(scanBitPlanes(new Uint8Array(16), 0, 8).length, 0);
});

// ---- 真题验收：BMP 行序维（BUG#6/打野）与 2-LSB 多位采样（G-3/10_lsb_png） ----
// 解码器为测试内最小实现（24bpp BMP / 非隔行 PNG），与 canvas/canvas 语义一致：产出的
// RGBA 均为 top-down 行序，行序维由 scanBitPlanes 的 rowOrder 组合覆盖。

const decodeBmp24Rgba = bytes => {
  assert.equal(String.fromCharCode(bytes[0], bytes[1]), 'BM', '真题应为 BMP');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const offset = view.getUint32(10, true);
  const width = view.getInt32(18, true);
  const height = view.getInt32(22, true);
  const bitCount = view.getUint16(28, true);
  assert.equal(bitCount, 24, '仅覆盖 24bpp 真题');
  const rows = Math.abs(height);
  const stride = (width * 3 + 3) & ~3;
  const rgba = new Uint8Array(width * rows * 4);
  for (let y = 0; y < rows; y += 1) {
    const srcRow = height < 0 ? y : rows - 1 - y;
    for (let x = 0; x < width; x += 1) {
      const base = offset + srcRow * stride + x * 3;
      const dst = (y * width + x) * 4;
      rgba[dst] = bytes[base + 2];
      rgba[dst + 1] = bytes[base + 1];
      rgba[dst + 2] = bytes[base];
      rgba[dst + 3] = 255;
    }
  }
  return { data: rgba, width, height: rows };
};

const decodePngRgba = bytes => {
  assert.deepEqual([...bytes.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], '真题应为 PNG');
  let pos = 8;
  let width = 0;
  let height = 0;
  let colorType = 0;
  const idat = [];
  let palette = null;
  while (pos + 8 <= bytes.length) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const length = view.getUint32(pos);
    const type = String.fromCharCode(bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7]);
    const data = bytes.subarray(pos + 8, pos + 8 + length);
    if (type === 'IHDR') {
      width = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
      height = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
      colorType = data[9];
    } else if (type === 'IDAT') idat.push(data);
    else if (type === 'PLTE') palette = data;
    else if (type === 'IEND') break;
    pos += 12 + length;
  }
  const channels = { 2: 3, 6: 4, 3: 1 }[colorType];
  const raw = zlib.inflateSync(Buffer.concat(idat.map(d => Buffer.from(d))));
  const stride = width * channels;
  const out = new Uint8Array(stride * height);
  const prev = new Uint8Array(stride);
  let p = 0;
  for (let y = 0; y < height; y += 1) {
    const filter = raw[p];
    p += 1;
    const cur = new Uint8Array(stride);
    for (let x = 0; x < stride; x += 1) cur[x] = raw[p + x];
    p += stride;
    for (let x = 0; x < stride; x += 1) {
      const a = x >= channels ? cur[x - channels] : 0;
      const b = prev[x];
      const c = x >= channels ? prev[x - channels] : 0;
      let value = cur[x];
      if (filter === 1) value = (value + a) & 0xff;
      else if (filter === 2) value = (value + b) & 0xff;
      else if (filter === 3) value = (value + ((a + b) >> 1)) & 0xff;
      else if (filter === 4) {
        const pa = Math.abs(b - c);
        const pb = Math.abs(a - c);
        const pc = Math.abs(a + b - 2 * c);
        value = (value + (pa <= pb && pa <= pc ? a : pb <= pc ? b : c)) & 0xff;
      }
      cur[x] = value;
    }
    out.set(cur, y * stride);
    prev.set(cur);
  }
  const rgba = new Uint8Array(width * height * 4);
  for (let i = 0; i < width * height; i += 1) {
    if (colorType === 6) rgba.set(out.subarray(i * 4, i * 4 + 4), i * 4);
    else if (colorType === 2) {
      rgba[i * 4] = out[i * 3];
      rgba[i * 4 + 1] = out[i * 3 + 1];
      rgba[i * 4 + 2] = out[i * 3 + 2];
      rgba[i * 4 + 3] = 255;
    } else if (colorType === 3) {
      const base = out[i] * 3;
      rgba[i * 4] = palette[base];
      rgba[i * 4 + 1] = palette[base + 1];
      rgba[i * 4 + 2] = palette[base + 2];
      rgba[i * 4 + 3] = 255;
    }
  }
  return { data: rgba, width, height };
};

// 真题附件不入库（tests/real-challenges 在 .gitignore）——缺失时跳过对应测试（干净 checkout 不红）
const realTest = (rel, title, fn) => (fs.existsSync(path.join(projectRoot, 'tests', 'real-challenges', ...rel.split('/'))) ? test : test.skip)(title, fn);

realTest('xctf-misc/21-打野/瞅啥.bmp', '真题 打野/瞅啥.bmp：rowOrder=bottomup 维命中 zsteg 式载荷', () => {
  const bmp = decodeBmp24Rgba(Uint8Array.from(
    fs.readFileSync(path.join(projectRoot, 'tests', 'real-challenges', 'xctf-misc', '21-打野', '瞅啥.bmp')),
  ));
  const hits = scanBitPlanes(bmp.data, bmp.width, bmp.height, { maxHits: 30 });
  const flagHit = hits.find(hit => hit.preview.includes('qwxf{you_say_chick_beautiful?}'));
  assert.ok(flagHit, `bottomup 应命中打野载荷，实际 ${JSON.stringify(hits.slice(0, 3).map(h => `${h.channel}/${h.bit}/${h.rowOrder}`))}`);
  assert.equal(flagHit.rowOrder, 'bottomup');
  assert.equal(flagHit.pixelOrder, 'row');
  assert.equal(flagHit.bitsPerSample, 1);
  assert.ok(flagHit.preview.startsWith('\\x1e\\x00\\x00\\x00'), '载荷前缀 \\x1e\\x00\\x00\\x00 长度头');
});

realTest('10_lsb_png/challenge_infinity_image_final.png', '真题 10_lsb_png：bitsPerSample=2 组合命中 writeup 载荷', () => {
  const png = decodePngRgba(Uint8Array.from(
    fs.readFileSync(path.join(projectRoot, 'tests', 'real-challenges', '10_lsb_png', 'challenge_infinity_image_final.png')),
  ));
  const hits = scanBitPlanes(png.data, png.width, png.height, { maxHits: 30 });
  const pageHit = hits.find(hit => hit.bitsPerSample === 2 && hit.preview.includes('Page 383 of Volume 22'));
  assert.ok(pageHit, `2-LSB 组合应命中 "Page 383…" 载荷，实际 ${JSON.stringify(hits.map(h => `${h.channel}/bps${h.bitsPerSample}`))}`);
  assert.equal(pageHit.channel, 'rgba');
  assert.equal(pageHit.lsbFirst, false, 'writeup 口径为 MSB-first');
  assert.equal(pageHit.rowOrder, 'topdown');
});
