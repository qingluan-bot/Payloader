// GIF 调色板排序隐写 gifshuffle 解码档测试（B3-6）：
// - 256 色=1683 位容量锚点（BigInt 阶乘独立对拍）；
// - 阶乘进制还原手算对拍（n=6、消息 'A' → m=386 的手工样例，模块头部注明推导）；
// - 测试侧独立实现 gifshuffle 编码器（bit 流 LSB 追加 + 阶乘进制出位 + 插入法构造排列），
//   对多条消息构造色表并整只 GIF 解码提取，闭环交叉验证；
// - 重复色剔除 / 空消息 / 加密压缩层提示 / 非 GIF 与唯一色不足护栏。
// gifshuffle 2.0 算法口径出处见 src/utils/ctf/gifShuffle.ts 模块头（Debian encode.c + man page）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { decodeGifShuffle, gifShuffleCapacityBits, permutationNumberFromColorTable, messageFromPermutationNumber } =
  loadModule(path.join(srcDir, 'utils', 'ctf', 'gifShuffle.ts'));

// ---- 测试侧 GIF 造流工厂（单帧 1×1，结构对齐 gifInspect 解析口径）----

const u16 = value => [value & 0xff, (value >> 8) & 0xff];

// LZW 编码器（与 gifInspect 解码宽度记账镜像；单像素流极短，仅 clear+码+eoi）。
const lzwEncode = (indices, minCodeSize) => {
  const clearCode = 1 << minCodeSize;
  const eoiCode = clearCode + 1;
  let codeWidth = minCodeSize + 1;
  let nextCode = eoiCode + 1;
  const dict = new Map();
  const out = [];
  let bitBuffer = 0;
  let bitCount = 0;
  const write = code => {
    bitBuffer |= code << bitCount;
    bitCount += codeWidth;
    while (bitCount >= 8) {
      out.push(bitBuffer & 0xff);
      bitBuffer >>>= 8;
      bitCount -= 8;
    }
  };
  write(clearCode);
  let previous = -1;
  for (const symbol of indices) {
    if (previous < 0) {
      previous = symbol;
      continue;
    }
    const key = previous * 256 + symbol;
    if (dict.has(key)) {
      previous = dict.get(key);
      continue;
    }
    write(previous);
    if (nextCode < 4096) {
      dict.set(key, nextCode);
      nextCode += 1;
      if (nextCode > (1 << codeWidth) && codeWidth < 12) codeWidth += 1;
    }
    previous = symbol;
  }
  if (previous >= 0) write(previous);
  write(eoiCode);
  if (bitCount > 0) out.push(bitBuffer & 0xff);
  return out;
};

// 整只 GIF：header + LSD + 全局色表（补位到 2 的幂，尾部用末色填充）+ 单帧 + Trailer。
const buildGif = paletteRGB => {
  const gctBits = Math.max(1, Math.ceil(Math.log2(Math.max(2, paletteRGB.length / 3))));
  const slots = 1 << gctBits;
  const gct = [...paletteRGB];
  const lastColor = paletteRGB.slice(paletteRGB.length - 3);
  while (gct.length < slots * 3) gct.push(...lastColor); // gifshuffle 补位口径：重复末色
  const pixel = [0];
  const lzw = lzwEncode(pixel, 2);
  const bytes = [];
  for (const char of 'GIF89a') bytes.push(char.charCodeAt(0));
  bytes.push(...u16(1), ...u16(1), 0x80 | (gctBits - 1), 0, 0);
  bytes.push(...gct);
  bytes.push(0x21, 0xf9, 0x04, 0x00, ...u16(0), 0, 0x00); // GCE
  bytes.push(0x2c, ...u16(0), ...u16(0), ...u16(1), ...u16(1), 0x00); // Image Descriptor
  bytes.push(2, lzw.length, ...lzw, 0x00);
  bytes.push(0x3b);
  return Uint8Array.from(bytes);
};

// ---- 测试侧独立 gifshuffle 编码器（权威对照实现）----

// 消息字节 → 位流（每字节 MSB 在前）→ 尾追加哨兵 1 → LSB=首追加位折成大整数。
const permutationNumberFromMessage = (messageBytes, uniqueColors) => {
  const bits = [];
  for (const byte of messageBytes) {
    for (let index = 7; index >= 0; index -= 1) bits.push((byte >> index) & 1);
  }
  bits.push(1); // gifshuffle 哨兵
  let value = 0n;
  for (let index = 0; index < bits.length; index += 1) {
    if (bits[index]) value |= 1n << BigInt(index);
  }
  // 阶乘进制出位：i=1..n，第 i 轮商给 sortedColors[n-i]，插入位置 = value mod i。
  const insertions = [];
  let remaining = value;
  for (let base = 1; base <= uniqueColors; base += 1) {
    insertions.push({ colourIndex: uniqueColors - base, position: Number(remaining % BigInt(base)) });
    remaining /= BigInt(base);
  }
  if (remaining !== 0n) throw new Error(`消息超出 ${uniqueColors} 色容量`);
  // 插入法构造最终槽位排列：slots[slot] = 秩。
  const slots = [];
  for (const { colourIndex, position } of insertions) slots.splice(position, 0, colourIndex);
  return { value, slots };
};

const greyPalette = slots => {
  const palette = [];
  for (const rank of slots) palette.push(rank, rank, rank); // 秩 k → RGB(k,k,k)，字节序=值序
  return palette;
};

// 满足容量的最小唯一色数（用被测模块的容量函数查找，测试侧 BigInt 阶乘复算校验）。
const minimumColorsFor = messageBytes => {
  const neededBits = messageBytes.length * 8 + 1;
  for (let n = 2; n <= 256; n += 1) {
    if (gifShuffleCapacityBits(n) >= neededBits) return n;
  }
  throw new Error('消息过长');
};

// ---- 用例 ----

test('容量锚点：256 唯一色 = 1683 位（BigInt 阶乘独立复算）+ 边界', () => {
  let factorial = 1n;
  for (let index = 2; index <= 256; index += 1) factorial *= BigInt(index);
  const expected = (factorial - 1n).toString(2).length - 1;
  assert.equal(expected, 1683, '独立复算 256!-1 的位长应为 1684，净容量 1683');
  assert.equal(gifShuffleCapacityBits(256), 1683);
  assert.equal(gifShuffleCapacityBits(2), 0);
  assert.equal(gifShuffleCapacityBits(1), 0);
});

test('阶乘进制手算对拍：消息 A(0x41) 6 色 → m=386 → 色表 [c2,c1,c4,c0,c3,c5]', () => {
  // 手算（模块头注明）：位流 01000001 + 哨兵 → m = rev(0x41) + 2^8 = 130 + 256 = 386。
  // 出位：d1=0(m386) d2=0(m193) d3=1(m64) d4=0(m16) d5=1(m3) d6=3(m0)
  // 插入序（i=1..6）：c5@0 c4@0 c3@1 c2@0 c1@1 c0@3 → slots = [2,1,4,0,3,5]。
  const { value, slots } = permutationNumberFromMessage([0x41], 6);
  assert.equal(value, 386n);
  assert.deepEqual(slots, [2, 1, 4, 0, 3, 5]);
  // 模块解码侧还原同一大整数（秩=灰度值序）。
  const palette = new Uint8Array(greyPalette(slots));
  const decoded = permutationNumberFromColorTable(palette);
  assert.equal(decoded.value, 386n);
  assert.equal(decoded.uniqueCount, 6);
});

test('messageFromPermutationNumber：哨兵剥离与 MSB 在前拼字节', () => {
  const { bytes, sentinelBitIndex, remainderBits } = messageFromPermutationNumber(386n);
  assert.equal(sentinelBitIndex, 8);
  assert.equal(remainderBits, 0);
  assert.deepEqual(Array.from(bytes), [0x41]);
  // 非整字节：17 位消息 → 2 字节 + 1 位余。
  const odd = messageFromPermutationNumber((1n << 17n) | 0b11n);
  assert.equal(odd.sentinelBitIndex, 17);
  assert.equal(odd.remainderBits, 1);
  // 空：m=0 / 仅哨兵 m=1 都产出空消息。
  assert.equal(messageFromPermutationNumber(0n).bytes.length, 0);
  assert.equal(messageFromPermutationNumber(1n).bytes.length, 0);
});

test('解码档交叉验证：独立编码器构造 9 色表，GIF 整链提取 "Hi"', () => {
  const message = 'Hi';
  const n = minimumColorsFor(Buffer.from(message, 'latin1'));
  assert.equal(n, 9, '2 字节 + 哨兵 17 位 → 9! 是最小容纳阶乘');
  const { slots } = permutationNumberFromMessage(Buffer.from(message, 'latin1'), n);
  const gif = buildGif(greyPalette(slots));
  const result = decodeGifShuffle(gif);
  assert.equal(result.text, message);
  assert.equal(result.uniqueColors, n);
  assert.equal(result.printableRatio, 1);
  assert.deepEqual(Array.from(result.bytes), Array.from(Buffer.from(message, 'latin1')));
});

test('解码档交叉验证：多消息多色数闭环（含 6 色手算样例整链）', () => {
  const cases = [
    { message: 'A', colors: 6 },
    { message: 'flag{gifshuffle_palette_order}', colors: null }, // 自动取最小色数
    { message: 'zh-CN 中文消息', colors: null },
  ];
  for (const { message, colors } of cases) {
    const messageBytes = Buffer.from(message, 'utf8');
    const n = colors ?? minimumColorsFor(messageBytes);
    const { slots } = permutationNumberFromMessage(messageBytes, n);
    const result = decodeGifShuffle(buildGif(greyPalette(slots)));
    assert.equal(result.text, message, `message=${message}`);
    assert.equal(result.uniqueColors, n);
  }
});

test('空消息与普通 GIF：m=1 仅哨兵 / 自然序色表 m=0，均提示未嵌入', () => {
  const emptyOnly = permutationNumberFromMessage([], 4);
  assert.equal(emptyOnly.value, 1n);
  const emptyResult = decodeGifShuffle(buildGif(greyPalette(emptyOnly.slots)));
  assert.equal(emptyResult.text, '');
  assert.ok(emptyResult.notes.some(note => note.includes('未嵌入消息')), `notes=${JSON.stringify(emptyResult.notes)}`);

  // 自然序色表（秩=槽位）：解码 m=0 → 普通 GIF 无隐写。
  const plainResult = decodeGifShuffle(buildGif(greyPalette([0, 1, 2, 3])));
  assert.equal(plainResult.permutationNumber, '0');
  assert.ok(plainResult.notes.some(note => note.includes('未嵌入消息')));
});

test('重复色剔除：8 槽色表 6 唯一色，容量按唯一色计', () => {
  const slots = [2, 1, 4, 0, 3, 5];
  const palette = greyPalette(slots);
  palette.push(...greyPalette([5])); // 追加 1 个重复槽（秩 5 重复出现）→ 7 槽
  const build8 = [...palette, ...greyPalette([5])]; // 再补 1 槽凑 8（GIF 幂长由 buildGif 兜底）
  const result = decodeGifShuffle(buildGif(build8));
  assert.equal(result.uniqueColors, 6, '重复色不计数');
  assert.equal(result.text, 'A');
});

test('加密/压缩层提示：字节不可打印 → 明确提示当前不支持', () => {
  const slots = permutationNumberFromMessage([0xff], 6).slots; // 单字节 0xFF 高熵噪声形态
  const result = decodeGifShuffle(buildGif(greyPalette(slots)));
  assert.equal(result.printableRatio, 0);
  assert.ok(result.notes.some(note => note.includes('加密/压缩层') && note.includes('不支持')), `notes=${JSON.stringify(result.notes)}`);
});

test('护栏：非 GIF 与唯一色不足抛中文错误', () => {
  assert.throws(() => decodeGifShuffle(Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0])), /不是 GIF/);
  // 两槽同色 → 唯一色 1 → 无存储空间。
  assert.throws(() => decodeGifShuffle(buildGif(greyPalette([0, 0]))), /唯一色/);
});
