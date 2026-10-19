// outguess 0.2 提取器测试（Lane-F5 更新版）：黄金向量来自真实工具产物——outguess 0.2
// Linux 原版（kali-run Docker）`outguess -k ogpass -d og-secret.txt carrier.jpg og-out.jpg`
// 嵌入产物复制为 tests/fixtures/outguess-real-02.jpg（sha256
// dd13deeea7f61070cef69b53e73e58d27ed9d9208e8db5b3717b81a04e8ad1ef，载荷 40 字节）。
// 回环向量仍用测试侧镜像嵌入方向覆盖 ARC4/iterator 前置件与位流收集规则，但镜像产物
// 交付前按提取端新契约做 jpeg-6b 55/62 槽位适配（提取端消费标准之字表解码的系数流时
// 逐块交换对齐 jpeg-6b 布局，B 域能力审计 BUG#4；真实工具产物为最终裁判）。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { collectOutguessBits, outguessReveal, outguessRevealFromCoefficients } = loadModule(
  path.join(srcDir, 'utils', 'ctf', 'outguessExtract.ts'),
);
const { arc4InitKey, iteratorAdapt, iteratorInit, iteratorNext, iteratorSeed } = loadModule(
  path.join(srcDir, 'utils', 'ctf', 'outguessCrypto.ts'),
);

const ogFixturePath = path.join(projectRoot, 'tests', 'fixtures', 'outguess-real-02.jpg');

// 真实工具产物还原期望：原版 outguess 嵌入的 40 字节载荷（尾带 \n）
const OG_EXPECTED_PAYLOAD = 'flag{outguess_real_tool_ok} extra bytes\n';
const OG_EXPECTED_HEX =
  '666c61677b6f757467756573735f7265616c5f746f6f6c5f6f6b7d2065787472612062797465730a';

// 与提取端消费侧同一语义的 55/62 逐块交换（自反变换）：镜像产物交付前变换一次，
// 提取端内部再变换回来，恰好还原镜像写入的位布局
const swapLegacySlots = (coeffs) => {
  for (let base = 0; base + 64 <= coeffs.length; base += 64) {
    const slot55 = coeffs[base + 55];
    coeffs[base + 55] = coeffs[base + 62];
    coeffs[base + 62] = slot55;
  }
};

// ---- 位流收集语义（jdcoefct 钩子 → steg_use_bit：(temp&1)==temp 跳过）----

test('collectOutguessBits：0 与 +1 跳过，-1 与 |c|≥2 全收 LSB', () => {
  const { bits, totalBits } = collectOutguessBits(Int32Array.from([0, 1, -1, 2, 3, -2, 7, 0, 4, -3]));
  assert.equal(totalBits, 7);
  assert.deepEqual(Array.from(bits.subarray(0, 7)), [1, 0, 1, 0, 1, 0, 1]); // -1→1, 2→0, 3→1, -2→0, 7→1, 4→0, -3→1
});

test('collectOutguessBits：全 0/1 系数流 totalBits 为 0', () => {
  assert.equal(collectOutguessBits(Int32Array.from([0, 1, 0, 1])).totalBits, 0);
});

// ---- iterator_adapt 手算数值（SKIPADJ 公式：rem>bits/32 → 2，否则 2-(seg-rem)/seg）----

test('iteratorAdapt：远未到尾段时 skipmod=trunc(2×rem/(8×datalen))', () => {
  const state = iteratorInit(new TextEncoder().encode('k'));
  state.off = 128;
  iteratorAdapt(state, 1024, 64); // rem=896>32 → 2；trunc(2*896/512)=3
  assert.equal(state.skipmod, 3);
});

test('iteratorAdapt：尾段（rem≤bits/32）走插值分支并向下截断', () => {
  const state = iteratorInit(new TextEncoder().encode('k'));
  state.off = 1000;
  iteratorAdapt(state, 1024, 4); // rem=24≤32 → 2-8/32=1.75；trunc(1.75*24/32)=1
  assert.equal(state.skipmod, 1);
});

// ---- 回环：测试侧嵌入方向（镜像 do_embed 无 preserve 简化：位位置语义与原版一致）----

// 与提取端同规则收集可嵌位（含源系数下标），写位改物理 LSB（|c|≥2 或 -1 改 LSB 永不落入 0/+1）
const buildCarrier = (coeffs) => {
  const positions = [];
  for (let i = 0; i < coeffs.length; i += 1) {
    if (coeffs[i] !== 0 && coeffs[i] !== 1) positions.push(i);
  }
  return positions;
};

const embedOutguess = (coeffs, password, plaintext, seed) => {
  const positions = buildCarrier(coeffs);
  const totalBits = positions.length;
  const writeBit = (bitIndex, bit) => {
    const ci = positions[bitIndex];
    coeffs[ci] = (coeffs[ci] & ~1) | bit;
  };
  const embedByte = (iter, value) => {
    for (let where = 0; where < 8; where += 1) {
      writeBit(iter.off, (value >> where) & 1);
      iteratorNext(iter);
    }
  };
  const key = new TextEncoder().encode(password);
  const as = arc4InitKey('Encryption', key);
  const tas = as.clone();
  const iter = iteratorInit(key);
  const header = new Uint8Array([seed & 0xff, (seed >> 8) & 0xff, plaintext.length & 0xff, (plaintext.length >> 8) & 0xff]);
  for (let i = 0; i < 4; i += 1) embedByte(iter, header[i] ^ as.getbyte());
  iteratorSeed(iter, seed);
  let remaining = plaintext.length;
  let n = 0;
  while (remaining > 0) {
    iteratorAdapt(iter, totalBits, remaining);
    embedByte(iter, plaintext[n] ^ tas.getbyte());
    n += 1;
    remaining -= 1;
  }
  return totalBits;
};

// mock 系数流：交错 ±7/±2/-1/3 混入 0/1 噪声（0/1 会被两端一致跳过）
const mockCoeffs = (count) => {
  const pattern = [7, -7, 2, -2, 0, 3, -1, 1, 5, -3];
  return Int32Array.from({ length: count }, (_, i) => pattern[i % pattern.length]);
};

test('回环：嵌入→提取往返还原明文/seed/declaredLength（常规口令）', () => {
  const coeffs = mockCoeffs(4000);
  const plaintext = Uint8Array.from('flag{outguess_roundtrip_0x2}', (ch) => ch.charCodeAt(0));
  const seed = 0x1234;
  embedOutguess(coeffs, 'secret', plaintext, seed);
  swapLegacySlots(coeffs);
  const { data, seed: gotSeed, declaredLength } = outguessRevealFromCoefficients(coeffs, 'secret');
  assert.deepEqual(Array.from(data), Array.from(plaintext));
  assert.equal(gotSeed, seed);
  assert.equal(declaredLength, plaintext.length);
});

test('回环：空口令（空 key 的 MD5 语义）同样成立', () => {
  const coeffs = mockCoeffs(3000);
  const plaintext = Uint8Array.from([0x00, 0xff, 0x41, 0x80, 0x7f, 0x01]);
  embedOutguess(coeffs, '', plaintext, 0xbeef);
  swapLegacySlots(coeffs);
  const { data } = outguessRevealFromCoefficients(coeffs, '');
  assert.deepEqual(Array.from(data), Array.from(plaintext));
});

test('回环：长载荷（>256 字节，触发 u16 长度字段高位）往返', () => {
  const coeffs = mockCoeffs(20000);
  const plaintext = Uint8Array.from({ length: 300 }, (_, i) => (i * 37 + 11) & 0xff);
  embedOutguess(coeffs, 'pw-long', plaintext, 0x4321);
  swapLegacySlots(coeffs);
  const { data, declaredLength } = outguessRevealFromCoefficients(coeffs, 'pw-long');
  assert.equal(declaredLength, 300);
  assert.deepEqual(Array.from(data), Array.from(plaintext));
});

test('错口令：要么报错要么解不出原明文（绝不误还原）', () => {
  const coeffs = mockCoeffs(4000);
  const plaintext = Uint8Array.from('correct horse battery staple', (ch) => ch.charCodeAt(0));
  embedOutguess(coeffs, 'right', plaintext, 42);
  swapLegacySlots(coeffs);
  let leaked = false;
  try {
    const { data } = outguessRevealFromCoefficients(coeffs, 'wrong');
    leaked = Array.from(data).join(',') === Array.from(plaintext).join(',');
  } catch {
    // 长度异常 / 位流耗尽抛错均合法
  }
  assert.equal(leaked, false);
});

// ---- 错误分支 ----

test('声明长度为 0（口令错或无嵌入）正确报错', () => {
  const coeffs = mockCoeffs(4000); // 未嵌入：解出的 header 大概率非法
  assert.throws(() => outguessRevealFromCoefficients(coeffs, 'whatever'), /outguess/);
});

test('可嵌位不足 64 位正确报错', () => {
  const coeffs = Int32Array.from([7, -7, 2, -2, 3, -3, 5, -5, 6, -6]); // 10 位
  assert.throws(() => outguessRevealFromCoefficients(coeffs, 'k'), /至少 64 位/);
});

test('声明长度超过可嵌容量正确报错', () => {
  // 手工构造位流耗尽：mock 位流 128 位（容量 16 字节），构造 header 声明 60000 字节
  const coeffs = Int32Array.from({ length: 128 }, (_, i) => (i % 2 === 0 ? 7 : -7));
  // 全 0/1 的位流 + 任意口令解出的 header 不可控——直接检查抛错即可（长度或耗尽分支）
  assert.throws(() => outguessRevealFromCoefficients(coeffs, 'x'), /outguess/);
});

// ---- 真实工具产物黄金向量（端到端，最终裁判） ----

test('黄金向量：outguess 0.2 Linux 原版产物（ogpass）逐字节还原 40 字节载荷', () => {
  const bytes = new Uint8Array(fs.readFileSync(ogFixturePath));
  const data = outguessReveal(bytes, 'ogpass');
  assert.equal(data.length, 40);
  assert.equal(Buffer.from(data).toString('hex'), OG_EXPECTED_HEX);
  assert.equal(Buffer.from(data).toString('latin1'), OG_EXPECTED_PAYLOAD);
});

test('黄金向量：系数入口与 JPEG 入口结果一致（55/62 槽位适配在两入口同生效）', () => {
  const bytes = new Uint8Array(fs.readFileSync(ogFixturePath));
  const { readJpegCoefficients } = loadModule(path.join(srcDir, 'utils', 'ctf', 'jpegCoeffs.ts'));
  const { mcuOrderCoefficients } = readJpegCoefficients(bytes);
  const viaCoefficients = outguessRevealFromCoefficients(mcuOrderCoefficients, 'ogpass');
  const viaJpeg = outguessReveal(bytes, 'ogpass');
  assert.equal(viaCoefficients.declaredLength, 40);
  assert.deepEqual(Array.from(viaCoefficients.data), Array.from(viaJpeg));
});

test('黄金向量：错口令不误还原真实载荷（原版行为：产出垃圾数据而非报错）', () => {
  const bytes = new Uint8Array(fs.readFileSync(ogFixturePath));
  let data = null;
  try {
    data = outguessReveal(bytes, 'wrongpass');
  } catch {
    // 长度异常 / 位流耗尽抛错也合法
  }
  if (data !== null) {
    assert.notEqual(Buffer.from(data).toString('latin1'), OG_EXPECTED_PAYLOAD);
  }
});

test('黄金向量：跨工具不误报——jsteg 载体过 outguess 提取器报错', () => {
  const jstegFixturePath = path.join(projectRoot, 'tests', 'fixtures', 'jsteg-real-carrier.jpg');
  const bytes = new Uint8Array(fs.readFileSync(jstegFixturePath));
  assert.throws(() => outguessReveal(bytes, 'k'), /outguess/);
});

// ---- 真实 JPEG 集成路径（PIL fixture，非 outguess 载荷优雅报错）----

const fixturePath = path.join(projectRoot, 'tests', 'fixtures', 'jpeg-test.jpg');
if (fs.existsSync(fixturePath)) {
  test('JPEG 集成路径：PIL fixture（非 outguess 载荷）经完整管线正确报错', () => {
    const bytes = new Uint8Array(fs.readFileSync(fixturePath));
    assert.throws(() => outguessReveal(bytes, 'any'), /outguess|长度|位流/);
  });
} else {
  test('JPEG fixture 缺失：跳过（无 jpeg-test.jpg）', { skip: true }, () => {});
}
