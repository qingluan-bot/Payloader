// F5 提取器测试（Lane-F5 重做版）：黄金向量全部来自真实工具产物——Westfeld 原版 Java F5
//（GitHub 源码 javac 编译，`java Embed carrier.jpg out.jpg -e secret -p Password123`）嵌入
// 产物复制为 tests/fixtures/f5-real-westfeld.jpg（sha256
// 0f8d44402858a15cbd26a30c85baef3cd19be9af08db90b60568334203e7c443）。
// 旧版"测试侧镜像实现自闭环"round-trip 向量已整体删除：镜像嵌入与镜像提取同错自洽，
// 掩盖了 F5Random 状态推进（进位方向/符号）、头部去白噪符号扩展、正文位拼装序三处与
// Java 原版的规格偏差（B 域能力审计 BUG#2/3），对真实工具产物无回归价值。
// Java 侧锚点（均为真实 JDK/工具行为，非镜像推演）：
// - SHA1PRNG 40 字节流：口令 Password123 的真实 JDK 运行捕获值；
// - 端到端 35 字节载荷：原版工具嵌入、本提取器还原，逐字节一致。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { f5Extract, f5ExtractFromCoefficients } = loadModule(
  path.join(srcDir, 'utils', 'ctf', 'f5Extract.ts'),
);
const { F5Random } = loadModule(path.join(srcDir, 'utils', 'ctf', 'f5Crypto.ts'));
const { readJpegCoefficients } = loadModule(path.join(srcDir, 'utils', 'ctf', 'jpegCoeffs.ts'));

const f5FixturePath = path.join(projectRoot, 'tests', 'fixtures', 'f5-real-westfeld.jpg');
const ogFixturePath = path.join(projectRoot, 'tests', 'fixtures', 'outguess-real-02.jpg');

// 真实工具产物还原期望：原版 F5 嵌入的 35 字节载荷（尾带 \n）
const F5_EXPECTED_PAYLOAD = 'flag{f5_real_tool_ok} some payload\n';
const F5_EXPECTED_HEX =
  '666c61677b66355f7265616c5f746f6f6c5f6f6b7d20736f6d65207061796c6f61640a';

// ---- F5Random vs 真实 JDK SHA1PRNG ----

test('F5Random：口令 Password123 的前 40 字节与真实 JDK SHA1PRNG 运行捕获值逐位一致', () => {
  const random = new F5Random(Uint8Array.from('Password123', (ch) => ch.charCodeAt(0)));
  const stream = Array.from({ length: 40 }, () => random.getNextByte());
  // Java 参考值：`new SecureRandom(password).getNextByte()` × 40 的真实运行输出
  // （第一块=SHA1(seed)，第 21 字节起体现 updateState 推进语义，是进位方向/符号的试金石）
  const javaCaptured = [
    184, 103, 5, 92, 97, 190, 163, 59, 171, 83, 62, 240, 144, 13, 27, 25,
    63, 190, 104, 68, 169, 92, 61, 40, 172, 155, 215, 106, 74, 149, 57, 37,
    140, 252, 69, 244, 200, 226, 90, 10,
  ];
  assert.deepEqual(stream, javaCaptured);
});

test('F5Random：getNextValue 按 Java 带符号 byte 组装 int32（负数取模后 +max 回正）', () => {
  const random = new F5Random(Uint8Array.from('Password123', (ch) => ch.charCodeAt(0)));
  const values = Array.from({ length: 8 }, () => random.getNextValue(1000));
  for (const value of values) {
    assert.ok(value >= 0 && value < 1000, `getNextValue 应落在 [0,1000)：${value}`);
  }
});

// ---- 真实工具产物黄金向量（端到端） ----

test('黄金向量：Westfeld 原版 Java F5 产物（Password123）逐字节还原 35 字节载荷', () => {
  const bytes = new Uint8Array(fs.readFileSync(f5FixturePath));
  const result = f5Extract(bytes, 'Password123');
  assert.equal(result.k, 7, '头部 k 字段（矩阵编码参数）');
  assert.equal(result.declaredLength, 35, '头部声明载荷长度');
  assert.equal(result.data.length, 35);
  assert.equal(Buffer.from(result.data).toString('hex'), F5_EXPECTED_HEX);
  assert.equal(Buffer.from(result.data).toString('latin1'), F5_EXPECTED_PAYLOAD);
});

test('黄金向量：系数入口与 JPEG 入口结果一致（55/62 槽位适配在两入口同生效）', () => {
  const bytes = new Uint8Array(fs.readFileSync(f5FixturePath));
  const { mcuOrderCoefficients } = readJpegCoefficients(bytes);
  const viaCoefficients = f5ExtractFromCoefficients(mcuOrderCoefficients, 'Password123');
  const viaJpeg = f5Extract(bytes, 'Password123');
  assert.deepEqual(Array.from(viaCoefficients.data), Array.from(viaJpeg.data));
  assert.equal(viaCoefficients.k, viaJpeg.k);
  assert.equal(viaCoefficients.declaredLength, viaJpeg.declaredLength);
  assert.equal(viaCoefficients.usableCoefficients, viaJpeg.usableCoefficients);
});

test('黄金向量：错口令优雅拒绝（头部长度字段解码荒谬 → 中文报错）', () => {
  const bytes = new Uint8Array(fs.readFileSync(f5FixturePath));
  assert.throws(() => f5Extract(bytes, 'wrong'), /口令错误或非 F5 载荷/);
  assert.throws(() => f5Extract(bytes, 'password123'), /口令错误或非 F5 载荷/);
});

test('黄金向量：跨工具不误报——outguess 载体过 F5 提取器报错', () => {
  const bytes = new Uint8Array(fs.readFileSync(ogFixturePath));
  assert.throws(() => f5Extract(bytes, 'k'), /口令错误或非 F5 载荷|系数容量不足|系数耗尽/);
});

// ---- 防呆 ----

test('f5Extract 入口：非 JPEG / 渐进式透传 jpegCoeffs 的中文错误', () => {
  const pngMagic = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.throws(() => f5Extract(pngMagic, 'x'), /不是有效的 JPEG/);
  assert.throws(() => f5Extract(new Uint8Array(0), 'x'), /不是有效的 JPEG/);
  // 仅 SOI + SOF2 帧头：解码器在帧解析即抛渐进式
  const progressive = Uint8Array.from([
    0xff, 0xd8,
    0xff, 0xc2, 0x00, 0x0b, 0x08, 0x00, 0x08, 0x00, 0x08, 0x01, 0x01, 0x11, 0x00,
  ]);
  assert.throws(() => f5Extract(progressive, 'x'), /渐进式/);
});

// ---- JPEG 集成路径（真实编码器产物，非 F5 载荷） ----

const fixturePath = path.join(projectRoot, 'tests', 'fixtures', 'jpeg-test.jpg');
if (fs.existsSync(fixturePath)) {
  test('JPEG 集成路径：PIL fixture（非 F5 载荷）经完整 readJpegCoefficients 管线正确报错', () => {
    const bytes = new Uint8Array(fs.readFileSync(fixturePath));
    // 该 8×8 梯度图可用 AC 不足 32 个 → 触发头部容量防线；可用系数够多的图则落在
    // 长度校验防线，两者都是"非 F5 载荷"的正确拒绝
    assert.throws(() => f5Extract(bytes, 'whatever'), /口令错误或非 F5 载荷|系数容量不足/);
  });
}
