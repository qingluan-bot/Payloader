// codec bases 域回归测试（A 域审计修复批次）：BUG-06 二进制解码 latin1 无损、BUG-10 base64
// 字符集门控、BUG-11 奇长 hex 报错、BUG-15 Base45 报错文案与 RFC 9285 官方向量。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const B = loadModule(path.join(srcDir, 'utils', 'codec', 'bases.ts'));

const latin1Buffer = text => Buffer.from(text, 'latin1');

// ---- BUG-06：Z85/Ascii85/Base91/Base62 二进制解码 latin1 无损 ----

test('BUG-06 Z85 spec 向量：HelloWorld → 864FD26FB559F75B（含 ≥0x80 字节无损）', () => {
  const decoded = B.decodeZ85('HelloWorld');
  assert.ok(latin1Buffer(decoded).equals(Buffer.from([0x86, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b])));
});

test('BUG-06 Ascii85/Base91/Base62：UTF-8 多字节载荷解码不再被 utf8 替换损毁', () => {
  for (const [name, encode, decode] of [
    ['ascii85', B.encodeAscii85, B.decodeAscii85],
    ['base91', B.encodeBase91, B.decodeBase91],
    ['base62', B.encodeBase62, B.decodeBase62],
  ]) {
    const encoded = encode('€uro×48');
    const decoded = decode(encoded);
    assert.ok(typeof encoded === 'string' && encoded.length > 0);
    assert.ok(latin1Buffer(decoded).equals(Buffer.from('€uro×48', 'utf8')), `${name} 解码应逐字节无损，实际 ${JSON.stringify(decoded)}`);
  }
});

// ---- BUG-10：base64ToBytes 前置 100% 字符集校验 ----

test('BUG-10 base64 非法字符报错（与浏览器 atob 行为一致），不再静默跳过', () => {
  assert.throws(() => B.base64ToBytes('ab@c$$'), /Base64 含非法字符/);
  assert.throws(() => B.base64ToBytes('QUJD=R Rem=='), /Base64/);
});

test('BUG-10 合法 base64 / 无填充 / URL-safe 全部不受影响', () => {
  assert.equal(Buffer.from(B.base64ToBytes('aGVsbG8=')).toString(), 'hello');
  assert.equal(Buffer.from(B.base64ToBytes('aGVsbG8')).toString(), 'hello');
  assert.equal(Buffer.from(B.base64ToBytes('aGVsbG8_')).toString(), 'hello?');
  assert.equal(Buffer.from(B.base64ToBytes('aGVs bG8\n')).toString(), 'hello');
  assert.equal(B.base64ToBytes('').length, 0);
  assert.equal(Buffer.from(B.base64ToBytes('aGVsbG8=')).toString(), 'hello');
});

// ---- BUG-11：bytesFromTextOrHex 奇数长度形似 hex 报错 ----

test('BUG-11 形似 hex（≥8 位纯 hex）但长度为奇数：报错而非静默按 UTF-8 编码', () => {
  assert.throws(() => B.bytesFromTextOrHex('deadbeefcaf'), /长度为奇数/);
  assert.throws(() => B.bytesFromTextOrHex('123456789'), /长度为奇数/);
});

test('BUG-11 正常路径不回归：偶长 hex / 短串 / 普通文本 / 带分隔 hex', () => {
  assert.equal(Buffer.from(B.bytesFromTextOrHex('deadbeef')).toString('hex'), 'deadbeef');
  assert.equal(Buffer.from(B.bytesFromTextOrHex('de:ad-be_ef')).toString('hex'), 'deadbeef');
  assert.equal(Buffer.from(B.bytesFromTextOrHex('hello')).toString(), 'hello');
  assert.equal(Buffer.from(B.bytesFromTextOrHex('abc')).toString(), 'abc');
});

// ---- BUG-15：Base45 报错文案 + RFC 9285 官方向量 ----

test('BUG-15 Base45 RFC 9285 官方向量形态："Hello, World!" → "%69 VDK2E:3404ESVDX0"（含空格字符）', () => {
  // 空格是 Base45 字母表第 36 个合法字符：编码输出含空格且解码必须原样还原
  assert.equal(B.encodeBase45('Hello, World!'), '%69 VDK2E:3404ESVDX0');
  assert.equal(B.decodeBase45('%69 VDK2E:3404ESVDX0'), 'Hello, World!');
});

test('BUG-15 报错文案完整（不再截断"超出范"）且奇数尾部显式报错', () => {
  // 三字符块：0 + 0*45 + 33*2025 = 66825 > 0xFFFF → 越界
  assert.throws(() => B.decodeBase45('00X'), /Base45 数据块超出范围/);
  // 4 字符 = 3+1：末尾剩 1 个字符 → 长度非法
  assert.throws(() => B.decodeBase45('%69V'), /长度非法/);
  assert.throws(() => B.decodeBase45('%6#'), /非法字符/);
});
