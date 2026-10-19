// codec crypto 域回归测试（A 域审计修复批次）：P1-2 二进制明文 hex 回退、BUG-03 ciphertext(base64)
// 标签识别、BUG-05/16 TEA/XTEA 无填充回退与 pkcs7Unpad 块长参数化。
// 加载统一走 tests/helpers/compileTsModule.mjs；向量用 FIPS-197/独立参考实现，不用引擎自身造。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const C = loadModule(path.join(srcDir, 'utils', 'codec', 'crypto.ts'));
const T = loadModule(path.join(srcDir, 'utils', 'codec', 'transform.ts'));

const TEA_KEY_HEX = '0123456789abcdeffedcba9876543210';

// 独立 TEA 参考实现（标准 32 轮，big-endian 字对），不依赖被测代码
const teaRefEncryptBlock = (v0, v1, keyWords) => {
  let sum = 0 >>> 0;
  let left = v0 >>> 0;
  let right = v1 >>> 0;
  const delta = 0x9e3779b9;
  for (let round = 0; round < 32; round += 1) {
    sum = (sum + delta) >>> 0;
    left = (left + ((((right << 4) + keyWords[0]) ^ (right + sum)) ^ ((right >>> 5) + keyWords[1]))) >>> 0;
    right = (right + ((((left << 4) + keyWords[2]) ^ (left + sum)) ^ ((left >>> 5) + keyWords[3]))) >>> 0;
  }
  return [left, right];
};
const wordsToHex = pairs => Buffer.concat(pairs.map(([l, r]) => Buffer.from([
  (l >>> 24) & 255, (l >>> 16) & 255, (l >>> 8) & 255, l & 255,
  (r >>> 24) & 255, (r >>> 16) & 255, (r >>> 8) & 255, r & 255,
]))).toString('hex');
const keyWords = [0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210];

// ---- P1-2：bytesToUtf8OrHexJson 的 fatal TextDecoder ----

test('P1-2 AES-ECB FIPS-197 C.1 向量：二进制明文输出 plaintextHex JSON 而非 mojibake', async () => {
  // FIPS-197 附录 C.1：key=000102...0f，明文=00112233445566778899aabbccddeeff（含非法 UTF-8 字节）
  const output = await T.transform('aes-ecb', 'decode', '69c4e0d86a7b0430d8cdb78070b4c55a', { secret: '000102030405060708090a0b0c0d0e0f', variant: 'hex' });
  assert.ok(output.includes('plaintextHex'), `应输出 plaintextHex JSON，实际: ${JSON.stringify(output.slice(0, 60))}`);
  assert.equal(JSON.parse(output).plaintextHex, '00112233445566778899aabbccddeeff');
  assert.ok(!/\uFFFD/.test(output), '不应出现 U+FFFD mojibake');
});

test('P1-2 正常文本解密不回归（hex 回退只在非法 UTF-8 时触发）', async () => {
  const encrypted = await T.transform('aes-ecb', 'encode', 'hello aes world!!', { secret: '0123456789abcdef0123456789abcdef', variant: '' });
  const decrypted = await T.transform('aes-ecb', 'decode', encrypted, { secret: '0123456789abcdef0123456789abcdef', variant: '' });
  assert.ok(decrypted.includes('hello aes world!!'));
});

// ---- BUG-03：ciphertext(base64) 标签识别（C10 整段粘贴一键路径） ----

test('BUG-03 C10 整段粘贴：ciphertext(base64)= 标签被识别，prose 一键解出 flag', async () => {
  const prose = 'key = 0123456789abcdef0123456789abcdef\niv = fedcba9876543210\nciphertext(base64) = KLDoF/7zZXGYUnkNJ2eYLZbxEkH1nCQeEcZpCdMt+Rs=';
  const output = await T.transform('aes-cbc-raw', 'decode', prose, {});
  assert.ok(String(output).includes('flag{aes_raw_key_iv_ok}'), `C10 prose 路径应命中 flag，实际: ${String(output).slice(0, 80)}`);
});

test('BUG-03 别名变体：ciphertext-b64 / ciphertext(b64) 同样识别', () => {
  const fields = C.parseSymmetricFields('ciphertext-b64 = aGVsbG8=');
  assert.equal(fields.ciphertext, 'aGVsbG8=');
  const fields2 = C.parseSymmetricFields('ciphertext(b64) = aGVsbG8=');
  assert.equal(fields2.ciphertext, 'aGVsbG8=');
});

// ---- BUG-05：TEA/XTEA 解码 PKCS#7 失败回退原文并附注 ----

test('BUG-05 TEA 零填充密文：不再抛错，回退原样输出并附注', async () => {
  const params = { secret: TEA_KEY_HEX };
  const zeroPadded = Buffer.concat([Buffer.from('TEA!', 'utf8'), Buffer.alloc(4, 0)]);
  const [l, r] = teaRefEncryptBlock(zeroPadded.readUInt32BE(0), zeroPadded.readUInt32BE(4), keyWords);
  const cipherHex = wordsToHex([[l, r]]);
  const decoded = await T.transform('tea', 'decode', cipherHex, params);
  assert.ok(decoded.includes('TEA!'), `应含原始明文: ${JSON.stringify(decoded.slice(0, 60))}`);
  assert.ok(decoded.includes('PKCS#7 padding 校验失败'), '应附无填充回退注记');
});

test('BUG-05 TEA 正常 PKCS#7 round-trip 不回归（独立参考实现对拍）', async () => {
  const params = { secret: TEA_KEY_HEX };
  const plain = 'teATEST!';
  const encrypted = await T.transform('tea', 'encode', plain, params);
  // 参考实现：PKCS#7 整块填充（8 字节 0x08）
  const padded = Buffer.concat([Buffer.from(plain, 'utf8'), Buffer.alloc(8, 8)]);
  const [l1, r1] = teaRefEncryptBlock(padded.readUInt32BE(0), padded.readUInt32BE(4), keyWords);
  const [l2, r2] = teaRefEncryptBlock(padded.readUInt32BE(8), padded.readUInt32BE(12), keyWords);
  assert.equal(encrypted.toLowerCase(), wordsToHex([[l1, r1], [l2, r2]]));
  const decrypted = await T.transform('tea', 'decode', encrypted, params);
  assert.equal(decrypted, plain);
});

// ---- BUG-16：pkcs7Unpad blockSize 参数化 ----

test('BUG-16 pkcs7Unpad：16 字节块（AES 合法填充 pad=16）可解，默认 8 不变', () => {
  const block16 = new Uint8Array(32).fill(16);
  const unpadded = C.pkcs7Unpad(block16, 16);
  assert.equal(unpadded.length, 16);
  // 默认 blockSize 仍为 8：pad=16 越界抛错（TEA 系语义不变）
  assert.throws(() => C.pkcs7Unpad(block16), /PKCS#7 padding 不合法/);
  // 非法填充依旧拒绝
  assert.throws(() => C.pkcs7Unpad(new Uint8Array([1, 2, 3, 9]), 8), /PKCS#7 padding 不合法/);
  const ok8 = C.pkcs7Unpad(new Uint8Array([0x61, 3, 3, 3]));
  assert.equal(ok8.length, 1);
});
