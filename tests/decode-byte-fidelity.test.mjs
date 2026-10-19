// 解码出口字节保真测试（B4-3 审计批次）：非 UTF-8 字节经解码出口必须以 \xNN 转义完整
// 呈现（不再静默替换 U+FFFD 丢字节）+ 附原始字节 hex；合法 UTF-8 纯文本输出逐字节不变。
// 权威向量：PNG 魔数 89 50 4E 47 0D 0A 1A 0A + 非法 UTF-8 尾 8A FF 80（0x8A 是断头多字节
// 引导符、FF 永非法、80 是孤悬续字节——三类非法形态齐备）；文本向量用引擎编码侧往返自证。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const B = loadModule(path.join(srcDir, 'utils', 'codec', 'bases.ts'));
const C = loadModule(path.join(srcDir, 'utils', 'codec', 'crypto.ts'));
const T = loadModule(path.join(srcDir, 'utils', 'codec', 'transform.ts'));

// PNG 魔数 8 字节 + 0x8A 0xFF 0x80（全部不可按 UTF-8 解码的字节形态）
const PNG_BYTES = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x8a, 0xff, 0x80]);
const PNG_HEX = Array.from(PNG_BYTES, byte => byte.toString(16).padStart(2, '0')).join('');
// 期望的保真呈现：≥0x80 字节 \xNN 转义，0x00-0x7F（含 \r\n \x1a 控制符）保持字面
const PNG_FIDELITY_PREFIX = '\\x89PNG\r\n\x1a\n\\x8a\\xff\\x80';
// PNG 魔数前 8 字节的保真呈现（TEA 单块用）
const PNG8_FIDELITY = '\\x89PNG\r\n\x1a\n';
const extractEscapedBytes = text => Array.from(text.matchAll(/\\x([0-9a-f]{2})/g), match => Number.parseInt(match[1], 16));
const assertFidelityShape = (text, label) => {
  assert.ok(!text.includes('\uFFFD'), `${label} 不应出现 U+FFFD`);
  assert.ok(text.startsWith(PNG_FIDELITY_PREFIX), `${label} 应以 \\xNN 保真形态开头，实际 ${JSON.stringify(text.slice(0, 40))}`);
  assert.ok(text.includes(`原始字节 hex: ${PNG_HEX}`), `${label} 文末应附原始字节 hex`);
};

// ---- 统一保真出口（bases.ts） ----

test('bytesToFidelityText：合法 UTF-8 逐字节不变（binary=false），非法走 \\xNN（binary=true）', () => {
  const text = '中文 flag{ok} ✓';
  const plain = B.bytesToFidelityText(new TextEncoder().encode(text));
  assert.equal(plain.text, text);
  assert.equal(plain.binary, false);
  const binary = B.bytesToFidelityText(PNG_BYTES);
  assert.equal(binary.text, PNG_FIDELITY_PREFIX);
  assert.equal(binary.binary, true);
});

test('decodeBytesToFidelityText：\\xNN 转义分支文末附原始 hex；反斜杠自转义可被 hexToBytes 还原', () => {
  const out = B.decodeBytesToFidelityText(PNG_BYTES);
  assertFidelityShape(out, 'decodeBytesToFidelityText');
  // 提取全部 \xNN token 还原字节：转义呈现的字节可原样复制给 hex 下一层
  assert.deepEqual(
    Buffer.from(B.hexToBytes(extractEscapedBytes(out).map(byte => byte.toString(16).padStart(2, '0')).join(''))),
    Buffer.from([0x89, 0x8a, 0xff, 0x80]),
  );
  // 页脚 hex 行还原全量字节
  assert.deepEqual(Buffer.from(B.hexToBytes(PNG_HEX)), Buffer.from(PNG_BYTES));
});

test('BOM 语义（ignoreBOM 核查）：前导 EF BB BF 以 U+FEFF 保留，不再被默认 TextDecoder 静默剥离', () => {
  const bomPrefixed = new Uint8Array([0xef, 0xbb, 0xbf, 0x68, 0x69]);
  assert.equal(B.decodeBytesToFidelityText(bomPrefixed), '\uFEFFhi');
});

test('控制字符边界：纯文本里的换行/制表保持字面（不转义），合法 UTF-8 不触发页脚', () => {
  assert.equal(B.decodeBytesToFidelityText(new TextEncoder().encode('a\nb\tc')), 'a\nb\tc');
});

// ---- base 家族 decode 出口：二进制载荷保真 ----

test('hex 解码出口（transform）：PNG 魔数 \\x89PNG 呈现 + 原始 hex 附行，零 U+FFFD', async () => {
  const out = await T.transform('hex', 'decode', PNG_HEX, {});
  assertFidelityShape(out, 'hex decode');
});

test('base64/base64url 解码出口（transform）：\\xNN 保真；共享层 base64ToText 保持 legacy（探针隔离）', async () => {
  const b64 = B.bytesToBase64(PNG_BYTES);
  assertFidelityShape(await T.transform('base64', 'decode', b64, {}), 'transform base64');
  assertFidelityShape(await T.transform('base64url', 'decode', B.base64ToBase64Url(b64), {}), 'transform base64url');
  // 探针隔离契约：smart-decode/magic-chain 直接消费共享文本函数，其候选剪枝依赖
  // "垃圾载荷得低分"语义——共享层必须保持 legacy 形态（U+FFFD），不得掺入保真附注。
  assert.ok(B.base64ToText(b64).includes('\uFFFD'), '共享层 base64ToText 应保持 legacy U+FFFD 形态');
  assert.ok(!B.base64ToText(b64).includes('\\x'), '共享层不得出现保真转义');
});

// ---- 独立参考编码器（构造二进制输入，不依赖引擎编码侧） ----

const refBase32 = bytes => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0; let bitLength = 0; let output = '';
  for (const byte of bytes) {
    bits = (bits << 8) | byte; bitLength += 8;
    while (bitLength >= 5) { output += alphabet[(bits >>> (bitLength - 5)) & 31]; bitLength -= 5; }
  }
  if (bitLength > 0) output += alphabet[(bits << (5 - bitLength)) & 31];
  return output.padEnd(Math.ceil(output.length / 8) * 8, '=');
};
const refBase32Hex = bytes => {
  const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
  let bits = 0; let bitLength = 0; let output = '';
  for (const byte of bytes) {
    bits = (bits << 8) | byte; bitLength += 8;
    while (bitLength >= 5) { output += alphabet[(bits >>> (bitLength - 5)) & 31]; bitLength -= 5; }
  }
  if (bitLength > 0) output += alphabet[(bits << (5 - bitLength)) & 31];
  return output;
};
const refZBase32 = bytes => {
  const alphabet = 'ybndrfg8ejkmcpqxot1uwisza345h769';
  let acc = 0; let bits = 0; let output = '';
  for (const byte of bytes) {
    acc = ((acc << 8) | byte) & 0xffff; bits += 8;
    while (bits >= 5) { output += alphabet[(acc >>> (bits - 5)) & 0x1f]; bits -= 5; }
  }
  if (bits > 0) output += alphabet[(acc << (5 - bits)) & 0x1f];
  return output;
};
const refBase45 = bytes => {
  const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
  let output = '';
  for (let index = 0; index < bytes.length; index += 2) {
    if (index + 1 < bytes.length) {
      let n = bytes[index] * 256 + bytes[index + 1];
      output += alphabet[n % 45]; n = Math.floor(n / 45);
      output += alphabet[n % 45]; n = Math.floor(n / 45);
      output += alphabet[n % 45];
    } else {
      let n = bytes[index];
      output += alphabet[n % 45]; n = Math.floor(n / 45);
      output += alphabet[n % 45];
    }
  }
  return output;
};
const refBase36 = bytes => {
  let n = 0n;
  for (const byte of bytes) n = (n << 8n) + BigInt(byte);
  return n.toString(36).toUpperCase();
};

test('Base32/Base32hex/Base45/Base36/Base58/z-base-32 解码出口（transform）：二进制载荷 \\xNN 保真（独立参考编码器构造输入）', async () => {
  assertFidelityShape(await T.transform('base32', 'decode', refBase32(PNG_BYTES), {}), 'base32');
  assertFidelityShape(await T.transform('base32', 'decode', refBase32Hex(PNG_BYTES), { variant: 'hex' }), 'base32hex 变体走同一出口');
  assertFidelityShape(await T.transform('base45', 'decode', refBase45(PNG_BYTES), {}), 'base45');
  assertFidelityShape(await T.transform('base36', 'decode', refBase36(PNG_BYTES), {}), 'base36');
  assertFidelityShape(await T.transform('base58', 'decode', B.encodeBase58Bytes(PNG_BYTES), {}), 'base58');
  assertFidelityShape(await T.transform('z-base-32', 'decode', refZBase32(PNG_BYTES), {}), 'z-base-32');
});

test('base64ToBytes 字节层对照：出口修复不触碰字节层（全程无损）', () => {
  assert.equal(Array.from(B.base64ToBytes(B.bytesToBase64(PNG_BYTES)), b => b.toString(16).padStart(2, '0')).join(''), PNG_HEX);
});

// ---- 纯文本零回归：全家族 round-trip 逐字节不变 ----

test('纯文本 round-trip：utf8 保真族全出口合法 UTF-8 输出逐字节不变、无页脚污染', () => {
  const text = '中文 flag{utf8_ok} ✓';
  const bytes = new TextEncoder().encode(text);
  assert.equal(B.base64ToText(B.textToBase64(text)), text);
  assert.equal(B.decodeBase32(B.encodeBase32(text)), text);
  assert.equal(B.decodeBase45(B.encodeBase45(text)), text);
  assert.equal(B.decodeBase58(B.encodeBase58(text)), text);
  assert.equal(B.decodeZBase32(B.encodeZBase32(text)), text);
  assert.equal(B.decodeBase32768(B.encodeBase32768(text)), text);
  assert.equal(B.decodeBase36(refBase36(bytes)), text, 'Base36 数值路径文本不变');
  assert.equal(B.hexToBytes(Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')).length, bytes.length);
});

test('纯文本 round-trip：latin1 直通族（BUG-06 口径）按字节比较不回归', () => {
  const text = '中文 flag{ok} ✓';
  const utf8Bytes = Buffer.from(text, 'utf8');
  const asLatin1Buffer = decoded => Buffer.from(decoded, 'latin1');
  assert.ok(asLatin1Buffer(B.decodeBase62(B.encodeBase62(text))).equals(utf8Bytes));
  assert.ok(asLatin1Buffer(B.decodeBase91(B.encodeBase91(text))).equals(utf8Bytes));
  assert.ok(asLatin1Buffer(B.decodeAscii85(B.encodeAscii85(text))).equals(utf8Bytes));
  assert.ok(asLatin1Buffer(B.decodeZ85(B.encodeZ85('abcd1234'))).equals(Buffer.from('abcd1234', 'utf8')), 'Z85 文本路径（长度 4 的倍数）');
  assert.ok(asLatin1Buffer(B.decodeUuencode(B.encodeUuencode(text, 'a.txt'))).equals(utf8Bytes));
  assert.ok(asLatin1Buffer(B.decodeXxencode(B.encodeXxencode(text))).equals(utf8Bytes));
});

// ---- JSON 报告出口（达标口径锚点）：hex 伴生字段不回归 ----

test('decodeBase58Check / decodeBech32：JSON 报告字段带 hex 伴生（达标口径锚定）', async () => {
  const encoded = await B.encodeBase58Check('deadbeef', '80');
  const check = JSON.parse(await B.decodeBase58Check(encoded));
  assert.equal(check.payloadHex, 'deadbeef');
  const bech32 = JSON.parse(B.decodeBech32(B.encodeBech32('deadbeef', 'bc', 'bech32')));
  assert.equal(bech32.dataHex, 'deadbeef');
});

// ---- 流密码 / 分组密码解密出口 ----

test('xor 解码出口（transform）：PNG 魔数密文解出 \\x89PNG 保真形态', async () => {
  const cipherHex = Array.from(PNG_BYTES, byte => (byte ^ 0x41).toString(16).padStart(2, '0')).join('');
  const out = await T.transform('xor', 'decode', cipherHex, { secret: 'A' });
  assertFidelityShape(out, 'xor decode');
});

test('rc4 解码出口：先提取密钥流，再验证 PNG 魔数解出保真形态（密钥流独立自证）', () => {
  // 全零明文编码即得原始密钥流（RC4 = 明文 XOR 密钥流）
  const keystream = Buffer.from(C.rc4Transform('\x00'.repeat(PNG_BYTES.length), 'k', false), 'hex');
  const cipher = Buffer.from(Array.from(PNG_BYTES, (byte, index) => byte ^ keystream[index]));
  const out = C.rc4Transform(cipher.toString('hex'), 'k', true);
  assertFidelityShape(out, 'rc4 decode');
});

test('rc4 文本路径零回归：加密文本解密回原文（无页脚）', () => {
  const cipher = C.rc4Transform('flag{rc4_ok}', 'secret', false);
  assert.equal(C.rc4Transform(cipher, 'secret', true), 'flag{rc4_ok}');
});

test('TEA 解码出口：PKCS#7 校验失败的无填充回退走 \\xNN 保真 + 附注', () => {
  // 用导出的 TEA 原语把 PNG 魔数前 8 字节加密成单块密文；明文末字节 0x0A=10 > 块长 8，
  // 解密侧 padding 校验必不合法 → 无填充回退 → 保真呈现原始明文块
  const key = C.blockCipherKeyWords('0123456789abcdef');
  const [left, right] = C.readUint32Pair(PNG_BYTES.slice(0, 8), 0);
  const [cipherLeft, cipherRight] = C.teaBlock(left, right, key, false);
  const block = new Uint8Array(8);
  C.writeUint32Pair(block, 0, cipherLeft, cipherRight);
  const out = C.teaTransform(B.bytesToHex(block), '0123456789abcdef', true);
  assert.ok(out.startsWith(PNG8_FIDELITY), `应保真呈现原始块，实际 ${JSON.stringify(out.slice(0, 40))}`);
  assert.ok(out.includes('PKCS#7 padding 校验失败'), '应保留无填充附注');
  assert.ok(!out.includes('\uFFFD'), '不应出现 U+FFFD');
});

test('XXTEA 解码出口：二进制负载经内部原语造密文后保真解出', () => {
  const key = C.blockCipherKeyWords('0123456789abcdef');
  const words = C.bytesToUint32Words(PNG_BYTES, true);
  const cipherHex = B.bytesToHex(C.uint32WordsToBytes(C.xxteaWords(words, key), false));
  const out = C.xxteaTransform(cipherHex, '0123456789abcdef', true);
  assertFidelityShape(out, 'xxtea decode');
});

test('XXTEA 文本路径零回归：round-trip 逐字节不变', () => {
  const cipher = C.xxteaTransform('flag{xxtea_ok}', '0123456789abcdef', false);
  assert.equal(C.xxteaTransform(cipher, '0123456789abcdef', true), 'flag{xxtea_ok}');
});

test('OpenSSL AES-256-CBC 解密出口：JSON 里 plaintext 字段 \\xNN 保真、plaintextHex 伴生不变', async () => {
  const salt = new Uint8Array([0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11]);
  const derived = C.opensslEvpBytesToKey('pw', salt);
  const key = await C.importOpenSslAesCbcKey(derived.key, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: B.bytesToBuffer(derived.iv) },
    key,
    B.bytesToBuffer(PNG_BYTES),
  ));
  const blob = new Uint8Array([...C.opensslMagic, ...salt, ...ciphertext]);
  const report = JSON.parse(await C.openSslAes256CbcTransform('decode', B.bytesToBase64(blob), 'pw'));
  assert.equal(report.plaintextHex, PNG_HEX, 'plaintextHex 伴生字段不变');
  assert.equal(report.plaintext, PNG_FIDELITY_PREFIX, 'plaintext 字段应为 \\xNN 保真文本');
  assert.ok(!report.plaintext.includes('\uFFFD'), '不应出现 U+FFFD');
});

test('bytesToUtf8OrHexJson 达标口径锚定：非法 UTF-8 落 plaintextHex JSON（P1-2 形态不变）', () => {
  const report = JSON.parse(C.bytesToUtf8OrHexJson(PNG_BYTES));
  assert.equal(report.plaintextHex, PNG_HEX);
  assert.ok(report.note.includes('不是有效 UTF-8'));
  const text = C.bytesToUtf8OrHexJson(new TextEncoder().encode('plain'));
  assert.equal(text, 'plain');
});
