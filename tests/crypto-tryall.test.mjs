// 密钥+密文组合枚举尝试器测试（Lane B）。
// 对拍锚点均为独立权威来源（规范原文向量，非"自己写自己验"）：
// - NIST SP 800-38A 附录 F 的 AES-128 五模式向量（key 2b7e151628aed2a6abf7158809cf4f3c）；
// - FIPS 81 的 DES ECB 向量（key 0123456789abcdef，"Now is t" → 3fa40e8a984d4815）；
// - Wikipedia RC4 向量（key="Key"，plaintext="Plaintext" → BBF316E8D940AF0AD3），
//   并与 crypto-js 的 RC4 独立实现互检（双实现对拍）。
// 注意：沙箱模块返回的数组不得 deepStrictEqual（vm realm 原型差异，AGENTS.md 踩坑记录）。
import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const T = loadModule(path.join(projectRoot, 'src', 'utils', 'codec', 'cryptoTryAll.ts'));
const {
  bytesToHex, hexToBytes, base64ToBytes, parseCipherBytes,
  rc4Crypt, xorRepeatCrypt, scorePlaintextBytes,
  tryAllCryptoDecryptions, cryptoTryAllSolve,
} = T;

// 测试侧独立 AES 封口（用 noble 原语构造密文；tryAll 内部同源但组合路径不同）
const { cbc, ctr, ecb } = await import('@noble/ciphers/aes.js');
const cryptoJs = (await import('crypto-js')).default;

const hex = '2b7e151628aed2a6abf7158809cf4f3c'; // SP 800-38A AES-128 key
const iv = '000102030405060708090a0b0c0d0e0f';
const ctrIv = 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';
const pt1 = '6bc1bee22e409f96e93d7e117393172a';
// SP 800-38A F.1/F.2/F.3/F.4/F.5 的首块密文（与明文 pt1 对应）
const ct1 = {
  ECB: '3ad77bb40d7a3660a89ecaf32466ef97',
  CBC: '7649abac8119b246cee98e9b12e9197d',
  CFB: '3b3fd92eb72dad20333449f8e83cfb4a', // CFB128 首块
  OFB: '3b3fd92eb72dad20333449f8e83cfb4a', // OFB 首块（与 CFB 首块相同）
  CTR: '874d6191b620e3261bef6864990db6ce',
};
const pt4 = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710';

const findHit = (report, algorithm, mode, keyEncoding) =>
  report.hits.find(h => h.algorithm === algorithm && h.mode === mode && h.keyEncoding === keyEncoding) || null;

// ---- 字节/编码工具 ----

test('hex/base64 编解码与密文形态识别', () => {
  assert.equal(bytesToHex(hexToBytes('0x01:02-03')), '010203');
  assert.equal(bytesToHex(base64ToBytes('AQID')), '010203');
  const parsed = parseCipherBytes('AQID'); // base64
  assert.equal(parsed.format, 'base64');
  assert.equal(bytesToHex(parsed.bytes), '010203');
  const parsedHex = parseCipherBytes('de ad be ef');
  assert.equal(parsedHex.format, 'hex');
  assert.equal(bytesToHex(parsedHex.bytes), 'deadbeef');
  assert.throws(() => parseCipherBytes(''), /密文不能为空/);
  assert.throws(() => parseCipherBytes('!!'), /既不是合法 hex/);
});

// ---- RC4 自写实现：权威向量 + crypto-js 独立实现互检 ----

test('RC4：Wikipedia 权威向量与 crypto-js 双实现对拍', async () => {
  // 向量 1（RFC 6229/Wikipedia 名向量）：key="Key" pt="Plaintext" → BBF316E8D940AF0AD3
  const out = rc4Crypt(
    new TextEncoder().encode('Key'),
    new TextEncoder().encode('Plaintext'),
  );
  assert.equal(bytesToHex(out), 'bbf316e8d940af0ad3');
  // 向量 2：key="Wiki" pt="pedia" → 1021BF0420
  assert.equal(
    bytesToHex(rc4Crypt(new TextEncoder().encode('Wiki'), new TextEncoder().encode('pedia'))),
    '1021bf0420',
  );
  // 与 crypto-js 的独立 RC4 实现互检（200 字节伪随机流；crypto-js 算法是 Cipher 对象，走 .encrypt）
  const key = new TextEncoder().encode('lane-b-cross-check');
  const data = new Uint8Array(200).map((_, i) => i & 0xff);
  const mine = bytesToHex(rc4Crypt(key, data));
  const theirs = cryptoJs.RC4.encrypt(cryptoJs.lib.WordArray.create(data), cryptoJs.enc.Hex.parse(bytesToHex(key)))
    .ciphertext.toString(cryptoJs.enc.Hex);
  assert.equal(mine, theirs.toLowerCase());
  assert.throws(() => rc4Crypt(new Uint8Array(0), data), /密钥不能为空/);
});

test('XOR 重复密钥：自反性与手算', () => {
  const data = new TextEncoder().encode('flag{xor}');
  const key = new TextEncoder().encode('k3y');
  const enc = xorRepeatCrypt(key, data);
  assert.equal(bytesToHex(xorRepeatCrypt(key, enc)), bytesToHex(data));
  // 手算：'a'(0x61) ^ 0xff = 0x9e
  assert.equal(bytesToHex(xorRepeatCrypt(new Uint8Array([0xff]), new Uint8Array([0x61]))), '9e');
});

// ---- 打分函数 ----

test('打分：printableRatio − entropy/16、crib 加权、U+FFFD 判零', () => {
  const ascii = new TextEncoder().encode('flag{readable_text_here}');
  const base = scorePlaintextBytes(ascii, []);
  assert.ok(base.printableRatio === 1);
  assert.ok(base.score > 0.5);
  const withCrib = scorePlaintextBytes(ascii, ['flag{']);
  assert.deepEqual(withCrib.cribHits, ['flag{']);
  assert.ok(withCrib.score === base.score + 0.5);
  const noise = scorePlaintextBytes(new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x10, 0x7f, 0x80, 0xfe, 0xff, 0x55]), []);
  assert.ok(noise.score < base.score, '随机噪声得分应低于可读文本');
  // U+FFFD 占比 > 10% 判 0 分
  const replacement = scorePlaintextBytes(new Uint8Array([0xff, 0xfe, 0xff, 0xfe, 0x41, 0x42]), []);
  assert.ok(replacement.replacementRatio > 0.1);
  assert.equal(replacement.score, 0);
  assert.equal(scorePlaintextBytes(new Uint8Array(0), ['x']).score, 0);
});

// ---- 组合枚举：SP 800-38A 五模式权威向量 ----

test('AES-128 五模式（SP 800-38A）：枚举命中 (aes, mode, hex)', async () => {
  // 每个模式用其官方密文 + 对应 IV/counter（单块裸向量，ECB/CBC 走 disablePadding 回退）
  for (const mode of ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']) {
    const modeIv = mode === 'CTR' ? ctrIv : iv;
    const report = await tryAllCryptoDecryptions(ct1[mode], hex, modeIv, {
      algorithms: ['aes'], modes: [mode], timeBudgetMs: 10000,
    });
    const hit = findHit(report, 'aes', mode, 'hex');
    assert.ok(hit, `缺少 (aes, ${mode}, hex) 命中`);
    assert.equal(hit.plaintextHex, pt1, `aes-${mode} 明文不符`);
  }
});

test('AES-128 四块多模式向量（noble 构造、无填充）逐字节命中', async () => {
  // 单块官方向量已锚定五种模式的正确性；此处用 4 块无填充密文覆盖多块长度路径
  const plainBytes = hexToBytes(pt4);
  const ivBytes = hexToBytes(iv);
  const keyBytes = hexToBytes(hex);
  const cases = [
    ['ECB', ecb(keyBytes, { disablePadding: true }).encrypt(plainBytes), null],
    ['CBC', cbc(keyBytes, ivBytes, { disablePadding: true }).encrypt(plainBytes), ivBytes],
    ['CTR', ctr(keyBytes, hexToBytes(ctrIv)).encrypt(plainBytes), hexToBytes(ctrIv)],
  ];
  for (const [mode, cipherBytes, modeIv] of cases) {
    const report = await tryAllCryptoDecryptions(bytesToHex(cipherBytes), hex, modeIv ? bytesToHex(modeIv) : '', {
      algorithms: ['aes'], modes: [mode], timeBudgetMs: 10000,
    });
    const hit = findHit(report, 'aes', mode, 'hex');
    assert.ok(hit, `缺少 (aes, ${mode}, hex) 命中`);
    assert.equal(hit.plaintextHex, pt4, `aes-${mode} 四块明文不符`);
  }
});

test('自造 AES-CBC(key hex + iv hex) 密文：枚举命中并解出原文', async () => {
  const plaintext = new TextEncoder().encode('payloader-lane-b says hello');
  const key = hexToBytes('00112233445566778899aabbccddeeff');
  const ivBytes = hexToBytes('0102030405060708090a0b0c0d0e0f10');
  const cipherBytes = cbc(key, ivBytes).encrypt(plaintext);
  const report = await tryAllCryptoDecryptions(bytesToHex(cipherBytes), bytesToHex(key), bytesToHex(ivBytes), {
    cribs: ['lane-b'],
  });
  const hit = findHit(report, 'aes', 'CBC', 'hex');
  assert.ok(hit, '缺少 (aes, CBC, hex) 命中');
  assert.equal(hit.plaintext, new TextDecoder().decode(plaintext));
  // crib 命中的组合应置顶
  assert.equal(report.hits[0].cribHits.includes('lane-b'), true);
  assert.equal(report.hits[0].score, hit.score);
});

test('MD5 派生密钥与 UTF-8 密钥命中（AES-ECB）', async () => {
  // md5("password") 由模块内 @noble/hashes 派生（测试侧用 crypto-js MD5 独立复核）
  const expectedMd5KeyHex = cryptoJs.MD5('password').toString(cryptoJs.enc.Hex);
  const plaintext = new TextEncoder().encode('md5-derived key hit!');
  const keyBytes = hexToBytes(expectedMd5KeyHex); // 16 字节 AES-128
  const cipherBytes = ecb(keyBytes).encrypt(plaintext);
  const report = await tryAllCryptoDecryptions(bytesToHex(cipherBytes), 'password', '', {
    algorithms: ['aes'], modes: ['ECB'], keyEncodings: ['md5', 'utf8'], timeBudgetMs: 10000,
  });
  const md5Hit = findHit(report, 'aes', 'ECB', 'md5');
  assert.ok(md5Hit, '缺少 md5 派生密钥命中');
  assert.equal(md5Hit.plaintext, new TextDecoder().decode(plaintext));
  assert.equal(md5Hit.ivEncoding, 'none');
  // utf8 编码 "password" 是 8 字节，不是合法 AES 密钥长度 → 不应有 utf8 命中
  assert.equal(findHit(report, 'aes', 'ECB', 'utf8'), null);
});

test('DES/3DES：FIPS 81 锚点与 PKCS7 组合命中', async () => {
  // FIPS 81 原语正确性锚点：crypto-js DES-ECB-NoPadding("Now is t") = 3fa40e8a984d4815
  const key = '0123456789abcdef';
  const rawBlock = cryptoJs.DES.encrypt(
    cryptoJs.enc.Hex.parse('4e6f772069732074'),
    cryptoJs.enc.Hex.parse(key),
    { mode: cryptoJs.mode.ECB, padding: cryptoJs.pad.NoPadding },
  ).ciphertext.toString(cryptoJs.enc.Hex);
  assert.equal(rawBlock, '3fa40e8a984d4815');
  // 组合枚举：PKCS7 加密密文 → (des, ECB, hex) 命中
  const padded = cryptoJs.DES.encrypt(
    cryptoJs.enc.Utf8.parse('DES lane hit'),
    cryptoJs.enc.Hex.parse(key),
    { mode: cryptoJs.mode.ECB, padding: cryptoJs.pad.Pkcs7 },
  ).ciphertext.toString(cryptoJs.enc.Hex);
  const report = await tryAllCryptoDecryptions(padded, key, '', { algorithms: ['des', '3des'] });
  const hit = findHit(report, 'des', 'ECB', 'hex');
  assert.ok(hit, '缺少 (des, ECB, hex) 命中');
  assert.ok(hit.plaintext.startsWith('DES lane hit'), `DES 明文异常：${hit.plaintext}`);
  // 3DES 16 字节 key（md5 派生即 16 字节）
  const tdesKey = cryptoJs.MD5('triple').toString(cryptoJs.enc.Hex);
  const tdesCipher = cryptoJs.TripleDES.encrypt(
    cryptoJs.enc.Utf8.parse('3des works too'),
    cryptoJs.enc.Hex.parse(tdesKey),
    { mode: cryptoJs.mode.ECB, padding: cryptoJs.pad.Pkcs7 },
  ).ciphertext.toString(cryptoJs.enc.Hex);
  const tdesReport = await tryAllCryptoDecryptions(tdesCipher, tdesKey, '', { algorithms: ['3des'] });
  const tdesHit = findHit(tdesReport, '3des', 'ECB', 'hex');
  assert.ok(tdesHit, '缺少 (3des, ECB, hex) 命中');
  assert.ok(tdesHit.plaintext.startsWith('3des works too'));
});

test('RC4/XOR 组合命中与零 IV 约定（AES-CBC 无 IV → zeros）', async () => {
  const rc4Key = new TextEncoder().encode('rc4secret');
  const rc4Data = new TextEncoder().encode('arcfour stream hit');
  const rc4Cipher = rc4Crypt(rc4Key, rc4Data);
  const rc4Report = await tryAllCryptoDecryptions(bytesToHex(rc4Cipher), 'rc4secret', '', { algorithms: ['rc4'] });
  const rc4Hit = findHit(rc4Report, 'rc4', 'stream', 'utf8');
  assert.ok(rc4Hit, '缺少 (rc4, stream, utf8) 命中');
  assert.equal(rc4Hit.plaintext, 'arcfour stream hit');

  const xorKey = new TextEncoder().encode('XKEY');
  const xorCipher = xorRepeatCrypt(xorKey, new TextEncoder().encode('xor hit here'));
  const xorReport = await tryAllCryptoDecryptions(bytesToHex(xorCipher), 'XKEY', '', { algorithms: ['xor'] });
  const xorHit = findHit(xorReport, 'xor', 'stream', 'utf8');
  assert.ok(xorHit, '缺少 (xor, stream, utf8) 命中');
  assert.equal(xorHit.plaintext, 'xor hit here');

  // AES-CBC 未给 IV：全零 IV 命中，ivEncoding = 'zeros'
  const zeroIv = new Uint8Array(16);
  const key = hexToBytes('00112233445566778899aabbccddeeff');
  const cipher = cbc(key, zeroIv).encrypt(new TextEncoder().encode('zero-iv convention'));
  const zeroReport = await tryAllCryptoDecryptions(bytesToHex(cipher), bytesToHex(key), '', { algorithms: ['aes'], modes: ['CBC'] });
  const zeroHit = findHit(zeroReport, 'aes', 'CBC', 'hex');
  assert.ok(zeroHit, '缺少零 IV 命中');
  assert.equal(zeroHit.ivEncoding, 'zeros');
  assert.equal(zeroHit.plaintext, 'zero-iv convention');
});

// ---- 护栏 ----

test('护栏：组合数上限与时间预算超限报错', async () => {
  // key "0123456789abcdef"（utf8/hex/md5 均为 16 字节）× 5 算法 × 5 模式 ≈ 88+ 组合
  await assert.rejects(
    () => tryAllCryptoDecryptions(pt1, '0123456789abcdef', iv, { maxCombos: 10 }),
    /超过上限 10/,
  );
  await assert.rejects(
    () => tryAllCryptoDecryptions(pt1, '0123456789abcdef', iv, { timeBudgetMs: 0 }),
    /时间预算/,
  );
  await assert.rejects(() => tryAllCryptoDecryptions(pt1, ''), /密钥不能为空/);
  // 密钥长度与算法不匹配 → 组合数为 0
  await assert.rejects(
    () => tryAllCryptoDecryptions(pt1, 'short', '', { algorithms: ['des'], keyEncodings: ['utf8'] }),
    /没有可尝试的组合/,
  );
});

// ---- 文本入口 ----

test('cryptoTryAllSolve 文本入口：key= 字段与 crib= 字段', async () => {
  const key = hexToBytes('00112233445566778899aabbccddeeff');
  const cipher = cbc(key, hexToBytes('0102030405060708090a0b0c0d0e0f10'))
    .encrypt(new TextEncoder().encode('flag{solver_wins} with padding'));
  const text = `cipher=${bytesToHex(cipher)}\nkey=00112233445566778899aabbccddeeff\niv=0102030405060708090a0b0c0d0e0f10\ncribs=flag{`;
  const parsed = JSON.parse(await cryptoTryAllSolve(text));
  assert.ok(Array.isArray(parsed.hits) && parsed.hits.length > 0);
  assert.equal(parsed.hits[0].cribHits.includes('flag{'), true);
  assert.ok(parsed.combosTried > 0);
  // 密文整段直填 + secret 参数传 key（改用 ECB 密文：无 IV 字段也能恢复）
  const ecbCipher = ecb(hexToBytes('00112233445566778899aabbccddeeff'))
    .encrypt(new TextEncoder().encode('flag{solver_wins} with padding'));
  const report2 = JSON.parse(await cryptoTryAllSolve(bytesToHex(ecbCipher), '00112233445566778899aabbccddeeff'));
  assert.ok(report2.hits.some(h => h.algorithm === 'aes' && h.plaintext.startsWith('flag{solver_wins}')));
  await assert.rejects(() => cryptoTryAllSolve('zzzz'), /需要 key=/);
});
