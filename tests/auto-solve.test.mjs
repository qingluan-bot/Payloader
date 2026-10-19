// 自动破译引擎测试：XOR 重叠密钥（xortool 思路）/ Vigenère（IC + 卡方）/ 单表替换（爬山）。
// 全部测试向量程序化构造（无外部 fixture），加载统一走 tests/helpers/compileTsModule.mjs。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const {
  xorAutoSolve,
  vigenereAutoSolve,
  substitutionAutoSolve,
  ENGLISH_LETTER_FREQUENCIES,
  COMMON_BIGRAM_WEIGHTS,
  ENGLISH_FREQUENCY_ORDER,
} = loadModule(path.join(srcDir, 'utils', 'codec', 'autoSolve.ts'));

// ---- 测试工厂 ----

const xorEncrypt = (plain, keyText) => {
  const plainBytes = Buffer.from(plain, 'latin1');
  const key = Buffer.from(keyText, 'latin1');
  return new Uint8Array(Array.from(plainBytes, (byte, index) => byte ^ key[index % key.length]));
};

const vigenereEncrypt = (plain, keyText) => {
  const key = keyText.toUpperCase().replace(/[^A-Z]/g, '');
  let keyIndex = 0;
  return Array.from(plain).map(char => {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base === null) return char;
    const shift = key.charCodeAt(keyIndex % key.length) - 65;
    keyIndex += 1;
    return String.fromCharCode(base + ((code - base + shift) % 26));
  }).join('');
};

const makePrng = seed => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
};

const shuffledAlphabet = seed => {
  const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
  const prng = makePrng(seed);
  for (let index = letters.length - 1; index > 0; index -= 1) {
    const swap = (prng() * (index + 1)) | 0;
    [letters[index], letters[swap]] = [letters[swap], letters[index]];
  }
  return letters.join('');
};

const substitutionEncrypt = (plain, alphabet) => Array.from(plain).map(char => {
  const upper = char.toUpperCase();
  const index = upper.charCodeAt(0) - 65;
  if (index < 0 || index > 25) return char;
  const mapped = alphabet[index];
  return char === upper ? mapped : mapped.toLowerCase();
}).join('');

const letterAccuracy = (actual, expected) => {
  const actualLetters = Array.from(actual.toLowerCase()).filter(char => char >= 'a' && char <= 'z');
  const expectedLetters = Array.from(expected.toLowerCase()).filter(char => char >= 'a' && char <= 'z');
  assert.equal(actualLetters.length, expectedLetters.length);
  const matches = actualLetters.filter((char, index) => char === expectedLetters[index]).length;
  return matches / expectedLetters.length;
};

// ---- 频率表常量 ----

test('内置英文频率表常量可用', () => {
  const frequencySum = Object.values(ENGLISH_LETTER_FREQUENCIES).reduce((left, right) => left + right, 0);
  assert.ok(Math.abs(frequencySum - 1) < 0.02);
  assert.equal(Object.keys(ENGLISH_LETTER_FREQUENCIES).length, 26);
  assert.equal(COMMON_BIGRAM_WEIGHTS.length, 20);
  for (const [bigram] of COMMON_BIGRAM_WEIGHTS) assert.match(bigram, /^[a-z]{2}$/);
  assert.equal(new Set(ENGLISH_FREQUENCY_ORDER).size, 26);
});

// ---- XOR：长文本重合指数定位密钥长度 ----

test('xorAutoSolve 长英文文本：命中 9 字节密钥 SecretKey 并恢复明文', () => {
  const plain = 'The quick brown fox jumps over the lazy dog. '.repeat(3);
  const cipher = xorEncrypt(plain, 'SecretKey');
  const result = xorAutoSolve(cipher);
  assert.equal(result.keyLen, 9);
  assert.equal(result.keyText, 'SecretKey');
  assert.ok(result.plaintext.startsWith('The quick brown fox '), `前 20 字符不符: ${JSON.stringify(result.plaintext.slice(0, 20))}`);
  assert.ok(result.plaintext === plain, '明文应完整恢复');
  assert.ok(result.confidence >= 0.7, `confidence=${result.confidence}`);
  // keyLenScore 覆盖 1..32 且正确长度的重合指数显著高于错误邻位
  assert.equal(result.keyLenScore.length, 32);
  const scoreOf = len => result.keyLenScore.find(item => item.len === len).score;
  assert.ok(scoreOf(9) > scoreOf(8), `len9=${scoreOf(9)} 应高于 len8=${scoreOf(8)}`);
  assert.ok(scoreOf(9) > scoreOf(10), `len9=${scoreOf(9)} 应高于 len10=${scoreOf(10)}`);
});

// ---- XOR：短密文 + knownHint 直推密钥 ----

test('xorAutoSolve 短密文：knownHint flag{ 辅助命中 3 字节密钥 abc', () => {
  const plain = 'flag{xortool_style_ok}';
  const cipher = xorEncrypt(plain, 'abc');
  const result = xorAutoSolve(cipher, { knownHint: 'flag{' });
  assert.equal(result.keyLen, 3);
  assert.equal(result.keyText, 'abc');
  assert.equal(result.plaintext, plain);
  assert.equal(result.hintVerified, true);
  assert.ok(result.confidence >= 0.5, `confidence=${result.confidence}`);
});

// ---- XOR：失败路径（过短输入不崩溃、低置信度） ----

test('xorAutoSolve 过短密文：低置信度返回且不崩溃', () => {
  const result = xorAutoSolve(new Uint8Array([0x11, 0x27, 0x5c, 0x93, 0xe6, 0x3a]));
  assert.ok(result.confidence <= 0.4, `confidence=${result.confidence}`);
  assert.equal(result.plaintext.length, 6);
  assert.ok(Array.isArray(result.keyLenScore));
  assert.equal(result.hintVerified, false);
  const empty = xorAutoSolve(new Uint8Array(0));
  assert.equal(empty.confidence, 0);
  assert.equal(empty.plaintext, '');
});

// ---- Vigenère：≥120 字母英文 + 密钥 crypto ----

const VIGENERE_PLAIN = 'cryptographers build and study methods that keep messages safe from eavesdroppers '
  + 'and tampering. classical systems relied on secret keys shared in advance, while modern designs '
  + 'rest on hard mathematical problems and careful implementations';

test('vigenereAutoSolve：IC+卡方命中密钥 CRYPTO，明文恢复不低于 95%', () => {
  const cipher = vigenereEncrypt(VIGENERE_PLAIN, 'crypto');
  const result = vigenereAutoSolve(cipher);
  assert.equal(result.key, 'CRYPTO');
  assert.equal(result.keyLen, 6);
  const accuracy = letterAccuracy(result.plaintext, VIGENERE_PLAIN);
  assert.ok(accuracy >= 0.95, `letters accuracy=${accuracy}`);
  assert.ok(result.confidence >= 0.7, `confidence=${result.confidence}`);
  // 非字母原样保留
  assert.equal(result.plaintext.length, cipher.length);
  assert.ok(result.plaintext.includes(' '));
});

// ---- Vigenère：失败路径 ----

test('vigenereAutoSolve 过短输入：低置信度返回且不崩溃', () => {
  const result = vigenereAutoSolve('xqz jk');
  assert.ok(result.confidence < 0.4, `confidence=${result.confidence}`);
  assert.equal(typeof result.key, 'string');
  assert.ok(result.keyLen >= 1);
  assert.equal(result.plaintext.length, 'xqz jk'.length);
  const noLetters = vigenereAutoSolve('123 !?');
  assert.equal(noLetters.confidence, 0);
});

// ---- P1-1（审计 BUG-01）：短凯撒/ROT13 不再被多列过拟合击败 ----
// 四向量独立构造（局部 shift 函数，不用引擎自身 encode）；112 字母英文 ≈ 审计报告的短文本场景。

const caesarShift = (text, k) => Array.from(text).map(char => {
  const code = char.charCodeAt(0);
  if (code >= 97 && code <= 122) return String.fromCharCode((code - 97 + k) % 26 + 97);
  if (code >= 65 && code <= 90) return String.fromCharCode((code - 65 + k) % 26 + 65);
  return char;
}).join('');

const CAESAR_SHORT = 'The history of cryptography begins thousands of years ago. Julius Caesar used a simple shift to protect military messages during wars.';

test('P1-1 短凯撒四向量（112 字母 × shift 3/7/13/25）：主候选命中单字母真解且高置信', () => {
  for (const k of [3, 7, 13, 25]) {
    const result = vigenereAutoSolve(caesarShift(CAESAR_SHORT, k));
    const expected = String.fromCharCode(65 + k);
    assert.equal(result.key, expected, `shift ${k} 应命中 key=${expected}，实际 key=${result.key}(${result.keyLen})`);
    assert.equal(result.keyLen, 1);
    assert.ok(result.confidence >= 0.7, `shift ${k} confidence=${result.confidence}`);
    assert.ok(result.plaintext.startsWith('The history'), `明文应还原，实际: ${JSON.stringify(result.plaintext.slice(0, 24))}`);
  }
});

test('P1-1 候选列表透明：返回 candidates 且主候选首位、key 各不相同', () => {
  const result = vigenereAutoSolve(caesarShift(CAESAR_SHORT, 3));
  assert.ok(Array.isArray(result.candidates) && result.candidates.length >= 2);
  assert.equal(result.candidates[0].key, result.key);
  const keys = new Set(result.candidates.map(item => item.key));
  assert.equal(keys.size, result.candidates.length);
  for (const item of result.candidates) {
    assert.ok(typeof item.key === 'string' && item.keyLen >= 1);
    assert.equal(item.plaintext.length, caesarShift(CAESAR_SHORT, 3).length);
  }
});

test('P1-1 长文本回归：300 字母 × keyLen 1/3/6/9/17（含因子族）全部命中', () => {
  const plain = ('cryptographers build and study methods that keep messages safe from eavesdroppers '
    + 'and tampering. classical systems relied on secret keys shared in advance, while modern '
    + 'designs rest on hard mathematical problems and careful implementations. ').repeat(3);
  for (const keyText of ['A', 'KEY', 'CRYPTO', 'XORSECRET', 'LONGERVIGENEREKEY']) {
    const result = vigenereAutoSolve(vigenereEncrypt(plain.slice(0, 340), keyText));
    assert.equal(result.key, keyText.toUpperCase(), `key=${keyText} 应命中，实际 ${result.key}(${result.keyLen})`);
  }
});

// ---- GAP-1/BUG-07：knownPlaintext crib ----

test('P1-1 crib knownPlaintext：C07 真题 flag{ 锁出 CRYP 前缀，更长 crib 锁出完整 CRYPTO', () => {
  // C07：21 字母短维吉尼亚（key=CRYPTO）；'flag{' 恰好约束 4 列 → key 前缀 CRYP
  const c07 = 'hcyv{owivltks_ecyhlwe_fi}';
  const withPrefix = vigenereAutoSolve(c07, { knownPlaintext: 'flag{' });
  assert.ok(withPrefix.key.startsWith('CRYP'), `crib 应锁出 CRYP 前缀，实际 key=${withPrefix.key}`);
  assert.ok(withPrefix.plaintext.startsWith('flag{'), `crib 锚定的明文应以 flag{ 开头: ${withPrefix.plaintext.slice(0, 10)}`);
  assert.ok(withPrefix.confidence >= 0.7, `crib 命中置信度应有背书: ${withPrefix.confidence}`);
  // 候选列表里应含与 crib 一致的解
  assert.ok((withPrefix.candidates ?? []).every(item => item.plaintext.startsWith('flag{')));
  // 7 字母 crib（flag{vi）约束全部 6 列 → 完整 key CRYPTO 与精确明文
  const fullCrib = vigenereAutoSolve(c07, { knownPlaintext: 'flag{vi' });
  assert.equal(fullCrib.key, 'CRYPTO');
  assert.equal(fullCrib.plaintext, 'flag{vigenere_classic_ok}');
});

test('P1-1 crib 与已知明文冲突的长度被排除：无一致长度时回退统计路径不崩溃', () => {
  // crib 'zzz' 与任何合理周期都可能不一致或一致——只验证不崩溃且返回结构完整
  const result = vigenereAutoSolve(caesarShift(CAESAR_SHORT, 3), { knownPlaintext: 'zzzz' });
  assert.ok(typeof result.key === 'string' && result.keyLen >= 1);
  assert.ok(Array.isArray(result.candidates));
});

// ---- BUG-09：xorAutoSolve 置信度长度比惩罚 + hintVerified 语义 ----

test('BUG-09 短密文错误 key 不再高置信：密文/keyLen < 8 倍时置信度按比例压低', () => {
  // 26 字节密文、8 字节 key：统计自由度过高，即使解错也不该给出 0.5+ 置信度
  const plain = 'flag{cross_fit_short_text!!}';
  const cipher = xorEncrypt(plain, 'Sup3rK3y!');
  const result = xorAutoSolve(cipher);
  const ratio = cipher.length / Math.max(1, result.keyLen);
  if (ratio < 8) {
    assert.ok(result.confidence <= 0.4 + 1e-9, `短密文置信度应被压低: confidence=${result.confidence} ratio=${ratio}`);
  }
  // 长文本不受影响：135 字节 / 9 字节 key = 15 倍，置信度照常
  const long = xorEncrypt('The quick brown fox jumps over the lazy dog. '.repeat(3), 'SecretKey');
  const longResult = xorAutoSolve(long);
  assert.ok(longResult.confidence >= 0.7, `长文本 confidence=${longResult.confidence}`);
});

test('BUG-09 hintVerified 语义 = 明文确含 hint（覆盖重合指数派生路径）', () => {
  const plain = 'The ceremony is scheduled for noon. ' + 'flag{xor_hint_found} ' + 'and the rest of the body continues with ordinary english text for analysis here.';
  const cipher = xorEncrypt(plain, 'Sup3rSecret!');
  const result = xorAutoSolve(cipher, { knownHint: 'flag{' });
  assert.equal(result.hintVerified, result.plaintext.includes('flag{'));
  assert.ok(result.plaintext.includes('flag{xor_hint_found}'));
  assert.equal(result.hintVerified, true);
  // 无 hint 时恒 false
  assert.equal(xorAutoSolve(cipher).hintVerified, false);
});

// ---- 单表替换：随机字母表 + cribs ----

const SUBSTITUTION_PLAIN = 'the secret message contains a hidden flag word and enough english text '
  + 'for frequency analysis';

test('substitutionAutoSolve：cribs flag 锚点 + 爬山恢复不低于 90% 字符', () => {
  const cipherAlphabet = shuffledAlphabet(0x51ee7a);
  const cipher = substitutionEncrypt(SUBSTITUTION_PLAIN, cipherAlphabet);
  const result = substitutionAutoSolve(cipher, { cribs: ['flag'], seed: 0x1234abcd });
  const accuracy = letterAccuracy(result.plaintext, SUBSTITUTION_PLAIN);
  assert.ok(accuracy >= 0.9, `letters accuracy=${accuracy}, plaintext=${result.plaintext}`);
  assert.ok(result.confidence >= 0.5, `confidence=${result.confidence}`);
  // mapping 是 26 项双射
  assert.equal(new Set(Object.values(result.mapping)).size, 26);
  assert.equal(new Set(Object.keys(result.mapping)).size, 26);
  assert.equal(result.mappingKey.length, 26);
  // mappingKey 与 mapping 互为逆映射
  for (const [cipherLetter, plainLetter] of Object.entries(result.mapping)) {
    assert.equal(result.mappingKey[plainLetter.charCodeAt(0) - 65], cipherLetter);
  }
});

// ---- 单表替换：失败路径 ----

test('substitutionAutoSolve 密文字母不足 25：低置信度返回且不崩溃', () => {
  const result = substitutionAutoSolve('xyz abc def', { cribs: ['the'] });
  assert.ok(result.confidence <= 0.35, `confidence=${result.confidence}`);
  assert.equal(result.plaintext.length, 'xyz abc def'.length);
  assert.equal(new Set(Object.values(result.mapping)).size, 26);
});
