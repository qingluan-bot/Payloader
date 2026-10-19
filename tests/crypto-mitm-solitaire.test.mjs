// Lane D CTF 能力补强批次一：2DES 中间相遇攻击 + Solitaire/Pontifex 扑克流密码。
// 测试向量全部取自独立权威来源（非被测引擎自造，避免同源循环）：
//  - DES KAT：Seberry & Pieprzyk《Cryptography: An Introduction to Computer Security》附录 /
//    J. Orlin Grabbe "The DES Algorithm Illustrated"（key=133457799BBCDFF1）；
//    FIPS PUB 81（1980）附录 ECB 样例首块（key=0123456789abcdef, "Now is t"）。
//  - Solitaire：Bruce Schneier 规范 v1.2（schneier.com/academic/solitaire/）及其官方
//    测试向量文件 sol-test.txt（unkeyed、key=f/fo/foo/a/aa/aaa/b/bc/bcd、cryptonomicon）。
// 加载统一走 tests/helpers/compileTsModule.mjs；沙箱数组断言前用主 realm Array.from 转换。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const C = loadModule(path.join(srcDir, 'utils', 'codec', 'crypto.ts'));
const K = loadModule(path.join(srcDir, 'utils', 'codec', 'classical.ts'));

// 测试内独立的 2DES 链（复用已过 KAT 锚定的单块 DES 原语，不经过被测 MitM 代码路径）
const twoDesEncrypt = async (k1Hex, k2Hex, plainHex) =>
  C.desEcbBlock(k2Hex, await C.desEcbBlock(k1Hex, plainHex));

// ==================== DES 单块原语 KAT（权威向量对拍） ====================

test('DES KAT（Seberry-Pieprzyk/Grabbe）：key=133457799BBCDFF1, PT=0123456789ABCDEF → 85E813540F0AB405', async () => {
  const cipher = await C.desEcbBlock('133457799BBCDFF1', '0123456789ABCDEF');
  assert.equal(cipher, '85e813540f0ab405');
  const plain = await C.desEcbBlock('133457799BBCDFF1', '85E813540F0AB405', true);
  assert.equal(plain, '0123456789abcdef');
});

test('DES KAT（FIPS 81 附录 ECB 样例首块）：key=0123456789abcdef, "Now is t" → 3FA40E8A984D4815', async () => {
  const plainHex = Buffer.from('Now is t', 'ascii').toString('hex');
  const cipher = await C.desEcbBlock('0123456789abcdef', plainHex);
  assert.equal(cipher, '3fa40e8a984d4815');
  const decoded = await C.desEcbBlock('0123456789abcdef', '3FA40E8A984D4815', true);
  assert.equal(decoded, plainHex);
});

test('DES 弱密钥对合性（FIPS 46-3 弱密钥定义）：0101010101010101 满足 E(E(P))=P', async () => {
  const once = await C.desEcbBlock('0101010101010101', '0000000000000000');
  const twice = await C.desEcbBlock('0101010101010101', once);
  assert.equal(twice, '0000000000000000');
});

test('desEcbBlock 护栏：非 16 位 hex 的 key/块一律拒绝', async () => {
  await assert.rejects(() => C.desEcbBlock('133457799BBCDFF', '0123456789ABCDEF'), /DES key 必须是 16 位 hex/);
  await assert.rejects(() => C.desEcbBlock('133457799BBCDFF1', '0123456789ABCDEFZZ'), /DES 数据块必须是 16 位 hex/);
});

test('desKeyBytesFromIndex：位索引按 8 字节大端填充，越界拒绝', () => {
  assert.deepEqual(Array.from(C.desKeyBytesFromIndex(0)), [0, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual(Array.from(C.desKeyBytesFromIndex(1)), [0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(Array.from(C.desKeyBytesFromIndex(0x1234)), [0, 0, 0, 0, 0, 0, 0x12, 0x34]);
  assert.throws(() => C.desKeyBytesFromIndex(2n ** 64n), /超出 8 字节/);
  assert.throws(() => C.desKeyBytesFromIndex(-1), /非负整数/);
});

// ==================== 2DES 中间相遇：正向恢复 ====================

const K1_INDEX = 321; // 0x0141
const K2_INDEX = 777; // 0x0309
const K1_HEX = '0000000000000141';
const K2_HEX = '0000000000000309';
const PAIR0_PLAIN = '5468652071756963'; // "The quic"（8 字节，DES 块对齐）
const PAIR1_PLAIN = '62726f776e20666f'; // "brown fo"（8 字节，DES 块对齐）

const buildPairs = async () => {
  const pair0Cipher = await twoDesEncrypt(K1_HEX, K2_HEX, PAIR0_PLAIN);
  const pair1Cipher = await twoDesEncrypt(K1_HEX, K2_HEX, PAIR1_PLAIN);
  return [
    { plaintextHex: PAIR0_PLAIN, ciphertextHex: pair0Cipher },
    { plaintextHex: PAIR1_PLAIN, ciphertextHex: pair1Cipher },
  ];
};

test('2DES 中间相遇：10+10 位双已知对恢复出真实 (k1,k2)，候选全过全链路复核', async () => {
  const pairs = await buildPairs();
  const report = JSON.parse(await C.twoDesMeetInTheMiddle(pairs, { k1Bits: 10, k2Bits: 10 }));
  assert.equal(report.attack.includes('meet-in-the-middle'), true);
  assert.equal(report.joinHits >= 1, true, 'join 至少命中真实密钥对');
  assert.equal(report.verifiedCount >= 1, true);
  const hit = report.verifiedCandidates.find(c => c.k1Index === K1_INDEX && c.k2Index === K2_INDEX);
  assert.ok(hit, `真实密钥 (321,777) 必须在验证候选中：${JSON.stringify(report.verifiedCandidates)}`);
  assert.equal(hit.k1Hex, K1_HEX);
  assert.equal(hit.k2Hex, K2_HEX);
  assert.equal(hit.verifiedPairCount, 2, '真实密钥应通过两组已知对复核');
  // 独立复核：每个 verified 候选都真的把两对明密文跑通（不依赖被测代码的判定）
  for (const candidate of report.verifiedCandidates) {
    for (const pair of pairs) {
      const reEncrypted = await twoDesEncrypt(candidate.k1Hex, candidate.k2Hex, pair.plaintextHex);
      assert.equal(reEncrypted, pair.ciphertextHex, `候选 (${candidate.k1Index},${candidate.k2Index}) 加密复核失败`);
    }
  }
});

test('2DES 中间相遇：单已知对也能恢复，报告提示补充第二把尺子', async () => {
  const pairs = await buildPairs();
  const report = JSON.parse(await C.twoDesMeetInTheMiddle([pairs[0]], { k1Bits: 10, k2Bits: 10 }));
  assert.ok(report.verifiedCandidates.some(c => c.k1Index === K1_INDEX && c.k2Index === K2_INDEX));
  assert.equal(report.verifiedCount, report.joinHits, '单把尺子下 join 命中对首块必然自洽，全部保留');
  assert.ok(report.notes.some(note => note.includes('第二组')), '应提示补充第二组已知对');
});

test('2DES 碰撞用例：末字节奇偶位不同的等价密钥在 join 表中全部命中且全部通过全链路复核', async () => {
  // DES 每字节仅高 7 位参与密钥编排（最低位奇偶位被 PC-1 丢弃）：仅奇偶位不同的索引是
  // 同一 DES 函数 → 前向表/反向扫描在同一中间值上形成多候选碰撞。10 位索引 321=0x141 的
  // 完整等价类 = {64,65,320,321}（hi 字节 0/1 同奇偶、lo 字节 0x40/0x41 同奇偶）。
  const parityClass = (index, bits) => {
    const hi = (index >> 8) & 0xff;
    const lo = index & 0xff;
    const members = [];
    for (let candidate = 0; candidate < 2 ** bits; candidate += 1) {
      if (((candidate >> 8) & 0xfe) === (hi & 0xfe) && ((candidate & 0xff) & 0xfe) === (lo & 0xfe)) members.push(candidate);
    }
    return members;
  };
  const siblingPlain = await C.desEcbBlock(K1_HEX, PAIR0_PLAIN);
  const siblingPlainAlt = await C.desEcbBlock('0000000000000140', PAIR0_PLAIN);
  assert.equal(siblingPlain, siblingPlainAlt, '等价密钥加密结果必须一致（DES PC-1 丢奇偶位）');
  const pairs = await buildPairs();
  const report = JSON.parse(await C.twoDesMeetInTheMiddle(pairs, { k1Bits: 10, k2Bits: 10 }));
  const k1Indexes = [...new Set(report.verifiedCandidates.map(c => c.k1Index))].sort((a, b) => a - b);
  const k2Indexes = [...new Set(report.verifiedCandidates.map(c => c.k2Index))].sort((a, b) => a - b);
  assert.deepEqual(k1Indexes, parityClass(K1_INDEX, 10), 'k1 侧恰为 321 的奇偶等价类');
  assert.deepEqual(k2Indexes, parityClass(K2_INDEX, 10), 'k2 侧恰为 777 的奇偶等价类');
  assert.equal(report.verifiedCount, report.joinHits, '碰撞产生的等价候选全部为真解，无一被误杀');
  for (const candidate of report.verifiedCandidates) {
    assert.equal(candidate.verified, true);
    const reEncrypted = await twoDesEncrypt(candidate.k1Hex, candidate.k2Hex, PAIR1_PLAIN);
    assert.equal(reEncrypted, pairs[1].ciphertextHex, '等价候选对第二组已知对同样成立');
  }
});

test('2DES 全链路验证剔除：第二组密文被篡改后，join 命中全部被复核挡下（verifiedCount=0）', async () => {
  const pairs = await buildPairs();
  const tamperedCipher = pairs[1].ciphertextHex.slice(0, -2) + (pairs[1].ciphertextHex.endsWith('00') ? '01' : '00');
  const report = JSON.parse(await C.twoDesMeetInTheMiddle([
    pairs[0],
    { plaintextHex: pairs[1].plaintextHex, ciphertextHex: tamperedCipher },
  ], { k1Bits: 10, k2Bits: 10 }));
  assert.equal(report.joinHits >= 1, true, '首块 join 照常产生候选');
  assert.equal(report.verifiedCount, 0, '篡改第二把尺子后没有任何候选能通过全链路复核');
  assert.equal(report.rejectedJoinHits, report.joinHits, '全部 join 命中被剔除并计数');
});

test('2DES 中间相遇：1+1 位最小空间恢复', async () => {
  const k1Hex = '0000000000000001';
  const k2Hex = '0000000000000000';
  const plain = 'deadbeef00112233';
  const cipher = await twoDesEncrypt(k1Hex, k2Hex, plain);
  const report = JSON.parse(await C.twoDesMeetInTheMiddle(
    [{ plaintextHex: plain, ciphertextHex: cipher }],
    { k1Bits: 1, k2Bits: 1 },
  ));
  assert.equal(report.keySpace.k1Candidates, 2);
  assert.equal(report.keySpace.k2Candidates, 2);
  const hit = report.verifiedCandidates.find(c => c.k1Index === 1 && c.k2Index === 0);
  assert.ok(hit, `最小空间必须命中 (1,0)：${JSON.stringify(report.verifiedCandidates)}`);
});

test('2DES 中间相遇护栏：单把超 10 位、非法位数、缺已知对、长度不齐一律明示拒绝', async () => {
  const pairs = await buildPairs();
  await assert.rejects(() => C.twoDesMeetInTheMiddle(pairs, { k1Bits: 11, k2Bits: 10 }), /每把密钥 1-10 位/);
  await assert.rejects(() => C.twoDesMeetInTheMiddle(pairs, { k1Bits: 10, k2Bits: 0 }), /每把密钥 1-10 位/);
  await assert.rejects(() => C.twoDesMeetInTheMiddle(pairs, { k1Bits: 10.5, k2Bits: 10 }), /每把密钥 1-10 位/);
  await assert.rejects(() => C.twoDesMeetInTheMiddle([], { k1Bits: 10, k2Bits: 10 }), /至少需要一组已知/);
  await assert.rejects(() => C.twoDesMeetInTheMiddle([{ plaintextHex: '00', ciphertextHex: '0011223344556677' }]), /8 字节对齐/);
  await assert.rejects(() => C.twoDesMeetInTheMiddle([
    { plaintextHex: PAIR0_PLAIN, ciphertextHex: '001122334455667788' },
  ]), /8 字节对齐/);
  await assert.rejects(() => C.twoDesMeetInTheMiddle([
    { plaintextHex: PAIR0_PLAIN, ciphertextHex: '0011223344556677' },
    { plaintextHex: PAIR1_PLAIN, ciphertextHex: '00112233445566778899aabbccddeeff' },
  ]), /长度不一致/);
});

// ==================== Solitaire：牌序解析 ====================

const NUMERIC_DECK = Array.from({ length: 54 }, (_, index) => index + 1);
const CARD_DECK_TEXT = 'AC 2C 3C 4C 5C 6C 7C 8C 9C TC JC QC KC '
  + 'AD 2D 3D 4D 5D 6D 7D 8D 9D TD JD QD KD '
  + 'AH 2H 3H 4H 5H 6H 7H 8H 9H TH JH QH KH '
  + 'AS 2S 3S 4S 5S 6S 7S 8S 9S TS JS QS KS '
  + 'AB BB';

test('parseSolitaireDeck：数字记法与牌面码记法解析一致（规范初始牌序）', () => {
  const numeric = Array.from(K.parseSolitaireDeck(NUMERIC_DECK.join(' ')));
  const cards = Array.from(K.parseSolitaireDeck(CARD_DECK_TEXT));
  assert.deepEqual(numeric, NUMERIC_DECK);
  assert.deepEqual(cards, NUMERIC_DECK);
});

test('parseSolitaireDeck：王的多记法（AB/BB/JA/JB/A/B）与 10/T 等价（整副 54 张校验内混用）', () => {
  const reference = Array.from(K.parseSolitaireDeck(CARD_DECK_TEXT));
  const variants = CARD_DECK_TEXT.replace('TC', '10C').replace('AB', 'JA').replace('BB', 'B');
  assert.deepEqual(Array.from(K.parseSolitaireDeck(variants)), reference);
  // 首字符定王：AB/JA/A 是 A 王，BB/JB/B 是 B 王
  const abDeck = Array.from(K.parseSolitaireDeck(CARD_DECK_TEXT.replace('AB', 'A').replace('BB', 'JB')));
  assert.deepEqual(abDeck, reference);
});

test('parseSolitaireDeck 护栏：数量、重复、范围、非法牌面全部拒绝', () => {
  assert.throws(() => K.parseSolitaireDeck(''), /牌序为空/);
  assert.throws(() => K.parseSolitaireDeck(NUMERIC_DECK.slice(0, 53).join(' ')), /恰好 54 张/);
  assert.throws(() => K.parseSolitaireDeck([...NUMERIC_DECK.slice(0, 53), 1].join(' ')), /重复牌/);
  assert.throws(() => K.parseSolitaireDeck([...NUMERIC_DECK.slice(0, 53), 55].join(' ')), /1-54/);
  assert.throws(() => K.parseSolitaireDeck([...NUMERIC_DECK.slice(0, 53), 0].join(' ')), /1-54/);
  assert.throws(() => K.parseSolitaireDeck([...NUMERIC_DECK.slice(0, 53), 'ZZ'].join(' ')), /无法识别牌面/);
});

// ==================== Solitaire：官方规范向量（sol-test.txt） ====================

test('Solitaire 官方样例 1：unkeyed 牌序前十个输出 4 49 10 (53) 24 8 51 44 6 4 33（跳王后）', () => {
  const outputs = Array.from(K.solitaireOutputValues(Array.from(K.solitaireInitialDeck()), 10));
  assert.deepEqual(outputs, [4, 49, 10, 24, 8, 51, 44, 6, 4, 33]);
});

const SOL_TESTS = [
  { key: '', text: 'A'.repeat(15), expected: 'EXKYIZSGEHUNTIQ', label: 'unkeyed A x15（规范样例 1）' },
  { key: '', text: 'A'.repeat(10), expected: 'EXKYIZSGEH', label: 'unkeyed A x10（规范样例 1 前 10 输出）' },
  { key: 'f', text: 'A'.repeat(15), expected: 'XYIUQBMHKKJBEGY', label: 'key=f（sol-test.txt）' },
  { key: 'fo', text: 'A'.repeat(15), expected: 'TUJYMBERLGXNDIW', label: 'key=fo（sol-test.txt）' },
  { key: 'foo', text: 'A'.repeat(15), expected: 'ITHZUJIWGRFARMW', label: 'key=foo（规范样例 2 / sol-test.txt）' },
  { key: 'a', text: 'A'.repeat(15), expected: 'XODALGSCULIQNSC', label: 'key=a（sol-test.txt）' },
  { key: 'aa', text: 'A'.repeat(15), expected: 'OHGWMXXCAIMCIQP', label: 'key=aa（sol-test.txt）' },
  { key: 'aaa', text: 'A'.repeat(15), expected: 'DCSQYHBQZNGDRUT', label: 'key=aaa（sol-test.txt）' },
  { key: 'b', text: 'A'.repeat(15), expected: 'XQEEMOITLZVDSQS', label: 'key=b（sol-test.txt）' },
  { key: 'bc', text: 'A'.repeat(15), expected: 'QNGRKQIHCLGWSCE', label: 'key=bc（sol-test.txt）' },
  { key: 'bcd', text: 'A'.repeat(15), expected: 'FMUBYBMAXHNQXCJ', label: 'key=bcd（sol-test.txt）' },
  { key: 'cryptonomicon', text: 'A'.repeat(25), expected: 'SUGSRSXSWQRMXOHIPBFPXARYQ', label: 'key=cryptonomicon A x25（sol-test.txt）' },
  { key: 'cryptonomicon', text: 'SOLITAIREX', expected: 'KIRAKSFJAN', label: 'key=cryptonomicon SOLITAIRE+X 补齐（规范样例 3）' },
];

for (const vector of SOL_TESTS) {
  test(`Solitaire 官方向量：${vector.label}`, () => {
    assert.equal(K.solitaireTransform(vector.text, '', vector.key), vector.expected);
  });
}

test('Solitaire：加解密互逆（keyword 牌序与显式牌序两条路径）', () => {
  const keyword = 'pontifex';
  const message = 'Meet me at the bridge at dawn!';
  const encrypted = K.solitaireTransform(message, '', keyword);
  assert.equal(K.solitaireTransform(encrypted, '', keyword, true), message);
  const deckText = NUMERIC_DECK.map((value, index) => (index + 7) % 54 + 1).join(' ');
  Array.from(K.parseSolitaireDeck(deckText)); // 显式牌序合法性自检（解析失败抛错即测试失败）
  const encryptedByDeck = K.solitaireTransform(message, deckText, '');
  assert.equal(K.solitaireTransform(encryptedByDeck, deckText, '', true), message);
  assert.notEqual(encrypted, encryptedByDeck, '不同牌序应产生不同密文');
});

test('Solitaire：非字母透传不消耗密钥流、大小写保留、deckText 优先于 keyword', () => {
  const plain = 'Abc-Def!';
  const encrypted = K.solitaireTransform(plain, '', 'foo');
  const lettersOnly = Array.from(encrypted).filter(char => /[a-z]/i.test(char)).length;
  assert.equal(lettersOnly, 6, '非字母不动：只有 6 个字母被加密');
  assert.ok(encrypted.includes('-') && encrypted.includes('!'));
  assert.equal(K.solitaireTransform(encrypted, '', 'foo', true), plain, '带非字母的混合文本加解密互逆');
  // 显式牌序（= 规范初始牌序）前两个输出是 4、49（官方 EXKYI 前两位），验证大小写保留
  const viaDeck = K.solitaireTransform(plain, CARD_DECK_TEXT, 'ignored-keyword');
  assert.equal(viaDeck[0], 'E', 'A(大写) + 输出牌 4 → E（官方 EXKYI 首位，大小写保留）');
  assert.equal(viaDeck[1], 'y', 'b(小写) + 输出牌 49（X 偏移 23）→ y（小写保留）');
  assert.equal(viaDeck, K.solitaireTransform(plain, CARD_DECK_TEXT, ''), 'deckText 非空时 keyword 不参与');
  assert.equal(K.solitaireTransform('AAAAA', '', 'FOO'), K.solitaireTransform('AAAAA', '', 'foo'), 'keyword 大小写不敏感');
});

test('Solitaire：solitaireKeyedDeck 确定性且依赖每个密钥字母', () => {
  const foo = Array.from(K.solitaireKeyedDeck('foo'));
  const fog = Array.from(K.solitaireKeyedDeck('fog'));
  assert.equal(foo.length, 54);
  assert.deepEqual(Array.from(new Set(foo)).sort((a, b) => a - b), NUMERIC_DECK, 'keyed deck 仍是 54 张全量排列');
  assert.notDeepEqual(foo, fog, '末字母不同应产生不同牌序');
  assert.throws(() => K.solitaireKeyedDeck('123'), /至少一个字母/);
});
