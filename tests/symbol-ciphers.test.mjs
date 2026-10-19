// 七族符号密码回归测试（批次三 Lane H）：Z408 键表对拍锚点与同音档位、Wabun 规则表锚点与浊点分解、
// 古文明数字三族进制规范形、天体/骰面/骨牌 Unicode 替换、Trilitère 与 Monome-Binome dCode 官方向量、
// 圣书体单辅音 20 字母编码与变体归一；每族含未知符号容错计数与 round-trip。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const SC = loadModule(path.join(srcDir, 'utils', 'codec', 'symbolCiphers.ts'));

const T = (id, direction, input, params = {}) => SC.symbolCiphersTransform(id, direction, input, params);
const enc = (id, input, params) => T(id, 'encode', input, params);
const dec = (id, input, params) => T(id, 'decode', input, params);
const glyph = String.fromCodePoint;

// ---- 元数据与分发契约 ----

test('元数据：11 个操作、id 唯一、双语 name/summary 齐备', () => {
  const ops = Array.from(SC.symbolCiphersOperations, op => op);
  assert.equal(ops.length, 11);
  assert.equal(new Set(ops.map(op => op.id)).size, 11);
  for (const op of ops) {
    assert.ok(op.name.zh && op.name.en, `${op.id} 缺双语名称`);
    assert.ok(op.summary.zh && op.summary.en, `${op.id} 缺双语摘要`);
  }
});

test('空输入一律返回空串；未知操作 id 报错', async () => {
  for (const op of Array.from(SC.symbolCiphersOperations, op => op.id)) {
    assert.equal(await T(op, 'encode', ''), '');
    assert.equal(await T(op, 'decode', ''), '');
  }
  await assert.rejects(() => T('no-such-op', 'encode', 'x'), /不支持的操作/);
});

// ---- 1. Zodiac Z408 ----

test('Z408 对拍锚点：密文首行 9%P/Z/UB%kOR=pX=B → ilikekillingpeopl', async () => {
  assert.equal(await dec('zodiac-408', '9%P/Z/UB%kOR=pX=B'), 'ilikekillingpeopl');
});

test('Z408 同音容量：54 符号 → 23 字母（e=7，t/a/o/i/n/s=4，r/l=3，无 J/Q/Z）', () => {
  const groups = Array.from(SC.z408Homophones, ([letter, symbols]) => [letter, symbols]);
  const total = groups.reduce((sum, [, symbols]) => sum + symbols.length, 0);
  assert.equal(total, 54);
  assert.equal(groups.length, 23);
  const sizeOf = letter => groups.find(([letterKey]) => letterKey === letter)?.[1].length;
  assert.equal(sizeOf('e'), 7);
  for (const letter of ['t', 'a', 'o', 'i', 'n', 's']) assert.equal(sizeOf(letter), 4);
  for (const letter of ['r', 'l']) assert.equal(sizeOf(letter), 3);
  for (const letter of 'jqz') assert.equal(sizeOf(letter), undefined);
});

test('Z408 round-trip：cycle 与 primary 两档均精确保达', async () => {
  const plain = 'ilikekillingpeoplebecauseitis';
  assert.equal(await dec('zodiac-408', await enc('zodiac-408', plain, { variant: 'cycle' })), plain);
  assert.equal(await dec('zodiac-408', await enc('zodiac-408', plain, { variant: 'primary' })), plain);
});

test('Z408 primary 档：k=/ i=P l=B，kill → /PBB；默认档为 cycle（同字母轮转异符号）', async () => {
  assert.equal(await enc('zodiac-408', 'kill', { variant: 'primary' }), '/PBB');
  assert.equal(await enc('zodiac-408', 'ii'), 'PU', '默认 variant 应取 cycle：i 的前两个同音符号轮转');
  assert.equal(await enc('zodiac-408', 'ii', { variant: 'primary' }), 'PP');
});

test('Z408 J/Q/Z 无符号如实报错', async () => {
  await assert.rejects(() => enc('zodiac-408', 'jazz'), /Z408 键表无字母/);
});

test('Z408 未知符号容错计数：原位保留 + 尾注', async () => {
  assert.equal(await dec('zodiac-408', '9?%'), 'i?l[未知符号x1]');
});

// ---- 2. Wabun 和文摩尔斯 ----

test('Wabun 规则表锚点：条文原文 ヘ=・ ム=－；全表 52 项点划无碰撞', async () => {
  assert.equal(await enc('wabun', 'ヘ'), '.');
  assert.equal(await enc('wabun', 'ム'), '-');
  const kanaList = [...'イロハニホヘトチリヌルヲワカヨタレソツネナラムウヰノオクヤマケフコエテアサキユメミシヱヒモセスン', glyph(0x309b), glyph(0x309c), 'ー', '、'];
  assert.equal(kanaList.length, 52);
  const encodedList = [];
  for (const kana of kanaList) encodedList.push(await enc('wabun', kana));
  assert.equal(new Set(encodedList).size, 52, '52 项码表必须两两不同（无同码冲突）');
});

test('Wabun round-trip：コンニチワ 与濁点/半濁点组合（解码归一片假名）', async () => {
  for (const [word, expected] of [['コンニチワ', 'コンニチワ'], ['がぎぐげご', 'ガギグゲゴ'], ['ぱぴぷぺぽ', 'パピプペポ'], ['ヒヤツカシ゛テン', 'ヒヤツカジテン'], ['ラーメン、タベタ', 'ラーメン、タベタ']]) {
    assert.equal(await dec('wabun', await enc('wabun', word)), expected, `round-trip 失败: ${word}`);
  }
});

test('Wabun NFD 濁点分解：ガ = カ+・・，解码 NFC 还原', async () => {
  assert.equal(await enc('wabun', 'ガ'), '.-.. ..');
  assert.equal(await enc('wabun', 'パ'), '-... ..--.');
  assert.equal(await dec('wabun', '.-.. ..'), 'ガ');
  assert.equal(await dec('wabun', '-... ..--.'), 'パ');
});

test('Wabun 平假名/小书字归一片假名', async () => {
  assert.equal(await enc('wabun', 'だいがく'), await enc('wabun', 'ダイガク'));
  assert.equal(await dec('wabun', await enc('wabun', 'にほんご')), 'ニホンゴ');
  assert.equal(await enc('wabun', 'ャ'), await enc('wabun', 'ヤ'));
});

test('Wabun 词间 / 与未知符号容错', async () => {
  assert.equal(await enc('wabun', 'ヤ マ'), '.-- / -..-');
  assert.equal(await dec('wabun', '.-- / -..-'), 'ヤ マ');
  assert.equal(await dec('wabun', '.- ....-'), 'イ....-[未知符号x1]', '未知点划组原位保留并尾注计数');
});

// ---- 3a. 巴比伦楔形数字 ----

test('巴比伦楔形：1=𒁹 10=𒌋 59=5横+9竖；零位占位与位值制', async () => {
  assert.equal(await enc('babylonian', '1', { variant: 'cuneiform' }), glyph(0x12079));
  assert.equal(await enc('babylonian', '10', { variant: 'cuneiform' }), glyph(0x12311));
  assert.equal(await enc('babylonian', '59', { variant: 'cuneiform' }), glyph(0x12311).repeat(5) + glyph(0x12079).repeat(9));
  assert.equal(await enc('babylonian', '3600', { variant: 'cuneiform' }), `${glyph(0x12079)} · ·`);
  assert.equal(await dec('babylonian', `${glyph(0x12079)} · 𒁹`), '3601');
});

test('巴比伦 ASCII 双档与 round-trip（含 BigInt 大数）', async () => {
  assert.equal(await enc('babylonian', '13', { variant: 'ascii' }), '-|||');
  assert.equal(await enc('babylonian', '0'), '·');
  for (const variant of ['cuneiform', 'ascii']) {
    for (const number of ['0', '1', '59', '60', '3601', '123456789']) {
      const cipher = await enc('babylonian', number, { variant });
      assert.equal(await dec('babylonian', cipher), number, `round-trip 失败: ${number} (${variant})`);
    }
  }
});

test('巴比伦单位值上限与未知符号容错', async () => {
  await assert.rejects(() => dec('babylonian', '------'), /超过 59/);
  assert.equal(await dec('babylonian', `${glyph(0x12079)} ？`), '1[未知符号x1]');
});

// ---- 3b. 玛雅数字 ----

test('玛雅 Unicode 块：0=𝋠 19=𝋿；20 与 400 的位值展开', async () => {
  assert.equal(await enc('mayan', '0'), glyph(0x1d2e0));
  assert.equal(await enc('mayan', '19'), glyph(0x1d2f3));
  assert.equal(await enc('mayan', '20'), `${glyph(0x1d2e1)} ${glyph(0x1d2e0)}`);
  assert.equal(await enc('mayan', '400'), `${glyph(0x1d2e1)} ${glyph(0x1d2e0)} ${glyph(0x1d2e0)}`);
});

test('玛雅 ASCII 点杠：13=...--，round-trip 双档（含大数）', async () => {
  assert.equal(await enc('mayan', '13', { variant: 'ascii' }), '...--');
  assert.equal(await enc('mayan', '0', { variant: 'ascii' }), '0');
  assert.equal(await dec('mayan', '...--'), '13');
  for (const variant of ['mayan', 'ascii']) {
    for (const number of ['0', '19', '20', '399', '123456789']) {
      const cipher = await enc('mayan', number, { variant });
      assert.equal(await dec('mayan', cipher), number, `round-trip 失败: ${number} (${variant})`);
    }
  }
});

test('玛雅位值上限与未知符号容错', async () => {
  await assert.rejects(() => dec('mayan', '------'), /超过 19/);
  assert.equal(await dec('mayan', `${glyph(0x1d2e1)} ?`), '1[未知符号x1]', '未知位被跳过并尾注计数');
});

// ---- 3c. 古埃及数字 ----

test('埃及降幂规范形：1/12/123 的 7 幂符号展开', async () => {
  assert.equal(await enc('egyptian-numerals', '1'), glyph(0x133e4));
  assert.equal(await enc('egyptian-numerals', '12'), glyph(0x13386) + glyph(0x133e4).repeat(2));
  assert.equal(await enc('egyptian-numerals', '123'), glyph(0x13362) + glyph(0x13386).repeat(2) + glyph(0x133e4).repeat(3));
});

test('埃及 round-trip 与加法求和', async () => {
  assert.equal(await dec('egyptian-numerals', glyph(0x13386).repeat(2)), '20');
  for (const number of ['1', '9', '10', '123456', '9999999']) {
    assert.equal(await dec('egyptian-numerals', await enc('egyptian-numerals', number)), number);
  }
});

test('埃及无零号与规范形上限如实报错', async () => {
  await assert.rejects(() => enc('egyptian-numerals', '0'), /没有零号/);
  await assert.rejects(() => enc('egyptian-numerals', '10000000'), /规范形/);
});

test('埃及未知符号容错计数', async () => {
  assert.equal(await dec('egyptian-numerals', `${glyph(0x133e4)}?`), '1[未知符号x1]');
});

// ---- 4. 天体符号 ----

test('天体符号：行星与黄道名称编码', async () => {
  assert.equal(await enc('astro-symbols', 'sun'), glyph(0x2609));
  assert.equal(await enc('astro-symbols', 'aries'), glyph(0x2648));
  assert.equal(await enc('astro-symbols', 'jupiter saturn'), `${glyph(0x2643)}${glyph(0x2644)}`);
});

test('天体变体归一：☾→moon、♁→earth、♓→pisces', async () => {
  assert.equal(await dec('astro-symbols', glyph(0x263e)), 'moon');
  assert.equal(await dec('astro-symbols', glyph(0x2641)), 'earth');
  assert.equal(await dec('astro-symbols', `${glyph(0x2609)}${glyph(0x2653)}`), 'sun pisces');
});

test('天体全表 round-trip（23 项）与未知处理', async () => {
  const names = ['sun', 'moon', 'mercury', 'venus', 'earth', 'mars', 'jupiter', 'saturn', 'uranus', 'neptune', 'pluto', ...'aries taurus gemini cancer leo virgo libra scorpio sagittarius capricorn aquarius pisces'.split(' ')];
  assert.equal(names.length, 23);
  for (const name of names) {
    assert.equal(await dec('astro-symbols', await enc('astro-symbols', name)), name);
  }
  await assert.rejects(() => enc('astro-symbols', 'pluto9'), /天体符号表无名称/);
  assert.equal(await dec('astro-symbols', `${glyph(0x2609)}?`), 'sun ?[未知符号x1]');
});

// ---- 5a. 骰面 ----

test('骰面：1-6 ↔ U+2680-2685，round-trip 与越界报错', async () => {
  const faces = glyph(0x2680) + glyph(0x2681) + glyph(0x2682) + glyph(0x2683) + glyph(0x2684) + glyph(0x2685);
  assert.equal(await enc('dice', '123456'), faces);
  assert.equal(await dec('dice', faces), '123456');
  assert.equal(await dec('dice', glyph(0x2684)), '5');
  await assert.rejects(() => enc('dice', '0'), /仅支持数字 1-6/);
  await assert.rejects(() => enc('dice', '8'), /仅支持数字 1-6/);
});

test('骰面未知符号容错计数', async () => {
  assert.equal(await dec('dice', `${glyph(0x2680)}XYZ`), '1XYZ[未知符号x3]');
});

// ---- 5b. 骨牌 ----

test('骨牌横排：00=1F031、06=1F037、有序对 60 保序为 HORIZONTAL-06-00', async () => {
  assert.equal(await enc('dominoes', '00'), glyph(0x1f031));
  assert.equal(await enc('dominoes', '06'), glyph(0x1f037));
  assert.equal(await enc('dominoes', '60'), glyph(0x1f031 + 6 * 7));
});

test('骨牌竖排变体与横竖解码兼容', async () => {
  assert.equal(await enc('dominoes', '00', { variant: 'vertical' }), glyph(0x1f063));
  assert.equal(await dec('dominoes', glyph(0x1f063 + 2 * 7 + 5)), '25');
});

test('骨牌无空格连续牌面解码仍按对分组', async () => {
  const contiguous = glyph(0x1f031) + glyph(0x1f04c) + glyph(0x1f061);
  assert.equal(await dec('dominoes', contiguous), '00 36 66');
});

test('骨牌 round-trip 双档与输入校验', async () => {
  for (const variant of ['horizontal', 'vertical']) {
    const input = '00 11 21 34 66';
    assert.equal(await dec('dominoes', await enc('dominoes', input, { variant }), ), input, `round-trip 失败 (${variant})`);
  }
  await assert.rejects(() => enc('dominoes', '77'), /两位 0-6 数字/);
  await assert.rejects(() => enc('dominoes', '353'), /两位 0-6 数字/);
});

test('骨牌未知符号容错计数', async () => {
  assert.equal(await dec('dominoes', '?'), '?[未知符号x1]');
});

// ---- 6a. Trilitère 三元 ----

test('Trilitère dCode 官方向量：DCODE → ABA AAC BBC ABA ABB', async () => {
  assert.equal(await enc('trilitere', 'dcode'), 'ABA AAC BBC ABA ABB');
  assert.equal(await dec('trilitere', 'ABAAACBBCABAABB'), 'dcode');
});

test('Trilitère 默认空格=CCC，aaa 变体空格=AAA 且 a=AAB', async () => {
  assert.equal(await enc('trilitere', ' '), 'CCC');
  assert.equal(await dec('trilitere', 'CCC'), ' ');
  assert.equal(await enc('trilitere', 'a', { variant: 'aaa' }), 'AAB');
  assert.equal(await enc('trilitere', ' ', { variant: 'aaa' }), 'AAA');
  assert.equal(await dec('trilitere', 'AAABBB', { variant: 'aaa' }), ' m', 'AAA=空格、BBB=m');
});

test('Trilitère round-trip 双变体、数字集兼容与长度校验', async () => {
  for (const variant of ['ccc', 'aaa']) {
    for (const text of ['hello world', 'attack at dawn', 'zzz']) {
      assert.equal(await dec('trilitere', await enc('trilitere', text, { variant }), { variant }), text, `round-trip 失败: ${text} (${variant})`);
    }
  }
  assert.equal(await dec('trilitere', '123123'), 'ff', '1/2/3 数字集按 A/B/C 归一（ABC=f）');
  await assert.rejects(() => dec('trilitere', 'AB'), /3 的倍数/);
});

// ---- 6b. Monome-Binome ----

test('Monome-Binome dCode 官方双向量：MONOME 编码与 4303536345 解码', async () => {
  assert.equal(await enc('monome-binome', 'MONOME'), '34 36 35 36 34 5');
  assert.equal(await dec('monome-binome', '4303536345'), 'DINOME');
});

test('Monome-Binome round-trip（含空格与 * 位）', async () => {
  for (const text of ['MONOME DINOME', 'SPACE JAM', 'XYZ *']) {
    assert.equal(await dec('monome-binome', await enc('monome-binome', text)), text);
  }
  assert.ok((await enc('monome-binome', '*')).endsWith('79'));
});

test('Monome-Binome 非法字符报错与未知数字容错', async () => {
  await assert.rejects(() => enc('monome-binome', 'HELLO!'), /仅支持 A-Z、空格与/);
  assert.equal(await dec('monome-binome', '4x5'), 'DE[未知符号x1]');
});

// ---- 7. 圣书体单辅音符 ----

test('圣书体：A=G1 秃鹫，20 字母全表 round-trip', async () => {
  assert.equal(await enc('hieroglyph-single', 'A'), glyph(0x1313f));
  const letters = 'ABDFGHIKLMNPQRSTWXYZ';
  assert.equal(letters.length, 20);
  const cipher = await enc('hieroglyph-single', letters);
  assert.equal(await dec('hieroglyph-single', cipher), letters);
});

test('圣书体变体归一：D36 臂→A、F40 动物肚→X、I10 眼镜蛇→D、N37 池→S', async () => {
  assert.equal(await dec('hieroglyph-single', glyph(0x1309d)), 'A');
  assert.equal(await dec('hieroglyph-single', glyph(0x1312b)), 'X');
  assert.equal(await dec('hieroglyph-single', glyph(0x13193)), 'D');
  assert.equal(await dec('hieroglyph-single', glyph(0x13219)), 'S');
});

test('圣书体 C/E/J/O/U/V 无字形如实报错', async () => {
  await assert.rejects(() => enc('hieroglyph-single', 'CEJOUV'), /C\/E\/J\/O\/U\/V/);
});

test('圣书体未知符号容错计数', async () => {
  assert.equal(await dec('hieroglyph-single', `${glyph(0x1313f)}?`), 'A?[未知符号x1]');
});
