// B4 批次 Lane N 测试：smartDecode 结构化有效信息加权与封顶（B4-1）+ 宽松字符种类准入档（B4-2）。
// 测试向量全部独立权威构造：翻转案例为手工构造文本对；喵呜表/emoji 表 0/1 样本由 ASCII 字节
// 程序化生成（8 位一字节，0/1 双符号映射），不依赖被测实现反推。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
// 同一沙箱加载器：transform 与 smartDecode/smartBase 共享模块缓存实例（与生产调用链一致）
const T = loadModule(path.join(srcDir, 'utils', 'codec', 'transform.ts'));
const S = loadModule(path.join(srcDir, 'utils', 'codec', 'smartDecode.ts'));
const BASE = loadModule(path.join(srcDir, 'utils', 'codec', 'smartBase.ts'));

// 把明文按 8 位一字节展开成比特串，再按给定 0/1 双符号渲染成变体字符表样本
const bitsOf = plain => [...Buffer.from(plain, 'utf8')].map(byte => byte.toString(2).padStart(8, '0')).join('');
const renderVariantTable = (bits, zeroChar, oneChar) => [...bits].map(bit => (bit === '0' ? zeroChar : oneChar)).join('');

// B4-1 翻转案例（权威构造）：弱符号词汤在旧基础分下压过真 JSON（可读 40 + 字母 + 词命中 +
// resolved 全吃满），新结构化分下 JSON 的 structure 信号桶胜出。
const WORD_SOUP = 'the test data value code name user{}{}{}';
const REAL_JSON = '{"status":"success","token":"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"}';
// 纯符号汤（零字母）：基础分本就低，且触发符号汤重罚
const PURE_SOUP = '}{_}{_~^__{}+-=_}{}}__{{__}_-_=}{_~^__{}';
// 弱符号海量堆量（刷分攻击形态）
const PILE_SOUP = 'a-b_' + '{}'.repeat(500);
// 普通英文句（无 flag/结构信号）：不允许被信号层误伤
const PLAIN_SENTENCE = 'the quick brown fox jumps over lazy dogs again';

const C08_CIPHER = '88810884108420888108108420421040810421081088408821084210821';

// ---- B4-1：信号集权重与封顶参数契约 ----

test('B4-1 信号权重与封顶参数表：确切口径钉死', () => {
  const w = S.SMART_DECODE_SIGNAL_WEIGHTS;
  // 分层：flagStrong > flagKeyword > 普通信号封顶 > weakSymbol 封顶
  assert.equal(w.flagStrong, 100);
  assert.equal(w.flagKeyword, 45);
  assert.equal(w.normalSignalCap, 32);
  assert.equal(w.weakSymbolCap, 6);
  assert.ok(w.flagStrong > w.flagKeyword, 'flagStrong 权重必须高于 flagKeyword');
  assert.ok(w.flagKeyword > w.normalSignalCap, 'flag 关键词权重必须高于普通信号封顶（不被翻转）');
  assert.ok(w.normalSignalCap > w.weakSymbolCap, 'structure 层量级必须高于 weakSymbol 层');
  // structure 各信号全部落在普通信号封顶之下
  for (const key of ['structureJson', 'structureJwt', 'structureCredential', 'structurePem', 'structureUrl', 'structureSuccess']) {
    assert.ok(w[key] > 0 && w[key] <= w.normalSignalCap, `${key}=${w[key]} 必须在 (0, ${w.normalSignalCap}] 内`);
  }
  // adjust 区间与符号汤惩罚
  assert.equal(w.adjustMin, -120);
  assert.equal(w.adjustMax, 40);
  assert.deepEqual([w.soupPenaltyLight, w.soupPenaltyMid, w.soupPenaltyHeavy], [-30, -60, -100]);
});

test('B4-1 弱符号刷分 vs 真 JSON：旧基础分排序错误，结构化分翻转为正确结果排前', () => {
  const soupBreakdown = S.smartDecodeSignalBreakdown(WORD_SOUP);
  const jsonBreakdown = S.smartDecodeSignalBreakdown(REAL_JSON);
  // 旧口径（基础分）：词汤吃满可读/词命中/resolved 加成，反而压过真 JSON —— 记录旧行为缺陷
  const soupBase = BASE.smartDecodeOutputScore(WORD_SOUP);
  const jsonBase = BASE.smartDecodeOutputScore(REAL_JSON);
  assert.ok(soupBase > jsonBase, `前置构造：旧基础分应词汤(${soupBase}) > JSON(${jsonBase})，否则翻转案例不成立`);
  // 新口径（结构化分）：JSON 的 structure 桶（json+credential+success=30，封顶 32）显著压过词汤的 weakSymbol
  //（沙箱跨 realm 数组：deepEqual 前先转主 realm，见 AGENTS.md 沙箱纪律）
  assert.deepEqual([...jsonBreakdown.structureHits], ['json', 'credential', 'success']);
  assert.equal(soupBreakdown.structureSum, 0, '词汤无任何结构信号');
  assert.ok(jsonBreakdown.structureSum >= 24, `JSON 结构信号合计应 ≥24，实际 ${jsonBreakdown.structureSum}`);
  assert.ok(jsonBreakdown.normalTotal <= 32, `普通信号合计不得突破封顶 32，实际 ${jsonBreakdown.normalTotal}`);
  assert.ok(S.smartDecodeStructuredScore(REAL_JSON) > S.smartDecodeStructuredScore(WORD_SOUP),
    `JSON(${S.smartDecodeStructuredScore(REAL_JSON)}) 必须压过弱符号词汤(${S.smartDecodeStructuredScore(WORD_SOUP)})`);
});

test('B4-1 弱符号海量堆量不涨分：weakSymbol 层封顶 6、普通信号合计封顶 32', () => {
  const breakdown = S.smartDecodeSignalBreakdown(PILE_SOUP);
  assert.equal(breakdown.structureSum, 0, '纯弱符号堆量不产生结构信号');
  assert.equal(breakdown.weakSymbolSum, 6, 'weakSymbol 层无论堆多少符号封顶 6');
  assert.ok(breakdown.normalTotal <= 32);
  // 堆量形态同时触发符号汤重罚：adjust 落到负区间
  assert.equal(breakdown.soupPenalty, -100);
  assert.ok(breakdown.adjust <= 0, `海量弱符号堆量的 adjust 应为负，实际 ${breakdown.adjust}`);
});

test('B4-1 flag 分层互斥且恒高：strong 不与 keyword 叠加', () => {
  const strong = S.smartDecodeSignalBreakdown('the secret is flag{b4_str0ng_signal}');
  assert.equal(strong.flagTier, 'strong');
  assert.equal(strong.flagBonus, 100);
  const keyword = S.smartDecodeSignalBreakdown('the flag is hidden here');
  assert.equal(keyword.flagTier, 'keyword');
  assert.equal(keyword.flagBonus, 45);
  // 结构信号单独存在时不带 flag 加成
  const structureOnly = S.smartDecodeSignalBreakdown(REAL_JSON);
  assert.equal(structureOnly.flagTier, 'none');
  assert.equal(structureOnly.flagBonus, 0);
});

test('B4-1 纯符号汤惩罚与 adjust 区间：普通文本零误伤', () => {
  const pure = S.smartDecodeSignalBreakdown(PURE_SOUP);
  assert.equal(pure.soupPenalty, -100);
  assert.ok(pure.adjust >= -120 && pure.adjust <= 40, `adjust 必须落在 [-120, 40]，实际 ${pure.adjust}`);
  // JSON 类结构化输出豁免符号汤惩罚（含大量标点但属结构信号）
  assert.equal(S.smartDecodeSignalBreakdown(REAL_JSON).soupPenalty, 0);
  // 普通英文句：无信号不加分，也无惩罚（adjust = 0）
  const plain = S.smartDecodeSignalBreakdown(PLAIN_SENTENCE);
  assert.equal(plain.structureSum, 0);
  assert.equal(plain.soupPenalty, 0);
  assert.equal(plain.adjust, 0);
  assert.equal(plain.total, plain.baseScore, '普通文本总分应等于基础分（信号层零干预）');
});

test('B4-1 恒等短路：输出与输入空白归一相同 → 0 分', () => {
  assert.equal(S.smartDecodeStructuredScore(WORD_SOUP, WORD_SOUP), 0);
  assert.equal(S.smartDecodeStructuredScore('a b c', 'abc'), 0);
  assert.ok(S.smartDecodeStructuredScore(REAL_JSON, WORD_SOUP) > 0);
});

// ---- B4-2：宽松字符种类准入档 ----

test('B4-2 准入参数契约：BINARY≤2 / DIGIT≤10 / HEX≤17 / BASE64ISH≤70，可打印率 0.9', () => {
  // 沙箱跨 realm 对象：展开为主 realm 后再断言（AGENTS.md 沙箱纪律）
  assert.deepEqual({ ...S.SMART_DECODE_LENIENT_LIMITS }, { binary: 2, digit: 10, hex: 17, base64ish: 70 });
  assert.equal(S.SMART_DECODE_LENIENT_PRINTABLE_FLOOR, 0.9);
  assert.equal(S.SMART_DECODE_LENIENT_MIN_SYMBOLS, 16);
});

test('B4-2 喵呜表 0/1 长串：端到端经宽松档解出明文', async () => {
  const plain = 'lenient_b4_meow_ok';
  const meowText = renderVariantTable(bitsOf(plain), '喵', '呜');
  assert.equal(meowText.length, plain.length * 8, '8 位一字节展开');
  // 单元层：宽松档分析器直接命中 binary 档并给出映射
  const hit = S.analyzeSmartDecodeLenient(meowText);
  assert.ok(hit, '喵呜 0/1 长串应被宽松档准入');
  assert.equal(hit.tier, 'binary');
  assert.equal(hit.output, plain);
  assert.deepEqual(Array.from(hit.mapping, entry => ({ from: entry.from, to: entry.to })), [{ from: '喵', to: '0' }, { from: '呜', to: '1' }]);
  assert.equal(hit.label, '宽松档二进制（喵→0，呜→1）');
  // 端到端：智能解出明文，且标注宽松档
  const output = String(await T.transform('smart-decode', 'decode', meowText, {}));
  assert.ok(output.includes(plain), `端到端应解出 ${plain}，实际: ${output.slice(0, 120).replace(/\n/g, ' ')}`);
  assert.ok(output.includes('宽松档二进制'), '端到端结果应标注宽松档来源');
});

test('B4-2 喵呜表反向映射（呜=0，喵=1）同样经宽松档解出', async () => {
  const plain = 'lenient_b4_meow_ok';
  const swapped = renderVariantTable(bitsOf(plain), '呜', '喵');
  const hit = S.analyzeSmartDecodeLenient(swapped);
  assert.ok(hit, '反向映射样本应被宽松档准入');
  assert.equal(hit.tier, 'binary');
  assert.equal(hit.output, plain);
  assert.deepEqual(Array.from(hit.mapping, entry => ({ from: entry.from, to: entry.to })), [{ from: '呜', to: '0' }, { from: '喵', to: '1' }], '两种比特指派都应尝试并择优');
  const output = String(await T.transform('smart-decode', 'decode', swapped, {}));
  assert.ok(output.includes(plain), `端到端应解出 ${plain}，实际: ${output.slice(0, 120).replace(/\n/g, ' ')}`);
});

test('B4-2 emoji 表二进制（双码元字符）经宽松档解出', async () => {
  const plain = 'lenient_b4_meow_ok';
  const emojiText = renderVariantTable(bitsOf(plain), '🌟', '🚀');
  const hit = S.analyzeSmartDecodeLenient(emojiText);
  assert.ok(hit, 'emoji 双符号表应被宽松档准入（按码点统计种类）');
  assert.equal(hit.tier, 'binary');
  assert.equal(hit.output, plain);
  const output = String(await T.transform('smart-decode', 'decode', emojiText, {}));
  assert.ok(output.includes(plain), `端到端应解出 ${plain}，实际: ${output.slice(0, 120).replace(/\n/g, ' ')}`);
});

test('B4-2 宽松档映射可解出非 Latin 明文（CJK）', () => {
  const cjkPlain = '中文';
  const hit = S.analyzeSmartDecodeLenient(renderVariantTable(bitsOf(cjkPlain), '喵', '呜'));
  assert.ok(hit, 'CJK 明文的比特串应被宽松档解出');
  assert.equal(hit.output, cjkPlain);
});

test('B4-2 严格档先行：常规二进制/Base64/云影样本行为零变化', async () => {
  // 常规 8 位二进制（空格分组）走严格 Binary 候选，不进宽松档。
  // 载荷尾字节不得以 11 结尾——否则会被既有「斐波那契码」形状探针抢先（HEAD 同款行为，非本批变化）。
  const binaryOutput = String(await T.transform('smart-decode', 'decode', '01001000 01100101 01101100 01101100 01101111 00100000 01110111 01101111 01110010 01101100 01100100 00101110', {}));
  assert.ok(binaryOutput.includes('识别链路: Binary'), `常规二进制应走严格档，实际: ${binaryOutput.slice(0, 90).replace(/\n/g, ' ')}`);
  assert.ok(binaryOutput.includes('Hello world.'));
  assert.ok(!binaryOutput.includes('宽松档'), '严格档命中的样本不得出现宽松档标注');
  // 常规 Base64（该样本 HEAD 即走「多重 Base 嵌套密文」直解路径，行为应原样保持）
  const b64Output = String(await T.transform('smart-decode', 'decode', 'aGVsbG8gd29ybGQ=', {}));
  assert.ok(b64Output.includes('识别链路'));
  assert.ok(b64Output.includes('hello world'));
  assert.ok(!b64Output.includes('宽松档'));
  // C08 云影真题回归镜像（codec-smartdecode.test.mjs 同源向量）
  const cloudOutput = String(await T.transform('smart-decode', 'decode', C08_CIPHER, {}));
  assert.ok(cloudOutput.includes('云影'));
  assert.ok(cloudOutput.toLowerCase().includes('yunyingdigitsok'));
  assert.ok(!cloudOutput.includes('宽松档'));
});

test('B4-2 垃圾输入不误呈现：符号汤与普通数字串保持诚实拒绝', async () => {
  // 与 verify-encoding-tools 负向断言同源：符号汤垃圾不得产出假 flag 或解码链
  const garbage = String(await T.transform('smart-decode', 'decode', 'W0w&x>0^Ie~|zK9#qP$', {}));
  assert.ok(!garbage.toLowerCase().includes('flag{'), `垃圾输入不得产出假 flag: ${garbage.slice(0, 80)}`);
  assert.ok(!garbage.includes('识别链路'), `垃圾输入不得被宽松档误呈现为解码链: ${garbage.slice(0, 80)}`);
  assert.ok(!garbage.includes('宽松档'));
  // 普通数字串不得被宽松档直解（verify 同源负向样本）
  for (const digits of ['1234 5678', '2024 0101', '7295 32489']) {
    const output = String(await T.transform('smart-decode', 'decode', digits, {}));
    assert.ok(!output.includes('识别链路'), `普通数字串被误直解：${digits} → ${output.slice(0, 90)}`);
    assert.ok(!output.includes('宽松档'));
  }
});

test('B4-2 准入边界：单符号/过短/超种类数/已 resolved 明文全部拒绝', () => {
  // 单符号无信息量：kinds=1 拒绝
  assert.equal(S.analyzeSmartDecodeLenient('喵'.repeat(64)), null);
  // 符号数不足 16：拒绝
  assert.equal(S.analyzeSmartDecodeLenient('喵呜喵呜喵呜喵呜'), null);
  // 符号总数不是 8 的倍数（binary 档无整字节）：其余档解不出可读文本时整体无解
  const ragged = renderVariantTable(bitsOf('ok!').slice(0, 20), '喵', '呜');
  const raggedHit = S.analyzeSmartDecodeLenient(ragged);
  if (raggedHit) assert.notEqual(raggedHit.tier, 'binary');
  // 71 种不同字符超出 BASE64ISH≤70 上限：拒绝（汉字码表取样）
  const manyKinds = [...'的一是了我不人在他有这上们来到时大地为子中你说生国年着就那和要她出也得里后自以会家可下而过天去能对小多然于心学么之都好看起发当没成只如事把还用第样道想作种开美总从无情己面最女但现前些所同日手又行意动方期它头经长儿回位分爱老因很给名法间斯知世什两次使身者被高已亲其进此话常与活正感']
    .slice(0, 71).join('');
  assert.equal(new Set(Array.from(manyKinds)).size, 71, '前置构造：71 种不同字符');
  assert.equal(S.analyzeSmartDecodeLenient(manyKinds), null, '71 种符号应超出 BASE64ISH 上限被拒');
  // 已 resolved 的普通明文不再宽松探测
  assert.equal(S.analyzeSmartDecodeLenient('the quick brown fox jumps over'), null);
  // 空输入
  assert.equal(S.analyzeSmartDecodeLenient(''), null);
});
