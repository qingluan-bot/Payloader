// 谐音对照解码契约测试：tihuan 真题三段全文独立重嵌（与源码向量同源但独立成文，防同源恒真）、
// 冲突/未映射/空对照/长度不一致边界、coverage 分母含未替换字符、transform 层 round-trip 与操作卡注册。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();

const parityChinese = loadModule(path.join(srcDir, 'utils', 'codec', 'parityChinese.ts'));
const operations = loadModule(path.join(srcDir, 'utils', 'codec', 'operations.ts'));

// tihuan.py 真题三段全文（MIT 来源：https://github.com/Dest1ny-Sec/Des-CTF-Knowledge
// CTF常用脚本及工具/谍报-替换普通话/tihuan.py），原样重嵌、零字符改动。
const STR1 = "今天上午，朝歌区梆子公司决定，在每天三更天不亮免费在各大小区门口设卡为全城提供二次震耳欲聋的敲更提醒，呼吁大家早睡早起，不要因为贪睡断送大好人生，时代的符号是前进。为此，全区老人都蹲在该公司东边树丛合力抵制，不给公司人员放行，场面混乱。李罗鹰住进朝歌区五十年了，人称老鹰头，几年孙子李虎南刚从东北当猎户回来，每月还寄回来几块鼹鼠干。李罗鹰当年遇到的老婆是朝歌一枝花，所以李南虎是长得非常秀气的一个汉子。李罗鹰表示：无论梆子公司做的对错，反正不能打扰他孙子睡觉，子曰：‘睡觉乃人之常情’。梆子公司这是连菩萨睡觉都不放过啊。李南虎表示：梆子公司智商捉急，小心居民猴急跳墙！这三伏天都不给睡觉，这不扯淡么！到了中午人群仍未离散，更有人提议要烧掉这个公司，公司高层似乎恨不得找个洞钻进去。直到治安人员出现才疏散人群归家，但是李南虎仍旧表示爷爷年纪大了，睡不好对身体不好。";
const STR2 = "喵天上午，汪歌区哞叽公司决定，在每天八哇天不全免费在各大小区门脑设卡为全城提供双次震耳欲聋的敲哇提醒，呼吁大家早睡早起，不要因为贪睡断送大好人生，时代的编号是前进。为此，全区眠人都足在该公司流边草丛合力抵制，不给公司人员放行，场面混乱。李罗鸟住进汪歌区五十年了，人称眠鸟顶，几年孙叽李熬值刚从流北当屁户回来，每月还寄回来几块报信干。李罗鸟当年遇到的眠婆是汪歌一枝花，所以李值熬是长得非常秀气的一个汉叽。李罗鸟表示：无论哞叽公司做的对错，反正不能打扰他孙叽睡觉，叽叶：‘睡觉乃人之常情’。哞叽公司这是连衣服睡觉都不放过啊。李值熬表示：哞叽公司智商捉急，小心居民猴急跳墙！这八伏天都不给睡觉，这不扯淡么！到了中午人群仍未离散，哇有人提议要烧掉这个公司，公司高层似乎恨不得找个洞钻进去。直到治安人员出现才疏散人群归家，但是李值熬仍旧表示爷爷年纪大了，睡不好对身体不好。";
const STR3 = "喵汪哞叽双哇顶，眠鸟足屁流脑，八哇报信断流脑全叽，眠鸟进北脑上草，八枝遇孙叽，孙叽对熬编叶：值天衣服放鸟捉猴顶。鸟对：北汪罗汉伏熬乱天门。合编放行，卡编扯呼。人离烧草，报信归洞，孙叽找爷爷。";
// 期望解码输出（主控预计算基准：str3 逐字回查 str2 首次出现位置→str1）。
const EXPECTED = "今朝梆子二更头，老鹰蹲猎东口，三更鼹鼠断东口亮子，老鹰进北口上树，三枝遇孙子，孙子对虎符曰：南天菩萨放鹰捉猴头。鹰对：北朝罗汉伏虎乱天门。合符放行，卡符扯呼。人离烧树，鼹鼠归洞，孙子找爷爷。";

test('tihuan 真题：对照文本构建映射 24 键全不冲突，coverage 严格 24/206', () => {
  const { map, coverage, conflicts } = parityChinese.buildHomophoneMap(STR1, STR2);
  assert.equal(map.size, 24, `映射键数应为 24，实际 ${map.size}`);
  assert.equal(new Set(map.values()).size, 24, '映射值去重数应为 24');
  assert.equal(conflicts, 0, '权威向量不应有映射冲突');
  assert.equal(coverage, 24 / 206, 'coverage 应严格等于 24/206（分母为参考明文全部不同字数，含未替换字符）');
});

test('tihuan 真题：decode str3 严格还原期望输出，unmapped 50', () => {
  const { map } = parityChinese.buildHomophoneMap(STR1, STR2);
  const { text, unmapped } = parityChinese.homophoneDecode(STR3, map);
  assert.equal(text, EXPECTED, 'str3 解码输出应与期望全文严格一致');
  assert.equal(unmapped, 50, '映射外字符计数应为 50');
});

test('同明字对多密字：保留首次且冲突计数正确', () => {
  // 逐位对齐 ababab/xyxyxz：a→x、b→y 已入映射，末位 b→z 为同明字对多密字，保留首次 b→y。
  const { map, conflicts, coverage } = parityChinese.buildHomophoneMap('ababab', 'xyxyxz');
  assert.equal(conflicts, 1, '冲突应计数 1');
  assert.equal(map.size, 2, '同明字重复出现不新增键');
  assert.equal(map.get('a'), 'x');
  assert.equal(map.get('b'), 'y', '同明字对多密字应保留首次映射');
  assert.equal(coverage, 1, '映射值去重 2 / 明文不同字 2');
});

test('未映射边界：映射外字符原样保留且计数正确', () => {
  const { map } = parityChinese.buildHomophoneMap('ab', 'xy');
  const { text, unmapped } = parityChinese.homophoneDecode('xyq!', map);
  assert.equal(text, 'abq!', '映射外字符应原样保留');
  assert.equal(unmapped, 2, '映射外字符应逐个计数');
});

test('空对照：任一侧为空即抛错', () => {
  assert.throws(() => parityChinese.buildHomophoneMap('', ''), /不能为空/);
  assert.throws(() => parityChinese.buildHomophoneMap('', 'abc'), /不能为空/);
});

test('长度不一致：两串码点数不同即抛错', () => {
  assert.throws(() => parityChinese.buildHomophoneMap('abc', 'ab'), /长度不一致/);
});

test('coverage 分母含未替换字符：ab/ax 小例严格等于 1/2', () => {
  // 位 0 a===a 未替换跳过（仍计入分母），位 1 b→x 入映射：值去重 1 / 明文不同字 2。
  const { map, coverage } = parityChinese.buildHomophoneMap('ab', 'ax');
  assert.equal(map.size, 1);
  assert.equal(coverage, 1 / 2, '未替换字符应计入 coverage 分母（1/2）');
});

test('transform 层：defaultParams 合并后 encode 权威样例 + decode 报告式输出', async () => {
  const params = { ...operations.defaultParams, referencePlain: STR1, referenceCipher: STR2 };
  const encoded = await parityChinese.parityCnTransform('homophone-contrast', 'encode', '今朝梆子二更头', params);
  assert.equal(encoded, '喵汪哞叽双哇顶', '正向替换应为权威样例输出（encode 保持纯文本）');
  const decoded = await parityChinese.parityCnTransform('homophone-contrast', 'decode', encoded, params);
  assert.ok(decoded.startsWith('今朝梆子二更头'), 'decode 输出应以还原文本开头');
  assert.match(decoded, /—— 谐音映射表（明→密，共 24 组）——/, 'decode 输出应附映射表展示');
  assert.match(decoded, /—— 映射外字符 0 个已原样保留 ——/, 'decode 输出应附未映射字符计数');
});

test('operations 表注册：id 存在且 params 含两个新 ParamKey', () => {
  const card = operations.operations.find(op => op.id === 'homophone-contrast');
  assert.ok(card, 'operations 表应有 homophone-contrast 操作卡');
  assert.equal(card.category, 'crypto');
  assert.deepEqual(Array.from(card.params), ['referencePlain', 'referenceCipher']);
});
