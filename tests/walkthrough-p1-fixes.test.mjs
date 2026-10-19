// 走查报告 P1 功能缺陷修复回归（E-01 / F-01 / F-02 / F-04）：
// E-01 工具命令高亮吞并 scheme（variables.replaceParts 命中区间未对齐到变量值精确出现区间）
// F-01 CSP 缺 media-src 放不进 blob 音频（http-helpers）+ AudioStegoCard 无加载失败兜底
// F-02 ZIP 爆破 tried=0 强制清空进度态（ZipBruteCard）→ 零反馈
// F-04 菜单选【…解密】后模式高亮仍停在编码（CodecWorkbench primary 硬编码）
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const read = relativePath => readFile(new URL(`../${relativePath}`, import.meta.url), 'utf8');
const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { resolveVariableParts, resolveVariableText } = loadModule(path.join(srcDir, 'utils', 'variables.ts'));
const { defaultGlobalVariables } = loadModule(path.join(srcDir, 'data', 'globalVariables.ts'));

const withVariable = (key, value) => defaultGlobalVariables.map(item => (item.key === key ? { ...item, value } : item));

test('E-01：sqlmap 命令含 scheme 时高亮分段拼接与原文逐字符一致（不再 http://http://）', () => {
  const command = 'sqlmap -u "http://127.0.0.1:8080/lab?id=1"';
  const parts = resolveVariableParts(command, defaultGlobalVariables);
  const joined = parts.map(part => part.text).join('');
  assert.equal(joined, command, '显示分段拼接必须还原原文');

  const highlighted = parts.filter(part => part.key);
  assert.equal(highlighted.length, 1);
  assert.equal(highlighted[0].key, 'PROXY');
  // 高亮段恰好是"变量值在原文中的精确匹配区间"：值本身出现在原文里，恒等替换
  assert.equal(highlighted[0].value, 'http://127.0.0.1:8080');
  assert.equal(highlighted[0].text, highlighted[0].value);
  assert.equal(highlighted[0].raw, highlighted[0].value);
  assert.ok(command.includes(highlighted[0].text));
  // 复制链路（resolveVariableText）同样不得产生双 scheme
  assert.equal(resolveVariableText(command, defaultGlobalVariables), command);
});

test('E-01：同一 URL 多次出现均按值出现区间恒等替换，拼接仍等于原文', () => {
  const command = 'curl -x http://127.0.0.1:8080 http://127.0.0.1:8080/admin';
  const parts = resolveVariableParts(command, defaultGlobalVariables);
  assert.equal(parts.map(part => part.text).join(''), command);
  const highlighted = parts.filter(part => part.key);
  assert.ok(highlighted.length >= 2);
  for (const part of highlighted) {
    assert.equal(part.key, 'PROXY');
    assert.equal(part.text, 'http://127.0.0.1:8080');
  }
});

test('E-01：自定义代理值时替换语义不受影响（扩展不吞正常替换）', () => {
  const command = 'sqlmap -u "http://127.0.0.1:8080/lab?id=1"';
  const custom = withVariable('PROXY', 'socks5://10.10.10.10:1080');
  const parts = resolveVariableParts(command, custom);
  assert.equal(parts.map(part => part.text).join(''), 'sqlmap -u "socks5://10.10.10.10:1080/lab?id=1"');
  const proxyPart = parts.find(part => part.key === 'PROXY');
  assert.equal(proxyPart.text, 'socks5://10.10.10.10:1080');
});

test('E-01：值是命中串后缀时（如 COOKIE 短值）保持原替换行为，不向前扩展', () => {
  const command = 'curl -H "Cookie: PHPSESSID=xxx" http://target.com/';
  const custom = withVariable('COOKIE', 'C=short');
  const parts = resolveVariableParts(command, custom);
  const joined = parts.map(part => part.text).join('');
  assert.equal(joined, 'curl -H "Cookie: C=short" http://target.com/');
});

test('E-01：占位符变量替换与高亮不受影响（{TARGET} 正常替换）', () => {
  const command = 'nmap -sV {TARGET}';
  const custom = withVariable('TARGET', '10.0.0.1');
  const parts = resolveVariableParts(command, custom);
  const targetPart = parts.find(part => part.key === 'TARGET');
  assert.ok(targetPart, '占位符必须仍被识别为变量段');
  assert.equal(targetPart.text, '10.0.0.1');
  assert.equal(parts.map(part => part.text).join(''), 'nmap -sV 10.0.0.1');
});

test('F-01：CSP 含 media-src \'self\' blob:（blob 音频不再被 default-src 拒载）', async () => {
  const { contentSecurityPolicy, baseResponseHeaders } = await import('../server/http-helpers.mjs');
  assert.match(contentSecurityPolicy, /media-src 'self' blob:/);
  assert.match(baseResponseHeaders['content-security-policy'], /media-src 'self' blob:/);
});

test('F-01：AudioStegoCard 倒放 audio 挂 onError，加载失败渲染双语红字兜底', async () => {
  const source = await read('src/components/ctf/AudioStegoCard.tsx');
  const audioBlock = source.match(/<audio[\s\S]*?\/>/)?.[0] ?? '';
  assert.match(audioBlock, /onError=/, 'audio 元素必须挂 onError');
  assert.match(source, /倒放音频加载失败/, '缺少 zh 文案');
  assert.match(source, /Reversed audio failed to load/, '缺少 en 文案');
});

test('F-02：ZipBruteCard 零尝试结果不再清空，终态区分"无法爆破"并给双语引导', async () => {
  const source = await read('src/components/ctf/ZipBruteCard.tsx');
  assert.doesNotMatch(source, /result\.tried > 0 \|\| result\.password !== null \? result : null/, 'tried=0 的结果不得被强制清空');
  assert.match(source, /setProgress\(result\)/, '终态一律保留');
  assert.match(source, /progress\.tried === 0/, '必须区分零尝试终态');
  assert.match(source, /疑似伪加密或无有效候选/, '缺少 zh 引导文案');
  assert.match(source, /pseudo-encryption or no valid candidates/, '缺少 en 引导文案');
  // 引擎拒绝（加密类型未知等 throw 路径）也要留下持久终态，不能只剩会自动消失的 toast
  assert.match(source, /setRunError/);
});

test('F-04：执行方向同步模式高亮（run 收口写入，编码/解码按钮按方向切换 primary）', async () => {
  const source = await read('src/components/CodecWorkbench.tsx');
  assert.match(source, /setActiveDirection\(direction\)/, 'run 是所有执行入口的收口，必须同步方向');
  assert.doesNotMatch(source, /className="mode-btn primary"/, 'primary 不得再硬编码在编码按钮上');
  assert.match(source, /mode-btn\$\{activeDirection === 'decode' \? ' primary' : ''\}/, '解码按钮按方向获得高亮');
  // 菜单动作项本身携带方向语义并按该方向执行
  assert.match(source, /void run\(action\.direction, action\.id\)/);
});
