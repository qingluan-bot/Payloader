// codec classical 域回归测试（A 域审计修复批次）：BUG-08 xor 已知明文完整 key 补全（C05）、
// BUG-12 rail fence 非法轨道数报错。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const CL = loadModule(path.join(srcDir, 'utils', 'codec', 'classical.ts'));
const T = loadModule(path.join(srcDir, 'utils', 'codec', 'transform.ts'));

// C05 真题向量：26 字节 hex 密文、8 字节 key 'SecRet1!'、已知明文前缀 'flag{'
const C05_CIPHER_HEX = '350902351e0c5e530c170622001545483d023c39000d6e4e3818';

// ---- BUG-08：xorKnownPlaintext 完整 key 补全 ----

test('BUG-08 C05：key 前缀 SecRe 补全为完整 SecRet1!，明文精确还原（top1）', async () => {
  const report = JSON.parse(await T.transform('xor-known-plaintext', 'decode', C05_CIPHER_HEX, { knownPlaintext: 'flag{' }));
  const candidate = report.candidates[0];
  assert.ok(Array.isArray(candidate.fullKeyCandidates) && candidate.fullKeyCandidates.length > 0);
  const top = candidate.fullKeyCandidates[0];
  assert.equal(top.keyTextPreview, 'SecRet1!');
  assert.equal(top.keyLen, 8);
  assert.equal(top.keyHex, Buffer.from('SecRet1!', 'latin1').toString('hex'));
  assert.ok(top.plaintextPreview.includes('flag{xor_repeating_key_ok}'));
});

test('BUG-08 补全不越界：6 字节 key 场景已知明文路径还原完整明文且前缀保持', async () => {
  // 31 字节明文、6 字节 key 'K3ys!6'：候选周期 L∈[5,31] 覆盖真周期 6
  const plain = 'flag{xor_completion_known_ok!!}';
  const key = Buffer.from('K3ys!6', 'latin1');
  const cipher = Buffer.from(Array.from(Buffer.from(plain, 'latin1'), (byte, index) => byte ^ key[index % key.length])).toString('hex');
  const report = JSON.parse(CL.xorKnownPlaintext(cipher, 'flag{'));
  const top = report.candidates[0].fullKeyCandidates[0];
  assert.ok(top.plaintextPreview.includes('flag{xor_completion_known_ok!!}'), `明文应还原: ${top.plaintextPreview}`);
  // 每个候选的 key 都必须以已知明文推出的 key 前缀开头（这里前缀即真 key 前 5 字节）
  const derivedPrefixHex = report.candidates[0].keyHexPrefix;
  assert.equal(derivedPrefixHex, Buffer.from('K3ys!', 'latin1').toString('hex'));
  for (const completion of report.candidates[0].fullKeyCandidates) {
    assert.ok(completion.keyHex.startsWith(derivedPrefixHex), `key 前缀应保持已知明文推导字节: ${completion.keyHex}`);
  }
});

test('BUG-08 无 knownPlaintext 参数：仅 flag{ 前缀做完整补全，其余前缀保持仅前缀输出', () => {
  const report = JSON.parse(CL.xorKnownPlaintext(C05_CIPHER_HEX, ''));
  assert.ok(Array.isArray(report.candidates) && report.candidates.length >= 10);
  for (const entry of report.candidates) {
    assert.ok(typeof entry.keyHexPrefix === 'string');
    assert.ok('fullKeyCandidates' in entry);
  }
  const flagEntry = report.candidates.find(entry => entry.knownPlaintext === 'flag{');
  assert.ok(flagEntry, '候选应包含 flag{ 前缀');
  assert.equal(flagEntry.fullKeyCandidates[0].keyTextPreview, 'SecRet1!');
  // 其余前缀不做完整补全（性能边界），输出空候选数组
  const otherEntry = report.candidates.find(entry => entry.knownPlaintext !== 'flag{');
  assert.deepEqual(Array.from(otherEntry.fullKeyCandidates), []);
});

// ---- BUG-12：rail fence 非法轨道数 ----

test('BUG-12 rails 非数字/空串/负号串报错，不再静默回落 3', () => {
  assert.throws(() => CL.railFenceEncode('abcdef', 'abc'), /Rail Fence 轨道数必须是数字/);
  assert.throws(() => CL.railFenceEncode('abcdef', ''), /Rail Fence 轨道数必须是数字/);
  assert.throws(() => CL.railFenceDecode('abcdef', '1.5'), /Rail Fence 轨道数必须是数字/);
});

test('BUG-12 rails=0/1 走"至少为 2"校验（与 railPattern 报错风格一致）', () => {
  assert.throws(() => CL.railFenceEncode('abcdef', '0'), /Rail Fence 轨道数至少为 2/);
  assert.throws(() => CL.railFenceDecode('abcdef', '1'), /Rail Fence 轨道数至少为 2/);
});

test('BUG-12 合法 rails round-trip 不回归（经典 3 轨向量）', () => {
  const classic = 'WEAREDISCOVEREDFLEEATONCE';
  assert.equal(CL.railFenceDecode(CL.railFenceEncode(classic, '3'), '3'), classic);
});
