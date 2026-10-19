// wafBypass 变体分类字段（2026-10 WAF 审查批次）sanitize 白名单测试：
// ① kind（bypass/control）与 effectiveness（A/B/C）合法值在 sanitizePayload 与
//    sanitizeStoredPublicPayload 两条链路都透传；
// ② 非法值丢弃（不输出键）；缺省条目 JSON 形态不变（无多余键）；
// ③ execution 域同样接受字段（共享 sanitizePayloadExecution），但不影响既有断言口径。
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  sanitizePayload,
  sanitizePayloadExecution,
  sanitizeStoredPublicPayload,
} from '../server/sanitize.mjs';

const baseEntry = {
  title: { zh: '大小写混淆', en: 'Case obfuscation' },
  command: "' UnIoN SeLeCt 1,database(),3--",
  description: { zh: '以大小写混合提交相同 UNION 语句验证过滤是否区分大小写。', en: 'Resubmit the UNION with mixed case to test case-sensitive filtering.' },
};

const withWaf = entry => ({
  id: 'p-classification',
  name: { zh: '分类字段测试载荷', en: 'Classification field fixture' },
  description: { zh: '用于验证 wafBypass 变体分类字段的白名单透传行为。', en: 'Fixture verifying whitelist passthrough of variant classification fields.' },
  category: { zh: 'SQL 注入', en: 'SQL Injection' },
  subCategory: { zh: '联合查询', en: 'UNION' },
  execution: [{ title: { zh: '基线', en: 'Baseline' }, command: "' union select 1,database(),3--", platform: 'all' }],
  wafBypass: [entry],
  references: ['https://example.com/classification'],
});

test('sanitizePayloadExecution 透传合法 kind/effectiveness', () => {
  const sanitized = sanitizePayloadExecution({
    ...baseEntry,
    kind: 'control',
    effectiveness: 'C',
  });
  assert.equal(sanitized.kind, 'control');
  assert.equal(sanitized.effectiveness, 'C');
});

test('sanitizePayloadExecution 丢弃非法 kind/effectiveness（不输出键）', () => {
  const sanitized = sanitizePayloadExecution({
    ...baseEntry,
    kind: 'fixture',
    effectiveness: 'D',
  });
  assert.equal('kind' in sanitized, false);
  assert.equal('effectiveness' in sanitized, false);
});

test('缺省分类字段的条目 JSON 形态不变', () => {
  const sanitized = sanitizePayloadExecution(baseEntry);
  assert.deepEqual(
    Object.keys(sanitized).sort(),
    ['command', 'description', 'platform', 'requiresAdmin', 'syntaxBreakdown', 'title'],
  );
  assert.equal(JSON.stringify(sanitized.kind), undefined);
});

test('sanitizePayload 的 wafBypass 链路保留分类字段', () => {
  const payload = sanitizePayload(withWaf({ ...baseEntry, kind: 'bypass', effectiveness: 'B' }));
  assert.equal(payload.wafBypass[0].kind, 'bypass');
  assert.equal(payload.wafBypass[0].effectiveness, 'B');
});

test('sanitizeStoredPublicPayload 的 wafBypass 链路保留分类字段', () => {
  const payload = sanitizeStoredPublicPayload(withWaf({ ...baseEntry, kind: 'control', effectiveness: 'A' }));
  assert.equal(payload.wafBypass[0].kind, 'control');
  assert.equal(payload.wafBypass[0].effectiveness, 'A');
  const scrubbed = sanitizeStoredPublicPayload(withWaf({ ...baseEntry, kind: 'demo', effectiveness: 'X' }));
  assert.equal('kind' in scrubbed.wafBypass[0], false);
  assert.equal('effectiveness' in scrubbed.wafBypass[0], false);
});

test('execution 域共享同一 sanitize 白名单', () => {
  const payload = sanitizePayload({
    ...withWaf(baseEntry),
    execution: [{ ...baseEntry, kind: 'bypass', effectiveness: 'A', command: 'id' }],
  });
  assert.equal(payload.execution[0].kind, 'bypass');
  assert.equal(payload.execution[0].effectiveness, 'A');
});
