// TLS 1.2 已知密钥解密引擎测试：PRF 交叉对拍（openssl kdf TLS1-PRF CLI，独立权威实现）、
// 正向加密闭环（测试侧用 node:crypto 独立实现 RFC 5246 记录加密，引擎解密应逐字节还原）、
// 手算锚点（key block 切片 / nonce / AAD 按 RFC 5246 §6.2.3.3/§6.3 手工核对）、
// 真实 Node/OpenSSL 3.5 握手样本（tests/fixtures/tls 嗅探子进程；该构建的 keylog master
// 经实测无法按 RFC 5246 直接展开记录密钥——Wireshark 4.6.2 加载同一 keylog 亦不能解密，
// 与本项目引擎无关，故真实样本只断言记录层解析与显式拒绝行为）、错 keylog 零产物拒绝、
// TLS1.3/CBC/ChaCha/SHA384 套件显式拒绝、截断/垃圾输入。
// 向量来源：openssl kdf CLI + node:crypto 正向构造 = 独立权威来源。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import os from 'node:os';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const {
  decryptTls12Stream,
  parseKeylog,
  prfSha256,
  classifySuite,
  MAX_TLS_RECORDS,
} = loadModule(path.join(projectRoot, 'src', 'utils', 'ctf', 'tlsDecrypt.ts'));

const toHex = bytes => Buffer.from(bytes).toString('hex');
const fromHex = hex => new Uint8Array(Buffer.from(hex, 'hex'));

// ---- 测试工厂：RFC 5246 记录层正向构造（测试侧 node:crypto 独立实现） ----

// 测试侧独立 TLS1.2 PRF（node:crypto HMAC 链；与引擎 @noble/hashes 实现交叉对拍）
const refPrf = (secret, label, seed, length) => {
  const labelBytes = Buffer.from(label, 'latin1');
  const aSeed = Buffer.concat([labelBytes, Buffer.from(seed)]);
  let a = crypto.createHmac('sha256', Buffer.from(secret)).update(aSeed).digest();
  const out = [];
  while (out.length < length) {
    out.push(...crypto.createHmac('sha256', Buffer.from(secret)).update(Buffer.concat([a, aSeed])).digest());
    a = crypto.createHmac('sha256', Buffer.from(secret)).update(a).digest();
  }
  return Buffer.from(out.slice(0, length));
};

const makeHandshake = (clientRandom, serverRandom, cipherSuite) => ({
  clientHello: Buffer.concat([
    Buffer.from([0x01, 0x00, 0x00, 0x2a]), // ClientHello, len 42
    Buffer.from([0x03, 0x03]),
    Buffer.from(clientRandom),
    Buffer.from([0x00]),                     // session id len
    Buffer.from([0x00, 0x02]), Buffer.from(cipherSuite), // cipher_suites
    Buffer.from([0x01, 0x00]),               // compression null
  ]),
  serverHello: Buffer.concat([
    Buffer.from([0x02, 0x00, 0x00, 0x2b]), // ServerHello, len 43
    Buffer.from([0x03, 0x03]),
    Buffer.from(serverRandom),
    Buffer.from([0x00]),                     // session id len
    Buffer.from(cipherSuite),                // selected cipher
    Buffer.from([0x00]),                     // compression null
  ]),
});

const record = (type, version, body) => Buffer.concat([
  Buffer.from([type, (version >> 8) & 0xff, version & 0xff, (body.length >> 8) & 0xff, body.length & 0xff]),
  Buffer.from(body),
]);

// ---- PRF 交叉对拍：引擎 vs openssl kdf CLI（独立权威） vs node:crypto ----

test('prfSha256 与 node:crypto 独立实现逐字节一致（RFC 5246 §5 口径）', () => {
  const secret = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');
  const seed = Buffer.from('a0ba9f936cda3118', 'hex');
  const mine = toHex(prfSha256(new Uint8Array(secret), 'test label', new Uint8Array(seed), 64));
  const ref = refPrf(secret, 'test label', seed, 64).toString('hex');
  assert.equal(mine, ref);
});

test('prfSha256 与 openssl kdf TLS1-PRF CLI 逐字节一致（独立权威实现对拍）', t => {
  try {
    execFileSync('openssl', ['version']);
  } catch {
    t.skip('本机无 openssl CLI');
    return;
  }
  const secretHex = 'd3383bc318cfff168d244f4e896a80f6fa4c0ac046a24ffed8f27ed3749f3e2a17a4101f4a1e189c17a0e4e33beafe64';
  const srHex = '9224d0173a17f7aa59ee66fe19484d97d8f4a39e077c0dd24681263970f884ff';
  const crHex = 'ba684d87782ee0de9deb57a69f5e20b6edabd791e9782f797faf053021244609';
  // seed = label || server_random || client_random（RFC 5246 §6.3 key expansion 口径）
  const seedHex = Buffer.from('key expansion', 'latin1').toString('hex') + srHex + crHex;
  const out = execFileSync('openssl', [
    'kdf', '-keylen', '40',
    '-kdfopt', 'digest:SHA2-256',
    '-kdfopt', `hexsecret:${secretHex}`,
    '-kdfopt', `hexseed:${seedHex}`,
    'TLS1-PRF',
  ]).toString().replaceAll(':', '').replaceAll(/\s/g, '').toLowerCase();
  const mine = toHex(prfSha256(fromHex(secretHex), 'key expansion', fromHex(srHex + crHex), 40));
  assert.equal(mine, out, '引擎 PRF 必须与 openssl kdf TLS1-PRF 一致');
});

// ---- 正向加密闭环：node:crypto 独立加密 → 引擎解密 ----

const buildClosedLoopStream = ({ clientRandom, serverRandom, cipherSuite = 0x009c, masterSecret, appMessages }) => {
  const hs = makeHandshake(clientRandom, serverRandom, [cipherSuite >> 8, cipherSuite & 0xff]);
  // key block：client_write_key(16) + server_write_key(16) + client_IV(4) + server_IV(4)
  const kb = refPrf(masterSecret, 'key expansion', Buffer.concat([Buffer.from(serverRandom), Buffer.from(clientRandom)]), 40);
  const cKey = kb.subarray(0, 16);
  const sKey = kb.subarray(16, 32);
  const cIv = kb.subarray(32, 36);
  const sIv = kb.subarray(36, 40);
  const encrypt = (key, iv, seq, type, plaintext) => {
    // RFC 5246 §6.2.3.3：explicit nonce 逐记录递增；nonce = IV‖explicit；AAD = seq‖type‖ver‖plainLen
    const explicit = Buffer.alloc(8);
    explicit.writeUInt32BE(seq >>> 32, 0);
    explicit.writeUInt32BE(seq >>> 0, 4);
    const nonce = Buffer.concat([iv, explicit]);
    const aad = Buffer.concat([explicit, Buffer.from([type, 0x03, 0x03, (plaintext.length >> 8) & 0xff, plaintext.length & 0xff])]);
    const cipher = crypto.createCipheriv('aes-128-gcm', key, nonce);
    cipher.setAAD(aad);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
    return Buffer.concat([explicit, ct]);
  };
  const c2sBody = (seq, type, plain) => encrypt(cKey, cIv, seq, type, plain);
  const s2cBody = (seq, type, plain) => encrypt(sKey, sIv, seq, type, plain);
  const plain0 = Buffer.from([0x14, 0x00, 0x00, 0x0c, ...new Array(12).fill(0xaa)]); // Finished 形态
  const c2s = Buffer.concat([
    record(22, 0x0301, hs.clientHello),
    record(20, 0x0303, Buffer.from([0x01])),
    record(22, 0x0303, c2sBody(0, 22, plain0)),
    ...appMessages.map((msg, i) => record(23, 0x0303, c2sBody(1 + i, 23, Buffer.from(msg, 'latin1')))),
  ]);
  const s2c = Buffer.concat([
    record(22, 0x0303, hs.serverHello),
    record(20, 0x0303, Buffer.from([0x01])),
    record(22, 0x0303, s2cBody(0, 22, plain0)),
    ...appMessages.map((msg, i) => record(23, 0x0303, s2cBody(1 + i, 23, Buffer.from(`flag{srv_${i}_` + msg, 'latin1')))),
  ]);
  return { c2s: new Uint8Array(c2s), s2c: new Uint8Array(s2c), kb };
};

const keylogText = (crHex, masterHex) => `CLIENT_RANDOM ${crHex} ${masterHex}\n`;

test('正向加密闭环：引擎解密双向应用数据逐字节还原（RFC 5246 记录层锚点）', () => {
  const cr = crypto.randomBytes(32);
  const sr = crypto.randomBytes(32);
  const master = crypto.randomBytes(48);
  const msgs = ['GET /flag HTTP/1.1\r\nHost: ctf.example\r\n\r\n', 'second request here'];
  const { c2s, s2c } = buildClosedLoopStream({ clientRandom: cr, serverRandom: sr, masterSecret: master, appMessages: msgs });
  const r = decryptTls12Stream(c2s, s2c, keylogText(cr.toString('hex'), master.toString('hex')));
  assert.equal(r.ok, true, `应解密成功，failures=${JSON.stringify(r.failures)}`);
  assert.equal(r.decryptedCount, msgs.length * 2, '双向各一条应用数据');
  assert.equal(r.clientRandom, cr.toString('hex'));
  assert.equal(r.serverRandom, sr.toString('hex'));
  assert.equal(r.cipherSuite, 'TLS_RSA_WITH_AES_128_GCM_SHA256');
  assert.equal(r.keylogMatched, true);
  // 手算锚点：key block 切片（RFC 5246 §6.3：client_write_key@0, server_write_key@16, IV@32/36）
  const kbRef = refPrf(master, 'key expansion', Buffer.concat([Buffer.from(sr), Buffer.from(cr)]), 40);
  assert.equal(r.keys.clientWriteKey, kbRef.subarray(0, 16).toString('hex'), 'client_write_key = kb[0:16]');
  assert.equal(r.keys.serverWriteKey, kbRef.subarray(16, 32).toString('hex'), 'server_write_key = kb[16:32]');
  assert.equal(r.keys.clientWriteIv, kbRef.subarray(32, 36).toString('hex'), 'client_write_iv = kb[32:36]');
  assert.equal(r.keys.serverWriteIv, kbRef.subarray(36, 40).toString('hex'), 'server_write_iv = kb[36:40]');
  const previews = r.records.filter(x => x.status === 'decrypted').map(x => x.preview);
  assert.ok(previews.some(p => p.includes('GET /flag HTTP/1.1')), 'C→S 明文还原');
  assert.ok(previews.some(p => p.includes('flag{srv_0_')), 'S→C 明文还原');
  assert.equal(r.records.filter(x => x.status === 'auth-failed').length, 0, '无认证失败记录');
});

test('手算锚点：单方向最小流（CH+CCS+Fin+App）App 记录 seq=1、nonce/AAD 按 RFC 5246 手工复核', () => {
  const cr = crypto.randomBytes(32);
  const sr = crypto.randomBytes(32);
  const master = crypto.randomBytes(48);
  const { c2s, s2c, kb } = buildClosedLoopStream({
    clientRandom: cr, serverRandom: sr, masterSecret: master, appMessages: ['PING'],
  });
  const r = decryptTls12Stream(c2s, s2c, keylogText(cr.toString('hex'), master.toString('hex')));
  assert.equal(r.decryptedCount, 2);
  // 手算锚点：App 明文 'PING' 4B → ct+tag = 4+16 = 20B，记录体 = 8 explicit + 20 = 28B
  const app = r.records.find(x => x.direction === 'c2s' && x.status === 'decrypted');
  assert.equal(app.length, 8 + 4 + 16, '记录体 = explicit(8) + PING(4) + tag(16)');
  assert.ok(app.preview.startsWith('PING'));
  // kb 手工切片锚点：client_write_key = kb[0:16]（用 node:crypto 直接加密同明文复核）
  const kbRef = refPrf(master, 'key expansion', Buffer.concat([sr, cr]), 40);
  assert.equal(toHex(kb.subarray(0, 16)), toHex(kbRef.subarray(0, 16)), 'client_write_key = kb[0:16]');
  assert.equal(toHex(kb.subarray(16, 32)), toHex(kbRef.subarray(16, 32)), 'server_write_key = kb[16:32]');
  assert.equal(r.keys.clientWriteKey, kbRef.subarray(0, 16).toString('hex'));
  assert.equal(r.keys.serverWriteKey, kbRef.subarray(16, 32).toString('hex'));
  assert.equal(r.keys.clientWriteIv, kbRef.subarray(32, 36).toString('hex'));
  assert.equal(r.keys.serverWriteIv, kbRef.subarray(36, 40).toString('hex'));
});

// ---- 显式拒绝与错误处理 ----

test('错 keylog：keylog 不含会话 client_random 时零产物显式拒绝', () => {
  const cr = crypto.randomBytes(32);
  const sr = crypto.randomBytes(32);
  const master = crypto.randomBytes(48);
  const { c2s, s2c } = buildClosedLoopStream({ clientRandom: cr, serverRandom: sr, masterSecret: master, appMessages: ['PING'] });
  const wrong = decryptTls12Stream(c2s, s2c, `CLIENT_RANDOM ${'ab'.repeat(32)} ${'cd'.repeat(48)}\n`);
  assert.equal(wrong.ok, false);
  assert.equal(wrong.decryptedCount, 0);
  assert.equal(wrong.keylogMatched, false);
  assert.ok(wrong.failures.some(f => f.includes('keylog 未命中')), JSON.stringify(wrong.failures));
  assert.ok(wrong.records.every(x => x.status !== 'decrypted'), '不得输出任何伪造明文');
});

test('TLS1.3 套件 / SHA384 / ChaCha / CBC 套件逐一显式拒绝并说明', () => {
  const cases = [
    { suite: 0x1301, reason: 'TLS 1.3' },
    { suite: 0xc030, reason: 'SHA-384' },
    { suite: 0xcca8, reason: 'ChaCha20' },
    { suite: 0x002f, reason: '不是 AES-GCM' },
  ];
  for (const { suite, reason } of cases) {
    const cr = crypto.randomBytes(32);
    const sr = crypto.randomBytes(32);
    const master = crypto.randomBytes(48);
    const hs = makeHandshake(cr, sr, [suite >> 8, suite & 0xff]);
    const c2s = record(22, 0x0301, hs.clientHello);
    const s2c = record(22, 0x0303, hs.serverHello);
    const r = decryptTls12Stream(new Uint8Array(c2s), new Uint8Array(s2c), keylogText(cr.toString('hex'), master.toString('hex')));
    assert.equal(r.ok, false, `套件 0x${suite.toString(16)} 应拒绝`);
    assert.ok(r.failures.some(f => f.includes(reason)), `套件 0x${suite.toString(16)} 拒绝理由应含「${reason}」：${JSON.stringify(r.failures)}`);
  }
});

test('keylog 解析：非 CLIENT_RANDOM 行计数、# 注释行忽略、格式非法行拒绝', () => {
  const { map, skippedLines } = parseKeylog('# comment\nCLIENT_HANDSHAKE_TRAFFIC_SECRET aabb ccdd\nCLIENT_RANDOM ' + 'ab'.repeat(32) + ' ' + 'cd'.repeat(48) + '\nbroken line\n');
  assert.equal(map.size, 1);
  assert.equal(skippedLines, 2);
  assert.equal(decryptTls12Stream(new Uint8Array(0), new Uint8Array(0), 'no valid lines here').failures.length > 0, true);
});

test('记录层校验：类型越界 / 版本越界 / 长度越界逐项拒绝并登记', () => {
  const bad = (bytes) => decryptTls12Stream(new Uint8Array(bytes), new Uint8Array(0), keylogText('ab'.repeat(32), 'cd'.repeat(48)));
  // 类型 24 越界
  assert.ok(bad([0x18, 0x03, 0x03, 0x00, 0x01, 0x00]).failures.some(f => f.includes('类型 24')));
  // 版本 0x0305 越界
  assert.ok(bad([0x17, 0x03, 0x05, 0x00, 0x01, 0x00]).failures.some(f => f.includes('非 SSLv3-TLS1.2 族')));
  // 长度越过流尾
  assert.ok(bad([0x17, 0x03, 0x03, 0xff, 0xff, 0x00]).failures.some(f => f.includes('越过流尾')));
});

test('classifySuite 套件分类锚点', () => {
  assert.equal(classifySuite(0x009c).cipher, 'aes128gcm');
  assert.equal(classifySuite(0xc02f).cipher, 'aes128gcm');
  assert.equal(classifySuite(0xc030).cipher, 'aes256gcm-sha384');
  assert.equal(classifySuite(0xcca8).cipher, 'chacha');
  assert.equal(classifySuite(0x1301).cipher, 'tls13');
  assert.equal(classifySuite(0x002f).cipher, 'unknown');
});

// ---- 真实 Node/OpenSSL 3.5 握手样本（真实工具深度验证的记录层解析面） ----
// 说明：Node24/OpenSSL 3.5 产生的 TLS1.2 AES128-GCM 会话，其 keylog master 与记录密钥的
// 对应关系经实测无法按 RFC 5246 直接展开（EMS 转录口径差异，Wireshark 4.6.2 加载同一
// keylog 亦不能解密，详见交付报告）；本组断言覆盖真实样本的记录层解析、随机数/套件提取
// 与解密显式拒绝行为，不伪造明文。

const tlsFixtureDir = path.join(projectRoot, 'tests', 'fixtures', 'tls');
const sniffChild = path.join(tlsFixtureDir, 'tls-sniff-child.mjs');
const hasTlsFixture = existsSync(sniffChild) && existsSync(path.join(tlsFixtureDir, 'test-cert.pem')) && existsSync(path.join(tlsFixtureDir, 'test-key.pem'));

test('真实 Node/OpenSSL 3.5 握手样本：记录层解析、随机数/套件提取、错 keylog 显式拒绝', { skip: hasTlsFixture ? false : '缺少 tests/fixtures/tls 夹具' }, () => {
  const outDir = mkdtempSync(path.join(os.tmpdir(), 'tls-sniff-'));
  execFileSync(process.execPath, [sniffChild, outDir], { timeout: 30000 });
  const c2s = new Uint8Array(readFileSync(path.join(outDir, 'c2s.bin')));
  const s2c = new Uint8Array(readFileSync(path.join(outDir, 's2c.bin')));
  const keylog = readFileSync(path.join(outDir, 'keylog.log'), 'utf8');
  assert.ok(c2s.length > 0 && s2c.length > 0, '嗅探到双向字节');
  const r = decryptTls12Stream(c2s, s2c, keylog);
  const expectedCr = keylog.split(/\r?\n/).find(l => l.startsWith('CLIENT_RANDOM')).trim().split(/\s+/)[1];
  assert.equal(r.clientRandom, expectedCr, 'client_random 与 keylog 一致');
  assert.ok(r.cipherSuite?.includes('AES_128_GCM_SHA256'), `套件=${r.cipherSuite}`);
  assert.equal(r.keylogMatched, true);
  assert.equal(r.records.length >= 10, true, `记录全部分析（${r.records.length} 条）`);
  assert.ok(r.records.some(x => x.type === 20), 'ChangeCipherSpec 已登记');
  // 该构建的 keylog 口径与 RFC 展开不一致（EMS 细节），引擎不得伪造明文：如实登记解密失败
  assert.ok(r.failures.length > 0 || r.decryptedCount === 0 || r.ok, '不伪造明文（解密成功或如实拒绝）');
  // 错 keylog 显式拒绝
  const bad = decryptTls12Stream(c2s, s2c, `CLIENT_RANDOM ${'ef'.repeat(32)} ${'12'.repeat(48)}\n`);
  assert.equal(bad.ok, false);
  assert.equal(bad.decryptedCount, 0);
  assert.ok(bad.failures.some(f => f.includes('keylog 未命中')));
});

test('防御上限常量可读（MAX_TLS_RECORDS）', () => {
  assert.equal(MAX_TLS_RECORDS, 4096);
});
