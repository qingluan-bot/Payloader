// Flask session 全链测试（itsdangerous 2.2.0 权威向量 + ECDSA ±s 符号消歧）：
// ① decode：明文 / 压缩（前导 "." 四段）/ 空时间戳段 / 从右拆拒绝旧 bug 场景
// ② sign：4 种 key_derivation × SHA1/SHA256 全对拍 itsdangerous 产出、sort_keys、压缩 auto/never/always
// ③ verify：正确 secret 通过、错误 secret 常数时间拒绝、maxAge 过期 / 未生效
// ④ ECDSA nonce 复用：secp256k1 独立向量（Python SEC1 仿射独立生成）、low-s 翻号对公钥锁定、
//    Schnorr ±s 组合、雅可比点乘 d·G==Q 自检
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const web = loadModule(path.join(projectRoot, 'src', 'utils', 'ctf', 'webTools.ts'));
const prng = loadModule(path.join(projectRoot, 'src', 'utils', 'codec', 'prng.ts'));
const {
  decodeFlaskSession, decodeFlaskSessionFull, flaskSessionSign, flaskSessionVerify,
  deriveFlaskSigningKey, parseFlaskSessionParts,
} = web;
const { signatureNonceReuseHelper, ecPublicKeyMatchesPrivateKey, ecSec1CurveParams } = prng;

// 权威向量：本机 Python 3.14 + itsdangerous 2.2.0 产出（生成脚本见交付报告；cookie 内容含中文/嵌套对象，
// 时间戳固定 1700000000）。向量经 itsdangerous 自身 loads() 回验。
const ITS_DANGEROUS_VERSION = '2.2.0';
const FIXED_TS = 1700000000;
const VECTORS = {
  // Flask 真实口径：URLSafeTimedSerializer(secret, salt='cookie-session', key_derivation='hmac', digest=sha1)
  flask_plain: 'eyJ1c2VyIjoiYWRtaW4iLCJ1aWQiOjEwMDEsInByb2ZpbGUiOnsicm9sZSI6InJvb3QiLCJ0YWdzIjpbImEiLCJiIl19LCLkuK3mlofplK4iOiLkuK3mloflgLwifQ.ZVPxAA.6sDbJaoc4uEeFAi1OsQWz6ZKh2o',
  // 同口径压缩版：zlib 显著变短触发 auto，payload 段带前导 "."（split 出四段——修复前的报错场景）
  flask_compressed: '.eJyrVsrJT1eyUkrLSUyvTs7PLShKLS5OTYkvTi0uzszPq1UYlShAl1DSUUrOU7JSetrX_XzPyid7Zr1YP_fZ1u4X66fSTkRJRylPycrEqBYASYXP7g.ZVPxAA.zwyXzKpiV4Y3bZuG6wNR61Un5O0',
  // itsdangerous Serializer 默认口径（salt='itsdangerous'、django-concat、sha1、原序）。
  // 注意：Python 侧 URLSafeTimedSerializer(salt=None) 时 Signer 会回落到自己的 b'itsdangerous.Signer'，
  // 与 Serializer 默认 salt='itsdangerous' 不同——本向量按 Serializer 真实默认（不显式传 None）生成。
  default_django_concat_sha1: 'eyJ1c2VyIjoiYWRtaW4iLCJ1aWQiOjEwMDEsInByb2ZpbGUiOnsicm9sZSI6InJvb3QiLCJ0YWdzIjpbImEiLCJiIl19LCLkuK3mlofplK4iOiLkuK3mloflgLwifQ.ZVPxAA.0QHnetibhLspeyjay1Ql_5A6jX8',
  // 四种 derivation × SHA1/SHA256（salt='itsdangerous'、secret='K'、payload {"a":1}）
  timed_concat_sha1: 'eyJhIjoxfQ.ZVPxAA.2mahePgx3y32_KWm1yt484CHVFM',
  timed_concat_sha256: 'eyJhIjoxfQ.ZVPxAA.Sqmu45wJR4mxG3A3OjouOhkOO_toeE84CGMt2reY0j0',
  timed_none_sha1: 'eyJhIjoxfQ.ZVPxAA.-kmx5zbMUV_Vcv1zlC3c746AxS4',
  timed_none_sha256: 'eyJhIjoxfQ.ZVPxAA.WqMif7ULX-l52q6XYuEMpimvJpOX19coe1BNRoLk5ms',
  timed_hmac_sha1: 'eyJhIjoxfQ.ZVPxAA.g3eLfq9lq2t9mP1Ia-kHWvZpmOY',
  timed_hmac_sha256: 'eyJhIjoxfQ.ZVPxAA.ukbAPR7childLm7aQSJqlhCTKONKEogE1lNr3ZMxerk',
  // sort_keys=True（Flask json dumps 排序口径）
  flask_sortkeys: 'eyJhbHBoYSI6MSwiYmV0YSI6MiwiY2giOiLkuK3mlocifQ.ZVPxAA.wSrykpbtfFMk3kuUNBDbDK3itSU',
  // 无时间戳两段（URLSafeSerializer，django-concat）
  untimed_django_concat_sha1: 'eyJ1c2VyIjoiYWRtaW4iLCJ1aWQiOjEwMDEsInByb2ZpbGUiOnsicm9sZSI6InJvb3QiLCJ0YWdzIjpbImEiLCJiIl19LCLkuK3mlofplK4iOiLkuK3mloflgLwifQ.zMBJ6y886VIWSk0Xm0Jp_x4zQeM',
  // 时间戳=0：int_to_bytes(0) 为空字节串 → 时间戳段为空
  ts_zero: 'eyJ6IjowfQ..d0x4JriaMN60pWoHCkZM2T68Clw',
};

test(`Flask 解码：明文三段（itsdangerous ${ITS_DANGEROUS_VERSION} Flask 口径向量）`, async () => {
  const full = await decodeFlaskSessionFull(VECTORS.flask_plain);
  assert.equal(full.ok, true, JSON.stringify(full));
  if (!full.ok) return;
  assert.equal(full.compressed, false);
  assert.equal(full.withTimestamp, true);
  assert.equal(full.isJson, true);
  const parsed = JSON.parse(full.payloadText);
  assert.equal(parsed.user, 'admin');
  assert.equal(parsed.uid, 1001);
  assert.equal(parsed.profile.role, 'root');
  assert.equal(parsed['中文键'], '中文值');
  assert.equal(full.timestamp?.value, FIXED_TS);
  assert.ok(full.timestamp?.iso.startsWith('2023-11-14'), full.timestamp?.iso);
  // 同步快速解码也接受同一段
  const sync = decodeFlaskSession(VECTORS.flask_plain);
  assert.equal(sync.ok, true);
  if (sync.ok) assert.equal(sync.timestamp?.value, FIXED_TS);
});

test('Flask 解码：压缩 cookie（前导点四段）在线解压——修复前直接报错的真 bug', async () => {
  // 修复前：split('.') 硬判 3 段，四段压缩 cookie 直接 error
  assert.equal(VECTORS.flask_compressed.split('.').length, 4);
  const parts = parseFlaskSessionParts(VECTORS.flask_compressed);
  assert.equal('error' in parts, false);
  if ('error' in parts) return;
  assert.equal(parts.compressed, true);
  assert.equal(parts.payloadSegment.startsWith('.'), true);
  assert.equal(parts.timestampB64, 'ZVPxAA');
  const full = await decodeFlaskSessionFull(VECTORS.flask_compressed);
  assert.equal(full.ok, true, JSON.stringify(full));
  if (!full.ok) return;
  assert.equal(full.compressed, true);
  const parsed = JSON.parse(full.payloadText);
  assert.equal(parsed.n, 42);
  assert.ok(parsed.log.startsWith('flag{compressed_session}'));
  assert.ok(parsed.cn.includes('压缩会话测试'));
  // 同步版对压缩段不再崩，给 HEX 提示
  const sync = decodeFlaskSession(VECTORS.flask_compressed);
  assert.equal(sync.ok, true);
  if (sync.ok) {
    assert.equal(sync.compressed, true);
    assert.ok(sync.decoded.includes('HEX:'), '压缩段应给出 HEX 提示');
  }
});

test('Flask 解码：空时间戳段（ts=0）与从右拆的非法段拒绝', async () => {
  const full = await decodeFlaskSessionFull(VECTORS.ts_zero);
  assert.equal(full.ok, true, JSON.stringify(full));
  if (!full.ok) return;
  assert.equal(full.timestamp?.value, 0);
  assert.equal(full.parts.timestamp, '');
  // payload 段含点（非 base64）→ 拒绝；两段无时间戳 → 同步版拒绝（无时效 cookie 走完整解码）
  assert.equal(decodeFlaskSession('not.a').ok, false);
  assert.equal(decodeFlaskSession('a.b.c.d').ok, false);
  assert.equal(decodeFlaskSession('').ok, false);
  const untimed = await decodeFlaskSessionFull(VECTORS.untimed_django_concat_sha1);
  assert.equal(untimed.ok, true, JSON.stringify(untimed));
  if (!untimed.ok) return;
  assert.equal(untimed.withTimestamp, false);
  assert.equal(JSON.parse(untimed.payloadText).uid, 1001);
});

const DERIVATION_CASES = [
  ['timed_hmac_sha1', 'hmac', 'sha1', 'K', 'itsdangerous'],
  ['timed_hmac_sha256', 'hmac', 'sha256', 'K', 'itsdangerous'],
  ['timed_concat_sha1', 'concat', 'sha1', 'K', 'itsdangerous'],
  ['timed_concat_sha256', 'concat', 'sha256', 'K', 'itsdangerous'],
  ['timed_none_sha1', 'none', 'sha1', 'K', 'itsdangerous'],
  ['timed_none_sha256', 'none', 'sha256', 'K', 'itsdangerous'],
];

test('Flask 签发：四种 key_derivation × SHA1/SHA256 全对拍 itsdangerous 向量', async () => {
  for (const [vectorName, derivation, digest, secret, salt] of DERIVATION_CASES) {
    const result = await flaskSessionSign({ a: 1 }, { secret, salt, derivation, digest, timestamp: FIXED_TS });
    assert.equal(result.ok, true, `${vectorName}: ${JSON.stringify(result)}`);
    if (!result.ok) continue;
    assert.equal(result.token, VECTORS[vectorName], `${vectorName} 重签 token 与 itsdangerous ${ITS_DANGEROUS_VERSION} 不一致`);
    assert.equal(result.timestamp, FIXED_TS);
    // derive_key 派生链本身与公式逐一对拍
    const key = await deriveFlaskSigningKey(secret, salt, derivation, digest);
    assert.equal(Buffer.from(key).toString('hex'), Buffer.from(await deriveFlaskSigningKey(secret, salt, derivation, digest)).toString('hex'));
  }
});

test('Flask 签发：原序 / sort_keys / django-concat 默认口径对拍', async () => {
  const flaskObj = { user: 'admin', uid: 1001, profile: { role: 'root', tags: ['a', 'b'] }, '中文键': '中文值' };
  // flask_plain 向量为 itsdangerous _CompactJSON 原序口径（未排序）；Flask json.dumps sort_keys=True
  // 的真实口径由下方 flask_sortkeys 向量钉死
  const originalOrder = await flaskSessionSign(flaskObj, {
    secret: 'secret-key-01', salt: 'cookie-session', derivation: 'hmac', digest: 'sha1', sortKeys: false, timestamp: FIXED_TS,
  });
  assert.equal(originalOrder.ok, true);
  if (originalOrder.ok) assert.equal(originalOrder.token, VECTORS.flask_plain);

  // sort_keys=true：键序 alpha/beta/ch 与 Python sort_keys 输出一致（Flask session 实际序列化口径）
  const sorted = await flaskSessionSign({ beta: 2, alpha: 1, ch: '中文' }, {
    secret: 'secret-key-01', salt: 'cookie-session', derivation: 'hmac', digest: 'sha1', sortKeys: true, timestamp: FIXED_TS,
  });
  assert.equal(sorted.ok, true);
  if (sorted.ok) {
    assert.equal(sorted.token, VECTORS.flask_sortkeys);
    const decoded = await decodeFlaskSessionFull(sorted.token);
    assert.equal(decoded.ok, true);
    if (decoded.ok) {
      const text = decoded.payloadText;
      assert.ok(text.indexOf('"alpha"') < text.indexOf('"beta"'), 'sort_keys 未生效');
    }
  }

  // itsdangerous Serializer 默认（salt='itsdangerous' + django-concat + sha1 + 原序）
  const djangoDefault = await flaskSessionSign(flaskObj, {
    secret: 's3cret', salt: 'itsdangerous', derivation: 'django-concat', digest: 'sha1', sortKeys: false, timestamp: FIXED_TS,
  });
  assert.equal(djangoDefault.ok, true);
  if (djangoDefault.ok) assert.equal(djangoDefault.token, VECTORS.default_django_concat_sha1);
});

test('Flask 签发：压缩 auto/never/always 与解压回读一致', async () => {
  const bigPayload = { log: 'flag{compressed_session} '.repeat(12), cn: '压缩会话测试'.repeat(6), n: 42 };
  // sortKeys:false 对齐 Python _CompactJSON 原序默认，压缩内容才能与向量逐字符对拍
  const base = { secret: 'secret-key-01', salt: 'cookie-session', derivation: 'hmac', digest: 'sha1', sortKeys: false, timestamp: FIXED_TS };

  // auto：大负载应触发压缩；zlib 字节流跨实现（Node CompressionStream vs Python zlib.compress）
  // 字节可不同，互操作一致性在内容层验证——解压后与 Python 向量解出的 JSON 逐字符一致
  const auto = await flaskSessionSign(bigPayload, { ...base });
  assert.equal(auto.ok, true);
  if (auto.ok) {
    assert.equal(auto.compressed, true, '大负载 auto 应压缩');
    assert.equal(auto.payloadSegment.startsWith('.'), true);
    const roundTrip = await decodeFlaskSessionFull(auto.token);
    assert.equal(roundTrip.ok, true, JSON.stringify(roundTrip));
    if (roundTrip.ok) {
      assert.deepEqual(JSON.parse(roundTrip.payloadText), bigPayload);
      const vectorDecoded = await decodeFlaskSessionFull(VECTORS.flask_compressed);
      assert.equal(vectorDecoded.ok, true);
      if (vectorDecoded.ok) {
        assert.equal(roundTrip.payloadText, vectorDecoded.payloadText, 'TS 序列化压缩内容应与 itsdangerous 向量解码内容逐字符一致');
      }
    }
    // 签出的压缩 cookie 必须能被本工具自身校验通过（sign→verify 闭环）
    const verified = await flaskSessionVerify(auto.token, { secret: 'secret-key-01', salt: 'cookie-session', derivation: 'hmac', digest: 'sha1' });
    assert.equal(verified.ok, true);
    if (verified.ok) assert.equal(verified.valid, true);
  }

  // never：同负载不压缩
  const never = await flaskSessionSign(bigPayload, { ...base, compression: 'never' });
  assert.equal(never.ok, true);
  if (never.ok) {
    assert.equal(never.compressed, false);
    assert.ok(!never.payloadSegment.startsWith('.'));
    const roundTrip = await decodeFlaskSessionFull(never.token);
    assert.equal(roundTrip.ok, true);
    if (roundTrip.ok) assert.equal(JSON.parse(roundTrip.payloadText).n, 42);
  }

  // always：小负载也压（内容压不小时仍强制 zlib 包装）
  const tiny = await flaskSessionSign({ a: 1 }, { secret: 'K', salt: 'itsdangerous', derivation: 'hmac', digest: 'sha1', compression: 'always', timestamp: FIXED_TS });
  assert.equal(tiny.ok, true);
  if (tiny.ok) {
    assert.equal(tiny.compressed, true);
    const roundTrip = await decodeFlaskSessionFull(tiny.token);
    assert.equal(roundTrip.ok, true);
    if (roundTrip.ok) assert.deepEqual(JSON.parse(roundTrip.payloadText), { a: 1 });
  }

  // 篡改压缩 payload 一个字符 → 解压失败明确报错
  const tampered = VECTORS.flask_compressed.replace('eJyrVsrJT1ey', 'eJyrVsrJT1eX');
  const broken = await decodeFlaskSessionFull(tampered);
  assert.equal(broken.ok, false);
  if (!broken.ok) assert.ok(broken.error.includes('解压失败'));
});

test('Flask 校验：正确 secret 通过、错误 secret 常数时间拒绝、双向一致', async () => {
  const good = await flaskSessionVerify(VECTORS.flask_plain, {
    secret: 'secret-key-01', salt: 'cookie-session', derivation: 'hmac', digest: 'sha1',
  });
  assert.equal(good.ok, true, JSON.stringify(good));
  if (!good.ok) return;
  assert.equal(good.valid, true);
  assert.equal(good.reason, null);
  assert.equal(good.signatureValid, true);
  assert.equal(good.timestamp, FIXED_TS);
  assert.equal(good.actualSignatureB64, '6sDbJaoc4uEeFAi1OsQWz6ZKh2o');

  // 错误 secret / 错误 derivation / 错误 salt 全部拒绝，且期望签名给出（可人工对拍）
  for (const wrong of [
    { secret: 'wrong-key', salt: 'cookie-session', derivation: 'hmac', digest: 'sha1' },
    { secret: 'secret-key-01', salt: 'cookie-session', derivation: 'django-concat', digest: 'sha1' },
    { secret: 'secret-key-01', salt: 'itsdangerous', derivation: 'hmac', digest: 'sha1' },
    { secret: 'secret-key-01', salt: 'cookie-session', derivation: 'hmac', digest: 'sha256' },
  ]) {
    const bad = await flaskSessionVerify(VECTORS.flask_plain, wrong);
    assert.equal(bad.ok, true);
    if (bad.ok) {
      assert.equal(bad.valid, false, `应拒绝 ${JSON.stringify(wrong)}`);
      assert.equal(bad.reason, 'bad-signature');
      assert.notEqual(bad.expectedSignatureB64, bad.actualSignatureB64);
    }
  }

  // sign → verify 双向一致（自签自验，含压缩与无时间戳形态）
  for (const options of [
    { secret: 's', salt: 'cookie-session', derivation: 'hmac', digest: 'sha1', timestamp: FIXED_TS },
    { secret: 's', salt: 'cookie-session', derivation: 'hmac', digest: 'sha256', compression: 'always', timestamp: FIXED_TS },
    { secret: 's', salt: 'cookie-session', derivation: 'none', digest: 'sha1', withTimestamp: false, timestamp: FIXED_TS },
  ]) {
    const signed = await flaskSessionSign({ role: 'root', i: 7 }, options);
    assert.equal(signed.ok, true);
    if (!signed.ok) continue;
    const verified = await flaskSessionVerify(signed.token, options);
    assert.equal(verified.ok, true);
    if (verified.ok) assert.equal(verified.valid, true, verified.message);
  }

  // 空 secret / 空输入明确报错
  assert.equal((await flaskSessionVerify(VECTORS.flask_plain, { secret: '' })).ok, false);
  assert.equal((await flaskSessionVerify('   ', { secret: 'x' })).ok, false);
  assert.equal((await flaskSessionSign('not-json', { secret: 'x' })).ok, false);
});

test('Flask 校验：maxAge 过期与未生效判定（itsdangerous unsign 语义）', async () => {
  // ts=1700000000，now=1700000100 → age=100
  const options = { secret: 'secret-key-01', salt: 'cookie-session', derivation: 'hmac', digest: 'sha1', now: FIXED_TS + 100 };
  const fresh = await flaskSessionVerify(VECTORS.flask_plain, { ...options, maxAge: 3600 });
  assert.equal(fresh.ok, true);
  if (fresh.ok) assert.equal(fresh.valid, true);
  const expired = await flaskSessionVerify(VECTORS.flask_plain, { ...options, maxAge: 99 });
  assert.equal(expired.ok, true);
  if (expired.ok) {
    assert.equal(expired.valid, false);
    assert.equal(expired.reason, 'expired');
    assert.equal(expired.ageSeconds, 100);
    assert.ok(expired.message.includes('100'));
  }
  // 边界：age == maxAge 未过期（itsdangerous 判 age > maxAge 才拒）
  const edge = await flaskSessionVerify(VECTORS.flask_plain, { ...options, maxAge: 100 });
  assert.equal(edge.ok, true);
  if (edge.ok) assert.equal(edge.valid, true);
  // 时间戳在未来：age = now - ts = -1 < 0 拒绝（itsdangerous 同样抛 SignatureExpired）
  const future = await flaskSessionVerify(VECTORS.flask_plain, { ...options, now: FIXED_TS - 1, maxAge: 3600 });
  assert.equal(future.ok, true);
  if (future.ok) {
    assert.equal(future.valid, false);
    assert.equal(future.reason, 'not-yet-valid');
    assert.equal(future.ageSeconds, -1);
  }
});

// ---- ECDSA ±s 符号消歧 ----
// 权威向量：Python 3.14 独立实现（SEC1 secp256k1 仿射坐标点乘，与 TS 侧雅可比实现零共享代码）。
// d=0xd15ea5e0...0001，k=0x11223344...4321 复用于 z1/z2 两条签名；s2_low = n - s2 模拟 low-s 归一化翻号。
const EC_VECTOR = {
  curve: 'secp256k1',
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  d: 0xd15ea5e0bad000c0de00000000c0ffee1234567890abcdef0000000000000001n,
  k: 0x11223344556677889900aabbccddeeff0123456789abcdef0fedcba987654321n,
  qx: 0x84864bbcfa25935c70e5b83dd45bd46fd6d31c4544aab00219967c1901393b99n,
  qy: 0xdb8ff76817945d1834176ebe66040f242a5b88671e3af6160771fc69e7d58157n,
  r: 0xb487624de72b9dd5a41c1f671684e548af03b71572a2357d67f6939ac35d20b9n,
  z1: 0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08n,
  z2: 0x60303ae22b998861bce3b28f334a9b3e3e6365f8bb0b8f9efea5c4a5fe4ee9c9n,
  s1: 0xf088eed18f69bc2de2819cb21bae92399d85e06ad8a45f6bee2efa318bf96c21n,
  s2: 0x51d7f138318156809847c32cce0f5eca42fddc8bd32e9372548839990312f2n,
  s2_low: 0xffae280ec7ce7ea97f67b83cd331f09ff06bdf0a237571a84d7dd65337332e4fn,
  d_bad: 0xdb2fd56fcdf9a0860cbfc2a2482e22d8bbddd635435e2096fca41acb67a0db1an,
};

const hex = value => `0x${value.toString(16)}`;

const buildNonceReuseInput = ({ qx, qy, s2Value }) => JSON.stringify({
  scheme: 'ecdsa',
  curve: 'secp256k1',
  n: hex(EC_VECTOR.n),
  ...(qx && qy ? { qx: hex(qx), qy: hex(qy) } : {}),
  signatures: [
    { name: 'sig1', r: hex(EC_VECTOR.r), s: hex(EC_VECTOR.s1), z: hex(EC_VECTOR.z1) },
    { name: 'sig2', r: hex(EC_VECTOR.r), s: hex(s2Value), z: hex(EC_VECTOR.z2) },
  ],
});

test('ECDSA ±s：公钥雅可比校验 d·G==Q 基础正确性（SEC1 域参数）', () => {
  // 正确私钥过校验；错误私钥（含翻号对朴素公式产物 d_bad）不过
  assert.equal(ecPublicKeyMatchesPrivateKey(EC_VECTOR.d, EC_VECTOR.qx, EC_VECTOR.qy, 'secp256k1'), true);
  assert.equal(ecPublicKeyMatchesPrivateKey(EC_VECTOR.d_bad, EC_VECTOR.qx, EC_VECTOR.qy, 'secp256k1'), false);
  assert.equal(ecPublicKeyMatchesPrivateKey(EC_VECTOR.d - 1n, EC_VECTOR.qx, EC_VECTOR.qy, 'secp256k1'), false);
  // 曲线方程粗检：非曲线上的点拒绝
  assert.equal(ecPublicKeyMatchesPrivateKey(EC_VECTOR.d, EC_VECTOR.qx, EC_VECTOR.qy + 1n, 'secp256k1'), false);
  // 越界私钥拒绝
  assert.equal(ecPublicKeyMatchesPrivateKey(0n, EC_VECTOR.qx, EC_VECTOR.qy, 'secp256k1'), false);
  assert.equal(ecPublicKeyMatchesPrivateKey(EC_VECTOR.n, EC_VECTOR.qx, EC_VECTOR.qy, 'secp256k1'), false);
  // P-256 域参数：d=1 → Q=G（SEC1 生成元常量锚点）
  assert.equal(ecPublicKeyMatchesPrivateKey(1n, ecSec1CurveParams.secp256r1.gx, ecSec1CurveParams.secp256r1.gy, 'secp256r1'), true);
  // secp256k1 同理：d=1 → Q=G
  assert.equal(ecPublicKeyMatchesPrivateKey(1n, ecSec1CurveParams.secp256k1.gx, ecSec1CurveParams.secp256k1.gy, 'secp256k1'), true);
});

test('ECDSA ±s：正常对 (s1,s2) 直接恢复 d/k，公钥校验命中 (+s1,+s2)', async () => {
  const report = JSON.parse(await signatureNonceReuseHelper(buildNonceReuseInput({ s2Value: EC_VECTOR.s2, qx: EC_VECTOR.qx, qy: EC_VECTOR.qy })));
  assert.equal(report.repeatedRCount, 1);
  const recovery = report.recoveries[0];
  assert.equal(recovery.recoverable, true);
  assert.equal(recovery.privateKey, EC_VECTOR.d.toString(), `朴素主路径应直接命中 d，实际 ${recovery.privateKey}`);
  assert.equal(recovery.nonceK, EC_VECTOR.k.toString());
  assert.equal(recovery.verifiedByPublicKey, true);
  assert.equal(recovery.signCombo, '(+s1,+s2)');
  const verifiedCandidates = recovery.candidates.filter(candidate => candidate.verified);
  assert.equal(verifiedCandidates.length, 1, '恰有一个组合过公钥校验');
  assert.equal(verifiedCandidates[0].privateKey, EC_VECTOR.d.toString());
});

test('ECDSA ±s：low-s 翻号对——朴素公式给出错误 d，枚举 + 公钥锁定组合恢复真 d', async () => {
  // 无公钥：主路径 (+s1,+s2) 恢复出 d_bad（错误但无从判定），候选里含真 d 但未锁定
  const noPub = JSON.parse(await signatureNonceReuseHelper(buildNonceReuseInput({ s2Value: EC_VECTOR.s2_low })));
  const noPubRecovery = noPub.recoveries[0];
  assert.equal(noPubRecovery.recoverable, true);
  assert.equal(noPubRecovery.privateKey, EC_VECTOR.d_bad.toString(), '翻号对朴素主路径应产出错误 d_bad（复现修复前公式失败场景）');
  assert.equal(noPubRecovery.verifiedByPublicKey, false);
  assert.ok(noPubRecovery.candidates.some(candidate => candidate.privateKey === EC_VECTOR.d.toString()), '候选集应含真 d（翻一条 s 的组合）');
  assert.ok(noPubRecovery.note.includes('无法自动锁定'), '无公钥应提示歧义未消');

  // 有公钥：d·G==Q 锁定正确组合，primary privateKey 翻转为真 d。
  // 数学事实：(−s1,+s2) 与 (+s1,−s2) 方程同解（k 互反、d 相同），去重后保留枚举序在前的 (−s1,+s2)，
  // 其 nonce k' = −k (mod n)——同样是合法 nonce 解（r(−kG) 与 r(kG) 的 x 坐标相同）。
  const withPub = JSON.parse(await signatureNonceReuseHelper(buildNonceReuseInput({ s2Value: EC_VECTOR.s2_low, qx: EC_VECTOR.qx, qy: EC_VECTOR.qy })));
  const recovery = withPub.recoveries[0];
  assert.equal(recovery.privateKey, EC_VECTOR.d.toString(), '公钥校验后应恢复真 d');
  assert.equal(recovery.signCombo, '(-s1,+s2)');
  assert.equal(recovery.nonceK, (EC_VECTOR.n - EC_VECTOR.k).toString(), '锁定组合的 nonce 为 −k（与 k 等价的合法解）');
  assert.equal(recovery.verifiedByPublicKey, true);
  assert.notEqual(recovery.signCombo, '(+s1,+s2)', '锁定组合不应是朴素主路径');
  const verified = recovery.candidates.filter(candidate => candidate.verified);
  assert.equal(verified.length, 1);
  assert.equal(verified[0].privateKey, EC_VECTOR.d.toString());
  assert.ok(recovery.note.includes('公钥锁定'));
});

test('Schnorr ±s：s=k+e·x 语义下翻号对枚举同样恢复 x', async () => {
  // 小素数域纯代数构造（Schnorr 恢复式与曲线无关，合成数字即权威）：
  // p=10007, q=4999（p-1 的素因子），x=2024, k=137；s=k+e·x mod q
  const q = 4999n;
  const x = 2024n;
  const k = 137n;
  const e1 = 123n;
  const e2 = 4560n;
  const s1 = (k + e1 * x) % q;
  const s2 = (k + e2 * x) % q;
  const s2Flipped = (q - s2) % q; // 翻号形态
  const input = JSON.stringify({
    scheme: 'schnorr',
    q: q.toString(),
    signatures: [
      { name: 'a', s: s1.toString(), z: e1.toString(), r: '7' },
      { name: 'b', s: s2Flipped.toString(), z: e2.toString(), r: '7' },
    ],
  });
  const report = JSON.parse(await signatureNonceReuseHelper(input));
  const recovery = report.recoveries[0];
  assert.equal(recovery.recoverable, true);
  assert.equal(recovery.scheme, 'schnorr');
  // (+s1,+s2) 朴素主路径对翻号 s2 给出错误 x；候选里 (−s2) 组合命中真 x
  const correct = recovery.candidates.find(candidate => candidate.privateKey === x.toString());
  assert.ok(correct, `候选应含真 x=${x}，实际 ${JSON.stringify(recovery.candidates)}`);
  assert.equal(correct.nonceK, k.toString());
});

test('ECDSA 退化输入：s1==s2 主路径分母为零 / 缺 z 不可恢复', async () => {
  // s1==s2：朴素 (s1,s2) 分母为零，主路径退化；±s 枚举仍给出未锁定候选并显式标注
  const sameSReport = JSON.parse(await signatureNonceReuseHelper(JSON.stringify({
    curve: 'secp256k1',
    n: hex(EC_VECTOR.n),
    signatures: [
      { r: hex(EC_VECTOR.r), s: hex(EC_VECTOR.s1), z: hex(EC_VECTOR.z1) },
      { r: hex(EC_VECTOR.r), s: hex(EC_VECTOR.s1), z: hex(EC_VECTOR.z2) },
    ],
  })));
  const sameSRecovery = sameSReport.recoveries[0];
  assert.equal(sameSRecovery.naivePathDegenerate, true, 's1==s2 应标记主路径退化');
  assert.ok(sameSRecovery.note.includes('主路径退化'), 'note 应说明主路径退化');
  assert.ok(sameSRecovery.candidates.every(candidate => candidate.signs !== '(+s1,+s2)'), '退化组合不应出现在候选里');

  // 缺 z：无法代入恢复式 → 不可恢复
  const missingZReport = JSON.parse(await signatureNonceReuseHelper(JSON.stringify({
    curve: 'secp256k1',
    signatures: [
      { r: hex(EC_VECTOR.r), s: hex(EC_VECTOR.s1) },
      { r: hex(EC_VECTOR.r), s: hex(EC_VECTOR.s2) },
    ],
  })));
  assert.equal(missingZReport.recoveries[0].recoverable, false);
});
