// 批次三 Lane G 回归测试：VIC 密码（Savard 全算例逐位对拍）与 GeoHash（公开权威向量）。
// 权威出处：
//   VIC —— John Savard "The VIC Cipher"（http://www.quadibloc.com/crypto/pp1324.htm），
//         按 Hayhanen 1957 年向 FBI 交代的规程复现的完整算例：date=741776、indicator=77651、
//         phrase="I DREAM OF JEANNIE WITH T"、personal number=8；中间行与最终密文逐位对拍。
//         Wikipedia "VIC cipher"（NSA 重建版）同规程可交叉核对。
//   GeoHash —— Wikipedia 官方算例 42.6,-5.6 → ezs42（含逐位二分推导）
//         https://en.wikipedia.org/wiki/Geohash；
//         Rosetta Code 多语言对拍值 https://rosettacode.org/wiki/Geohash
//         （57.64911,10.40744 → u4pruydqqvj 等 10 组）；
//         上海坐标 31.231706,121.472644 → wtw3sjt9v 经 latlng.work 在线转换器独立核对。
// 纪律：沙箱模块返回的数组一律先 Array.from 转主 realm 再 deepEqual（AGENTS.md 踩坑记录）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const CL = loadModule(path.join(srcDir, 'utils', 'codec', 'classical.ts'));
const PN = loadModule(path.join(srcDir, 'utils', 'codec', 'parityNumeric.ts'));

// ==================== VIC 密码 ====================

const VIC_PHRASE = 'I dream of Jeannie with t';
const VIC_DATE = '741776';
const VIC_PERSONAL = '8';
const VIC_INDICATOR = '77651';
const SAVARD_MESSAGE = 'We are pleased to hear of your success in establishing your false identity. You will be sent some money to cover expenses within a month.';
const SAVARD_CLEAN = 'WEAREPLEASEDTOHEAROFYOURSUCCESSINESTABLISHINGYOURFALSEIDENTITYYOUWILLBESENTSOMEMONEYTOCOVEREXPENSESWITHINAMONTH';
// Savard 页面给出的最终传输形态：150 位密文 30 组 + 插入的指示组 77651 = 31 组
const SAVARD_CIPHER_GROUPS = [
  '36178', '05428', '99592', '53507', '01440', '00113', '42004', '74684', '58426', '75048',
  '42503', '10084', '69181', '77284', '83603', '47503', '50076', '68483', '88242', '42838',
  '90960', '35071', '37586', '89914', '05000', '77651', '80429', '00873', '78601', '44725', '44860',
];
const SAVARD_CIPHER = SAVARD_CIPHER_GROUPS.join('');

test('VIC 密钥派生：Savard 算例逐行锚点（line1/chain10/消息密钥/块末行/表头/列宽/列读出）', () => {
  const material = CL.vicDeriveKeys(VIC_PHRASE, VIC_DATE, VIC_PERSONAL, VIC_INDICATOR);
  assert.equal(material.line1, '03584'); // 77651-74177，mod 10 无借位
  assert.equal(material.chain10, '0358438327'); // 链式加法 5→10
  assert.equal(material.messageKey, '0221215831'); // 加短语前半序列 + 按短语后半序列编码
  assert.deepEqual(Array.from(material.blockRows), [
    '2433363143', '6766994579', '3325839262', '6573121888', '1204339669',
  ]);
  assert.equal(material.lastRow, '1204339669');
  assert.equal(material.header, '1205348679'); // 块末行序列化（0 视作最大）
  assert.deepEqual(Array.from(material.straddleDigits), ['0', '8']); // 表头第 3/7 列留空
  assert.equal(material.width1, 14); // 个人号 8 + 末两位不等数字 6
  assert.equal(material.width2, 17); // 个人号 8 + 9
  assert.equal(material.readOut, '36534693233928947352362703981347686349191528626361'); // 按消息密钥列序读全块 50 位
  assert.equal(material.key1, '36534693233928'); // 前 14 位（列宽 14）
  assert.equal(material.key2, '94735236270398134'); // 后 17 位（列宽 17）
  assert.equal(material.insertionOffset, 6); // 日期末位 6
});

test('VIC 加密：Savard 算例密文 155 位逐位一致（指示组落在倒数第 6 组）', () => {
  const cipherText = CL.vicTransform(SAVARD_MESSAGE, VIC_PHRASE, VIC_DATE, VIC_PERSONAL, VIC_INDICATOR);
  const digits = cipherText.replace(/\s+/g, '');
  assert.equal(digits, SAVARD_CIPHER);
  const groups = digits.match(/.{5}/g);
  assert.equal(groups.length, 31);
  assert.equal(groups[groups.length - 6], '77651');
});

test('VIC 解密：Savard 密文（带指示组、任意空白分组）还原明文', () => {
  const plain = CL.vicTransform(SAVARD_CIPHER_GROUPS.join(' '), VIC_PHRASE, VIC_DATE, VIC_PERSONAL, VIC_INDICATOR, true);
  assert.equal(plain, SAVARD_CLEAN);
});

test('VIC round-trip：含数字段（数字移位符 + 每位三连）的消息加解密互逆', () => {
  const message = 'ATTACK AT 0500 OR 0915 NEAR THE CLOCK';
  const cipher = CL.vicTransform(message, VIC_PHRASE, VIC_DATE, VIC_PERSONAL, VIC_INDICATOR);
  assert.equal(CL.vicTransform(cipher, VIC_PHRASE, VIC_DATE, VIC_PERSONAL, VIC_INDICATOR, true), 'ATTACKAT0500OR0915NEARTHECLOCK');
});

test('VIC round-trip：另一套密钥材料（不同短语/日期/个人号/密钥组）', () => {
  const cipher = CL.vicTransform('RENDEZVOUS MOVED TO 1900 HOURS BRING THE MAPS', 'TOPSECRETBLUEBIRDFLY', '221463', '5', '31084');
  assert.equal(CL.vicTransform(cipher, 'TOPSECRETBLUEBIRDFLY', '221463', '5', '31084', true), 'RENDEZVOUSMOVEDTO1900HOURSBRINGTHEMAPS');
});

test('VIC 参数校验：短语/日期/个人号/密钥组/空明文非法输入逐一报错', () => {
  assert.throws(() => CL.vicTransform('HI', 'SEVENONE', VIC_DATE, VIC_PERSONAL, VIC_INDICATOR), /至少 20 个字母/);
  assert.throws(() => CL.vicTransform('HI', VIC_PHRASE, '74177', VIC_PERSONAL, VIC_INDICATOR), /至少 6 位数字/);
  assert.throws(() => CL.vicTransform('HI', VIC_PHRASE, VIC_DATE, '0', VIC_INDICATOR), /1-9/);
  assert.throws(() => CL.vicTransform('HI', VIC_PHRASE, VIC_DATE, '12', VIC_INDICATOR), /1-9/);
  assert.throws(() => CL.vicTransform('HI', VIC_PHRASE, VIC_DATE, VIC_PERSONAL, '7734'), /5 位数字/);
  assert.throws(() => CL.vicTransform('', VIC_PHRASE, VIC_DATE, VIC_PERSONAL, VIC_INDICATOR), /需要可编码的明文/);
  assert.throws(() => CL.vicTransform('abc', VIC_PHRASE, VIC_DATE, VIC_PERSONAL, VIC_INDICATOR, true), /需要数字密文/);
});

test('VIC 解密指示组校验：密钥组不符给出明确报错（防错钥静默出乱码）', () => {
  assert.throws(
    () => CL.vicTransform(SAVARD_CIPHER_GROUPS.join(' '), VIC_PHRASE, VIC_DATE, VIC_PERSONAL, '77652', true),
    /指示组不匹配/,
  );
});

// ==================== GeoHash ====================

test('GeoHash：Wikipedia 官方算例 42.6,-5.6 → ezs42，decode 中点与误差对拍', () => {
  assert.equal(PN.geohashEncode(42.6, -5.6, 5), 'ezs42');
  const cell = PN.geohashDecode('ezs42');
  assert.ok(Math.abs(cell.lat - 42.605) < 0.001, `lat ${cell.lat}`);
  assert.ok(Math.abs(cell.lon - (-5.603)) < 0.001, `lon ${cell.lon}`);
  // 5 位精度 = 纬 12 位 + 经 13 位 → 半格误差 90/2^12 = 180/2^13 = 0.02197265625（Wikipedia ±0.022）
  assert.ok(Math.abs(cell.latError - 90 / 2 ** 12) < 1e-12, `latError ${cell.latError}`);
  assert.ok(Math.abs(cell.lonError - 180 / 2 ** 13) < 1e-12, `lonError ${cell.lonError}`);
});

test('GeoHash：Rosetta Code 多语言对拍向量（10 组）', () => {
  assert.equal(PN.geohashEncode(57.64911, 10.40744, 11), 'u4pruydqqvj');
  assert.equal(PN.geohashEncode(51.433718, -0.214126, 2), 'gc');
  assert.equal(PN.geohashEncode(51.433718, -0.214126, 5), 'gcpue');
  assert.equal(PN.geohashEncode(51.433718, -0.214126, 9), 'gcpue5hp4');
  assert.equal(PN.geohashEncode(59.358639, 24.744778, 4), 'ud99');
  assert.equal(PN.geohashEncode(59.358639, 24.744778, 7), 'ud99ejf');
  assert.equal(PN.geohashEncode(29.2021188, 81.5324561, 4), 'tv1y');
  assert.equal(PN.geohashEncode(29.2021188, 81.5324561, 7), 'tv1ypk4');
  assert.equal(PN.geohashEncode(59.1158, -151.687312, 7), 'bds0k38');
  assert.equal(PN.geohashEncode(38.743586, -109.499336, 8), '9wfhkm11');
});

test('GeoHash：上海坐标外部核对值 + 原点必须落在格内且中点误差 ≤ 半格', () => {
  assert.equal(PN.geohashEncode(31.231706, 121.472644, 9), 'wtw3sjt9v');
  const cell = PN.geohashDecode('wtw3sjt9v');
  assert.ok(cell.latMin <= 31.231706 && 31.231706 <= cell.latMax);
  assert.ok(cell.lonMin <= 121.472644 && 121.472644 <= cell.lonMax);
  assert.ok(Math.abs(cell.lat - 31.231706) <= cell.latError);
  assert.ok(Math.abs(cell.lon - 121.472644) <= cell.lonError);
});

test('GeoHash：往返误差 ≤ 半格（多点 × 精度 1/5/12，含经纬极端值）', () => {
  const points = [
    [31.2304, 121.4737], [-33.8688, 151.2093], [51.5007, -0.1246],
    [40.7128, -74.006], [-90, 180], [90, -180], [0, 0], [-43.1729, -70.5667],
  ];
  for (const [lat, lon] of points) {
    for (const precision of [1, 5, 12]) {
      const hash = PN.geohashEncode(lat, lon, precision);
      assert.equal(hash.length, precision);
      const cell = PN.geohashDecode(hash);
      assert.ok(cell.latMin <= lat && lat <= cell.latMax, `lat ${lat} 不在区间 ${cell.latMin}~${cell.latMax}`);
      assert.ok(cell.lonMin <= lon && lon <= cell.lonMax, `lon ${lon} 不在区间 ${cell.lonMin}~${cell.lonMax}`);
      assert.ok(Math.abs(cell.lat - lat) <= cell.latError + 1e-9, `往返纬度误差超半格: ${cell.lat} vs ${lat}`);
      assert.ok(Math.abs(cell.lon - lon) <= cell.lonError + 1e-9, `往返经度误差超半格: ${cell.lon} vs ${lon}`);
    }
  }
});

test('GeoHash：前缀性质——短精度 hash 是长精度 hash 的前缀（Wikipedia 算例首字符 e）', () => {
  assert.equal(PN.geohashEncode(42.6, -5.6, 1), 'e');
  assert.ok(PN.geohashEncode(42.6, -5.6, 5).startsWith(PN.geohashEncode(42.6, -5.6, 1)));
  assert.ok(PN.geohashEncode(42.6, -5.6, 9).startsWith(PN.geohashEncode(42.6, -5.6, 5)));
});

test('GeoHash：精度边界 1/12 与非法输入报错', () => {
  const deepHash = PN.geohashEncode(42.6, -5.6, 12);
  assert.equal(deepHash.length, 12);
  const deep = PN.geohashDecode(deepHash);
  assert.ok(deep.latError <= 90 / 2 ** 30 + 1e-12, `latError ${deep.latError}`);
  assert.ok(deep.lonError <= 180 / 2 ** 30 + 1e-12, `lonError ${deep.lonError}`);
  assert.throws(() => PN.geohashEncode(42.6, -5.6, 0), /1-12/);
  assert.throws(() => PN.geohashEncode(42.6, -5.6, 13), /1-12/);
  assert.throws(() => PN.geohashEncode(90.1, 0, 9), /纬度/);
  assert.throws(() => PN.geohashEncode(0, -180.1, 9), /经度/);
  assert.throws(() => PN.geohashDecode('ezsa2'), /不是合法的 geohash 字符/);
  assert.throws(() => PN.geohashDecode('e'.repeat(13)), /最多 12 位/);
});

test('GeoHash：transform 包装（encode「纬度,经度」与 decode 文本报告）', () => {
  assert.equal(PN.geohashTransform('31.231706,121.472644', 'encode', '9'), 'wtw3sjt9v');
  assert.equal(PN.geohashTransform('42.6 -5.6', 'encode', '5'), 'ezs42');
  const report = PN.geohashTransform('ezs42', 'decode', '');
  assert.ok(report.includes('42.6049804688'), report);
  assert.ok(report.includes('-5.6030273438'), report);
  assert.ok(report.includes('±0.0219726563'), report);
  assert.throws(() => PN.geohashTransform('42.6', 'encode', '5'), /纬度,经度/);
  assert.throws(() => PN.geohashTransform('42.6,-5.6', 'encode', 'abc'), /精度必须是 1-12 的整数/);
});
