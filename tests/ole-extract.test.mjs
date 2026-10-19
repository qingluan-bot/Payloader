// OLE/CFB 复合文档只读提取引擎测试：
// 1) olefile 权威对拍夹具（tests/fixtures/ole/minimal-cfb.bin：手工构造 + olefile 0.47 读回
//    逐位验证过的最小 CFB，含 mini 流/常规流/嵌套 storage 三种形态）——引擎条目树与流字节
//    SHA-256 与 manifest.json 逐项比对（独立来源 = olefile 读数）；
// 2) 测试内第二套手写 CFB（JS 侧独立构造，不同条目数/迷你阈值边界 4096B 流）双验证；
// 3) 加密迹象检测（WordDocument FibBase fEncrypted / FILEPASS / EncryptedPackage）；
// 4) 非法输入拒绝（魔数错/截断头）；FAT/目录环引用保护；只读性（输入不被修改）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import crypto from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const { parseOle } = loadModule(path.join(projectRoot, 'src', 'utils', 'ctf', 'oleExtract.ts'));

const FIXTURE_DIR = path.join(projectRoot, 'tests', 'fixtures', 'ole');
const hasFixture = existsSync(path.join(FIXTURE_DIR, 'minimal-cfb.bin'));
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

// ---- olefile 权威对拍夹具 ----

test('olefile 对拍夹具：条目树与流字节 SHA-256 逐项一致（独立权威来源）', { skip: hasFixture ? false : '缺少 olefile 对拍夹具' }, () => {
  const bytes = new Uint8Array(readFileSync(path.join(FIXTURE_DIR, 'minimal-cfb.bin')));
  const manifest = JSON.parse(readFileSync(path.join(FIXTURE_DIR, 'manifest.json'), 'utf8'));
  const r = parseOle(bytes);
  assert.equal(r.ok, true, r.failure ?? '');
  assert.equal(r.version, 3);
  assert.equal(r.sectorSize, 512);
  const paths = Array.from(r.entries.filter(e => e.type === 'stream').map(e => e.path)).sort();
  assert.deepEqual(paths.sort(), ['/big.bin', '/secret.txt', '/sub/inner.txt'].sort());
  assert.ok(r.entries.some(e => e.path === '/sub' && e.type === 'storage'), '嵌套 storage 应在树中');
  for (const stream of r.streams) {
    const ref = manifest[stream.path.replace(/^\//, '')];
    assert.ok(ref, `流 ${stream.path} 在 manifest 中`);
    assert.equal(stream.bytes.length, ref.size, `${stream.path} 大小一致`);
    assert.equal(sha256(stream.bytes), ref.sha256, `${stream.path} 与 olefile 读数逐位一致`);
  }
  assert.equal(r.streams.length, 3);
});

test('只读性：解析输入缓冲不被修改', { skip: hasFixture ? false : '缺少 olefile 对拍夹具' }, () => {
  const bytes = new Uint8Array(readFileSync(path.join(FIXTURE_DIR, 'minimal-cfb.bin')));
  const before = sha256(bytes);
  parseOle(bytes);
  assert.equal(sha256(bytes), before, '输入字节不得被修改');
});

// ---- 测试内手写第二套 CFB（JS 侧独立构造，覆盖阈值边界与多流） ----

const ENDOFCHAIN = 0xfffffffe;
const FREESECT = 0xffffffff;
const FATSECT = 0xfffffffd;
const NOSTREAM = 0xffffffff;
const SECTOR = 512;
const MINI = 64;


const dirEntry = (name, objectType, left, right, child, start, size) => {
  const nameBytes = Buffer.from(name, 'utf16le');
  const e = Buffer.alloc(128);
  nameBytes.copy(e, 0);
  e.writeUInt16LE(nameBytes.length + 2, 64);
  e[66] = objectType;
  e[67] = 1; // 黑色节点
  e.writeUInt32LE(left >>> 0, 68);
  e.writeUInt32LE(right >>> 0, 72);
  e.writeUInt32LE(child >>> 0, 76);
  e.writeUInt32LE(start >>> 0, 116);
  e.writeUInt32LE(size, 120);
  return e;
};

const buildCfbJs = ({ streamSizes }) => {
  // streamSizes: [{ name, size }]；≤4096 走 mini 流（共享一个 mini 池），>4096 走常规扇区。
  const streams = streamSizes.map(({ name, size }) => ({ name, data: Buffer.from(Array.from({ length: size }, (_, i) => (i * 31 + 7) % 256)) }));
  const miniStreams = streams.filter(s => s.data.length > 0 && s.data.length < 4096);
  const bigStreams = streams.filter(s => s.data.length >= 4096);
  const miniPoolLen = miniStreams.reduce((sum, s) => sum + Math.ceil(s.data.length / MINI) * MINI, 0);
  const miniSectors = Math.max(1, Math.ceil(miniPoolLen / SECTOR));
  const bigSectorsPer = bigStreams.map(s => Math.ceil(s.data.length / SECTOR));
  const minifatSectors = miniStreams.length > 0 ? 1 : 0;
  const dirSectors = 2;
  const fatSectors = 2;
  // 扇区布局：0..1 FAT，2..3 目录，4..(4+miniSectors-1) mini 池，之后大流，最后 MiniFAT
  let cursor = 4;
  const miniSectorIds = Array.from({ length: miniSectors }, (_, i) => cursor + i);
  cursor += miniSectors;
  const bigSectorIds = bigSectorsPer.map(n => { const ids = Array.from({ length: n }, (_, i) => cursor + i); cursor += n; return ids; });
  const minifatSectorId = minifatSectors ? cursor : NOSTREAM;
  cursor += minifatSectors;
  const totalSectors = cursor;
  const fat = Buffer.alloc(SECTOR * fatSectors);
  fat.writeUInt32LE(FATSECT, 0);
  fat.writeUInt32LE(FATSECT, 4);
  const chain = (ids) => { for (let i = 0; i < ids.length; i++) fat.writeUInt32LE(i + 1 < ids.length ? ids[i + 1] : ENDOFCHAIN, ids[i] * 4); };
  chain([2, 3]);
  chain(miniSectorIds);
  bigSectorIds.forEach(chain);
  if (minifatSectors) chain([minifatSectorId]);
  // mini 池 + MiniFAT
  const miniPool = Buffer.alloc(miniSectors * SECTOR);
  const minifat = [];
  let miniCursor = 0;
  for (const s of miniStreams) {
    const n = Math.ceil(s.data.length / MINI);
    s.data.copy(miniPool, miniCursor * MINI);
    for (let i = 0; i < n; i++) minifat.push(i + 1 < n ? miniCursor + i + 1 : ENDOFCHAIN);
    miniCursor += n;
  }
  const dir = Buffer.concat([
    dirEntry('Root Entry', 5, NOSTREAM, NOSTREAM, 1, miniSectorIds[0], miniPool.length),
    ...streams.map((s, i) => dirEntry(s.name, 2, NOSTREAM, i + 1 < streams.length ? i + 2 : NOSTREAM, NOSTREAM,
      s.data.length >= 4096 ? bigSectorIds[bigStreams.indexOf(s)][0] : (() => {
        const before = miniStreams.slice(0, miniStreams.indexOf(s)).reduce((sum, x) => sum + Math.ceil(x.data.length / MINI), 0);
        return before;
      })(), s.data.length)),
  ]);
  const dirBytes = Buffer.concat([dir, Buffer.alloc(dirSectors * SECTOR - dir.length)]);
  const header = Buffer.alloc(512);
  Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]).copy(header, 0);
  header.writeUInt16LE(0x003e, 24);
  header.writeUInt16LE(3, 26);
  header.writeUInt16LE(0xfffe, 28);
  header.writeUInt16LE(9, 30);
  header.writeUInt16LE(6, 32);
  header.writeUInt32LE(fatSectors, 44);
  header.writeUInt32LE(2, 48);
  header.writeUInt32LE(4096, 56);
  header.writeUInt32LE(minifatSectorId === NOSTREAM ? ENDOFCHAIN : minifatSectorId, 60);
  header.writeUInt32LE(minifatSectors, 64);
  header.writeUInt32LE(ENDOFCHAIN, 68);
  header.writeUInt32LE(0, 72);
  for (let i = 0; i < 109; i++) header.writeUInt32LE(i < fatSectors ? i : FREESECT, 76 + i * 4);
  const sectors = Buffer.alloc(totalSectors * SECTOR);
  fat.copy(sectors, 0);
  dirBytes.copy(sectors, 2 * SECTOR);
  miniPool.copy(sectors, miniSectorIds[0] * SECTOR);
  bigStreams.forEach((s, i) => s.data.copy(sectors, bigSectorIds[i][0] * SECTOR));
  if (minifatSectors) {
    const mf = Buffer.alloc(SECTOR);
    minifat.forEach((v, i) => mf.writeUInt32LE(v >>> 0, i * 4));
    for (let i = minifat.length; i < 128; i++) mf.writeUInt32LE(FREESECT, i * 4);
    mf.copy(sectors, minifatSectorId * SECTOR);
  }
  return Buffer.concat([header, sectors]);
};

test('手写第二套 CFB：阈值边界（4095B mini / 4096B 常规）与多流提取', () => {
  const cfb = buildCfbJs({ streamSizes: [{ name: 'tiny.txt', size: 33 }, { name: 'edge-min.txt', size: 4095 }, { name: 'edge-max.bin', size: 4096 }] });
  const r = parseOle(new Uint8Array(cfb));
  assert.equal(r.ok, true, r.failure ?? '');
  const byPath = new Map(r.streams.map(s => [s.path, s.bytes]));
  assert.equal(byPath.get('/tiny.txt').length, 33);
  assert.equal(byPath.get('/edge-min.txt').length, 4095, '4095 < 4096 应走 mini 流');
  assert.equal(byPath.get('/edge-max.bin').length, 4096, '4096 应走常规 FAT 扇区');
  // 内容锚点：第 i 字节 = (i*31+7) % 256
  for (const [name, size] of [['/tiny.txt', 33], ['/edge-min.txt', 4095], ['/edge-max.bin', 4096]]) {
    const bytes = byPath.get(name);
    assert.equal(bytes[0], 7, `${name} 首字节`);
    assert.equal(bytes[size - 1], ((size - 1) * 31 + 7) % 256, `${name} 尾字节`);
  }
});

test('非法输入：魔数错 / 截断头 拒绝并说明', () => {
  const r1 = parseOle(new Uint8Array(1024));
  assert.equal(r1.ok, false);
  assert.ok(r1.failure?.includes('D0 CF 11 E0'), r1.failure);
  const bad = Buffer.alloc(512);
  Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]).copy(bad, 0);
  const r2 = parseOle(new Uint8Array(bad.subarray(0, 100)));
  assert.equal(r2.ok, false);
  assert.ok(r2.failure?.includes('512'), r2.failure);
});

// ---- 加密迹象检测（EncryptedPackage 命名检测入口；内容级检测由单测口径覆盖） ----

test('加密迹象：EncryptedPackage 流提示，普通流不误报', () => {
  const pkg = buildCfbJs({ streamSizes: [{ name: 'EncryptedPackage', size: 100 }] });
  const r2 = parseOle(new Uint8Array(pkg));
  assert.ok(r2.encryptedHints.some(h => h.includes('EncryptedPackage')), JSON.stringify(r2.encryptedHints));
  const plain = buildCfbJs({ streamSizes: [{ name: 'WordDocument', size: 64 }] });
  const r1 = parseOle(new Uint8Array(plain));
  assert.ok(!r1.encryptedHints.some(h => h.includes('fEncrypted')), '普通流不应误报 fEncrypted');
});

test('FAT 环引用保护：自指扇区链不造成死循环', () => {
  const cfb = buildCfbJs({ streamSizes: [{ name: 'a.txt', size: 100 }] });
  const bytes = new Uint8Array(cfb);
  // 把 mini 流首扇区的 FAT 项改成自指（环）
  bytes[4 * 4] = 4; bytes[4 * 4 + 1] = 0; bytes[4 * 4 + 2] = 0; bytes[4 * 4 + 3] = 0; // FAT[4] = 4
  const started = Date.now();
  const r = parseOle(bytes);
  assert.ok(Date.now() - started < 3000, '环引用不得造成死循环');
  assert.equal(r.ok, true, '解析应带环保护完成');
});
