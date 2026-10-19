// Minecraft NBT 解析引擎测试（B3-5）：14 种 tag 全覆盖手工字节构造、gzip/zlib/裸压缩头判别、
// Long BigInt 精度、树转储与截断、路径过滤、护栏（深度/节点/截断/负长度/原型污染）、
// level.dat 摘要（代表性手工样本，含 WorldGenSettings.seed / GameRules / DataVersion=3465）。
// 真实 level.dat 样本说明：本机没有真实存档，采用按 minecraft.wiki NBT 格式手工构造的
// 代表性样本（结构对齐 1.18+ 官方 level.dat：根 Compound→Data→WorldGenSettings.seed + Spawn +
// GameRules + DataVersion + Version.Name），并在用例注明。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import zlib from 'node:zlib';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const {
  parseNbt,
  parseNbtAuto,
  detectNbtCompression,
  queryNbtPath,
  dumpNbt,
  levelDatSummary,
  NBT_MAX_NODES,
} = loadModule(path.join(srcDir, 'utils', 'ctf', 'mcNbt.ts'));

// ---- 手工 NBT 字节构造器（大端）----

const be = {
  u8: value => [value & 0xff],
  u16: value => [(value >> 8) & 0xff, value & 0xff],
  i32: value => [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff],
  f32: value => { const view = new DataView(new ArrayBuffer(4)); view.setFloat32(0, value, false); return Array.from(new Uint8Array(view.buffer)); },
  f64: value => { const view = new DataView(new ArrayBuffer(8)); view.setFloat64(0, value, false); return Array.from(new Uint8Array(view.buffer)); },
  i64: value => { const view = new DataView(new ArrayBuffer(8)); view.setBigInt64(0, value, false); return Array.from(new Uint8Array(view.buffer)); },
  // NBT String 长度字段是 UTF-8 字节数（不是 UTF-16 码元数），中文样本必须按字节长声明。
  str: text => { const bytes = Array.from(Buffer.from(text, 'utf8')); return [...be.u16(bytes.length), ...bytes]; },
  // 命名 tag：type + name + payload（payload 由调用方给字节）。
  tag: (type, name, payload) => [type, ...be.str(name), ...payload],
};

// 14 种 tag 全覆盖样本：根 Compound("") 下 1-12 各型子节点 + 嵌套 List/Compound + End 收口。
// Long 用 2^53 以上的 123456789012345678n 验证 BigInt 精度（number 会丢精度）。
const buildFullTagSample = () => Uint8Array.from([
  10, ...be.str(''),
  ...be.tag(1, 'byteTag', [0xfe]), // 有符号 -2
  ...be.tag(2, 'shortTag', [...be.u16(0xfffe)]), // -2
  ...be.tag(3, 'intTag', be.i32(-123456)),
  ...be.tag(4, 'longTag', be.i64(123456789012345678n)),
  ...be.tag(5, 'floatTag', be.f32(3.5)),
  ...be.tag(6, 'doubleTag', be.f64(-2.25)),
  ...be.tag(7, 'byteArrayTag', [...be.i32(4), 0xde, 0xad, 0xbe, 0xef]),
  ...be.tag(8, 'stringTag', ...[be.str('flag{nbt_中文}')]),
  ...be.tag(9, 'intListTag', [3, ...be.i32(3), ...be.i32(10), ...be.i32(-20), ...be.i32(30)]),
  ...be.tag(9, 'compoundListTag', [
    10, ...be.i32(2),
    ...be.tag(3, 'id', be.i32(1)), 0,
    ...be.tag(3, 'id', be.i32(2)), 0,
  ]),
  ...be.tag(10, 'nestedCompound', [...be.tag(2, 'inner', [...be.u16(0x0007)]), 0]),
  ...be.tag(11, 'intArrayTag', [...be.i32(3), ...be.i32(1), ...be.i32(-2), ...be.i32(3)]),
  ...be.tag(12, 'longArrayTag', [...be.i32(2), ...be.i64(1n), ...be.i64(-1n)]),
  0, // TAG_End 收口
]);

const FULL_SAMPLE = buildFullTagSample();

test('detectNbtCompression：gzip/zlib/裸 三种头判别', () => {
  assert.equal(detectNbtCompression(Uint8Array.from([0x1f, 0x8b, 0x00])), 'gzip');
  assert.equal(detectNbtCompression(Uint8Array.from([0x78, 0x9c, 0x00])), 'zlib');
  assert.equal(detectNbtCompression(Uint8Array.from([0x0a, 0x00, 0x00])), 'raw');
  // 裸 NBT 0x0a 不满足 zlib 校验（0x0a0a % 31 != 0），不误判。
  assert.equal(detectNbtCompression(FULL_SAMPLE), 'raw');
});

test('14 种 tag 全覆盖解析：各型载荷与值逐项对拍', () => {
  const result = parseNbt(FULL_SAMPLE);
  assert.equal(result.rootName, '');
  assert.equal(result.compression, 'raw');
  const root = result.root;
  assert.equal(root.byteTag.type, 1);
  assert.equal(root.byteTag.value, -2);
  assert.equal(root.shortTag.value, -2);
  assert.equal(root.intTag.value, -123456);
  assert.equal(root.longTag.value, 123456789012345678n, 'Long 必须无损（超出 2^53）');
  assert.equal(root.floatTag.value, 3.5);
  assert.equal(root.doubleTag.value, -2.25);
  assert.deepEqual(Array.from(root.byteArrayTag.value), [0xde, 0xad, 0xbe, 0xef]);
  assert.equal(root.stringTag.value, 'flag{nbt_中文}');
  const intList = root.intListTag.value;
  assert.equal(root.intListTag.elementType, 3);
  assert.deepEqual(Array.from(intList, item => item.value), [10, -20, 30]);
  const compoundList = root.compoundListTag.value;
  assert.equal(root.compoundListTag.elementType, 10);
  assert.equal(compoundList.length, 2);
  assert.equal(compoundList[1].value.id.value, 2);
  assert.equal(root.nestedCompound.value.inner.value, 7);
  assert.deepEqual(Array.from(root.intArrayTag.value), [1, -2, 3]);
  assert.deepEqual(Array.from(root.longArrayTag.value), [1n, -1n]);
  assert.equal(Object.keys(root).length, 13, '根 Compound 13 个命名子节点');
});

test('gzip/zlib 自动解压：node:zlib 压缩样本走 parseNbtAuto', async () => {
  const gz = zlib.gzipSync(FULL_SAMPLE);
  const gzResult = await parseNbtAuto(new Uint8Array(gz));
  assert.equal(gzResult.compression, 'gzip');
  assert.equal(gzResult.root.longTag.value, 123456789012345678n);

  const zl = zlib.deflateSync(FULL_SAMPLE);
  const zlResult = await parseNbtAuto(new Uint8Array(zl));
  assert.equal(zlResult.compression, 'zlib');
  assert.equal(zlResult.root.stringTag.value, 'flag{nbt_中文}');

  const rawResult = await parseNbtAuto(FULL_SAMPLE);
  assert.equal(rawResult.compression, 'raw');
  assert.equal(rawResult.byteLength, FULL_SAMPLE.length);
});

test('树缩进转储：Long/嵌套显示正确，ByteArray/LongArray 截断预览', () => {
  const result = parseNbt(FULL_SAMPLE);
  const dump = dumpNbt(result.root);
  assert.ok(dump.includes('byteTag: TAG_Byte(-2)'), dump);
  assert.ok(dump.includes('longTag: TAG_Long(123456789012345678)'), dump);
  assert.ok(dump.includes('stringTag: TAG_String("flag{nbt_中文}")'), dump);
  assert.ok(dump.includes('byteArrayTag: TAG_Byte_Array [4 字节] de ad be ef'), dump);
  assert.ok(dump.includes('TAG_List<TAG_Int>(3)'), dump);
  assert.ok(dump.includes('TAG_Compound(13)'), dump);
  // 长数组截断：12 项 LongArray 只显示前 2 项 + 省略号。
  const longArrayLine = dump.split('\n').find(line => line.includes('longArrayTag'));
  assert.ok(longArrayLine.includes('[2 项] 1, -1'), longArrayLine);
  // 截断预览上限生效：4 字节 ByteArray 在 maxArrayPreview=2 下只显示 2 字节。
  const shortDump = dumpNbt(result.root, { maxArrayPreview: 2 });
  const byteArrayLine = shortDump.split('\n').find(line => line.includes('byteArrayTag'));
  assert.ok(byteArrayLine.includes('de ad …'), byteArrayLine);
});

test('路径过滤：Data.Player.Inventory 式下钻与 List 下标', () => {
  const result = parseNbt(FULL_SAMPLE);
  const hit = queryNbtPath(result.root, 'compoundListTag.1.id');
  assert.equal(hit.value, 2);
  assert.throws(() => queryNbtPath(result.root, '不存在.路径'), /路径.*不存在/);
  assert.throws(() => queryNbtPath(result.root, 'intListTag.99'), /合法 List 下标/);
  assert.throws(() => queryNbtPath(result.root, 'stringTag.x'), /无法下钻/);
  // dump + path 组合：只转储子树。
  const subtree = dumpNbt(result.root, { path: 'nestedCompound' });
  assert.ok(subtree.includes('inner: TAG_Short(7)'), subtree);
  assert.ok(!subtree.includes('byteTag'), subtree);
});

test('护栏：截断流/负长度/深度超限/节点超限/根类型错误', () => {
  // 截断：砍掉最后 3 字节（End 收口 + 尾部数据）。
  // 砍尾 3 字节：LongArray 长度护栏先于读取器截断检查触发（两类消息都算截断口径）。
  assert.throws(() => parseNbt(FULL_SAMPLE.slice(0, FULL_SAMPLE.length - 3)), /截断|剩余字节/);
  // 根类型非 Compound。
  assert.throws(() => parseNbt(Uint8Array.from([8, ...be.str('s'), ...be.str('x')])), /TAG_Compound\(10\)/);
  // 负长度 ByteArray。
  const negativeArray = Uint8Array.from([10, ...be.str(''), ...be.tag(7, 'bad', be.i32(-1)), 0]);
  assert.throws(() => parseNbt(negativeArray), /长度为负/);
  // ByteArray 声明长度超过剩余字节。
  const overlongArray = Uint8Array.from([10, ...be.str(''), ...be.tag(7, 'bad', be.i32(999)), 0]);
  assert.throws(() => parseNbt(overlongArray), /截断/);
  // 深度超限：200 层嵌套 Compound（root + d0..d199 共 201 个 Compound，各需一个 End 收口）。
  const deepParts = [10, ...be.str('')];
  for (let index = 0; index < 200; index += 1) deepParts.push(10, ...be.str(`d${index}`));
  deepParts.push(...new Array(201).fill(0));
  assert.throws(() => parseNbt(Uint8Array.from(deepParts)), /深度超过/);
  // 节点超限：真实携带 100001 个 Int 元素的 List（数据必须在场，否则先撞截断护栏）。
  const listParts = [10, ...be.str(''), ...be.tag(9, 'big', [3, ...be.i32(NBT_MAX_NODES + 1)])];
  for (let index = 0; index <= NBT_MAX_NODES; index += 1) listParts.push(...be.i32(index));
  listParts.push(0);
  assert.throws(() => parseNbt(Uint8Array.from(listParts)), /节点数超过/);
  // 越界 tag 类型。
  assert.throws(() => parseNbt(Uint8Array.from([10, ...be.str(''), ...be.tag(13, 'x', []), 0])), /越界/);
});

test('原型污染防护：键名 "__proto__"/"prototype" 只当普通键', () => {
  const sample = Uint8Array.from([
    10, ...be.str(''),
    ...be.tag(3, '__proto__', be.i32(1)),
    ...be.tag(3, 'prototype', be.i32(2)),
    ...be.tag(3, 'constructor', be.i32(3)),
    0,
  ]);
  const { root } = parseNbt(sample);
  assert.equal(root.__proto__.value, 1, 'Object.create(null) 下 __proto__ 是普通数据键');
  assert.equal(root.prototype.value, 2);
  assert.equal(root.constructor.value, 3);
  assert.equal(Object.getPrototypeOf(root), null);
});

// ---- level.dat 摘要（代表性手工样本；本机无真实存档，结构对齐 1.18+ 官方 level.dat）----

// 手工构造 1.18+ 形态 level.dat：
//   根("") → Data → WorldGenSettings{seed: 12345678901234567, generate_features:1} /
//   SpawnX="flag" 的 ASCII 字节（0x666c6167）/ SpawnY=64 / SpawnZ=普通坐标 /
//   GameRules{keepInventory:"true"(改过,非常规), randomTickSpeed:"3"(默认), ctfCustom:"42"(不在默认表)} /
//   DataVersion=3465（1.20.1 锚点）/ Version{Name:"1.20.1"}；根下另藏非标准顶层字段 HiddenNote。
const buildLevelDat = () => {
  const body = Uint8Array.from([
    10, ...be.str(''),
    ...be.tag(10, 'Data', [
      ...be.tag(10, 'WorldGenSettings', [
        ...be.tag(4, 'seed', be.i64(12345678901234567n)),
        ...be.tag(1, 'generate_features', [1]),
        0,
      ]),
      ...be.tag(3, 'SpawnX', be.i32(0x666c6167)), // "flag"
      ...be.tag(3, 'SpawnY', be.i32(64)),
      ...be.tag(3, 'SpawnZ', be.i32(1024)),
      ...be.tag(10, 'GameRules', [
        ...be.tag(8, 'keepInventory', be.str('true')),
        ...be.tag(8, 'randomTickSpeed', be.str('3')),
        ...be.tag(8, 'ctfCustom', be.str('42')),
        0,
      ]),
      ...be.tag(3, 'DataVersion', be.i32(3465)),
      ...be.tag(10, 'Version', [...be.tag(8, 'Name', be.str('1.20.1')), 0]),
      0,
    ]),
    ...be.tag(8, 'HiddenNote', be.str('s3cret')),
    0,
  ]);
  return zlib.gzipSync(body);
};

test('level.dat 摘要：种子/出生点/DataVersion 锚点/GameRules 高亮/顶层隐藏字段', async () => {
  const gz = buildLevelDat();
  assert.equal(detectNbtCompression(new Uint8Array(gz)), 'gzip');
  const { root } = await parseNbtAuto(new Uint8Array(gz));
  const summary = levelDatSummary(root);

  assert.equal(summary.seed, 12345678901234567n);
  assert.equal(summary.seedSource, 'WorldGenSettings.seed');
  assert.deepEqual([summary.spawn.x, summary.spawn.y, summary.spawn.z], [0x666c6167, 64, 1024]);
  assert.equal(summary.dataVersion, 3465);
  assert.equal(summary.dataVersionAnchor, '1.20.1');
  assert.equal(summary.versionName, '1.20.1');

  const keep = summary.gameRules.find(rule => rule.name === 'keepInventory');
  assert.ok(keep.unusual, 'keepInventory=true 与默认 false 不同 → 非常规');
  const tick = summary.gameRules.find(rule => rule.name === 'randomTickSpeed');
  assert.equal(tick.unusual, false, 'randomTickSpeed=3 是默认值');
  const custom = summary.gameRules.find(rule => rule.name === 'ctfCustom');
  assert.ok(custom.unusual, '不在默认表的规则 → 非常规');
  // 排序：非常规在前。
  assert.equal(summary.gameRules[0].unusual, true);

  assert.ok(summary.asciiHints.some(hint => hint.includes('SpawnX') && hint.includes('"flag"')), `asciiHints=${JSON.stringify(summary.asciiHints)}`);
  assert.ok(!summary.asciiHints.some(hint => hint.includes('SpawnZ')), 'SpawnZ=1024 字节不可打印不命中');

  assert.deepEqual(Array.from(summary.topLevelExtra), ['HiddenNote']);
  assert.ok(summary.notes.some(note => note.includes('非标准顶层字段') && note.includes('HiddenNote')));
});

test('level.dat 摘要：旧版回落 RandomSeed + DataVersion 无精确锚点给区间', async () => {
  const body = Uint8Array.from([
    10, ...be.str(''),
    ...be.tag(10, 'Data', [
      ...be.tag(4, 'RandomSeed', be.i64(-42n)),
      ...be.tag(3, 'DataVersion', be.i32(3500)), // 不在锚点表
      0,
    ]),
    0,
  ]);
  const { root } = await parseNbtAuto(body);
  const summary = levelDatSummary(root);
  assert.equal(summary.seed, -42n);
  assert.equal(summary.seedSource, 'RandomSeed');
  assert.equal(summary.dataVersionAnchor, '介于 1.20.1（3465）与后续版本之间');
  assert.ok(summary.notes.some(note => note.includes('GameRules')));
  assert.equal(summary.topLevelExtra.length, 0);
});

test('level.dat 摘要：非 level.dat 结构抛中文错误', () => {
  const body = Uint8Array.from([10, ...be.str(''), ...be.tag(3, 'NotData', be.i32(1)), 0]);
  const { root } = parseNbt(body);
  assert.throws(() => levelDatSummary(root), /没有 Data Compound/);
});
