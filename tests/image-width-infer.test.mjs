// 位流还原图宽度推断测试（B4-4 批次）：行边界连续性判据（候选约数宽度中"全部纵向邻居
// 平均色差最小"者胜 + 置信度回报）、√n 仅作正方形兜底、列主序扫描开关。
// 权威向量程序化构造：设计 A = 基行 P + 逐行漂移（每行相对上一行翻转 2 格），真实行宽下
// 纵向差率 = 2/12（42.5/255），错误宽度退化为近随机基线——判据的构造性正例。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const ops = loadModule(path.join(srcDir, 'utils', 'ctf', 'imageOps.ts'));

const pixelGray = (image, x, y) => {
  const base = (y * image.width + x) * 4;
  return image.data[base]; // 黑白图 R 通道即灰度
};

// 设计 A：12 列 × 25 行（300 bit）。基行 P，row(y+1) = row(y) 在 (3y)%12 与 (3y+5)%12 翻转
// ——相邻两行恰差 2 格（纵向连续），行结构非周期（无整行重复）。
const buildDesignA = () => {
  const baseRow = [1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1];
  const bits = [];
  let row = baseRow.slice();
  for (let y = 0; y < 25; y += 1) {
    for (let x = 0; x < 12; x += 1) bits.push(row[x]);
    const next = row.slice();
    next[(3 * y) % 12] ^= 1;
    next[(3 * y + 5) % 12] ^= 1;
    row = next;
  }
  return bits.join('');
};

// 行主序位流转列主序流（转置）：原像素 (x,y) 落到流下标 x*height + y
const transposeToColumnMajor = (bits, width, height) => {
  const out = [];
  for (let x = 0; x < width; x += 1) {
    for (let y = 0; y < height; y += 1) out.push(bits[y * width + x]);
  }
  return out.join('');
};

// ---- 验收主向量：12×25 非方阵位流 ----

test('验收：300 bit 非方阵位流（宽 12 高 25 与宽 25 高 12 两可）连续性推断给出 12×25 并回报置信度', () => {
  const bits = buildDesignA();
  assert.equal(bits.length, 300);
  const outcome = ops.bitsToImage(bits, undefined, { autoWidth: true });
  assert.equal(outcome.image.width, 12, `应推断宽 12（实际 ${outcome.image.width}）`);
  assert.equal(outcome.image.height, 25, `应推断高 25（实际 ${outcome.image.height}）`);
  assert.match(outcome.widthGuess, /行边界连续性推断 12×25/);
  assert.ok(outcome.confidence !== undefined && outcome.confidence >= 0.4, `置信度应 ≥0.4（实际 ${outcome.confidence}）`);
  // 逐像素还原自证：位 1=黑、位 0=白，行主序落位
  for (let index = 0; index < bits.length; index += 1) {
    const x = index % 12;
    const y = Math.floor(index / 12);
    assert.equal(pixelGray(outcome.image, x, y), bits[index] === '1' ? 0 : 255, `像素 (${x},${y}) 应还原位流`);
  }
});

test('opt-in 边界：同一非方阵位流不带 autoWidth 仍按原口径报错（默认行为零变化）', () => {
  assert.throws(() => ops.bitsToImage(buildDesignA()), /请在参数里指定宽度/);
});

test('行结构优先：行长一致的矩形文本行不受 autoWidth 影响（行宽仍权威）', () => {
  const lined = ops.bitsToImage('10\n01\n11\n00', undefined, { autoWidth: true });
  assert.equal(lined.image.width, 2);
  assert.equal(lined.image.height, 4);
  assert.match(lined.widthGuess, /按行宽 2/);
  assert.equal(lined.confidence, undefined, '行结构路径不产出置信度');
});

// ---- √n 兜底语义 ----

test('√n 兜底：完全平方位流 autoWidth 仍解析 4×4（候选打分后 √n 胜出），指定宽覆盖保留', () => {
  const square = ops.bitsToImage('1000010001100001', undefined, { autoWidth: true });
  assert.equal(square.image.width, 4);
  assert.equal(square.image.height, 4);
  const forced = ops.bitsToImage('1000010001100001', 8, { autoWidth: true });
  assert.equal(forced.image.width, 8, '指定宽优先于 autoWidth');
  assert.equal(forced.image.height, 2);
  assert.equal(forced.confidence, undefined, '指定宽路径不产出置信度');
});

test('单候选置信度为 0：4 bit 只有 w=2 一个候选，无可比对象不虚报', () => {
  const outcome = ops.bitsToImage('1001', undefined, { autoWidth: true });
  assert.equal(outcome.image.width, 2);
  assert.equal(outcome.image.height, 2);
  assert.equal(outcome.confidence, 0);
});

test('推断函数直连：inferBitstreamWidth 返回宽度/置信度/判据说明，无候选时显式抛错', () => {
  const values = new Uint8Array(Array.from(buildDesignA(), ch => (ch === '1' ? 0 : 255)));
  const inference = ops.inferBitstreamWidth(values);
  assert.equal(inference.width, 12);
  assert.equal(inference.height, 25);
  assert.match(inference.note, /纵向平均色差/);
  assert.throws(() => ops.inferBitstreamWidth(new Uint8Array(7)), /无候选/);
});

// ---- 列主序扫描开关 ----

test('columnMajor：转置流按列主序解释还原原图（宽 12 高 25），误按行主序推断不出 12', () => {
  const bitsA = buildDesignA();
  const transposed = transposeToColumnMajor(bitsA, 12, 25);
  const columnMajor = ops.bitsToImage(transposed, undefined, { autoWidth: true, columnMajor: true });
  assert.equal(columnMajor.image.width, 12);
  assert.equal(columnMajor.image.height, 25);
  assert.match(columnMajor.widthGuess, /列主序扫描/);
  // 逐像素对照设计 A：列主序落位 i → (floor(i/25), i%25)，应精确还原原图
  for (let index = 0; index < transposed.length; index += 1) {
    const x = Math.floor(index / 25);
    const y = index % 25;
    assert.equal(pixelGray(columnMajor.image, x, y), bitsA[y * 12 + x] === '1' ? 0 : 255, `列主序像素 (${x},${y})`);
  }
  const rowMajor = ops.bitsToImage(transposed, undefined, { autoWidth: true });
  assert.notEqual(rowMajor.image.width, 12, '同一流不按列主序解释时不应命中宽 12');
});

test('columnMajor 默认关闭：不带开关的落位与行主序一致（零回归）', () => {
  const outcome = ops.bitsToImage('100010', 3);
  // '100 010'：黑在 (0,0) 与 (1,1)
  assert.equal(pixelGray(outcome.image, 0, 0), 0);
  assert.equal(pixelGray(outcome.image, 1, 0), 255);
  assert.equal(pixelGray(outcome.image, 1, 1), 0);
});

// ---- coordsToImage 轴序开关 ----

test('coordsToImage columnMajor：坐标按 (行,列) 轴序解释，默认 (x,y) 口径不变', () => {
  // 坐标 "0,2 1,0"：默认口径 (x,y) → 画布 2×3、白点 raster(0,2) 与 (1,0)；
  // 列主序 (行,列) → x=列,y=行 → 点 (2,0) 与 (0,1) → 画布 3×2、白点 raster(2,0) 与 (0,1)。
  // 画布宽高随轴序互换，坐标归一化（减 min）后位置可精确断言。
  const byXY = ops.coordsToImage('0,2 1,0');
  assert.equal(byXY.image.width, 2);
  assert.equal(byXY.image.height, 3);
  assert.equal(pixelGray(byXY.image, 0, 2), 255, '默认口径白点在 raster (0,2)');
  assert.equal(pixelGray(byXY.image, 1, 0), 255, '默认口径白点在 raster (1,0)');
  assert.equal(pixelGray(byXY.image, 0, 0), 0, '默认口径左上角是黑底');
  const byRowCol = ops.coordsToImage('0,2 1,0', { columnMajor: true });
  assert.equal(byRowCol.image.width, 3, '轴序互换后画布宽高互换');
  assert.equal(byRowCol.image.height, 2);
  assert.equal(pixelGray(byRowCol.image, 2, 0), 255, '(行,列) 轴序白点在 raster (2,0)');
  assert.equal(pixelGray(byRowCol.image, 0, 1), 255, '(行,列) 轴序白点在 raster (0,1)');
  assert.equal(pixelGray(byRowCol.image, 0, 0), 0, '轴序下黑底校验');
});
