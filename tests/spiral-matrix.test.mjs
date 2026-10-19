// 螺旋矩阵编解码测试（B3-3）：手算 4×4 顺/逆时针逐字符对拍、encode/decode 互逆幂等、
// 列数指定与自动 √n、多行右补空对齐、单行切块补位、变体别名、护栏（空输入/尺寸上限）。
// 测试向量独立权威来源：spiralMatrix.ts 模块头部手算锚点（行主序 A..P 的两条螺旋序）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { spiralCoordinates, spiralMatrixDecode, spiralMatrixEncode, parseSpiralDirection, SPIRAL_MATRIX_MAX_CELLS } =
  loadModule(path.join(srcDir, 'utils', 'codec', 'spiralMatrix.ts'));

// 手算锚点一（顺时针 4×4）：行主序 A..P，螺旋读出 = A..P。
const CW_4X4 = ['ABCD', 'LMNE', 'KPOF', 'JIHG'].join('\n');
// 手算锚点二（逆时针 4×4）：行主序 A..P，螺旋读出 = A..P。
const CCW_4X4 = ['ALKJ', 'BMPI', 'CNOH', 'DEFG'].join('\n');

test('spiralCoordinates：4×4 顺时针坐标序逐点对拍（右→下→左→上内收）', () => {
  const cells = spiralCoordinates(4, 4, 'clockwise');
  assert.deepEqual(Array.from(cells, cell => `${cell.y},${cell.x}`), [
    '0,0', '0,1', '0,2', '0,3',
    '1,3', '2,3', '3,3',
    '3,2', '3,1', '3,0',
    '2,0', '1,0',
    '1,1', '1,2',
    '2,2',
    '2,1',
  ]);
});

test('spiralCoordinates：4×4 逆时针坐标序逐点对拍（先向下）+ 非方形 2×5', () => {
  const cells = spiralCoordinates(4, 4, 'counterclockwise');
  assert.deepEqual(Array.from(cells, cell => `${cell.y},${cell.x}`), [
    '0,0', '1,0', '2,0', '3,0',
    '3,1', '3,2', '3,3',
    '2,3', '1,3', '0,3',
    '0,2', '0,1',
    '1,1', '2,1',
    '2,2',
    '1,2',
  ]);
  // 非方形：2×5 逆时针（先向下走 2 格，再向右 4 格，再向上，再向左内收）。
  const wide = spiralCoordinates(2, 5, 'counterclockwise');
  assert.deepEqual(Array.from(wide, cell => `${cell.y},${cell.x}`), [
    '0,0', '1,0',
    '1,1', '1,2', '1,3', '1,4',
    '0,4',
    '0,3', '0,2', '0,1',
  ]);
});

test('decode 顺时针：手算 4×4 锚点逐字符一致', () => {
  assert.equal(spiralMatrixDecode(CW_4X4, 'clockwise'), 'ABCDEFGHIJKLMNOP');
});

test('decode 逆时针：手算 4×4 锚点逐字符一致', () => {
  assert.equal(spiralMatrixDecode(CCW_4X4, 'counterclockwise'), 'ABCDEFGHIJKLMNOP');
});

test('encode 顺时针：16 字符 + 指定 4 列 → 手算锚点矩阵', () => {
  assert.equal(spiralMatrixEncode('ABCDEFGHIJKLMNOP', 'clockwise', '4'), CW_4X4);
});

test('encode 逆时针：16 字符 + 指定 4 列 → 手算锚点矩阵', () => {
  assert.equal(spiralMatrixEncode('ABCDEFGHIJKLMNOP', 'counterclockwise', '4'), CCW_4X4);
});

test('encode 自动列数：ceil(sqrt(n))，16 字符自动 4 列与手算锚点一致', () => {
  assert.equal(spiralMatrixEncode('ABCDEFGHIJKLMNOP', 'clockwise'), CW_4X4);
  // 17 字符 → 自动 5 列 4 行，末位补 3 空格；解码时补位空格尾巴被 trimEnd。
  const encoded17 = spiralMatrixEncode('ABCDEFGHIJKLMNOPQ', 'clockwise');
  assert.equal(encoded17.split('\n').length, 4);
  for (const line of encoded17.split('\n')) assert.equal(Array.from(line).length, 5);
  assert.equal(spiralMatrixDecode(encoded17, 'clockwise'), 'ABCDEFGHIJKLMNOPQ');
});

test('encode(decode(x)) 幂等：顺/逆时针 4×4 与 3×5 矩形', () => {
  for (const [matrix, variant] of [[CW_4X4, 'clockwise'], [CCW_4X4, 'counterclockwise']]) {
    const round = spiralMatrixEncode(spiralMatrixDecode(matrix, variant), variant, '4');
    assert.equal(round, matrix, `variant=${variant}`);
  }
  const rect = ['ABCDE', 'FGHIJ', 'KLMNO'].join('\n');
  assert.equal(spiralMatrixEncode(spiralMatrixDecode(rect, 'counterclockwise'), 'counterclockwise', '5'), rect);
});

test('decode(encode(y)) 幂等：任意线性文本两个方向', () => {
  for (const variant of ['clockwise', 'counterclockwise']) {
    const text = 'flag{sp1ral_m4tr1x_r0und_tr1p}';
    assert.equal(spiralMatrixDecode(spiralMatrixEncode(text, variant), variant), text);
  }
});

test('退化环回归：5×6（内圈 1×2）/ 单行 / 单列 不重不漏', () => {
  for (const variant of ['clockwise', 'counterclockwise']) {
    for (const text of ['ABCDEFGHIJKLMNOPQRSTU', 'ABCDEFGH', 'ABCDEFGHIJ']) {
      assert.equal(spiralMatrixDecode(spiralMatrixEncode(text, variant), variant), text, `variant=${variant} len=${text.length}`);
    }
  }
  // 单行矩阵：顺时针坐标序即行主序；单列：即列主序。
  assert.deepEqual(Array.from(spiralCoordinates(1, 4, 'clockwise'), cell => `${cell.y},${cell.x}`), ['0,0', '0,1', '0,2', '0,3']);
  assert.deepEqual(Array.from(spiralCoordinates(4, 1, 'clockwise'), cell => `${cell.y},${cell.x}`), ['0,0', '1,0', '2,0', '3,0']);
});

test('多行 encode：右侧补空格对齐后整体入阵（手算 2×4：AB␣␣ / FEDC）', () => {
  // 行主序线性 = "AB␣␣CDEF"（8 格），顺时针填 2×4：
  // (0,0)A(0,1)B(0,2)' '(0,3)' ' (1,3)C(1,2)D(1,1)E(1,0)F。
  assert.equal(spiralMatrixEncode('AB\nCDEF', 'clockwise'), 'AB  \nFEDC');
  // 解码读回逐字符忠实（含行 0 的补位空格）：AB␣␣CDEF。
  assert.equal(spiralMatrixDecode('AB  \nFEDC', 'clockwise'), 'AB  CDEF');
});

test('变体别名：中文与缩写与英文等价', () => {
  assert.equal(parseSpiralDirection('顺时针'), 'clockwise');
  assert.equal(parseSpiralDirection('逆时针'), 'counterclockwise');
  assert.equal(parseSpiralDirection('cw'), 'clockwise');
  assert.equal(parseSpiralDirection('ccw'), 'counterclockwise');
  assert.equal(parseSpiralDirection(''), 'clockwise');
  assert.equal(parseSpiralDirection(undefined), 'clockwise');
  assert.throws(() => parseSpiralDirection('diagonal'), /未知螺旋方向/);
  // 中文别名直传编解码入口行为一致。
  assert.equal(spiralMatrixDecode(CW_4X4, '顺时针'), 'ABCDEFGHIJKLMNOP');
  assert.equal(spiralMatrixDecode(CCW_4X4, '逆时针'), 'ABCDEFGHIJKLMNOP');
});

test('护栏：空输入抛中文错误；尺寸超上限抛错', () => {
  assert.throws(() => spiralMatrixDecode(''), /输入为空/);
  assert.throws(() => spiralMatrixEncode(''), /输入为空/);
  assert.throws(() => spiralMatrixDecode('\n\n'), /输入为空|矩阵/);
  const big = Math.floor(Math.sqrt(SPIRAL_MATRIX_MAX_CELLS)) + 1;
  const huge = 'x'.repeat(SPIRAL_MATRIX_MAX_CELLS + 1);
  assert.throws(() => spiralMatrixEncode(huge, 'clockwise', String(big)), /超过.*上限/);
});

test('CRLF 输入归一：\\r\\n 行距不影响解码', () => {
  assert.equal(spiralMatrixDecode(CW_4X4.split('\n').join('\r\n'), 'clockwise'), 'ABCDEFGHIJKLMNOP');
});
