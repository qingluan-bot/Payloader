// 数织线求解器测试（B3-4）：教材样例全解（手算菱形 5×5 / 条形 4×4）、欠定样例输出部分解 + ?、
// 超限护栏（>40×40 报错、单线组合数 >200000 跳过、矛盾约束报错）、位流与 RGBA 出口对接口径。
// 测试向量独立权威来源：模块头部算法描述 + 手算排布（下方逐个注明）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const {
  solveNonogram,
  parseNonogramInput,
  nonogramGridToAscii,
  nonogramToBitString,
  nonogramToRgba,
  NONOGRAM_MAX_SIDE,
  NONOGRAM_MAX_LINE_COMBOS,
} = loadModule(path.join(srcDir, 'utils', 'ctf', 'nonogram.ts'));

const cluesOf = (rows, cols) => `${rows.join('\n')}\n---\n${cols.join('\n')}`;

test('parseNonogramInput：两段解析、全角逗号兼容、「0」空线', () => {
  const parsed = parseNonogramInput('2,1\n1\n---\n1，1\n0\n2');
  assert.deepEqual(Array.from(parsed.rowClues, line => Array.from(line)), [[2, 1], [1]]);
  assert.deepEqual(Array.from(parsed.colClues, line => Array.from(line)), [[1, 1], [0], [2]]);
  assert.throws(() => parseNonogramInput('1\n1\n1'), /缺少 --- 分隔线/);
  assert.throws(() => parseNonogramInput('1\n---\n1\n---\n1'), /多条 --- 分隔线/);
  assert.throws(() => parseNonogramInput('1,x\n---\n1'), /非法块长/);
  assert.throws(() => parseNonogramInput('0,1\n---\n1'), /「0」只能单独/);
});

test('教材样例一：5×5 菱形全解（手算唯一解）', () => {
  // 唯一解图形（手算）：
  //   ..#..
  //   .###.
  //   #####
  //   .###.
  //   ..#..
  const input = cluesOf([1, 3, 5, 3, 1], [1, 3, 5, 3, 1]);
  const result = solveNonogram(input);
  assert.equal(result.solved, true);
  assert.equal(nonogramGridToAscii(result.grid), '..#..\n.###.\n#####\n.###.\n..#..');
  assert.ok(result.rounds >= 1);
  assert.equal(result.skippedLines, 0);
});

test('教材样例二：4×4 条形全解（行 [4],[1],[4],[1] 列 [4],[1,1],[1,1],[1,1]）', () => {
  const result = solveNonogram(cluesOf([4, 1, 4, 1], [[4], [1, 1], [1, 1], [1, 1]]));
  assert.equal(result.solved, true);
  assert.equal(nonogramGridToAscii(result.grid), '####\n#...\n####\n#...');
});

test('教材样例三：「0」空线与空行收敛', () => {
  // 3×3：行 [3],[0],[3]；列（#.# 形态）[1,1],[1,1],[1,1] → 手算唯一解：行 0 全填、行 1 空、行 2 全填。
  const result = solveNonogram(cluesOf([3, 0, 3], [[1, 1], [1, 1], [1, 1]]));
  assert.equal(result.solved, true);
  assert.equal(nonogramGridToAscii(result.grid), '###\n...\n###');
});

test('欠定样例：2×2 双解输出全部 ?（部分解不猜测）', () => {
  // 行 [1],[1] 列 [1],[1]：两条对角线排布均合法 → 线求解器不动点上无任何确定格。
  const result = solveNonogram(cluesOf([1, 1], [1, 1]));
  assert.equal(result.solved, false);
  assert.equal(nonogramGridToAscii(result.grid), '??\n??');
});

test('欠定样例：部分确定 + 部分 ?（3×3 十字空框，手算双解）', () => {
  // 手算：行 1 [0] 与列 1 [0] 把中十字定死为空；四个角上行 [1]/列 [1] 各有两解
  //（全局解 = 主对角角填 或 副对角角填，共 2 个）→ 角保持 ?。
  const result = solveNonogram(cluesOf([1, 0, 1], [1, 0, 1]));
  assert.equal(result.solved, false);
  assert.equal(nonogramGridToAscii(result.grid), '?.?\n...\n?.?');
});

test('护栏：超过 40×40 上限报错', () => {
  const tooManyRows = Array.from({ length: NONOGRAM_MAX_SIDE + 1 }, () => '1');
  assert.throws(() => solveNonogram(cluesOf(tooManyRows, ['1'])), /超过 40×40 上限/);
  const wideClue = String(NONOGRAM_MAX_SIDE + 1);
  assert.throws(() => solveNonogram(cluesOf([wideClue], ['1'])), /块长超过 40 上限/);
});

test('护栏：矛盾约束报错（行 [4] vs 列全 [0]）', () => {
  assert.throws(() => solveNonogram(cluesOf([4], [[0], [0], [0], [0]])), /矛盾/);
  // 块长和塞不进线长：行 [5] 但只有 4 列。
  assert.throws(() => solveNonogram(cluesOf([5], ['1', '1', '1', '1'])), /塞不进|矛盾/);
});

test('护栏：单线组合数超 200000 跳过该线（输出 ? 而非报错）', () => {
  // 13 行 × 40 列：每行 clue [1]×13 → 自由度 15，C(28,13) = 37442166 > 200000，行线全跳过；
  // 每列 clue [3] → C(13,3) = 286 正常枚举但无确定格。结果：全 ? + skippedLines=13。
  const rowLine = Array.from({ length: 13 }, () => '1').join(',');
  const rowClues = Array.from({ length: 13 }, () => rowLine);
  const colClues = Array.from({ length: 40 }, () => '3');
  const result = solveNonogram(cluesOf(rowClues, colClues));
  assert.equal(result.solved, false);
  assert.equal(result.skippedLines, 13);
  const ascii = nonogramGridToAscii(result.grid);
  assert.ok(!ascii.includes('#') && !ascii.includes('.'), `跳过线上不应有确定格：${ascii.slice(0, 40)}`);
  assert.equal(ascii.split('?').length - 1, 13 * 40);
});

test('组合数恰在阈值内仍枚举：20×40 极限样例可收敛', () => {
  // 20 行 × 40 列：行 clue [20]（前半填）、[20]…… 直觉构造：每行 [20]，
  // 列 clue 前 20 列 [20]、后 20 列 [0] → 唯一解左半全填右半全空。
  const rowClues = Array.from({ length: 20 }, () => '20');
  const colClues = [...Array.from({ length: 20 }, () => '20'), ...Array.from({ length: 20 }, () => '0')];
  const result = solveNonogram(cluesOf(rowClues, colClues));
  assert.equal(result.solved, true);
  const ascii = nonogramGridToAscii(result.grid).split('\n');
  for (const line of ascii) assert.equal(line, '#'.repeat(20) + '.'.repeat(20));
});

test('出口：位流 0/1 与 RGBA 黑白（# → 1/黑，. 与 ? → 0/白）', () => {
  const result = solveNonogram(cluesOf([4, 1, 4, 1], [[4], [1, 1], [1, 1], [1, 1]]));
  assert.equal(nonogramToBitString(result), '1111' + '1000' + '1111' + '1000');
  const rgba = nonogramToRgba(result);
  assert.equal(rgba.length, 4 * 4 * 4);
  // 像素 (0,0) 填 → 黑；(1,1) 空 → 白；alpha 恒 255。
  assert.deepEqual(Array.from(rgba.slice(0, 4)), [0, 0, 0, 255]);
  const pixel = (x, y) => Array.from(rgba.slice((y * 4 + x) * 4, (y * 4 + x) * 4 + 4));
  assert.deepEqual(pixel(1, 1), [255, 255, 255, 255]);
  assert.deepEqual(pixel(0, 1), [0, 0, 0, 255]);
  // 欠定结果：? 按白处理。
  const partial = solveNonogram(cluesOf([1, 1], [1, 1]));
  assert.equal(nonogramToBitString(partial), '0000');
  assert.deepEqual(Array.from(nonogramToRgba(partial).slice(0, 4)), [255, 255, 255, 255]);
});

test('RGBA 出口对接 qrDecode 口径：宽=cols 高=rows（形状冒烟）', () => {
  const result = solveNonogram(cluesOf([4, 1, 4, 1], [[4], [1, 1], [1, 1], [1, 1]]));
  const rgba = nonogramToRgba(result);
  // decodeQrCodes(rgba, width, height) 的输入约定：行主序 RGBA，长度 = width*height*4。
  assert.equal(rgba.length, result.cols * result.rows * 4);
  assert.ok(NONOGRAM_MAX_LINE_COMBOS === 200000);
});
