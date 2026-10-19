// 螺旋矩阵编解码（codec 古典换位补充，CTF 能力补强批次三 B3-3）。
// 把线性文本按螺旋顺序填入 N×M 方阵（encode），或把多行矩阵按螺旋顺序读出线性文本（decode）。
// 对拍锚点（手算 4×4，行主序填 A..P，两例读出均为 ABCDEFGHIJKLMNOP）：
//   顺时针（右→下→左→上逐圈内收）：
//     ┌ A B C D ┐      螺旋序 (0,0)(0,1)(0,2)(0,3)(1,3)(2,3)(3,3)(3,2)(3,1)(3,0)(2,0)(1,0)(1,1)(1,2)(2,2)(2,1)
//     │ L M N E │  →   逐格字符 = A B C D E F G H I J K L M N O P
//     │ K P O F │
//     └ J I H G ┘
//   逆时针（先向下）：
//     ┌ A L K J ┐      螺旋序 (0,0)(1,0)(2,0)(3,0)(3,1)(3,2)(3,3)(2,3)(1,3)(0,3)(0,2)(0,1)(1,1)(2,1)(2,2)(1,2)
//     │ B M P I │  →   逐格字符 = A B C D E F G H I J K L M N O P
//     │ C N O H │
//     └ D E F G ┘
// 两条序列即测试权威向量（tests/spiral-matrix.test.mjs 逐字符断言）。
// 语义约定：encode 输入多行时右侧补空格对齐成矩形再拼接为线性序列（N=行数 M=最宽行）；
// 单行输入按列数切块（列数可指定，缺省自动 ceil(sqrt(n))），末块右侧补空格补满方阵。
// decode 输出去掉尾随空白（补位空格读进来的尾巴不属内容）。纯函数、零依赖、同步。

// 单次编解码的格子总量红线（防超大输入吃内存）。
export const SPIRAL_MATRIX_MAX_CELLS = 4_000_000;

export type SpiralDirection = 'clockwise' | 'counterclockwise';

// variant 参数解析：接受 clock/counterclock 的英文与中文别名，缺省顺时针。
// 'special' 是参数面板未注册 options 时的 select 缺省档位（挂载兼容），按顺时针处理。
export const parseSpiralDirection = (variant?: string): SpiralDirection => {
  const normalized = (variant ?? '').trim().toLowerCase();
  if (normalized === '' || normalized === 'special' || normalized === 'clockwise' || normalized === 'cw' || normalized === '顺时针') return 'clockwise';
  if (normalized === 'counterclockwise' || normalized === 'anticlockwise' || normalized === 'ccw' || normalized === '逆时针') return 'counterclockwise';
  throw new Error(`未知螺旋方向变体：${variant}（支持 clockwise/顺时针、counterclockwise/逆时针）`);
};

export interface SpiralCell {
  y: number; // 行号（0 起）
  x: number; // 列号（0 起）
}

// 生成 rows×cols 的螺旋坐标序列。顺时针：首行向右 → 右列向下 → 末行向左 → 左列向上，逐圈内收；
// 逆时针：首列向下 → 末行向右 → 尾列向上 → 首行向左，逐圈内收。
// 退化环（内圈只剩单行/单列）防重复：单行环的首行腿已覆盖整行，末行腿必须跳过；单列环同理。
export const spiralCoordinates = (rows: number, cols: number, direction: SpiralDirection = 'clockwise'): SpiralCell[] => {
  const cells: SpiralCell[] = [];
  let top = 0;
  let bottom = rows - 1;
  let left = 0;
  let right = cols - 1;
  while (top <= bottom && left <= right) {
    if (direction === 'clockwise') {
      for (let x = left; x <= right; x += 1) cells.push({ y: top, x });
      for (let y = top + 1; y <= bottom; y += 1) cells.push({ y, x: right });
      if (top !== bottom) for (let x = right - 1; x >= left; x -= 1) cells.push({ y: bottom, x });
      if (left !== right) for (let y = bottom - 1; y >= top + 1; y -= 1) cells.push({ y, x: left });
    } else {
      for (let y = top; y <= bottom; y += 1) cells.push({ y, x: left });
      for (let x = left + 1; x <= right; x += 1) cells.push({ y: bottom, x });
      if (left !== right) for (let y = bottom - 1; y >= top; y -= 1) cells.push({ y, x: right });
      if (top !== bottom) for (let x = right - 1; x >= left + 1; x -= 1) cells.push({ y: top, x });
    }
    top += 1;
    bottom -= 1;
    left += 1;
    right -= 1;
  }
  return cells;
};

// 行拆分：统一 \r\n → \n，去掉末尾整行换行产生的空行（输入末尾格式性换行不算矩阵行）。
const splitLines = (input: string): string[] => {
  const normalized = input.replaceAll('\r\n', '\n').replaceAll('\r', '\n').replace(/\n+$/u, '');
  return normalized.split('\n');
};

// 矩阵化：每行按码点切格（代理对/扩展区字符算一格），右侧补空格对齐到最宽行。
const toGrid = (lines: string[]): string[][] => {
  const width = Math.max(...lines.map(line => Array.from(line).length));
  return lines.map(line => {
    const cells = Array.from(line);
    while (cells.length < width) cells.push(' ');
    return cells;
  });
};

// decode：把多行矩阵按螺旋顺序读出线性文本。非矩形输入先右侧补空格对齐；输出去掉尾随空白。
export const spiralMatrixDecode = (input: string, variant?: string): string => {
  const direction = parseSpiralDirection(variant);
  const lines = splitLines(input);
  if (lines.length === 0 || (lines.length === 1 && lines[0].length === 0)) {
    throw new Error('螺旋矩阵解码输入为空：请提供多行矩阵文本');
  }
  const grid = toGrid(lines);
  const rows = grid.length;
  const cols = grid[0].length;
  if (rows * cols > SPIRAL_MATRIX_MAX_CELLS) {
    throw new Error(`螺旋矩阵尺寸 ${rows}×${cols}=${rows * cols} 超过 ${SPIRAL_MATRIX_MAX_CELLS} 格上限`);
  }
  const cells = spiralCoordinates(rows, cols, direction);
  let out = '';
  for (const cell of cells) out += grid[cell.y][cell.x];
  return out.trimEnd();
};

// 列数解析：非正整数/非法值返回 null（调用方走自动 √n）。
const parseColumns = (columns?: string | number): number | null => {
  if (columns === undefined || columns === null) return null;
  const value = typeof columns === 'number' ? columns : Number.parseInt(columns.trim(), 10);
  if (!Number.isInteger(value) || value < 1) return null;
  return value;
};

// encode：把线性文本按螺旋顺序填入 N×M 方阵并按行输出。
// 输入含换行：视为已有矩阵（各行右补空格对齐），N=行数、M=最宽行；
// 单行输入：按列数切块（columns 缺省自动 ceil(sqrt(n))），N=ceil(n/M)，末块补空格补满。
export const spiralMatrixEncode = (input: string, variant?: string, columns?: string | number): string => {
  const direction = parseSpiralDirection(variant);
  const single = !/\n/u.test(input.replaceAll('\r\n', '\n').replaceAll('\r', '\n'));
  let sequence: string[];
  let rows: number;
  let cols: number;
  if (single) {
    sequence = Array.from(input);
    if (sequence.length === 0) throw new Error('螺旋矩阵编码输入为空');
    const requested = parseColumns(columns);
    cols = requested ?? Math.ceil(Math.sqrt(sequence.length));
    rows = Math.ceil(sequence.length / cols);
  } else {
    const grid = toGrid(splitLines(input));
    rows = grid.length;
    cols = grid[0].length;
    sequence = grid.flat();
    if (sequence.length === 0) throw new Error('螺旋矩阵编码输入为空');
  }
  if (rows * cols > SPIRAL_MATRIX_MAX_CELLS) {
    throw new Error(`螺旋矩阵尺寸 ${rows}×${cols}=${rows * cols} 超过 ${SPIRAL_MATRIX_MAX_CELLS} 格上限`);
  }
  while (sequence.length < rows * cols) sequence.push(' ');
  const grid: string[][] = Array.from({ length: rows }, () => Array.from({ length: cols }, () => ' '));
  const cells = spiralCoordinates(rows, cols, direction);
  for (let index = 0; index < cells.length; index += 1) {
    grid[cells[index].y][cells[index].x] = sequence[index];
  }
  return grid.map(row => row.join('')).join('\n');
};
