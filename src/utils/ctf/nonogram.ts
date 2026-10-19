// 数织（Nonogram/Picross）线求解器（杂项取证域，CTF 能力补强批次三 B3-4）。
// 算法：线求解器（line solver）迭代收敛——对每行/列枚举满足块约束与已知格的全部合法排布，
// 逐格取 canFill/canEmpty 交集，唯一可能者定为确定格；行/列交替扫至不动点（无新确定格即停）。
// 多解位置保持未定（输出 '?'）。防爆护栏：边长 ≤40×40；单线组合数估算 >200000 跳过该线本轮；
// 总迭代 ≤200 轮；约束矛盾（某线 0 个合法排布）直接抛错。
// 输入格式：两段用 --- 分隔（前=行约束每行一条，后=列约束每列一条），每行逗号分隔块长，
// 「0」表示空线；兼容全角逗号/顿号。输出字符画 # 填 / . 空 / ? 未定。
// 对接出口：nonogramToRgba 把结果栅格转 RGBA（#→黑，其余→白），可直接喂
// qrDecode.decodeQrCodes(rgba, cols, rows)（输入接口已核对：ArrayLike<number> + 宽 + 高）。
// 组合数估算口径：free = L - (Σb + k - 1)，组合数 = C(free + k, k)（L ≤ 40 下 double 精确）。
// 纯函数、零依赖、同步；测试权威向量见 tests/nonogram.test.mjs（手算菱形/欠定/矛盾样例）。

export const NONOGRAM_MAX_SIDE = 40;
export const NONOGRAM_MAX_LINE_COMBOS = 200000;
export const NONOGRAM_MAX_ROUNDS = 200;

// 格状态：1=填 0=空 -1=未定。
export type NonogramCell = -1 | 0 | 1;

export interface NonogramResult {
  rows: number;
  cols: number;
  grid: NonogramCell[][];
  solved: boolean; // 是否全部格确定（真·唯一解收敛）
  rounds: number; // 实际迭代轮数
  skippedLines: number; // 因组合数超限被跳过的线数（含行列）
}

export interface NonogramClues {
  rowClues: number[][];
  colClues: number[][];
}

// ---- 输入解析 ----

const parseClueLine = (line: string, kind: string, index: number): number[] => {
  const normalized = line.trim().replaceAll('，', ',').replaceAll('、', ',');
  if (normalized.length === 0) throw new Error(`数织${kind}约束第 ${index + 1} 行为空`);
  const blocks = normalized.split(',').map(token => {
    const trimmed = token.trim();
    if (!/^\d+$/u.test(trimmed)) throw new Error(`数织${kind}约束第 ${index + 1} 行含非法块长："${trimmed}"`);
    return Number.parseInt(trimmed, 10);
  });
  if (blocks.some(value => value > NONOGRAM_MAX_SIDE)) {
    throw new Error(`数织${kind}约束第 ${index + 1} 行块长超过 ${NONOGRAM_MAX_SIDE} 上限`);
  }
  if (blocks.length > 1 && blocks.includes(0)) {
    throw new Error(`数织${kind}约束第 ${index + 1} 行「0」只能单独表示空线`);
  }
  return blocks;
};

// 解析两段式输入：--- 分隔行约束/列约束；段落内每个非空行一条线约束。
export const parseNonogramInput = (input: string): NonogramClues => {
  const normalized = input.replaceAll('\r\n', '\n').replaceAll('\r', '\n');
  const lines = normalized.split('\n').map(line => line.trim());
  const separators = lines.filter(line => /^-{3,}$/u.test(line)).length;
  if (separators === 0) throw new Error('数织输入缺少 --- 分隔线（上行约束、下列约束两段）');
  if (separators > 1) throw new Error('数织输入含多条 --- 分隔线（只允许行/列两段）');
  const separatorIndex = lines.findIndex(line => /^-{3,}$/u.test(line));
  const rowLines = lines.slice(0, separatorIndex).filter(line => line.length > 0);
  const colLines = lines.slice(separatorIndex + 1).filter(line => line.length > 0);
  const rowClues = rowLines.map((line, index) => parseClueLine(line, '行', index));
  const colClues = colLines.map((line, index) => parseClueLine(line, '列', index));
  if (rowClues.length === 0 || colClues.length === 0) throw new Error('数织输入行/列约束段不能为空');
  if (rowClues.length > NONOGRAM_MAX_SIDE || colClues.length > NONOGRAM_MAX_SIDE) {
    throw new Error(`数织规模 ${rowClues.length}×${colClues.length} 超过 ${NONOGRAM_MAX_SIDE}×${NONOGRAM_MAX_SIDE} 上限`);
  }
  return { rowClues, colClues };
};

// 块长列表规范化：「0」→ 空块表。
const normalizeBlocks = (blocks: number[]): number[] => (blocks.length === 1 && blocks[0] === 0 ? [] : blocks);

// 约束可行性：块长 + 最少间隔是否塞得进线长。
const clueFitsLine = (blocks: number[], lineLength: number): boolean => {
  const list = normalizeBlocks(blocks);
  const needed = list.reduce((sum, value) => sum + value, 0) + Math.max(0, list.length - 1);
  return needed <= lineLength;
};

// ---- 线求解器 ----

interface LineScan {
  canFill: boolean[];
  canEmpty: boolean[];
  count: number; // 合法排布数（供测试/诊断）
}

// 组合数估算（跳线门槛）：free = L - (Σb + k - 1)，C(free + k, k)。
// 这是该线"理论排布数"（不含已知格剪枝），即任务口径「单线组合数>200000 跳过」的组合数。
const estimateCombinations = (blocks: number[], lineLength: number): number => {
  const list = normalizeBlocks(blocks);
  const k = list.length;
  const free = lineLength - (list.reduce((sum, value) => sum + value, 0) + Math.max(0, k - 1));
  if (free < 0) return 0;
  // C(free + k, k)：L ≤ 40 时结果 ≤ C(40,20) ≈ 1.4e11，double 精确无损。
  let result = 1;
  for (let index = 1; index <= k; index += 1) {
    result = (result * (free + index)) / index;
  }
  return Math.round(result);
};

// 枚举一条线的全部合法排布（已知格剪枝）。返回 null 表示组合数超限跳过；
// count=0 表示约束矛盾（调用方抛错）。state: 1 填 / 0 空 / -1 未定。
const scanLine = (state: NonogramCell[], blocks: number[], maxCombos: number): LineScan | null => {
  const length = state.length;
  const list = normalizeBlocks(blocks);
  const canFill = Array.from({ length }, () => false);
  const canEmpty = Array.from({ length }, () => false);
  // current 为当前部分排布（1 填 / 0 空），到达叶节点（排布完成）时整体并入 can 集合。
  const current: number[] = Array.from({ length }, () => -1);
  let count = 0;

  // 后缀最小占位：suffixNeed[i] = 放置 blocks[i..] 所需的最小线长（块长和 + 块间间隔）。
  const suffixNeed = new Array<number>(list.length + 1);
  suffixNeed[list.length] = 0;
  for (let index = list.length - 1; index >= 0; index -= 1) {
    suffixNeed[index] = suffixNeed[index + 1] + list[index] + (index < list.length - 1 ? 1 : 0);
  }

  const place = (blockIndex: number, position: number): boolean => {
    if (blockIndex === list.length) {
      // 末块之后的尾段：含强制填格则该排布矛盾（放弃本分支，非超限）。
      for (let cell = position; cell < length; cell += 1) {
        if (state[cell] === 1) return false;
      }
      for (let cell = position; cell < length; cell += 1) current[cell] = 0;
      for (let cell = 0; cell < length; cell += 1) {
        if (current[cell] === 1) canFill[cell] = true;
        else canEmpty[cell] = true;
      }
      count += 1;
      return count > maxCombos; // 超限即中断整线
    }
    const blockLength = list[blockIndex];
    const isLast = blockIndex === list.length - 1;
    const maxStart = isLast ? length - blockLength : length - blockLength - 1;
    for (let start = position; start <= maxStart; start += 1) {
      // 前导空格段：起点右移只会让空格段变大，撞到强制填格即可剪断整条 start 循环。
      let feasible = true;
      for (let cell = position; cell < start; cell += 1) {
        if (state[cell] === 1) {
          feasible = false;
          break;
        }
      }
      if (!feasible) break;
      // 块体：不能压到强制空格。
      for (let cell = start; cell < start + blockLength; cell += 1) {
        if (state[cell] === 0) {
          feasible = false;
          break;
        }
      }
      if (!feasible) continue;
      // 块后分隔空格（非末块必需）：不能压到强制填格。
      if (!isLast && state[start + blockLength] === 1) continue;
      // 标记本段并递归。
      for (let cell = position; cell < start; cell += 1) current[cell] = 0;
      for (let cell = start; cell < start + blockLength; cell += 1) current[cell] = 1;
      if (!isLast) current[start + blockLength] = 0;
      const overflow = place(blockIndex + 1, isLast ? start + blockLength : start + blockLength + 1);
      if (overflow) return true;
    }
    return false;
  };

  const overflow = place(0, 0);
  if (overflow) return null;
  if (count === 0) return { canFill, canEmpty, count: 0 };
  return { canFill, canEmpty, count };
};

// ---- 主求解循环 ----

export const solveNonogram = (input: string): NonogramResult => {
  const { rowClues, colClues } = parseNonogramInput(input);
  const rows = rowClues.length;
  const cols = colClues.length;
  for (const [index, blocks] of rowClues.entries()) {
    if (!clueFitsLine(blocks, cols)) {
      throw new Error(`数织行约束第 ${index + 1} 行（块长和 + 间隔）塞不进 ${cols} 列，约束矛盾`);
    }
  }
  for (const [index, blocks] of colClues.entries()) {
    if (!clueFitsLine(blocks, rows)) {
      throw new Error(`数织列约束第 ${index + 1} 列（块长和 + 间隔）塞不进 ${rows} 行，约束矛盾`);
    }
  }

  // grid[y][x]：-1 未定 / 0 空 / 1 填。行视图直接引用 grid 行；列视图为独立切片数组，
  // 每次扫描前从 grid 刷新、确定后立即回写（保证行/列修正互相可见）。
  const grid: NonogramCell[][] = Array.from({ length: rows }, (): NonogramCell[] => Array.from({ length: cols }, (): NonogramCell => -1));
  const rowsView: NonogramCell[][] = Array.from({ length: rows }, (_, y) => grid[y]);
  const colsView: NonogramCell[][] = Array.from({ length: cols }, () => Array.from({ length: rows }, (): NonogramCell => -1));
  const dirtyRows = Array.from({ length: rows }, () => true);
  const dirtyCols = Array.from({ length: cols }, () => true);
  const skipped = new Set<string>();
  let rounds = 0;

  const applyLine = (line: NonogramCell[], scan: LineScan, touched: boolean[]): boolean => {
    let changed = false;
    for (let cell = 0; cell < line.length; cell += 1) {
      if (line[cell] !== -1) continue;
      const fillOnly = scan.canFill[cell] && !scan.canEmpty[cell];
      const emptyOnly = !scan.canFill[cell] && scan.canEmpty[cell];
      if (fillOnly || emptyOnly) {
        line[cell] = fillOnly ? 1 : 0;
        touched[cell] = true;
        changed = true;
      } else if (!scan.canFill[cell] && !scan.canEmpty[cell]) {
        throw new Error('数织约束矛盾：存在无合法排布的线（行列约束互相冲突）');
      }
    }
    return changed;
  };

  while (rounds < NONOGRAM_MAX_ROUNDS) {
    rounds += 1;
    let changed = false;
    for (let y = 0; y < rows; y += 1) {
      if (!dirtyRows[y]) continue;
      dirtyRows[y] = false;
      // 理论组合数超限先跳过（scanLine 内部计数是第二道防线，防估算口径偏差）。
      if (estimateCombinations(rowClues[y], cols) > NONOGRAM_MAX_LINE_COMBOS) {
        skipped.add(`r${y}`);
        continue;
      }
      const scan = scanLine(rowsView[y], rowClues[y], NONOGRAM_MAX_LINE_COMBOS);
      if (scan === null) {
        skipped.add(`r${y}`);
        continue;
      }
      if (scan.count === 0) {
        throw new Error(`数织约束矛盾：行 ${y + 1} 无合法排布`);
      }
      if (applyLine(rowsView[y], scan, dirtyCols)) changed = true;
    }
    for (let x = 0; x < cols; x += 1) {
      if (!dirtyCols[x]) continue;
      dirtyCols[x] = false;
      const line = colsView[x];
      for (let y = 0; y < rows; y += 1) line[y] = grid[y][x]; // 刷新：吸收行侧修正
      if (estimateCombinations(colClues[x], rows) > NONOGRAM_MAX_LINE_COMBOS) {
        skipped.add(`c${x}`);
        continue;
      }
      const scan = scanLine(line, colClues[x], NONOGRAM_MAX_LINE_COMBOS);
      if (scan === null) {
        skipped.add(`c${x}`);
        continue;
      }
      if (scan.count === 0) {
        throw new Error(`数织约束矛盾：列 ${x + 1} 无合法排布`);
      }
      if (applyLine(line, scan, dirtyRows)) {
        changed = true;
        for (let y = 0; y < rows; y += 1) grid[y][x] = line[y]; // 立即回写：列侧修正对行可见
      }
    }
    if (!changed) break; // 不动点：无新确定格
  }

  let unknown = 0;
  for (const row of grid) for (const cell of row) if (cell === -1) unknown += 1;
  return {
    rows,
    cols,
    grid,
    solved: unknown === 0,
    rounds,
    skippedLines: skipped.size,
  };
};

// ---- 输出格式 ----

// 字符画：# 填 / . 空 / ? 未定，行间换行。
export const nonogramGridToAscii = (grid: NonogramCell[][]): string =>
  grid.map(row => row.map(cell => (cell === 1 ? '#' : cell === 0 ? '.' : '?')).join('')).join('\n');

// 0/1 位流出口：# → 1，. 与 ? → 0（未定格按空处理，调用方自行判断 solved）。
export const nonogramToBitString = (result: NonogramResult): string =>
  result.grid.map(row => row.map(cell => (cell === 1 ? '1' : '0')).join('')).join('');

// RGBA 出口（对接 qrDecode.decodeQrCodes(rgba, width=cols, height=rows)）：
// # → 黑 (0,0,0,255)，. 与 ? → 白 (255,255,255,255)。行主序像素。
export const nonogramToRgba = (result: NonogramResult): Uint8ClampedArray => {
  const rgba = new Uint8ClampedArray(result.rows * result.cols * 4);
  for (let y = 0; y < result.rows; y += 1) {
    for (let x = 0; x < result.cols; x += 1) {
      const black = result.grid[y][x] === 1;
      const base = (y * result.cols + x) * 4;
      rgba[base] = black ? 0 : 255;
      rgba[base + 1] = black ? 0 : 255;
      rgba[base + 2] = black ? 0 : 255;
      rgba[base + 3] = 255;
    }
  }
  return rgba;
};
