// LLL 格基归约与背包低密度攻击（Lane B）。
// 算法出处：
// - LLL：A. K. Lenstra, H. W. Lenstra Jr., L. Lovász, "Factoring polynomials with rational
//   coefficients", Math. Ann. 261 (1982) 515-534。δ=99/100 的 Lovász 条件与 size-reduce
//   循环采用标准定义（见 H. Cohen, A Course in Computational Algebraic Number Theory,
//   GTM 138, Springer, §2.6）。
// - 整数化 GSO 变量：d_k（前 k 个基向量的 Gram 行列式）与 μ̃_{i,j} = d_{j+1}·μ_{i,j}
//   （Cohen GTM 138 §2.6.3 integral LLL / Bottesch-Haslbeck-Thiemann, LPAR 2018 的 μ̃-d 表示）。
//   全程 BigInt 精确整数运算，消元采用 fraction-free（Bareiss 1968 单步整型消元）思想，
//   所有除法均由 Desnanot-Jacobi/Sylvester 恒等式保证整除，无浮点、无 gcd 瓶颈。
// - 初始 Gram-Schmidt 系数由整数 Gram 矩阵的对称 fraction-free 消元得到：
//   v^{(k)}_{ij} = (v^{(k-1)}_{ij}·P_{k-1} − v^{(k-1)}_{ik}·v^{(k-1)}_{jk}) / d_{k-2}，
//   其中 P_k = v^{(k)}_{kk} = d_{k+1}/d_{k-1}，μ̃_{i,k} = v^{(k)}_{ik}·d_{k-1}。
// - 背包低密度攻击：CJLOSS 格构造出自 M. J. Coster, A. Joux, B. A. LaMacchia,
//   A. M. Odlyzko, C.-P. Schnorr, "Improved low-density subset sum algorithms",
//   Designs, Codes and Cryptography 1 (1992) 227-245：密度 < 0.9408 时目标向量
//   (±1,...,±1,0) 为格中（唯一）最短向量，LLL 归约即可恢复。
//   前身：J. C. Lagarias, A. M. Odlyzko, "Solving low-density subset sum problems",
//   JACM 32 (1985)。
// - Babai 最近平面 CVP：L. Babai, "On Lovász' lattice reduction and the nearest lattice
//   point problem", Combinatorica 6 (1986) 1-13。
// 对拍锚点（tests/lattice-knapsack.test.mjs）：
// - Wikipedia LLL 词条样例：基 (1,-1,3),(1,0,5),(1,2,6) 归约为 (0,1,-1),(1,0,0),(0,1,2)。
// - Stinson《Cryptography: Theory and Practice》Merkle-Hellman 公钥
//   (295,592,301,14,28,353,120,236)，密度 8/log2(592)≈0.869 < 0.9408。
// - Fraction 四则与手算 2x2/3x3 LLL（GSO 系数逐值比对）。

// ---------- 精确有理数（Fraction{n,d}，d>0 已约分） ----------

export interface Fraction {
  n: bigint;
  d: bigint;
}

const bigintAbs = (value: bigint) => (value < 0n ? -value : value);

const bigintGcd = (a: bigint, b: bigint): bigint => {
  let x = bigintAbs(a);
  let y = bigintAbs(b);
  while (y !== 0n) {
    [x, y] = [y, x % y];
  }
  return x;
};

/** 构造约分有理数；d 归一为正；d=0 抛错。 */
export const frac = (n: bigint, d: bigint = 1n): Fraction => {
  if (d === 0n) throw new Error('Fraction 分母不能为 0');
  if (d < 0n) {
    n = -n;
    d = -d;
  }
  const g = bigintGcd(n, d);
  if (g > 1n) {
    n /= g;
    d /= g;
  }
  return { n, d };
};

export const fracFromBigint = (value: bigint): Fraction => ({ n: value, d: 1n });

export const fracAdd = (a: Fraction, b: Fraction): Fraction => frac(a.n * b.d + b.n * a.d, a.d * b.d);
export const fracSub = (a: Fraction, b: Fraction): Fraction => frac(a.n * b.d - b.n * a.d, a.d * b.d);
export const fracMul = (a: Fraction, b: Fraction): Fraction => frac(a.n * b.n, a.d * b.d);
export const fracDiv = (a: Fraction, b: Fraction): Fraction => {
  if (b.n === 0n) throw new Error('Fraction 除数不能为 0');
  return frac(a.n * b.d, a.d * b.n);
};
export const fracNeg = (a: Fraction): Fraction => ({ n: -a.n, d: a.d });
export const fracCmp = (a: Fraction, b: Fraction): number => {
  const left = a.n * b.d;
  const right = b.n * a.d;
  return left < right ? -1 : left > right ? 1 : 0;
};
/** floor：向负无穷取整。 */
export const fracFloor = (a: Fraction): bigint => {
  const q = a.n / a.d;
  return a.n % a.d === 0n || a.n >= 0n ? q : q - 1n;
};
/** round：四舍五入（.5 向上），= floor(x + 1/2)。 */
export const fracRound = (a: Fraction): bigint => fracFloor(fracAdd(a, { n: 1n, d: 2n }));
export const fracIsZero = (a: Fraction): boolean => a.n === 0n;
export const fracToNumber = (a: Fraction): number => Number(a.n) / Number(a.d);
export const fracToString = (a: Fraction): string => a.d === 1n ? a.n.toString() : `${a.n.toString()}/${a.d.toString()}`;

// ---------- 向量小工具（BigInt） ----------

const dotProduct = (a: readonly bigint[], b: readonly bigint[]): bigint => {
  let sum = 0n;
  for (let index = 0; index < a.length; index += 1) sum += a[index] * b[index];
  return sum;
};

const vectorSubScaled = (target: bigint[], source: readonly bigint[], scale: bigint): void => {
  for (let index = 0; index < target.length; index += 1) target[index] -= scale * source[index];
};

export const cloneMatrix = (basis: readonly (readonly bigint[])[]): bigint[][] =>
  basis.map(row => Array.from(row, value => value));

// ---------- 精确 Gram-Schmidt（Fraction 口径，Babai 与测试对拍用） ----------

export interface GramSchmidtResult {
  /** mu[i][j] = <b_i, b*_j> / |b*_j|^2（j < i） */
  mu: Fraction[][];
  /** r[i] = |b*_i|^2 */
  r: Fraction[];
  /** 正交化向量 b*_i（Fraction 坐标） */
  ortho: Fraction[][];
}

export const gramSchmidtFractions = (basis: readonly (readonly bigint[])[]): GramSchmidtResult => {
  const n = basis.length;
  const ortho: Fraction[][] = basis.map(row => Array.from(row, value => ({ n: value, d: 1n })));
  const mu: Fraction[][] = Array.from({ length: n }, () => Array.from({ length: n }, () => ({ n: 0n, d: 1n })));
  const r: Fraction[] = Array.from({ length: n }, () => ({ n: 1n, d: 1n }));
  for (let i = 0; i < n; i += 1) {
    let normSq: Fraction = { n: 0n, d: 1n };
    for (let c = 0; c < basis[i].length; c += 1) {
      normSq = fracAdd(normSq, fracMul(ortho[i][c], ortho[i][c]));
    }
    if (fracIsZero(normSq)) throw new Error('基向量线性相关，无法做 Gram-Schmidt 正交化');
    r[i] = normSq;
    for (let k = i + 1; k < n; k += 1) {
      let proj: Fraction = { n: 0n, d: 1n };
      for (let c = 0; c < basis[k].length; c += 1) {
        proj = fracAdd(proj, fracMul(ortho[i][c], { n: basis[k][c], d: 1n }));
      }
      mu[k][i] = fracDiv(proj, normSq);
      for (let c = 0; c < basis[k].length; c += 1) {
        ortho[k][c] = fracSub(ortho[k][c], fracMul(mu[k][i], ortho[i][c]));
      }
    }
  }
  return { mu, r, ortho };
};

// ---------- LLL 归约（整数 μ̃-d 表示，无浮点） ----------

/**
 * 初始化 (d, μ̃)：对整数 Gram 矩阵做对称 fraction-free 消元（Bareiss 单步整型消元的对称形）。
 * 不变量：a^{(k)}_{ij} = M^{(k+1)}_{ij}（行 0..k−1∪{i} 列 0..k−1∪{j} 的 (k+1) 阶子式，纯整数）。
 * 由此：d_{k+1} = a^{(k)}_{kk}（主元即前导主子式），μ̃_{i,k} = a^{(k)}_{ik} = d_{k+1}μ_{i,k}，
 * 消元 v[i][j] ← (v[i][j]·P − v[i][k]·v[j][k]) / d_k（除数为上一主元，Sylvester 恒等式保证整除）。
 */
const initIntegralGso = (basis: readonly bigint[][]): { d: bigint[]; mu: bigint[][] } => {
  const n = basis.length;
  const gram = basis.map(rowI => basis.map(rowJ => dotProduct(rowI, rowJ)));
  const v = gram.map(row => Array.from(row, value => value));
  const d = Array.from({ length: n + 1 }, () => 0n);
  d[0] = 1n;
  const mu: bigint[][] = Array.from({ length: n }, () => Array.from({ length: n }, () => 0n));
  for (let k = 0; k < n; k += 1) {
    const pivot = v[k][k];
    if (pivot === 0n) throw new Error('基向量线性相关（Gram 主子式为 0），LLL 需要线性无关基');
    d[k + 1] = pivot;
    for (let i = k + 1; i < n; i += 1) {
      mu[i][k] = v[i][k];
    }
    if (k + 1 < n) {
      const divisor = d[k];
      for (let i = k + 1; i < n; i += 1) {
        for (let j = k + 1; j < n; j += 1) {
          const next = v[i][j] * pivot - v[i][k] * v[j][k];
          v[i][j] = divisor === 1n ? next : next / divisor;
        }
      }
    }
  }
  return { d, mu };
};

/** floorDiv：BigInt 截断除法修正为向下取整。 */
const floorDiv = (x: bigint, y: bigint): bigint => {
  const q = x / y;
  return x % y === 0n || (x < 0n) === (y < 0n) ? q : q - 1n;
};

export interface LllReduceOptions {
  /** Lovász δ，默认 99/100；以 num/den 传入（如 3/4） */
  deltaNum?: bigint;
  deltaDen?: bigint;
  /** swap 次数保险上限，默认 400·n² */
  maxSwaps?: number;
}

/**
 * LLL 归约（返回新矩阵，不修改入参）。
 * δ 默认 99/100；全程 BigInt：size-reduce 与 swap 使用 μ̃-d 增量更新公式（Cohen integral LLL）。
 */
export const lllReduce = (basis: readonly (readonly bigint [])[], options: LllReduceOptions = {}): bigint[][] => {
  const n = basis.length;
  if (n === 0) throw new Error('LLL 需要非空基');
  const dim = basis[0].length;
  for (const row of basis) {
    if (row.length !== dim) throw new Error('LLL 基矩阵每行长度必须一致');
  }
  const deltaNum = options.deltaNum ?? 99n;
  const deltaDen = options.deltaDen ?? 100n;
  if (deltaNum * 4n <= deltaDen) throw new Error('LLL 要求 δ > 1/4');
  const B = cloneMatrix(basis);
  if (n === 1) return B;
  const { d, mu } = initIntegralGso(B);
  const maxSwaps = options.maxSwaps ?? 400 * n * n;
  let swaps = 0;
  let k = 1;
  while (k < n) {
    // size-reduce：j = k-1 .. 0
    for (let j = k - 1; j >= 0; j -= 1) {
      const dj = d[j + 1];
      const q = floorDiv(2n * mu[k][j] + dj, 2n * dj); // round(μ̃/d_{j+1})
      if (q !== 0n) {
        vectorSubScaled(B[k], B[j], q);
        for (let i = 0; i < j; i += 1) {
          // μ̃_{k,i} ← μ̃_{k,i} − q·μ̃_{j,i}（μ̃_{k,i} 与 μ̃_{j,i} 同以 d_{i+1} 归一，直接相减）
          mu[k][i] -= q * mu[j][i];
        }
        mu[k][j] -= q * dj;
      }
    }
    // Lovász 条件：d_{k+1}d_{k-1} + μ̃² ≥ δ·d_k²（两边乘 d_k²d_{k-1} 的整数形式）
    const lam = mu[k][k - 1];
    const lhs = d[k + 1] * d[k - 1] + lam * lam;
    if (lhs * deltaDen >= deltaNum * d[k] * d[k]) {
      k += 1;
      continue;
    }
    // swap b_{k-1} ↔ b_k 并增量更新 (d, μ̃)
    swaps += 1;
    if (swaps > maxSwaps) throw new Error(`LLL swap 次数超过保险上限 ${maxSwaps}，疑似病态输入`);
    const dk = d[k];
    const dkm1 = d[k - 1];
    const dkp1 = d[k + 1];
    d[k] = (dkm1 * dkp1 + lam * lam) / dk;
    const tmp = B[k - 1];
    B[k - 1] = B[k];
    B[k] = tmp;
    for (let j = 0; j <= k - 2; j += 1) {
      const t = mu[k - 1][j];
      mu[k - 1][j] = mu[k][j];
      mu[k][j] = t;
    }
    mu[k][k - 1] = lam;
    for (let i = k + 1; i < n; i += 1) {
      const m1 = mu[i][k - 1];
      const m2 = mu[i][k];
      mu[i][k - 1] = (dkm1 * m2 + lam * m1) / dk;
      mu[i][k] = (dkp1 * m1 - lam * m2) / dk;
    }
    k = k > 1 ? k - 1 : 1;
  }
  return B;
};

// ---------- Babai 最近平面 CVP ----------

export interface BabaiResult {
  point: bigint[];
  coefficients: bigint[];
}

/**
 * Babai 最近平面算法：先 LLL 归约基，再自底向上取整求最近格点。
 * 返回离 target 最近的格点 point = Σ c_i·b_i（基于归约基的系数）。
 */
export const babaiNearestPlane = (basis: readonly (readonly bigint[])[], target: readonly bigint[]): BabaiResult => {
  if (basis.length === 0) throw new Error('Babai 需要非空基');
  if (basis[0].length !== target.length) throw new Error('Babai 目标向量维度必须与基一致');
  const reduced = lllReduce(basis);
  const gs = gramSchmidtFractions(reduced);
  const n = reduced.length;
  // y 为残差向量（逐元素更新，绑定本身不重 assigned）
  const y: Fraction[] = Array.from(target, value => ({ n: value, d: 1n }));
  const coefficients = Array.from({ length: n }, () => 0n);
  for (let i = n - 1; i >= 0; i -= 1) {
    let proj: Fraction = { n: 0n, d: 1n };
    for (let c = 0; c < y.length; c += 1) {
      proj = fracAdd(proj, fracMul(y[c], gs.ortho[i][c]));
    }
    const coefficient = fracRound(fracDiv(proj, gs.r[i]));
    coefficients[i] = coefficient;
    if (coefficient !== 0n) {
      for (let c = 0; c < y.length; c += 1) {
        y[c] = fracSub(y[c], fracMul({ n: coefficient, d: 1n }, gs.ortho[i][c]));
      }
    }
  }
  // y 此时应为 0 向量；point 由系数重建
  const point = Array.from({ length: target.length }, () => 0n);
  for (let i = 0; i < n; i += 1) {
    if (coefficients[i] === 0n) continue;
    for (let c = 0; c < target.length; c += 1) point[c] += coefficients[i] * reduced[i][c];
  }
  return { point, coefficients };
};

// ---------- CJLOSS 背包低密度攻击 ----------

export interface KnapsackAttackResult {
  found: boolean;
  /** 恢复的 0/1 位向量（found=true 时有效） */
  bits: number[];
  /** 子集和密度 n / log2(max(weights)) */
  density: number;
  /** 格维度（n+1） */
  dimension: number;
  method: string;
  notes: string[];
}

/** CJLOSS 密度阈值：Coster-Joux-LaMacchia-Odlyzko-Schnorr 1992。 */
export const CJLOSS_DENSITY_BOUND = 0.9408;

const bigintLog2Number = (value: bigint): number => {
  const bits = value.toString(2).length;
  if (bits <= 52) return Math.log2(Number(value));
  // 高位精度：取最高 53 位做尾数
  const top = Number(value >> BigInt(bits - 53));
  return (bits - 53) + Math.log2(top);
};

/**
 * CJLOSS 背包低密度攻击：给定权重序列与子集和 s，恢复 0/1 位向量。
 * 格为 (n+1)×(n+1)：前 n 行 (2N·e_i | 2)，末行 (1,...,1 | N·s)，N = ⌊√n⌋+1。
 * LLL 归约后目标向量 (±1,...,±1,0)（norm √n）成为最短向量（密度 < 0.9408 时）。
 */
export const solveKnapsackCjloss = (weights: readonly bigint[], total: bigint, options: LllReduceOptions = {}): KnapsackAttackResult => {
  const n = weights.length;
  if (n < 2) throw new Error('背包攻击至少需要 2 个权重');
  if (weights.some(w => w <= 0n)) throw new Error('背包权重必须为正整数');
  if (total < 0n) throw new Error('子集和不能为负');
  const maxWeight = weights.reduce((acc, w) => (w > acc ? w : acc), 0n);
  const density = n / bigintLog2Number(maxWeight);
  const notes: string[] = [];
  if (density > CJLOSS_DENSITY_BOUND) {
    notes.push(`密度 ${density.toFixed(4)} 超过 CJLOSS 理论界 0.9408，目标向量未必是唯一最短向量，攻击可能失败。`);
  }
  const cap = bigintAbs(total) > 0n
    ? bigintAbs(total)
    : weights.reduce((acc, w) => acc + w, 0n);
  if (bigintLog2Number(cap) * 6 < n) {
    notes.push('权重/总和相对位数过小，解可能不唯一。');
  }
  const bigN = bigintSqrt(BigInt(n)) + 1n;
  const dimension = n + 1;
  const lattice: bigint[][] = Array.from({ length: dimension }, () => Array.from({ length: dimension }, () => 0n));
  for (let i = 0; i < n; i += 1) {
    lattice[i][i] = 2n;
    lattice[i][n] = bigN * weights[i];
  }
  for (let j = 0; j < n; j += 1) lattice[n][j] = 1n;
  lattice[n][n] = bigN * total;
  const reduced = lllReduce(lattice, options);
  const verifyBits = (bits: number[]): bigint => {
    let sum = 0n;
    for (let i = 0; i < n; i += 1) sum += BigInt(bits[i]) * weights[i];
    return sum;
  };
  // 扫描归约后的行：末位为 0 且前 n 位 ∈ {±1}（允许个别 0 的退化形态），正反两个符号都验证
  for (const row of reduced) {
    if (row[n] !== 0n) continue;
    for (const sign of [1n, -1n] as const) {
      const bits: number[] = [];
      let ok = true;
      for (let j = 0; j < n; j += 1) {
        const coord = sign * row[j];
        if (coord === 1n) bits.push(1);
        else if (coord === -1n) bits.push(0);
        else if (coord === 0n) {
          // 退化：0 位无法确定，尝试两种取值由求和验证兜底
          bits.push(-1);
        } else {
          ok = false;
          break;
        }
      }
      if (!ok) continue;
      if (!bits.includes(-1)) {
        if (verifyBits(bits) === total) {
          return { found: true, bits, density, dimension, method: 'CJLOSS 格 + LLL（目标向量命中）', notes };
        }
        continue;
      }
      // 0 位枚举（退化情形，数量通常极少）
      const zeroPositions = bits.map((bit, index) => (bit === -1 ? index : -1)).filter(index => index >= 0);
      if (zeroPositions.length > 20) continue;
      for (let mask = 0; mask < (1 << zeroPositions.length); mask += 1) {
        const candidate = bits.slice();
        for (let p = 0; p < zeroPositions.length; p += 1) {
          candidate[zeroPositions[p]] = (mask >> p) & 1;
        }
        if (verifyBits(candidate) === total) {
          return { found: true, bits: candidate, density, dimension, method: 'CJLOSS 格 + LLL（含退化 0 位枚举）', notes };
        }
      }
    }
  }
  notes.push('LLL 归约后未找到满足求和验证的 ±1 目标向量：可尝试降低密度（更多权重位数）、换 δ 或用 BKZ/Sage 复核。');
  return { found: false, bits: [], density, dimension, method: 'CJLOSS 格 + LLL', notes };
};

// ---------- 文本入口（供操作卡挂载/transform 分派） ----------

const parseIntegerToken = (token: string): bigint | null => {
  const text = token.trim().replace(/^0x/i, '');
  if (/^-?\d+$/.test(text)) return BigInt(text);
  if (/^[0-9a-fA-F]+$/.test(text) && token.trim().toLowerCase().startsWith('0x')) return BigInt(token.trim());
  return null;
};

/** 解析整数矩阵：支持 JSON [[..],[..]]、分号/换行分行、逗号/空白分隔。 */
export const parseBigIntMatrix = (value: string): bigint[][] => {
  const text = String(value || '').trim();
  if (!text) throw new Error('矩阵输入不能为空');
  try {
    const parsed = JSON.parse(text) as unknown;
    if (Array.isArray(parsed) && parsed.every(row => Array.isArray(row))) {
      return parsed.map(row => (row as unknown[]).map(item => BigInt(item as string | number | bigint)));
    }
  } catch {
    // 继续按宽松文本解析
  }
  const rows = text
    .replace(/^\s*\[+|\]+\s*$/g, '')
    .split(/[\n;]+/)
    .map(row => row.replace(/[[\]]/g, '').trim())
    .filter(Boolean)
    .map(row => row.split(/[,\s]+/).filter(Boolean).map(token => {
      const parsed = parseIntegerToken(token);
      if (parsed == null) throw new Error(`无法解析矩阵元素：${token}`);
      return parsed;
    }));
  if (!rows.length) throw new Error('矩阵输入没有可解析的行');
  return rows;
};

const parseBigintList = (value: string): bigint[] => {
  const list = value
    .replace(/[[\]]/g, ' ')
    .split(/[,\s]+/)
    .filter(Boolean)
    .map(token => {
      const parsed = parseIntegerToken(token);
      if (parsed == null) throw new Error(`无法解析数字：${token}`);
      return parsed;
    });
  if (!list.length) throw new Error('数字列表为空');
  return list;
};

const extractLabeledField = (value: string, labels: string[]): string | null => {
  // 分隔符（或行首）后紧跟 label 与 :=；值向右延伸到下一个 "word=" 字段、分号或换行为止，
  // 因此 "basis=3,0;0,2 target=10,5" 能完整取出 "3,0;0,2"（分号在值内保留作行分隔）。
  const pattern = new RegExp(`(?:^|[\\n;,\\s])(?:${labels.join('|')})\\s*[:=]\\s*`, 'i');
  const match = pattern.exec(value);
  if (!match) return null;
  const rest = value.slice(match.index + match[0].length);
  const stop = rest.search(/[\s;][A-Za-z_]\w*\s*[:=]/);
  const raw = stop < 0 ? rest : rest.slice(0, stop);
  return raw.trim() || null;
};

/** 文本入口：weights/a=... 与 sum/s=...（缺一不可），执行 CJLOSS 攻击并输出 JSON 报告。 */
export const knapsackLowDensitySolve = (value: string): string => {
  const weightsField = extractLabeledField(value, ['weights', 'weight', 'a\\b', 'knapsack', 'pubkey', 'public']);
  const sumField = extractLabeledField(value, ['sum', 's\\b', 'total', 'ciphertext', 'ct']);
  if (!weightsField || !sumField) {
    throw new Error('背包攻击需要 weights=<权重列表> 与 sum=<子集和> 两个字段（如 "weights=2,3,5,7 sum=17"）');
  }
  const weights = parseBigintList(weightsField);
  const total = parseBigintList(sumField)[0];
  const result = solveKnapsackCjloss(weights, total);
  return JSON.stringify({
    ...result,
    weights: weights.map(w => w.toString()),
    total: total.toString(),
    bits: result.found ? result.bits.join('') : null,
    plaintextHint: result.found
      ? `位向量按索引对应权重：${result.bits.map((bit, index) => (bit ? weights[index].toString() : '')).filter(Boolean).join('+')} = ${total.toString()}`
      : null,
  }, null, 2);
};

/** 文本入口：matrix=<基矩阵>（或直接矩阵文本）做 LLL 归约。 */
export const latticeReduceText = (value: string): string => {
  const field = extractLabeledField(value, ['matrix', 'basis', 'B']);
  const matrix = parseBigIntMatrix(field || value);
  const reduced = lllReduce(matrix);
  return JSON.stringify({
    dimension: reduced.length,
    original: matrix.map(row => row.map(v => v.toString())),
    reduced: reduced.map(row => row.map(v => v.toString())),
    notes: ['LLL δ=99/100，整数精确运算；输出行为归约后的基。'],
  }, null, 2);
};

/** 文本入口：matrix=<基> 与 target=<目标向量> 做 Babai 最近平面 CVP。 */
export const babaiCvpSolve = (value: string): string => {
  const matrixField = extractLabeledField(value, ['matrix', 'basis', 'B']);
  const targetField = extractLabeledField(value, ['target', 't\\b', 'point']);
  if (!matrixField || !targetField) throw new Error('Babai CVP 需要 basis=<矩阵> 与 target=<向量> 两个字段');
  const matrix = parseBigIntMatrix(matrixField);
  const target = parseBigintList(targetField);
  const result = babaiNearestPlane(matrix, target);
  return JSON.stringify({
    nearestPoint: result.point.map(v => v.toString()),
    coefficients: result.coefficients.map(v => v.toString()),
    notes: ['先 LLL 归约再做最近平面取整（Babai 1986）；系数基于归约基。'],
  }, null, 2);
};

// ---- 本地小工具（避免引入 codec 内其他模块造成环） ----

function bigintSqrt(value: bigint): bigint {
  if (value < 2n) return value;
  let small = 1n;
  let large = value;
  while (large - small > 1n) {
    const mid = (small + large) >> 1n;
    if (mid * mid <= value) small = mid;
    else large = mid;
  }
  return small;
}
