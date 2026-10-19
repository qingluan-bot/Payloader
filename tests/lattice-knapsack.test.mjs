// LLL 格基归约 + CJLOSS 背包低密度攻击测试（Lane B）。
// 对拍锚点均为独立权威来源：
// - Wikipedia LLL 词条样例（列约定输入 cols (1,1,1),(-1,0,2),(3,5,6)，归约结果首两向量 (0,1,0),(1,0,1)）；
// - Stinson《Cryptography: Theory and Practice》Merkle-Hellman 教材公钥 (295,592,301,14,28,353,120,236)；
// - CJLOSS 密度理论界 0.9408（Coster-Joux-LaMacchia-Odlyzko-Schnorr 1992）；
// - 2x2/3x3 LLM 手算 trace 与 Fraction GSO 手算值（逐值）。
// 断言刻意逐字段 equal：沙箱模块返回的数组/对象是 vm realm 产物，deepStrictEqual 会因原型差异误报（AGENTS.md 踩坑记录）。
import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const L = loadModule(path.join(projectRoot, 'src', 'utils', 'codec', 'lattice.ts'));
const {
  frac, fracFromBigint, fracAdd, fracSub, fracMul, fracDiv, fracNeg, fracCmp,
  fracFloor, fracRound, fracIsZero, fracToString, fracToNumber,
  gramSchmidtFractions, lllReduce, babaiNearestPlane,
  solveKnapsackCjloss, CJLOSS_DENSITY_BOUND,
  parseBigIntMatrix, knapsackLowDensitySolve, latticeReduceText, babaiCvpSolve,
} = L;

// ---- 测试侧确定性工具 ----

const dot = (a, b) => a.reduce((s, x, i) => s + x * b[i], 0n);
const norm2 = v => v.reduce((s, x) => s + x * x, 0n);
// 沙箱数组必须经主 realm 的 Array.from 转换再断言（vm realm 原型差异，AGENTS.md 踩坑记录）
const fmt = m => Array.from(m, r => Array.from(r, v => v.toString()));
const strArray = a => Array.from(a, v => v.toString());
const detGramOf = basis => {
  // Gram 行列式（Fraction 高斯消元，精确）
  const n = basis.length;
  const a = basis.map(ri => basis.map(rj => fracFromBigint(dot(ri, rj))));
  let det = fracFromBigint(1n);
  for (let col = 0; col < n; col++) {
    let pivot = -1;
    for (let row = col; row < n; row++) if (!fracIsZero(a[row][col])) { pivot = row; break; }
    if (pivot < 0) return fracFromBigint(0n);
    if (pivot !== col) { [a[pivot], a[col]] = [a[col], a[pivot]]; det = fracNeg(det); }
    det = fracMul(det, a[col][col]);
    for (let row = col + 1; row < n; row++) {
      const factor = fracDiv(a[row][col], a[col][col]);
      for (let c = col; c < n; c++) a[row][c] = fracSub(a[row][c], fracMul(factor, a[col][c]));
    }
  }
  return det;
};
// 格成员判定：解 O^T x = b（Fraction 高斯消元），x 全整数则在格中
const latticeMembershipCoeffs = (latticeBasis, vector) => {
  const n = latticeBasis.length;
  const dim = vector.length;
  // 构造增广矩阵 [O^T | b]，行 = 坐标维
  const m = Array.from({ length: dim }, (_, c) => [...latticeBasis.map(row => fracFromBigint(row[c])), fracFromBigint(vector[c])]);
  // 高斯-若尔当消元
  for (let col = 0; col < n; col++) {
    let pivot = -1;
    for (let row = col; row < dim; row++) if (!fracIsZero(m[row][col])) { pivot = row; break; }
    if (pivot < 0) continue;
    [m[pivot], m[col]] = [m[col], m[pivot]];
    for (let row = 0; row < dim; row++) {
      if (row === col || fracIsZero(m[row][col])) continue;
      const factor = fracDiv(m[row][col], m[col][col]);
      for (let c2 = col; c2 <= n; c2++) m[row][c2] = fracSub(m[row][c2], fracMul(factor, m[col][c2]));
    }
  }
  // 回代：m[i][i]·x_i = m[i][n]
  const coeffs = Array.from({ length: n }, () => fracFromBigint(0n));
  for (let i = 0; i < n; i++) {
    if (fracIsZero(m[i][i])) return null; // 自由变量 → 该基无法唯一表示，判不合格
  }
  for (let i = 0; i < n; i++) coeffs[i] = fracDiv(m[i][n], m[i][i]);
  for (let row = n; row < dim; row++) {
    let residual = fracFromBigint(0n);
    for (let i = 0; i < n; i++) residual = fracAdd(residual, fracMul(m[row][i], coeffs[i]));
    if (fracCmp(residual, m[row][n]) !== 0) return null;
  }
  return coeffs;
};
const sameLattice = (basisA, basisB) => {
  if (fracCmp(detGramOf(basisA), detGramOf(basisB)) !== 0) return false;
  for (const row of basisB) {
    const coeffs = latticeMembershipCoeffs(basisA, row);
    if (!coeffs || coeffs.some(c => c.d !== 1n)) return false;
  }
  for (const row of basisA) {
    const coeffs = latticeMembershipCoeffs(basisB, row);
    if (!coeffs || coeffs.some(c => c.d !== 1n)) return false;
  }
  return true;
};
// LLL 归约不变量（独立 Fraction GSO 复核）：|μ|≤1/2、Lovász δ、实数域
const assertLllReduced = (basis, deltaNum = 99n, deltaDen = 100n) => {
  const gs = gramSchmidtFractions(basis);
  const n = basis.length;
  for (let i = 1; i < n; i++) {
    for (let j = 0; j < i; j++) {
      const mu = gs.mu[i][j];
      const absNum = mu.n < 0n ? -mu.n : mu.n;
      assert.ok(absNum * 2n <= mu.d, `μ[${i}][${j}]=${fracToString(mu)} 超出 |μ|≤1/2`);
    }
  }
  for (let k = 1; k < n; k++) {
    // Lovász：R_k + μ²R_{k-1} ≥ δ·R_{k-1} ⇔ lhs·den ≥ r_{k-1}·num
    const lhs = fracAdd(gs.r[k], fracMul(fracMul(gs.mu[k][k - 1], gs.mu[k][k - 1]), gs.r[k - 1]));
    assert.ok(fracCmp(fracMul(lhs, fracFromBigint(deltaDen)), fracMul(gs.r[k - 1], fracFromBigint(deltaNum))) >= 0,
      `Lovász 条件在 k=${k} 违反`);
  }
};

// ---- Fraction 四则与边界 ----

test('Fraction 约分与 d<0 归一', () => {
  const f = frac(6n, -4n);
  assert.equal(f.n, -3n);
  assert.equal(f.d, 2n);
  const zero = frac(0n, 5n);
  assert.equal(zero.n, 0n);
  assert.equal(zero.d, 1n);
  const integer = fracFromBigint(7n);
  assert.deepEqual([integer.n, integer.d], [7n, 1n]);
  assert.throws(() => frac(1n, 0n), /分母/);
});

test('Fraction 四则精确运算', () => {
  assert.equal(fracToString(fracAdd(frac(1n, 3n), frac(1n, 6n))), '1/2');
  assert.equal(fracToString(fracSub(frac(1n, 3n), frac(1n, 2n))), '-1/6');
  assert.equal(fracToString(fracMul(frac(2n, 3n), frac(3n, 4n))), '1/2');
  assert.equal(fracToString(fracDiv(frac(1n, 2n), frac(3n, 4n))), '2/3');
  assert.throws(() => fracDiv(frac(1n, 2n), frac(0n, 1n)), /除数/);
  assert.equal(fracCmp(frac(1n, 3n), frac(1n, 2n)), -1);
  assert.equal(fracCmp(frac(2n, 4n), frac(1n, 2n)), 0);
  assert.equal(fracCmp(frac(-3n, 2n), frac(-2n, 3n)), -1);
});

test('Fraction floor/round 边界（向负无穷取整、半值向上）', () => {
  assert.equal(fracFloor(frac(-1n, 2n)), -1n);
  assert.equal(fracFloor(frac(3n, 2n)), 1n);
  assert.equal(fracFloor(frac(-4n, 2n)), -2n);
  assert.equal(fracRound(frac(1n, 2n)), 1n);
  assert.equal(fracRound(frac(-1n, 2n)), 0n);
  assert.equal(fracRound(frac(2n, 3n)), 1n);
  assert.equal(fracRound(frac(-3n, 2n)), -1n);
  assert.equal(fracToNumber(frac(1n, 4n)), 0.25);
  assert.equal(fracIsZero(frac(0n, 9n)), true);
});

// ---- Gram-Schmidt（Fraction 口径，手算锚点） ----

test('gramSchmidtFractions 手算 2x3 锚点', () => {
  const gs = gramSchmidtFractions([[2n, 1n], [0n, 3n]]);
  // b*_0 = (2,1), R0 = 5；μ10 = 3/5；b*_1 = (0,3) − (3/5)(2,1) = (−6/5, 12/5)，R1 = 36/5
  assert.deepEqual(fmt([[gs.r[0].n]]), [['5']]);
  assert.equal(fracToString(gs.mu[1][0]), '3/5');
  assert.equal(fracToString(gs.ortho[1][0]), '-6/5');
  assert.equal(fracToString(gs.ortho[1][1]), '12/5');
  assert.equal(fracToString(gs.r[1]), '36/5');
  assert.throws(() => gramSchmidtFractions([[1n, 2n], [2n, 4n]]), /线性相关/);
});

// ---- LLL 手算 trace（2x2，覆盖 size-reduce + swap + 二次 size-reduce） ----

test('LLL 2x2 手算 trace：size-reduce → swap → size-reduce', () => {
  // b0=(2,0), b1=(1,1)：μ10=1/2 → q=1 得 b1=(−1,1)、μ̃=−2；Lovász 失败 → swap；
  // 新 μ10=−1 → q=−1 得 b1=(1,1)、μ̃=0；Lovász 通过。
  const reduced = lllReduce([[2n, 0n], [1n, 1n]]);
  assert.deepEqual(fmt(reduced), [['-1', '1'], ['1', '1']]);
  assertLllReduced(Array.from(reduced, row => Array.from(row, v => v)));
});

test('LLL 3x3 手算（已知 GSO 系数的整数基）', () => {
  // b0=(1,0,0), b1=(1,2,0), b2=(0,0,3)：μ10=1、μ20=0、μ21=0
  // k=1：q=1 → b1=(0,2,0)，μ̃=0，Lovász: 4 ≥ 0.99·1 通过；
  // k=2：μ20=0, μ21=0 无 reduce，Lovász: 9 ≥ 0.99·4 通过 → 输出不变（除 b1 已归约）。
  const reduced = lllReduce([[1n, 0n, 0n], [1n, 2n, 0n], [0n, 0n, 3n]]);
  assert.deepEqual(fmt(reduced), [['1', '0', '0'], ['0', '2', '0'], ['0', '0', '3']]);
  assertLllReduced(reduced);
});

// ---- Wikipedia 锚点（列约定） ----

test('Wikipedia LLL 样例：列约定输入，首两向量精确命中', () => {
  // 输入列 (1,1,1),(-1,0,2),(3,5,6)；Wikipedia 给出归约结果 (0,1,0),(1,0,1),(-1,0,2)。
  const input = [[1n, 1n, 1n], [-1n, 0n, 2n], [3n, 5n, 6n]];
  const reduced = lllReduce(input);
  assert.deepEqual(fmt(reduced)[0], ['0', '1', '0']);
  assert.deepEqual(fmt(reduced)[1], ['1', '0', '1']);
  // 第三向量与 Wikipedia 列出的 (-1,0,2) 同为范数²=5 的合法 tie-break（实现间可差）
  assert.equal(norm2(reduced[2]), 5n);
  assertLllReduced(reduced);
  // 行列式绝对值保持 |det|=3，且两方向格相等
  const detIn = fracCmp(detGramOf(input), fracFromBigint(9n));
  assert.equal(fracToString(detGramOf(input)), '9');
  assert.equal(detIn, 0);
  assert.equal(sameLattice(input, reduced), true);
});

// ---- 随机基 property：不变量 + 格等价 + det 保持 ----

test('随机基 LLL property：归约不变量与格等价（确定性种子 200 组）', () => {
  let seed = 0xc0ffee123456789an;
  const rnd = modulus => {
    seed = (seed + 0x9e3779b97f4a7c15n) & 0xffffffffffffffffn;
    let z = seed;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & 0xffffffffffffffffn;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & 0xffffffffffffffffn;
    z = z ^ (z >> 31n);
    return z % modulus;
  };
  let checked = 0;
  for (let trial = 0; trial < 200 && checked < 60; trial += 1) {
    const n = 2 + Number(rnd(4n));
    const bits = 2 + Number(rnd(12n));
    const half = 1n << BigInt(bits - 1);
    const basis = Array.from({ length: n }, () => Array.from({ length: n }, () => rnd(1n << BigInt(bits)) - half));
    let det = fracFromBigint(1n);
    try {
      det = detGramOf(basis);
    } catch { continue; }
    if (fracIsZero(det)) continue; // 随机基可能奇异，跳过
    let reduced;
    try {
      reduced = lllReduce(basis);
    } catch (error) {
      assert.match(error.message, /swap/); // 仅允许保险上限类错误，不应有其他异常
      continue;
    }
    checked += 1;
    assertLllReduced(reduced);
    assert.equal(fracCmp(detGramOf(reduced), det), 0, 'Gram 行列式必须保持');
    if (n <= 4) assert.equal(sameLattice(basis, reduced), true, '格必须等价');
  }
  assert.ok(checked >= 40, `有效样本不足：${checked}`);
});

// ---- Babai 最近平面 CVP ----

test('Babai 正交基精确命中（手算锚点）', () => {
  // 基 {(3,0),(0,2)}（正交），target (10,5)：c=round(10/3)=3、round(5/2)=3（半值向上）→ (9,6)
  const r = babaiNearestPlane([[3n, 0n], [0n, 2n]], [10n, 5n]);
  assert.deepEqual(strArray(r.point), ['9', '6']);
  assert.deepEqual(strArray(r.coefficients), ['3', '3']);
});

test('Babai 非正交基逐步手算 trace（最近平面近似性锚点）', () => {
  // 基 {(2,1),(0,3)}：LLL 归约得 {(2,1),(-2,2)}；GSO: b*0=(2,1),R0=5；μ10=-2/5；b*1=(-6/5,12/5),R1=36/5
  // y=(4,4)：c1=round((24/5)/(36/5))=round(2/3)=1 → y=(26/5,8/5)；c0=round((60/5)/5)=round(12/5)=2
  // 最近平面输出 (2,4)（Babai 是 2^(n/2) 近似，不承诺全局最近点——这正是锚点价值）
  const r = babaiNearestPlane([[2n, 1n], [0n, 3n]], [4n, 4n]);
  assert.deepEqual(strArray(r.point), ['2', '4']);
  assert.deepEqual(strArray(r.coefficients), ['2', '1']);
  assert.throws(() => babaiNearestPlane([[1n, 0n], [0n, 1n]], [1n]), /维度/);
});

// ---- CJLOSS 背包低密度攻击 ----

test('Stinson Merkle-Hellman 教材公钥：低密度背包恢复（两组手选明文）', () => {
  const weights = [295n, 592n, 301n, 14n, 28n, 353n, 120n, 236n];
  // 教材公钥（m=881），密度 8/log2(592)≈0.869 < 0.9408
  for (const bits of [[1, 0, 1, 1, 0, 1, 0, 1], [1, 1, 1, 1, 1, 1, 1, 1], [0, 1, 0, 0, 1, 0, 0, 1]]) {
    const total = weights.reduce((acc, w, i) => acc + BigInt(bits[i]) * w, 0n);
    const result = solveKnapsackCjloss(weights, total);
    assert.equal(result.found, true, `bits=${bits.join('')} 未恢复`);
    assert.equal(result.bits.join(''), bits.join(''));
    assert.equal(result.dimension, 9);
    assert.ok(result.density > 0.86 && result.density < 0.87, `密度异常：${result.density}`);
    assert.ok(result.density < CJLOSS_DENSITY_BOUND);
    assert.ok(!result.notes.some(note => note.includes('密度')), '低于阈值不应有密度警告');
  }
});

test('高密度实例明示密度警告（CJLOSS 阈值 0.9408）', () => {
  // 权重全 3 位：密度 4/log2(11) ≈ 1.15 > 0.9408
  const result = solveKnapsackCjloss([3n, 5n, 7n, 11n], 15n);
  assert.ok(result.notes.some(note => note.includes('0.9408')), '应给出密度过高警告');
  assert.equal(CJLOSS_DENSITY_BOUND, 0.9408);
});

test('背包输入校验', () => {
  assert.throws(() => solveKnapsackCjloss([5n], 5n), /至少需要 2 个权重/);
  assert.throws(() => solveKnapsackCjloss([3n, -5n], 2n), /正整数/);
  assert.throws(() => solveKnapsackCjloss([3n, 5n], -1n), /不能为负/);
});

// ---- 文本入口 ----

test('文本入口：knapsack/lattice/babai 三件套', () => {
  const weights = [295n, 592n, 301n, 14n, 28n, 353n, 120n, 236n];
  const total = weights.reduce((acc, w, i) => acc + BigInt([1, 0, 1, 1, 0, 1, 0, 1][i]) * w, 0n);
  const ks = JSON.parse(knapsackLowDensitySolve(`weights=295,592,301,14,28,353,120,236\nsum=${total}`));
  assert.equal(ks.found, true);
  assert.equal(ks.bits, '10110101');
  const lr = JSON.parse(latticeReduceText('matrix=[[2,0],[1,1]]'));
  assert.deepEqual(lr.reduced, [['-1', '1'], ['1', '1']]);
  const bv = JSON.parse(babaiCvpSolve('basis=3,0;0,2 target=10,5'));
  assert.deepEqual(bv.nearestPoint, ['9', '6']);
  const parsed = parseBigIntMatrix('[[1,2],[3,4]]');
  assert.equal(parsed.length, 2);
  assert.equal(parsed[1][0], 3n);
  assert.throws(() => knapsackLowDensitySolve('weights=1,2,3'), /sum/);
});

// ---- 性能抽查：n≤60 低密度背包限时 ----

test('性能：n=40 与 n=60 低密度背包 3 秒内出正确结果', () => {
  let seed = 0xdeadbeefcafeb0ban;
  const rnd64 = () => {
    seed = (seed + 0xa0761d6478bd642fn) & 0xffffffffffffffffn;
    let z = seed;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & 0xffffffffffffffffn;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & 0xffffffffffffffffn;
    return z ^ (z >> 31n);
  };
  const runCase = (n, growthBits) => {
    // 每项按固定位增长构造低密度实例（密度 = n/(growthBits·n) = 1/growthBits 量级）
    const weights = [];
    let acc = 1n;
    for (let i = 0; i < n; i += 1) {
      acc = (acc << BigInt(growthBits)) | (rnd64() & 0xffn);
      weights.push(acc);
    }
    const chosen = Array.from({ length: n }, () => (Number(rnd64() % 4n) === 0 ? 1 : 0));
    chosen[0] = 1;
    const total = weights.reduce((a, w, i) => a + BigInt(chosen[i]) * w, 0n);
    const started = Date.now();
    const result = solveKnapsackCjloss(weights, total);
    const elapsed = Date.now() - started;
    assert.equal(result.found, true, `n=${n} 未恢复（${elapsed}ms）`);
    // 沙箱 realm 数组禁用 deepEqual（原型差异误报，AGENTS.md 踩坑记录），逐字符比较
    assert.equal(result.bits.join(''), chosen.join(''));
    assert.ok(elapsed < 3000, `n=${n} 耗时 ${elapsed}ms 超过 3s`);
    return elapsed;
  };
  runCase(40, 8);
  const ms60 = runCase(60, 8);
  assert.ok(ms60 < 1000, `n=60 实测 ${ms60}ms，应满足 1 秒预期`);
});
