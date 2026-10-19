// Lane A CTF 能力补强批次一：xorshift 状态恢复与预测 / 截断 LCG 种子恢复 / LFSR 序列外推。
//
// 权威对拍锚点（独立来源，禁止"自己写自己验"）：
// 1. Marsaglia, "Xorshift RNGs", Journal of Statistical Software 8(14), 2003（doi:10.18637/jss.v008.i14）
//    - 32 位单寄存器 (13,17,5)、64 位单寄存器 (12,25,27)（论文 64 位全周期三元组表）、
//      128 状态版 t=(x^(x<<13)); x=y; y=z; z=w; w=(w^(w>>17))^(t^(t>>5))。
//    - 手算样例（逐位演算，机器复核）：seed=1 时 32 位版首输出 270369
//      （1^1<<13=8193 → 8193>>17=0 → 8193<<5=262176，8193^262176=0x42021=270369）；
//      64 位版首输出 549890035713（4097<<27=549890031616，4097^549890031616）；
//      128 版状态 (1,2,3,4) 首输出 8453（t=8193，4^8193^256=8453）。
// 2. Rosetta Code "Linear congruential generator" 条目公开序列（seed=1）：
//    - glibc/BSD（a=1103515245,c=12345,m=2^31）：1103527590 377401575 662824084 1147902781
//      2035015474 368800899 1508029952 486256185 1062517886 267834847
//    - MS rand（a=214013,c=2531011，rand=(state>>16)&0x7fff）：41 18467 6334 26500 19169 15724
// 3. JDK java.util.Random 规格公式（javadoc + 源码：seed=(seed^0x5DEECE66D)&(2^48-1)，
//    next(32)=seed>>>16）：new Random(42).nextInt() = -1170105035（无符号 3124862261）。
// 4. LFSR 抽头 3,2、种子 1,1,1 的手算样例：s[n]=s[n-3]^s[n-2] → 序列 11100101…，
//    外推 s8..s11 = 1,1,0,0。
//
// 测试侧参考实现与 attacks.ts 实现零共享代码：正向公式直接按上述规格内联重写，
// 恢复库函数（被测对象）只提供逆向/分析能力，两侧结果对拍。
// 注意：attacks.ts 在 vm 沙箱中加载，其返回数组需 Array.from 转主 realm 再 deepStrictEqual。
import assert from 'node:assert/strict';
import test from 'node:test';
import { randomInt } from 'node:crypto';
import { createTsModuleLoader } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const attacks = loadModule('src/utils/codec/attacks.ts');

const M32 = (1n << 32n) - 1n;
const M48 = (1n << 48n) - 1n;
const M64 = (1n << 64n) - 1n;
const toMain = array => Array.from(array, item => item);

// ---------- 测试侧独立参考实现（公式直接来自规格定义） ----------
const refXorshift32Next = x => {
  x &= M32;
  x ^= (x << 13n) & M32;
  x ^= x >> 17n;
  x ^= (x << 5n) & M32;
  return x & M32;
};
const refXorshift64Next = x => {
  x &= M64;
  x ^= (x << 12n) & M64;
  x ^= x >> 25n;
  x ^= (x << 27n) & M64;
  return x & M64;
};
const refXorshift128Next32 = ([x, y, z, w]) => {
  const t = (x ^ ((x << 13n) & M32)) & M32;
  return [y, z, w, ((w ^ (w >> 17n)) ^ t ^ (t >> 5n)) & M32];
};
const refXorshift128Next64 = ([x, y, z, w]) => {
  const t = (x ^ ((x << 13n) & M64)) & M64;
  return [y, z, w, ((w ^ (w >> 17n)) ^ t ^ (t >> 5n)) & M64];
};
const refLcgNext = (state, a, c, bits) => (a * state + c) & ((1n << BigInt(bits)) - 1n);
// 独立实现的扩展欧几里得模逆（性能用例构造成打点种子时使用）
const refModInverse = (value, mod) => {
  let [oldR, r] = [((value % mod) + mod) % mod, mod];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return oldR === 1n ? ((oldS % mod) + mod) % mod : null;
};
// 独立实现的 MSVC rand / Java Random 参考生成器
const refMsvcRands = (seed, count) => {
  let state = BigInt(seed);
  const rands = [];
  for (let index = 0; index < count; index += 1) {
    state = refLcgNext(state, 214013n, 2531011n, 32);
    rands.push((state >> 16n) & 0x7FFFn);
  }
  return rands;
};
const refJavaStates = (constructorSeed, count) => {
  let seed = (BigInt(constructorSeed) ^ 0x5DEECE66Dn) & M48;
  const outputs = [];
  for (let index = 0; index < count; index += 1) {
    seed = refLcgNext(seed, 0x5DEECE66Dn, 11n, 48);
    outputs.push(seed >> 16n);
  }
  return { scrambledSeed: (BigInt(constructorSeed) ^ 0x5DEECE66Dn) & M48, outputs };
};

// ===================== 1. invXorLeft / invXorRight 单射自检 =====================

test('invXorLeft/invXorRight 与测试侧正向公式往返 1 万次（32/64 位 × 多档移位）', () => {
  const leftShifts = [1, 5, 13, 17, 27, 31];
  const rightShifts = [1, 7, 17, 25, 31];
  let roundTrips = 0;
  for (let iteration = 0; iteration < 1000; iteration += 1) {
    const x32 = BigInt(randomInt(0, 0x100000000));
    for (const k of leftShifts) {
      const y = x32 ^ ((x32 << BigInt(k)) & M32);
      assert.equal(attacks.invXorLeft(y, k, 32), x32, `invXorLeft 往返失败 k=${k} x=0x${x32.toString(16)}`);
      roundTrips += 1;
    }
    const x64 = (BigInt(randomInt(0, 0x100000000)) << 32n) | BigInt(randomInt(0, 0x100000000));
    for (const k of leftShifts) {
      const y = x64 ^ ((x64 << BigInt(k)) & M64);
      assert.equal(attacks.invXorLeft(y, k, 64), x64, `invXorLeft 64 位往返失败 k=${k}`);
      roundTrips += 1;
    }
    for (const k of rightShifts) {
      const y = x32 ^ (x32 >> BigInt(k));
      assert.equal(attacks.invXorRight(y, k, 32), x32, `invXorRight 往返失败 k=${k} x=0x${x32.toString(16)}`);
      roundTrips += 1;
    }
    for (const k of rightShifts) {
      const y = x64 ^ (x64 >> BigInt(k));
      assert.equal(attacks.invXorRight(y, k, 64), x64, `invXorRight 64 位往返失败 k=${k}`);
      roundTrips += 1;
    }
  }
  assert.ok(roundTrips >= 10000, `往返次数应 ≥10000，实际 ${roundTrips}`);
});

test('invXorLeft/invXorRight 手算锚点', () => {
  // x=8193: 8193^(8193<<5)=270369 → 逆回 8193
  assert.equal(attacks.invXorLeft(270369n, 5, 32), 8193n);
  // x=0x84000021: x^(x>>17)=2214609441 → 逆回原值
  assert.equal(attacks.invXorRight(2214609441n, 17, 32), 2214592545n);
  // x=4097: 4097^(4097<<27) → 逆回 4097（64 位）
  assert.equal(attacks.invXorLeft(4097n ^ ((4097n << 27n) & M64), 27, 64), 4097n);
});

// ===================== 2. xorshift32/64 单寄存器种子恢复与预测 =====================

test('xorshift32：测试侧规格实现对拍手算锚点，种子由首个输出逆推', () => {
  // 测试侧规格实现必须复现手算锚点（对拍锚点有效性自证）
  assert.equal(refXorshift32Next(1n), 270369n, 'seed=1 首输出手算锚点 270369');
  assert.equal(refXorshift32Next(270369n), 67634689n);
  // 首个输出逆推初始种子
  assert.equal(attacks.xorshift32SeedFromOutput(270369n), 1n);
  // 第二个输出逆推得到的是第一个输出（前一状态）
  assert.equal(attacks.xorshift32SeedFromOutput(67634689n), 270369n);
});

test('xorshift32：10 连续输出判定版本/种子并预测后续', () => {
  const outputs = [];
  let state = 123456789n;
  for (let index = 0; index < 10; index += 1) {
    state = refXorshift32Next(state);
    outputs.push(state);
  }
  const analysis = attacks.xorshiftAnalyzeFromOutputs(outputs, 3);
  assert.equal(analysis.version, 'xorshift32');
  assert.equal(analysis.wordSize, 32);
  assert.equal(analysis.seed, 123456789n);
  assert.equal(analysis.verified, true);
  assert.equal(analysis.verifiedOutputs, 9);
  const predicted = toMain(analysis.predicted);
  assert.equal(predicted.length, 3);
  assert.deepEqual(predicted, [
    refXorshift32Next(state),
    refXorshift32Next(refXorshift32Next(state)),
    refXorshift32Next(refXorshift32Next(refXorshift32Next(state))),
  ]);
});

test('xorshift32：单输出仅给种子不验证', () => {
  const analysis = attacks.xorshiftAnalyzeFromOutputs([270369n], 2);
  assert.equal(analysis.version, 'xorshift32');
  assert.equal(analysis.seed, 1n);
  assert.equal(analysis.verified, false);
  assert.deepEqual(toMain(analysis.predicted), [67634689n, refXorshift32Next(67634689n)]);
});

test('xorshift64(12,25,27)：手算锚点 + 种子恢复 + 预测', () => {
  assert.equal(refXorshift64Next(1n), 549890035713n, 'seed=1 首输出手算锚点 549890035713');
  const outputs = [];
  let state = 0x0123456789ABCDEFn;
  for (let index = 0; index < 6; index += 1) {
    state = refXorshift64Next(state);
    outputs.push(state);
  }
  const analysis = attacks.xorshiftAnalyzeFromOutputs(outputs, 4);
  assert.equal(analysis.version, 'xorshift64');
  assert.equal(analysis.wordSize, 64);
  assert.equal(analysis.seed, 0x0123456789ABCDEFn);
  assert.equal(analysis.verified, true);
  assert.deepEqual(toMain(analysis.predicted), [
    refXorshift64Next(state),
    refXorshift64Next(refXorshift64Next(state)),
    refXorshift64Next(refXorshift64Next(refXorshift64Next(state))),
    refXorshift64Next(refXorshift64Next(refXorshift64Next(refXorshift64Next(state)))),
  ]);
});

// ===================== 3. xorshift128 状态定位与预测 =====================

test('xorshift128(32 位字)：手算锚点 (1,2,3,4) → 8453，论文种子序列判定与预测', () => {
  assert.equal(attacks.xorshift128Next32([1n, 2n, 3n, 4n])[3], 8453n, '手算锚点：t=8193, w=4^8193^256=8453');
  // 论文示例种子 123456789/362436069/521288629/88675123（Marsaglia 2003）
  let state = [123456789n, 362436069n, 521288629n, 88675123n];
  const outputs = [];
  for (let index = 0; index < 9; index += 1) {
    state = refXorshift128Next32(state);
    outputs.push(state[3]);
  }
  const analysis = attacks.xorshiftAnalyzeFromOutputs(outputs, 5);
  assert.equal(analysis.version, 'xorshift128');
  assert.equal(analysis.wordSize, 32);
  assert.equal(analysis.verified, true);
  assert.equal(analysis.verifiedOutputs, 5);
  // 4 个连续输出即滚动状态 (x,y,z,w)=(o1,o2,o3,o4)
  assert.deepEqual(toMain(analysis.state128), outputs.slice(0, 4));
  assert.deepEqual(toMain(analysis.predicted), [
    refXorshift128Next32(state)[3],
    refXorshift128Next32(refXorshift128Next32(state))[3],
    refXorshift128Next32(refXorshift128Next32(refXorshift128Next32(state)))[3],
    refXorshift128Next32(refXorshift128Next32(refXorshift128Next32(refXorshift128Next32(state))))[3],
    refXorshift128Next32(refXorshift128Next32(refXorshift128Next32(refXorshift128Next32(refXorshift128Next32(state)))))[3],
  ]);
});

test('xorshift128：恰 4 个输出可定位状态并预测（无交叉验证）', () => {
  let state = [7n, 8n, 9n, 10n];
  const outputs = [];
  for (let index = 0; index < 6; index += 1) {
    state = refXorshift128Next32(state);
    outputs.push(state[3]);
  }
  const analysis = attacks.xorshiftAnalyzeFromOutputs(outputs.slice(0, 4), 2);
  assert.equal(analysis.version, 'xorshift128');
  assert.equal(analysis.verified, false, '只有 4 个输出时没有第 5 个做交叉验证');
  assert.deepEqual(toMain(analysis.predicted), [outputs[4], outputs[5]]);
});

test('xorshift128(64 位字)：大输出走 64 位分支', () => {
  let state = [0x9E3779B97F4A7C15n, 0xBF58476D1CE4E5B9n, 0x94D049BB133111EBn, 0x2545F4914F6CDD1Dn];
  const outputs = [];
  for (let index = 0; index < 7; index += 1) {
    state = refXorshift128Next64(state);
    outputs.push(state[3]);
  }
  const analysis = attacks.xorshiftAnalyzeFromOutputs(outputs, 3);
  assert.equal(analysis.version, 'xorshift128');
  assert.equal(analysis.wordSize, 64);
  assert.equal(analysis.verified, true);
  assert.deepEqual(toMain(analysis.state128), outputs.slice(0, 4));
  assert.deepEqual(toMain(analysis.predicted), [
    refXorshift128Next64(state)[3],
    refXorshift128Next64(refXorshift128Next64(state))[3],
    refXorshift128Next64(refXorshift128Next64(refXorshift128Next64(state)))[3],
  ]);
});

test('非 xorshift 序列返回 unknown 且不抛错', () => {
  const analysis = attacks.xorshiftAnalyzeFromOutputs([1n, 2n, 3n, 4n, 5n], 3);
  assert.equal(analysis.version, 'unknown');
  assert.equal(analysis.predicted.length, 0);
  assert.equal(analysis.verified, false);
});

// ===================== 4. xorshiftHelper 文本入口 =====================

test('xorshiftHelper：十进制与 hex 文本输入均能判定种子并预测', () => {
  const outputs = [];
  let state = 42n;
  for (let index = 0; index < 8; index += 1) {
    state = refXorshift32Next(state);
    outputs.push(state);
  }
  const decimal = attacks.xorshiftHelper(outputs.map(item => item.toString()).join(' '), '3');
  const parsedDecimal = JSON.parse(decimal);
  assert.equal(parsedDecimal.version, 'xorshift32');
  assert.equal(parsedDecimal.seed, '42');
  assert.equal(parsedDecimal.verified, true);
  assert.equal(parsedDecimal.predicted.length, 3);
  assert.deepEqual(parsedDecimal.predicted, [
    refXorshift32Next(state).toString(),
    refXorshift32Next(refXorshift32Next(state)).toString(),
    refXorshift32Next(refXorshift32Next(refXorshift32Next(state))).toString(),
  ]);
  const hex = attacks.xorshiftHelper(outputs.map(item => `0x${item.toString(16)}`).join(','), '');
  assert.equal(JSON.parse(hex).seed, '42');
});

test('xorshiftHelper：无关数字序列返回 unknown JSON 而不抛错', () => {
  const parsed = JSON.parse(attacks.xorshiftHelper('outputs=1 2 3 4 5', ''));
  assert.equal(parsed.version, 'unknown');
});

// ===================== 5. 截断 LCG 种子恢复 =====================

test('对拍锚点自证：glibc/BSD seed=1 复现 Rosetta Code 公开序列', () => {
  const published = [1103527590n, 377401575n, 662824084n, 1147902781n, 2035015474n, 368800899n, 1508029952n, 486256185n, 1062517886n, 267834847n];
  let state = 1n;
  const generated = published.map(() => {
    state = refLcgNext(state, 1103515245n, 12345n, 31);
    return state;
  });
  assert.deepEqual(generated, published);
});

test('对拍锚点自证：MSVC srand(1) 复现 Rosetta Code 公开 rand 序列', () => {
  assert.deepEqual(refMsvcRands(1, 6).map(item => item.toString()), ['41', '18467', '6334', '26500', '19169', '15724']);
});

test('截断 LCG：glibc 参数 k=24 档闭环（seed→生成→截断→恢复）', () => {
  let state = 1n;
  const states = [];
  for (let index = 0; index < 12; index += 1) {
    state = refLcgNext(state, 1103515245n, 12345n, 31);
    states.push(state);
  }
  const outputs = states.slice(0, 5).map(item => item >> 7n); // 观测高 24 位
  const recovery = attacks.truncatedLcgRecover(outputs, {
    modulus: 1n << 31n,
    multiplier: 1103515245n,
    increment: 12345n,
    observedBits: 24,
    predictCount: 4,
  });
  assert.equal(recovery.recovered, true);
  assert.equal(recovery.seed, 1n, '恢复的种子应为 srand(1) 的 1');
  assert.equal(recovery.firstState, states[0]);
  const predicted = toMain(recovery.predictedOutputs);
  assert.deepEqual(predicted, states.slice(5, 9).map(item => item >> 7n));
});

test('截断 LCG：glibc 参数 k=16 与 k=31 档闭环', () => {
  let state = 31337n;
  const states = [];
  for (let index = 0; index < 14; index += 1) {
    state = refLcgNext(state, 1103515245n, 12345n, 31);
    states.push(state);
  }
  for (const [observedBits, shift] of [[16, 15n], [31, 0n]]) {
    const outputs = states.slice(0, 6).map(item => item >> shift);
    const recovery = attacks.truncatedLcgRecover(outputs, {
      modulus: 1n << 31n,
      multiplier: 1103515245n,
      increment: 12345n,
      observedBits,
      predictCount: 3,
    });
    assert.equal(recovery.recovered, true, `k=${observedBits} 应回收成功`);
    assert.equal(recovery.seed, 31337n, `k=${observedBits} 种子应还原`);
    assert.deepEqual(toMain(recovery.predictedOutputs), states.slice(6, 9).map(item => item >> shift));
  }
});

test('截断 LCG：m=2^32 自定义参数 k=16/24/31 三档闭环（任务口径 a=214013,c=2531011）', () => {
  let state = 987654321n;
  const states = [];
  for (let index = 0; index < 16; index += 1) {
    state = refLcgNext(state, 214013n, 2531011n, 32);
    states.push(state);
  }
  for (const [observedBits, shift] of [[16, 16n], [24, 8n], [31, 1n]]) {
    const outputs = states.slice(0, 5).map(item => item >> shift);
    const recovery = attacks.truncatedLcgRecover(outputs, {
      modulus: 1n << 32n,
      multiplier: 214013n,
      increment: 2531011n,
      observedBits,
      predictCount: 3,
    });
    assert.equal(recovery.recovered, true, `k=${observedBits} 应回收成功`);
    assert.equal(recovery.seed, 987654321n, `k=${observedBits} 种子应还原`);
    assert.deepEqual(toMain(recovery.predictedOutputs), states.slice(5, 8).map(item => item >> shift));
  }
});

test('截断 LCG：MSVC preset 走真实 rand 语义（rand=(state>>16)&0x7fff）', () => {
  const rands = refMsvcRands(1, 11);
  const observed = rands.slice(0, 6).map(item => item.toString()).join(' ');
  const parsed = JSON.parse(attacks.truncatedLcgHelper(`preset=msvc\noutputs=${observed}\npredict=5`, ''));
  assert.equal(parsed.preset, 'msvc');
  assert.equal(parsed.recovered, true);
  assert.equal(parsed.seed, '1', '恢复的种子应为 srand(1) 的 1（mod 2^31 口径）');
  assert.equal(parsed.observedBits, 15);
  assert.deepEqual(parsed.predictedOutputs, rands.slice(6, 11).map(item => item.toString()));
});

test('截断 LCG：Java preset 恢复加扰种子并预测 nextInt', () => {
  // JDK 规格锚点：new Random(42).nextInt() = -1170105035 = 无符号 3124862261
  const reference = refJavaStates(42, 10);
  assert.equal(reference.outputs[0], 3124862261n, 'Random(42) 首个 nextInt 锚点');
  const observed = reference.outputs.slice(0, 6).map(item => item.toString()).join(' ');
  const parsed = JSON.parse(attacks.truncatedLcgHelper(`preset=java\noutputs=${observed}\npredict=4`, ''));
  assert.equal(parsed.preset, 'java');
  assert.equal(parsed.recovered, true);
  assert.equal(parsed.observedBits, 32);
  assert.equal(BigInt(parsed.seed), reference.scrambledSeed, '恢复的种子应为 JDK 加扰后的 48 位种子');
  assert.deepEqual(parsed.predictedOutputs, reference.outputs.slice(6, 10).map(item => item.toString()));
});

test('截断 LCG：穷举护栏触发（m=2^48, k=8 → 空间 2^40）', () => {
  assert.throws(
    () => attacks.truncatedLcgRecover([1n, 2n, 3n], {
      modulus: 1n << 48n,
      multiplier: 25214903917n,
      increment: 11n,
      observedBits: 8,
    }),
    error => /2\^40.*上限.*lattice|lattice.*2\^40/.test(error.message),
    '护栏报错应指明穷举空间并给出 lattice 方向',
  );
});

test('截断 LCG：参数护栏（k 越界 / 单输出 / 输出超范围 / 非幂模数）', () => {
  const base = { modulus: 1n << 32n, multiplier: 214013n, increment: 2531011n };
  assert.throws(() => attacks.truncatedLcgRecover([1n, 2n], { ...base, observedBits: 33 }), /k=33/);
  assert.throws(() => attacks.truncatedLcgRecover([1n], { ...base, observedBits: 16 }), /至少需要 2 个/);
  assert.throws(() => attacks.truncatedLcgRecover([70000n, 1n], { ...base, observedBits: 16 }), /超出 k=16/);
  assert.throws(() => attacks.truncatedLcgRecover([1n, 2n], { ...base, modulus: 99991n, observedBits: 8 }), /2 的幂/);
});

test('截断 LCG：无命中时 recovered=false 并报满穷举', () => {
  const recovery = attacks.truncatedLcgRecover([0n, 1n, 2n, 3n], {
    modulus: 1n << 32n,
    multiplier: 214013n,
    increment: 2531011n,
    observedBits: 16,
  });
  assert.equal(recovery.recovered, false);
  assert.equal(recovery.seed, null);
  assert.equal(recovery.candidatesTried, 65536, '应报满 2^16 个候选');
});

test('截断 LCG：m=2^48 k=24 档 2^24 穷举在数秒内完成（命中点压在穷举尾部）', () => {
  // 构造 x1 的低 24 位 = 0xFFFFFE（倒数第 2 个候选才命中），种子由 a⁻¹ 回推得到
  const a = 0x5DEECE66Dn;
  const c = 11n;
  const aInverse = refModInverse(a, 1n << 48n);
  assert.ok(aInverse != null, 'a 与 2^48 互素');
  const targetX1 = 0x123456FFFFFEn; // 低 24 位 = 0xFFFFFE
  const seed = ((targetX1 - c) % (1n << 48n)) * aInverse % (1n << 48n);
  assert.equal(refLcgNext(seed, a, c, 48) & 0xFFFFFFn, 0xFFFFFEn, '构造的种子应使首输出低 24 位命中点在穷举尾部');
  const states = [targetX1];
  let cursor = targetX1;
  for (let index = 0; index < 5; index += 1) {
    cursor = refLcgNext(cursor, a, c, 48);
    states.push(cursor);
  }
  const outputs = states.slice(0, 4).map(item => item >> 24n); // k=24，观测高 24 位
  const startedAt = Date.now();
  const recovery = attacks.truncatedLcgRecover(outputs, {
    modulus: 1n << 48n,
    multiplier: a,
    increment: c,
    observedBits: 24,
    predictCount: 2,
  });
  const elapsed = Date.now() - startedAt;
  assert.equal(recovery.recovered, true);
  assert.equal(recovery.seed, seed);
  assert.ok(elapsed < 5000, `2^24 穷举应在数秒内完成，实际 ${elapsed}ms`);
});

test('截断 LCG：truncatedLcgHelper 缺参数时报错并列出缺失项', () => {
  assert.throws(() => attacks.truncatedLcgHelper('outputs=1 2 3', ''), /缺少参数.*k=/);
});

test('truncatedLcgPresets：内置标准参数与文献一致', () => {
  assert.equal(attacks.truncatedLcgPresets.glibc.multiplier, 1103515245n);
  assert.equal(attacks.truncatedLcgPresets.glibc.increment, 12345n);
  assert.equal(attacks.truncatedLcgPresets.glibc.modulus, 1n << 31n);
  assert.equal(attacks.truncatedLcgPresets.msvc.multiplier, 214013n);
  assert.equal(attacks.truncatedLcgPresets.msvc.increment, 2531011n);
  assert.equal(attacks.truncatedLcgPresets.msvc.observedBits, 15);
  assert.equal(attacks.truncatedLcgPresets.java.multiplier, 25214903917n);
  assert.equal(attacks.truncatedLcgPresets.java.increment, 11n);
  assert.equal(attacks.truncatedLcgPresets.java.modulus, 1n << 48n);
  assert.equal(attacks.truncatedLcgPresets.java.observedBits, 32);
});

// ===================== 6. LFSR 序列外推预测 =====================

test('LFSR 外推：抽头 3,2 手算锚点（种子 111 → 11100101…，外推 1100）', () => {
  const extrapolation = attacks.lfsrExtrapolate([1, 1, 1, 0, 0, 1, 0, 1], [3, 2], 4);
  assert.deepEqual(toMain(extrapolation.predictedBits), [1, 1, 0, 0], '手算：s8=s5^s6=1, s9=s6^s7=1, s10=0, s11=0');
  assert.equal(extrapolation.replayVerified, true);
  assert.deepEqual(toMain(extrapolation.taps), [2, 3]);
  assert.deepEqual(toMain(extrapolation.seedBits), [1, 1, 1]);
});

test('LFSR 外推：抽头 8,6,5,4 前 32 位恢复 → 外推 16 位与真值一致', () => {
  const taps = [8, 6, 5, 4];
  const truth = [1, 0, 1, 1, 0, 0, 0, 1];
  while (truth.length < 64) {
    let bit = 0;
    for (const tap of taps) bit ^= truth[truth.length - tap];
    truth.push(bit);
  }
  const extrapolation = attacks.lfsrExtrapolate(truth.slice(0, 32), taps, 16);
  assert.equal(extrapolation.replayVerified, true, '32 位观测回代应逐位一致');
  assert.deepEqual(toMain(extrapolation.predictedBits), truth.slice(32, 48), '外推 16 位应与真值一致');
  assert.deepEqual(toMain(extrapolation.taps), [4, 5, 6, 8]);
});

test('LFSR 外推：回代发现序列被篡改时标记不可信', () => {
  const taps = [8, 6, 5, 4];
  const bits = [1, 0, 1, 1, 0, 0, 0, 1];
  while (bits.length < 20) {
    let bit = 0;
    for (const tap of taps) bit ^= bits[bits.length - tap];
    bits.push(bit);
  }
  const tampered = bits.slice();
  tampered[12] ^= 1;
  const extrapolation = attacks.lfsrExtrapolate(tampered, taps, 4);
  assert.equal(extrapolation.replayVerified, false);
  assert.equal(extrapolation.replayMismatchIndex, 12);
});

test('LFSR 外推：位数不足时明确报错', () => {
  assert.throws(() => attacks.lfsrExtrapolate([1, 0, 1, 0], [8, 6, 5, 4], 4), /至少 8 bit/);
  assert.throws(() => attacks.lfsrExtrapolate([1, 0, 1, 0], [], 4), /抽头列表/);
});

test('lfsrPredictHelper：自动 Berlekamp-Massey 恢复抽头并外推', () => {
  const taps = [8, 6, 5, 4];
  const truth = [1, 0, 1, 1, 0, 0, 0, 1];
  while (truth.length < 48) {
    let bit = 0;
    for (const tap of taps) bit ^= truth[truth.length - tap];
    truth.push(bit);
  }
  const binaryText = truth.slice(0, 32).join('');
  const parsed = JSON.parse(attacks.lfsrPredictHelper(`${binaryText}\npredict=16`));
  assert.deepEqual(parsed.taps, [4, 5, 6, 8], 'Berlekamp-Massey 应恢复 x^8+x^6+x^5+x^4+1 的抽头');
  assert.equal(parsed.linearComplexity, 8);
  assert.equal(parsed.replayVerified, true);
  assert.equal(parsed.predictedBits, truth.slice(32, 48).join(''));
});

test('lfsrPredictHelper：显式 taps 与 0x 掩码两种写法等价', () => {
  const taps = [8, 6, 5, 4];
  const truth = [1, 0, 1, 1, 0, 0, 0, 1];
  while (truth.length < 48) {
    let bit = 0;
    for (const tap of taps) bit ^= truth[truth.length - tap];
    truth.push(bit);
  }
  const bitsText = `bits=${truth.slice(0, 24).join('')}\npredict=16`;
  const explicit = JSON.parse(attacks.lfsrPredictHelper(`${bitsText}\ntaps=8,6,5,4`));
  const masked = JSON.parse(attacks.lfsrPredictHelper(`${bitsText}\ntaps=0xB8`));
  assert.deepEqual(explicit.taps, [4, 5, 6, 8]);
  assert.deepEqual(masked.taps, [4, 5, 6, 8], '0xB8 = 0b10111000 → bit3/4/5/7 → 抽头 4/5/6/8');
  assert.equal(explicit.predictedBits, masked.predictedBits);
  assert.equal(explicit.predictedBits, truth.slice(24, 40).join(''));
});

test('lfsrPredictHelper：无 keystream 时明确报错', () => {
  assert.throws(() => attacks.lfsrPredictHelper('这里没有二进制序列'), /keystream/);
});
