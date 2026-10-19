// WaterMarkH 频域水印测试（批次 B3·E 线）：单图幅度谱提取。
// 权威向量：本机 numpy 2.5.4 复刻公式（|fft2(x/256)|·256/√N·gain，trunc+clip）对随机
// 16×16 通道的全量 256 值（RandomState(20261012) 通道矩阵以字面量内嵌——numpy randint
// 的 Lemire 拒绝采样序列无法在 TS 侧重现，直接固定输入）；autoGain 锚点同源。
// 可读性/误报判据全部量化：水印区/对照区对比度比值（嵌入 ≥3，无水印 ≤2），不依赖人眼。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const wmh = loadModule(path.join(srcDir, 'utils', 'ctf', 'watermarkhFft.ts'));

// numpy RandomState(20261012).randint(0,256,(16,16)) 的通道矩阵（见文件头说明）
const CHANNEL_16X16 = [
  238, 57, 45, 238, 126, 181, 239, 78, 90, 146, 26, 27, 144, 107, 255, 201,
  80, 78, 27, 146, 64, 68, 58, 140, 71, 26, 135, 142, 94, 112, 24, 254,
  106, 254, 41, 223, 103, 90, 48, 54, 253, 21, 198, 211, 68, 160, 220, 138,
  43, 183, 243, 187, 110, 23, 56, 110, 214, 106, 243, 237, 8, 220, 146, 227,
  182, 171, 53, 44, 134, 231, 39, 1, 189, 44, 46, 28, 184, 79, 103, 195,
  215, 73, 156, 156, 92, 2, 19, 50, 97, 12, 134, 95, 97, 190, 251, 206,
  213, 176, 60, 98, 84, 129, 50, 68, 41, 87, 2, 223, 191, 218, 79, 42,
  129, 18, 37, 190, 134, 92, 142, 107, 100, 204, 55, 73, 28, 43, 201, 101,
  154, 192, 126, 21, 182, 243, 8, 132, 157, 98, 64, 174, 177, 106, 229, 15,
  72, 207, 231, 204, 64, 204, 148, 44, 84, 104, 251, 101, 86, 232, 50, 239,
  30, 247, 43, 206, 164, 11, 48, 66, 113, 140, 62, 195, 194, 18, 36, 240,
  224, 239, 252, 74, 162, 21, 30, 107, 21, 55, 227, 29, 150, 255, 97, 197,
  233, 213, 93, 243, 29, 206, 71, 24, 176, 147, 87, 128, 156, 139, 223, 205,
  91, 20, 46, 133, 3, 169, 254, 101, 215, 228, 49, 37, 61, 172, 196, 50,
  123, 227, 216, 30, 212, 230, 136, 154, 142, 153, 215, 34, 183, 51, 200, 57,
  33, 46, 197, 176, 98, 0, 20, 126, 166, 199, 204, 237, 174, 51, 158, 156,
];
// numpy 参考提取输出（gain=3）：|fft2(ch/256)|·256/√N·3 → trunc → clip 0..255
const EXTRACT_16X16 = [
  255, 255, 99, 245, 66, 138, 161, 255, 131, 255, 161, 138, 66, 245, 99, 255,
  217, 94, 150, 93, 76, 184, 191, 8, 106, 189, 133, 155, 255, 145, 41, 255,
  116, 255, 255, 49, 181, 93, 63, 255, 255, 255, 255, 104, 217, 96, 90, 240,
  215, 255, 136, 76, 216, 182, 255, 52, 149, 141, 234, 255, 255, 77, 224, 255,
  135, 84, 255, 47, 78, 151, 184, 44, 134, 255, 183, 255, 150, 207, 255, 136,
  255, 255, 205, 38, 128, 255, 90, 83, 255, 139, 255, 255, 178, 172, 255, 214,
  191, 106, 172, 255, 255, 198, 255, 211, 190, 131, 255, 145, 184, 132, 66, 167,
  235, 255, 110, 225, 59, 179, 69, 100, 205, 94, 129, 191, 255, 147, 240, 196,
  149, 171, 168, 255, 255, 255, 255, 255, 43, 255, 255, 255, 255, 255, 168, 171,
  235, 196, 240, 147, 255, 191, 129, 94, 205, 100, 69, 179, 59, 225, 110, 255,
  191, 167, 66, 132, 184, 145, 255, 131, 190, 211, 255, 198, 255, 255, 172, 106,
  255, 214, 255, 172, 178, 255, 255, 139, 255, 83, 90, 255, 128, 38, 205, 255,
  135, 136, 255, 207, 150, 255, 183, 255, 134, 44, 184, 151, 78, 47, 255, 84,
  215, 255, 224, 77, 255, 255, 234, 141, 149, 52, 255, 182, 216, 76, 136, 255,
  116, 240, 90, 96, 217, 104, 255, 255, 255, 255, 63, 93, 181, 49, 255, 255,
  217, 255, 41, 145, 255, 155, 133, 189, 106, 8, 191, 184, 76, 93, 150, 94,
];
// 同通道的 numpy autoGain 参考：p995（sorted[floor(N·0.995)]）归 240
const AUTOGAIN_16X16 = 1.315827213812351;

// 渐变+噪声载体（确定性 LCG），默认 128×128
const gradientCarrier = (width = 128, height = 128) => {
  const data = new Uint8ClampedArray(width * height * 4);
  let state = 42;
  const rand = () => {
    state = (state * 1103515245 + 12345) % 2147483648;
    return state / 2147483648;
  };
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const base = 40 + (x * 150) / width + (y * 60) / height;
      const value = Math.max(0, Math.min(255, base + (rand() - 0.5) * 24));
      const index = (y * width + x) * 4;
      data[index] = value;
      data[index + 1] = value;
      data[index + 2] = value;
      data[index + 3] = 255;
    }
  }
  return { data, width, height };
};

// 黑底白字块图案（模拟文字笔画，居中偏上），再做原软件的中心对称镜像
const textPattern = (width, height) => {
  const pattern = new Uint8Array(width * height);
  for (let y = 20; y < 30; y += 1) {
    for (let x = 34; x < 94; x += 1) pattern[y * width + x] = 255;
  }
  return wmh.watermarkhMirrorPattern(pattern);
};

test('watermarkhExtractChannel：与 numpy 复刻公式全量 256 值一致（16×16 权威向量）', () => {
  const width = 16;
  const height = 16;
  const channel = new Float64Array(CHANNEL_16X16);
  const extracted = wmh.watermarkhExtractChannel(channel, width, height, 3);
  assert.equal(extracted.length, 256);
  let exact = 0;
  for (let index = 0; index < 256; index += 1) {
    if (extracted[index] === EXTRACT_16X16[index]) exact += 1;
    // fft.ts 与 numpy.fft 双精度差 ~1e-12，截断边界可能产生 ±1
    assert.ok(Math.abs(extracted[index] - EXTRACT_16X16[index]) <= 1, `cell[${index}] got ${extracted[index]} expect ${EXTRACT_16X16[index]}`);
  }
  assert.ok(exact >= 250, `截断边界容差下应几乎全等，exact=${exact}/256`);
});

test('watermarkhAutoGain：99.5 分位归 240（numpy 锚点 + 常数图边界行为）', () => {
  // 同一 16×16 通道的 numpy 精确锚点
  const image16 = { data: new Uint8ClampedArray(256 * 4), width: 16, height: 16 };
  CHANNEL_16X16.forEach((value, index) => {
    image16.data[index * 4] = value;
    image16.data[index * 4 + 1] = value;
    image16.data[index * 4 + 2] = value;
    image16.data[index * 4 + 3] = 255;
  });
  assert.ok(wmh.watermarkhIsPowerOfTwo(16));
  const gain = wmh.watermarkhAutoGain(image16);
  assert.ok(Math.abs(gain - AUTOGAIN_16X16) < 1e-9, `autoGain got ${gain} expect ${AUTOGAIN_16X16}`);
  // 常数图：除 DC 外全零，99.5 分位落在 0 → 回退 1 → 240
  const flat = { data: new Uint8ClampedArray(64 * 64 * 4).fill(128), width: 64, height: 64 };
  for (let index = 0; index < 64 * 64; index += 1) flat.data[index * 4 + 3] = 255;
  assert.equal(wmh.watermarkhAutoGain(flat), 240);
});

test('watermarkhExtract：嵌入→提取水印区对比度 ≥3×（量化判据，不依赖人眼）', () => {
  const carrier = gradientCarrier();
  const stego = wmh.watermarkhEmbed(carrier, textPattern(128, 128), { alpha: 0.1 });
  // 嵌入可见性：逐像素平均变化 <2（肉眼看不出），但必须真的改了图
  let sumDiff = 0;
  let maxDiff = 0;
  for (let index = 0; index < carrier.data.length; index += 4) {
    const diff = Math.abs(stego.data[index] - carrier.data[index]);
    sumDiff += diff;
    if (diff > maxDiff) maxDiff = diff;
  }
  const meanDiff = sumDiff / (128 * 128);
  assert.ok(meanDiff < 2 && maxDiff > 0, `嵌入应不可见但生效：mean=${meanDiff} max=${maxDiff}`);

  const result = wmh.watermarkhExtract(stego, { autoGain: true, normalize: true });
  assert.ok(!result.notes.some(note => note.includes('2 的幂')), 'POT 尺寸不应产生缩放提示');
  const spec = result.image.data;
  const regionMean = (x0, x1, y0, y1) => {
    let sum = 0;
    let count = 0;
    for (let y = y0; y < y1; y += 1) {
      for (let x = x0; x < x1; x += 1) {
        sum += spec[(y * 128 + x) * 4];
        count += 1;
      }
    }
    return sum / count;
  };
  const patternMean = regionMean(34, 94, 20, 30);
  const mirrorMean = regionMean(34, 94, 98, 108); // 中心对称镜像副本区
  const controlMean = regionMean(4, 24, 60, 70);
  assert.ok(patternMean / controlMean >= 3, `水印区/对照区对比度应 ≥3，got ${patternMean / controlMean}`);
  assert.ok(mirrorMean / controlMean >= 3, `镜像区/对照区对比度应 ≥3，got ${mirrorMean / controlMean}`);
});

test('watermarkhExtract：正常图（无水印）不误报——同区域对比度 ≤2 且中部无亮簇', () => {
  const carrier = gradientCarrier();
  const result = wmh.watermarkhExtract(carrier, { autoGain: true, normalize: true });
  const spec = result.image.data;
  const regionMean = (x0, x1, y0, y1) => {
    let sum = 0;
    let count = 0;
    for (let y = y0; y < y1; y += 1) {
      for (let x = x0; x < x1; x += 1) {
        sum += spec[(y * 128 + x) * 4];
        count += 1;
      }
    }
    return sum / count;
  };
  const patternMean = regionMean(34, 94, 20, 30);
  const controlMean = regionMean(4, 24, 60, 70);
  assert.ok(patternMean / controlMean <= 2, `无水印图的假水印区对比度应 ≤2，got ${patternMean / controlMean}`);
  // 峰值分布：无水印图的提取谱能量集中在低频（角落），中部"文字带"不应出现孤立亮簇
  let midBandBright = 0;
  for (let y = 16; y < 112; y += 1) {
    for (let x = 16; x < 112; x += 1) {
      if (spec[(y * 128 + x) * 4] > 180) midBandBright += 1;
    }
  }
  assert.ok(midBandBright <= 30, `中部亮簇应稀少，got ${midBandBright}`);
});

test('watermarkhSuppressMirror：max(0, v−旋转180°副本) 逐像素语义', () => {
  const width = 4;
  const height = 4;
  const data = new Uint8ClampedArray(width * height * 4);
  const values = [10, 20, 30, 40, 50, 60, 70, 80, 90, 15, 25, 35, 45, 55, 65, 75];
  values.forEach((value, index) => {
    data[index * 4] = value;
    data[index * 4 + 1] = value;
    data[index * 4 + 2] = value;
    data[index * 4 + 3] = 255;
  });
  const result = wmh.watermarkhSuppressMirror({ data, width, height });
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const index = y * width + x;
      const mirror = (height - 1 - y) * width + (width - 1 - x);
      const expected = Math.max(0, values[index] - values[mirror]);
      assert.equal(result.data[index * 4], expected, `(${x},${y})`);
      assert.equal(result.data[index * 4 + 3], 255);
    }
  }
});

test('watermarkhNormalize：直方图分位数拉伸（0.60→0.995）', () => {
  const width = 4;
  const height = 4;
  const data = new Uint8ClampedArray(width * height * 4);
  // R 值：12 个 10 + 2 个 100 + 2 个 200 → 60% 分位=10，99.5% 分位=200
  const values = [10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 100, 100, 200, 200];
  values.forEach((value, index) => {
    data[index * 4] = value;
    data[index * 4 + 1] = value;
    data[index * 4 + 2] = value;
    data[index * 4 + 3] = 255;
  });
  const result = wmh.watermarkhNormalize({ data, width, height });
  // a=10（累计 12 ≥ 0.6·16=9.6），b=200（累计 16 ≥ 0.995·16=15.92）
  // 10 → 0；100 → (100−10)·255/190 ≈ 120.8 → trunc 120；200 → 255
  assert.equal(result.data[0], 0);
  assert.equal(result.data[12 * 4], 120);
  assert.equal(result.data[14 * 4], 255);
  assert.equal(result.data[3], 255);
});

test('watermarkhExtract：非 2 幂自动缩放（100×80 → 128×64）并带提示，POT 直通无提示', () => {
  const carrier = gradientCarrier(100, 80);
  const result = wmh.watermarkhExtract(carrier, { gain: 5 });
  assert.equal(result.image.width, 128);
  assert.equal(result.image.height, 64);
  assert.equal(result.gain, 5);
  assert.ok(result.notes.some(note => note.includes('2 的幂')), '必须有缩放提示');
  // POT 输入直通
  const pot = gradientCarrier(128, 64);
  const direct = wmh.watermarkhExtract(pot, { gain: 5 });
  assert.equal(direct.image.width, 128);
  assert.equal(direct.notes.length, 0);
});

test('watermarkhEmbed：非 2 幂报错、图案长度不匹配报错、alpha 保留、确定性', () => {
  const nonPot = gradientCarrier(100, 100);
  const pattern = new Uint8Array(128 * 128);
  assert.throws(() => wmh.watermarkhEmbed(nonPot, pattern), /2 的幂/);
  const carrier = gradientCarrier();
  assert.throws(() => wmh.watermarkhEmbed(carrier, new Uint8Array(64)), /图案长度/);
  // alpha 原样保留
  const embedded = wmh.watermarkhEmbed(carrier, pattern);
  assert.equal(embedded.width, 128);
  assert.equal(embedded.data[3], carrier.data[3]);
  // 确定性：同输入两次嵌入逐像素一致
  const again = wmh.watermarkhEmbed(carrier, pattern);
  assert.deepEqual(Array.from(embedded.data), Array.from(again.data));
});

test('watermarkhMirrorPattern：p[N−1−i] = p[i] 原软件中心对称', () => {
  const mirrored = wmh.watermarkhMirrorPattern([1, 2, 3, 4, 5, 6, 7, 8]);
  assert.deepEqual(Array.from(mirrored), [1, 2, 3, 4, 4, 3, 2, 1]);
  // 奇数长度：中位不动
  const odd = wmh.watermarkhMirrorPattern([9, 8, 7, 6, 5]);
  assert.deepEqual(Array.from(odd), [9, 8, 7, 8, 9]);
});
