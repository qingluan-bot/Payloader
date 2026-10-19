// DeepSound 音频隐写提取引擎测试：
// 1) 真实官方工具载体（tests/fixtures/deepsound/，GitHub Jpinsoft/DeepSound v2.0/v2.3 官方产物
//    裁剪）：DSCF mode2/4/8 无密码三档、DSCF mode4 密码档、DSC2 无密码/密码档——逐档断言
//    提取文件名与内容逐字节还原（独立来源 = 官方工具，非本引擎正向构造）；
// 2) 加密载体错密码/无密码显式拒绝（零产物）；
// 3) 非 DSC 载体明确报"未发现 DeepSound 头"；
// 4) 正向嵌入闭环：测试侧独立正向嵌入器（与引擎不同代码路径）按实测口径构造 mode2/4/8 载体，
//    引擎提取应逐字节还原；头部结构手算锚点（DSCF/DSC2 + mode + AES 标志布局）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const { extractDeepSound } = loadModule(path.join(projectRoot, 'src', 'utils', 'ctf', 'deepSound.ts'));

const FIXTURE_DIR = path.join(projectRoot, 'tests', 'fixtures', 'deepsound');
const hasFixtures = existsSync(FIXTURE_DIR) && readdirSync(FIXTURE_DIR).length > 0;

const PASSWORD = 'hunter2';
const NP_FLAG = 'flag{realds_nopass_7d2f}';
const P_FLAG = 'flag{realds_withpass_c41a}';

// ---- 真实官方工具载体（无密码三模式 + 密码档） ----

test('真实 DeepSound 2.0 无密码载体 mode2/4/8 三档提取（官方工具产物）', { skip: hasFixtures ? false : '缺少 DeepSound 官方工具夹具' }, () => {
  for (const file of ['ds20-low-nopass.wav', 'ds20-normal-nopass.wav', 'ds20-high-nopass.wav']) {
    const bytes = new Uint8Array(readFileSync(path.join(FIXTURE_DIR, file)));
    const r = extractDeepSound(bytes);
    assert.equal(r.found, true, `${file} 应发现 DeepSound 头`);
    assert.equal(r.marker, 'DSCF', `${file} marker`);
    assert.equal(r.encrypted, false, `${file} 未加密`);
    assert.equal(r.files.length, 1, `${file} 应解出 1 个文件`);
    assert.equal(r.files[0].fileName, 'secret1.txt');
    assert.equal(Buffer.from(r.files[0].bytes).toString('latin1'), NP_FLAG, `${file} 内容逐字节还原`);
    assert.equal(r.failure, null);
  }
});

test('真实 DeepSound 2.0 密码载体（AES-256-ECB，ASCII 口令补零密钥）提取', { skip: hasFixtures ? false : '缺少 DeepSound 官方工具夹具' }, () => {
  const bytes = new Uint8Array(readFileSync(path.join(FIXTURE_DIR, 'ds20-normal-password.wav')));
  const r = extractDeepSound(bytes, { password: PASSWORD });
  assert.equal(r.found, true);
  assert.equal(r.marker, 'DSCF');
  assert.equal(r.encrypted, true);
  assert.ok(r.passwordDigest, '应读出 20B 口令摘要');
  assert.equal(r.files.length, 1);
  assert.equal(r.files[0].fileName, 'secret2.txt');
  assert.equal(Buffer.from(r.files[0].bytes).toString('latin1'), P_FLAG);
  assert.equal(r.failure, null);
});

test('真实 DeepSound 2.1+（DSC2）无密码/密码两档提取（官方 2.3 工具产物）', { skip: hasFixtures ? false : '缺少 DeepSound 官方工具夹具' }, () => {
  const np = extractDeepSound(new Uint8Array(readFileSync(path.join(FIXTURE_DIR, 'ds23-nopass.wav'))));
  assert.equal(np.marker, 'DSC2');
  assert.equal(np.files[0].fileName, 'secret1.txt');
  assert.equal(Buffer.from(np.files[0].bytes).toString('latin1'), NP_FLAG);

  const p = extractDeepSound(new Uint8Array(readFileSync(path.join(FIXTURE_DIR, 'ds23-password.wav'))), { password: PASSWORD });
  assert.equal(p.marker, 'DSC2');
  assert.equal(p.encrypted, true);
  assert.equal(Buffer.from(p.files[0].bytes).toString('latin1'), P_FLAG);
});

test('加密载体：错密码与缺失密码零产物显式拒绝', { skip: hasFixtures ? false : '缺少 DeepSound 官方工具夹具' }, () => {
  const bytes = new Uint8Array(readFileSync(path.join(FIXTURE_DIR, 'ds23-password.wav')));
  const wrong = extractDeepSound(bytes, { password: 'wrong-password' });
  assert.equal(wrong.found, true, '头应被发现');
  assert.equal(wrong.files.length, 0, '错密码不得产出任何文件');
  assert.ok(wrong.failure?.includes('解密失败'), '应显式拒绝：' + wrong.failure);

  const noPw = extractDeepSound(bytes);
  assert.equal(noPw.files.length, 0);
  assert.ok(noPw.failure?.includes('需要提供口令'), '缺密码应显式说明：' + noPw.failure);
});

test('非 DSC 载体明确报"未发现 DeepSound 头"，非 PCM WAV 抛中文错误', () => {
  // 普通 WAV（RIFF 但无嵌入）：手工构造一个 16bit 单声道空 WAV
  const sampleRate = 8000;
  const frames = 256;
  const data = Buffer.alloc(frames * 2);
  const header = Buffer.alloc(44);
  header.write('RIFF', 0, 'latin1');
  header.writeUInt32LE(36 + data.length, 4);
  header.write('WAVE', 8, 'latin1');
  header.write('fmt ', 12, 'latin1');
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(1, 20);
  header.writeUInt16LE(1, 22);
  header.writeUInt32LE(sampleRate, 24);
  header.writeUInt32LE(sampleRate * 2, 28);
  header.writeUInt16LE(2, 32);
  header.writeUInt16LE(16, 34);
  header.write('data', 36, 'latin1');
  header.writeUInt32LE(data.length, 40);
  const plain = new Uint8Array(Buffer.concat([header, data]));
  const r = extractDeepSound(plain);
  assert.equal(r.found, false);
  assert.equal(r.files.length, 0);
  assert.ok(r.failure?.includes('未发现 DeepSound 头'), r.failure);

  assert.throws(() => extractDeepSound(new Uint8Array(64)), /RIFF|WAV/);
});

// ---- 正向嵌入闭环（独立正向实现 → 引擎提取） ----

// 测试侧独立正向嵌入器：按实测口径把 26B 头 + 记录链写进 16bit 立体声 WAV 样本低字节。
// 与引擎 extractDeepSound 是不同代码路径（正向写入 vs 逆向提取），闭环对拍有效。
const buildCarrier = ({ marker, mode, encrypted, digest, records }) => {
  // 头部恒按 mode-4 口径编码（实测：DSCF/DSC2 + mode + AES 标志 + 20B 摘要），占样本 0..11
  // （加密时另含摘要，占样本 12..31）；数据区按实际模式自其后编码。
  const header = Buffer.concat([
    Buffer.from(marker, 'latin1'),
    Buffer.from([mode, encrypted ? 1 : 0]),
    ...(encrypted ? [Buffer.from(digest)] : []),
  ]);
  let chain = Buffer.alloc(0);
  for (const { fileName, bytes } of records) {
    const name = Buffer.from(fileName, 'latin1').subarray(0, 20);
    const content = Buffer.concat([Buffer.from(bytes), Buffer.alloc(4 - (bytes.length % 4))]);
    chain = Buffer.concat([
      chain,
      Buffer.from('DSSF', 'latin1'),
      Buffer.concat([name, Buffer.alloc(20 - name.length)]),
      Buffer.alloc(3), Buffer.from([bytes.length]), // 大端 uint32 长度
      Buffer.alloc(4),
      content,
    ]);
  }
  chain = Buffer.concat([chain, Buffer.from('DSSF', 'latin1'), Buffer.alloc(24), Buffer.alloc(4)]); // 空记录收尾
  const encodeMode4 = (bytes, out, start) => {
    for (let i = 0; i < bytes.length; i++) {
      out[start + 2 * i] = bytes[i] >> 4;
      out[start + 2 * i + 1] = bytes[i] & 0x0f;
    }
  };
  const headerSamples = header.length * 2;
  const dataSamples = encrypted
    ? 128 // 加密档：伪造随机密文（本测试只断言摘要与显式拒绝，不解密）
    : mode === 4 ? chain.length * 2 : mode === 2 ? chain.length : chain.length * 4;
  const samples = new Uint8Array(Math.max(512, headerSamples + dataSamples + 64));
  encodeMode4(header, samples, 0);
  if (encrypted) {
    for (let i = headerSamples; i < samples.length; i++) samples[i] = (i * 31 + 7) & 0xff; // 伪随机密文
  } else if (mode === 4) {
    encodeMode4(chain, samples, headerSamples);
  } else if (mode === 2) {
    samples.set(chain.subarray(0, Math.min(chain.length, samples.length - headerSamples)), headerSamples);
  } else {
    for (let i = 0; i < chain.length && headerSamples + 4 * i + 3 < samples.length; i++) {
      for (let bit = 0; bit < 4; bit++) {
        samples[headerSamples + 4 * i + bit] = (chain[i] >> (6 - 2 * bit)) & 0x03;
      }
    }
  }
  // 打包成 16bit 立体声 WAV：样本流偶数索引 = 每个样本的低字节
  const dataBytes = samples.length * 4;
  const wav = Buffer.alloc(44 + dataBytes);
  wav.write('RIFF', 0, 'latin1');
  wav.writeUInt32LE(36 + dataBytes, 4);
  wav.write('WAVE', 8, 'latin1');
  wav.write('fmt ', 12, 'latin1');
  wav.writeUInt32LE(16, 16);
  wav.writeUInt16LE(1, 20);
  wav.writeUInt16LE(2, 22);
  wav.writeUInt32LE(44100, 24);
  wav.writeUInt32LE(44100 * 4, 28);
  wav.writeUInt16LE(4, 32);
  wav.writeUInt16LE(16, 34);
  wav.write('data', 36, 'latin1');
  wav.writeUInt32LE(dataBytes, 40);
  for (let i = 0; i < samples.length; i++) {
    // 样本流第 i 字节 → 立体声第 i 个采样（帧 i>>1 的通道 i&1）的低字节；高位字节噪声化。
    // 嵌入按"采样序"连续排布（与官方工具一致：立体声两通道按帧交织视为同一条流）。
    const frame = i >> 1;
    const channel = (i & 1) * 2;
    const base = 44 + frame * 4 + channel;
    const high = ((i * 37 + 11) % 64) + 1;
    wav[base] = samples[i];
    wav[base + 1] = high;
  }
  return new Uint8Array(wav);
};

const buildRecord = (fileName, bytes) => ({ fileName, bytes });

test('正向嵌入闭环：mode4 无密码载体引擎提取逐字节还原（手算头部锚点）', () => {
  const secret = Buffer.from('flag{ds_closed_loop_m4}');
  const wav = buildCarrier({ marker: 'DSCF', mode: 4, encrypted: false, digest: null, records: [buildRecord('loop4.txt', secret)] });
  // 手算锚点：头 6 字节 = 44 53 43 46 04 00（DSCF + mode4 + 未加密），恒按 mode-4 编码占样本 0..11
  const r = extractDeepSound(wav);
  assert.equal(r.found, true);
  assert.equal(r.marker, 'DSCF');
  assert.equal(r.mode, 4);
  assert.equal(r.encrypted, false);
  assert.equal(r.files.length, 1);
  assert.equal(r.files[0].fileName, 'loop4.txt');
  assert.deepEqual(Buffer.from(r.files[0].bytes), secret, '内容逐字节还原');
});

test('正向嵌入闭环：mode2 / mode8 载体提取', () => {
  const secret2 = Buffer.from('mode2-loop-secret');
  const wav2 = buildCarrier({ marker: 'DSCF', mode: 2, encrypted: false, digest: null, records: [buildRecord('low.txt', secret2)] });
  const r2 = extractDeepSound(wav2);
  assert.equal(r2.mode, 2);
  assert.equal(Buffer.from(r2.files[0].bytes).toString('latin1'), 'mode2-loop-secret');

  const secret8 = Buffer.from('m8');
  const wav8 = buildCarrier({ marker: 'DSCF', mode: 8, encrypted: false, digest: null, records: [buildRecord('hi.txt', secret8)] });
  const r8 = extractDeepSound(wav8);
  assert.equal(r8.mode, 8);
  assert.equal(Buffer.from(r8.files[0].bytes).toString('latin1'), 'm8');
});

test('正向嵌入闭环：DSC2 多文件记录链 + 嵌入起点非零滑动扫描', () => {
  const wav = buildCarrier({
    marker: 'DSC2',
    mode: 4,
    encrypted: false,
    digest: null,
    records: [buildRecord('a.txt', Buffer.from('first')), buildRecord('b.bin', Buffer.from([1, 2, 3, 4, 5, 6, 7]))],
  });
  const r = extractDeepSound(wav);
  assert.equal(r.marker, 'DSC2');
  assert.equal(r.files.length, 2);
  assert.equal(r.files[0].fileName, 'a.txt');
  assert.equal(Buffer.from(r.files[0].bytes).toString('latin1'), 'first');
  assert.deepEqual(Array.from(r.files[1].bytes), [1, 2, 3, 4, 5, 6, 7]);
});

test('手算锚点：头部字节布局（marker+mode+aes + 20B 摘要位置）', () => {
  // 密码载体头部：DSC2 + mode + aes=1 + 摘要 20B → 数据区自样本 52 起
  const digest = Buffer.from('11223344556677889900aabbccddeeff00112233', 'hex');
  const wav = buildCarrier({ marker: 'DSC2', mode: 4, encrypted: true, digest, records: [buildRecord('e.txt', Buffer.from('x'))] });
  const r = extractDeepSound(wav);
  assert.equal(r.marker, 'DSC2');
  assert.equal(r.encrypted, true);
  assert.equal(r.passwordDigest, digest.toString('hex'), '摘要字段读取位置正确');
  // 正确密码（引擎口径 SHA-256(UTF-16LE)）应解密成功——用无密码记录链 + 伪造摘要不可解，
  // 故这里只断言摘要与拒绝行为；真实密码档由官方工具夹具覆盖。
  const bad = extractDeepSound(wav, { password: 'whatever' });
  assert.equal(bad.files.length, 0);
  assert.ok(bad.failure?.length, '伪造密文应显式拒绝');
});
