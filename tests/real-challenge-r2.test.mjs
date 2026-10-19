// CTF 能力第三批修复（r2）黄金向量回归测试。
// 纪律：真题文件即黄金向量；官方工具对拍（openssl CLI）；执行器 E2E 断言 verdict——
// 禁止镜像自闭环（测试断言的实现在 src/utils 引擎与 scripts 执行器，本文件只消费）。
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { createTsModuleLoader } from './helpers/compileTsModule.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { loadModule } = createTsModuleLoader();
const rc = (...parts) => path.join(projectRoot, 'tests', 'real-challenges', ...parts);

const engines = {};
before(async () => {
  engines.pdfInspect = loadModule('src/utils/ctf/pdfInspect.ts');
  engines.pdfText = loadModule('src/utils/ctf/pdfText.ts');
  engines.textChains = loadModule('src/utils/ctf/executorTextChains.ts');
  engines.embedScan = loadModule('src/utils/ctf/embedScan.ts');
  engines.crypto = loadModule('src/utils/codec/crypto.ts');
  engines.rarInspect = loadModule('src/utils/ctf/rarInspect.ts');
  engines.rarExtract = loadModule('src/utils/ctf/rarExtract.ts');
  engines.audioStego = loadModule('src/utils/ctf/audioStego.ts');
});

// —— P1-2：PDF 文本层 AB 串摩尔斯（07-stegano）——
describe('P1-2 07-stegano AB 串摩尔斯', () => {
  test('extracted.txt（writeup 带空格形态）秒解出 CONGRATULATIONS,FLAG:1NV151BL3M3554G3', () => {
    const text = readFileSync(rc('xctf-misc', '07-stegano', 'extracted.txt'), 'utf8');
    const hits = [];
    engines.textChains.collectAbMorse(text, decoded => hits.push(decoded));
    assert.ok(hits.some(hit => hit.includes('CONGRATULATIONS') && hit.includes('1NV151BL3M3554G3')), `实际解出: ${JSON.stringify(hits)}`);
  });

  test('stegano.pdf 内容流经 TJ 字距还原（|n|≥100→空格）后按字母边界解出同一明文', () => {
    const bytes = new Uint8Array(readFileSync(rc('xctf-misc', '07-stegano', 'stegano.pdf')));
    const inspected = engines.pdfInspect.inspectPdf(bytes);
    let decoded = null;
    for (const stream of inspected.streams) {
      const raw = bytes.subarray(stream.offset, Math.min(bytes.length, stream.offset + stream.length));
      const inflated = stream.filter?.includes('FlateDecode')
        ? (() => { try { return zlib.inflateSync(Buffer.from(raw)); } catch { return null; } })()
        : Buffer.from(raw);
      if (!inflated) continue;
      const pieces = engines.pdfText.extractPdfContentText(inflated, { kernSpaceThreshold: 100 });
      for (const line of pieces.join('\n').split(/\r?\n/)) {
        engines.textChains.collectAbMorse(line, candidate => {
          if (candidate.includes('1NV151BL3M3554G3')) decoded = candidate;
        });
      }
    }
    assert.ok(decoded, 'PDF 字距还原通道未解出目标串');
    assert.ok(decoded.includes('CONGRATULATIONS'));
  });
});

// —— P1-4：GIF 尾附 base64 → OpenSSL Salted AES 双解（15-Aesop）——
describe('P1-4 15-Aesop 尾附 Salted 双解链', () => {
  test('findGifTrailer 提出尾附且以 U2FsdGVkX1 开头', () => {
    const bytes = new Uint8Array(readFileSync(rc('xctf-misc', '15-Aesop_secret', 'Aesop.gif')));
    const trailer = engines.embedScan.findGifTrailer(bytes);
    assert.ok(trailer, '未检出 GIF 尾附');
    const tail = Buffer.from(trailer.trailing).toString('latin1');
    assert.match(tail, /U2FsdGVkX1[A-Za-z0-9+/=]{16,}/);
  });

  test('密钥 ISCC 连解两层得 flag{DugUpADiamondADeepDarkMine}', async () => {
    const bytes = new Uint8Array(readFileSync(rc('xctf-misc', '15-Aesop_secret', 'Aesop.gif')));
    const trailer = engines.embedScan.findGifTrailer(bytes);
    const b64 = Buffer.from(trailer.trailing).toString('latin1').match(/U2FsdGVkX1[A-Za-z0-9+/=]{16,}/)[0];
    const round1 = JSON.parse(await engines.crypto.openSslAes256CbcTransform('decode', b64, 'ISCC')).plaintext;
    assert.match(round1, /^U2FsdGVkX1/, '第一层解密结果应仍是 Salted__ 嵌套层');
    const round2 = JSON.parse(await engines.crypto.openSslAes256CbcTransform('decode', round1, 'ISCC')).plaintext;
    assert.equal(round2, 'flag{DugUpADiamondADeepDarkMine}');
  });

  test('独立实现对拍：node 内置 OpenSSL（非引擎 WebCrypto 路径）+ 测试内独立重算 EVP_BytesToKey', () => {
    // 本机 Windows 的 openssl CLI 构建存在文件读取缺陷（3.3/3.5 均报 error reading input file），
    // 对拍改走 node:crypto：AES 原语用 node 捆绑的 OpenSSL（与引擎的 WebCrypto 不同实现），
    // KDF 在测试内独立重算 MD5 链（不 import 引擎代码）——口径仍为 EVP_BytesToKey-MD5。
    const bytes = new Uint8Array(readFileSync(rc('xctf-misc', '15-Aesop_secret', 'Aesop.gif')));
    const trailer = engines.embedScan.findGifTrailer(bytes);
    const b64 = Buffer.from(trailer.trailing).toString('latin1').match(/U2FsdGVkX1[A-Za-z0-9+/=]{16,}/)[0];
    const derive = (password, salt) => {
      const md5 = data => crypto.createHash('md5').update(data).digest();
      let previous = Buffer.alloc(0);
      const material = [];
      while (material.length < 48) {
        previous = md5(Buffer.concat([previous, Buffer.from(password, 'utf8'), salt]));
        material.push(...previous);
      }
      const derived = Buffer.from(material);
      return { key: derived.subarray(0, 32), iv: derived.subarray(32, 48) };
    };
    const decryptLayer = (layerB64, password) => {
      const blob = Buffer.from(layerB64, 'base64');
      assert.equal(blob.subarray(0, 8).toString('latin1'), 'Salted__', '对拍层应带 Salted__ 头');
      const { key, iv } = derive(password, blob.subarray(8, 16));
      const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      return Buffer.concat([decipher.update(blob.subarray(16)), decipher.final()]).toString('utf8');
    };
    const round1 = decryptLayer(b64, 'ISCC');
    assert.match(round1, /^U2FsdGVkX1/, '独立实现第一层应解出嵌套 Salted__');
    assert.equal(decryptLayer(round1.trim(), 'ISCC'), 'flag{DugUpADiamondADeepDarkMine}');
  });
});

// —— P1-6：RAR 修复 → XOR 还原 WAV → 倒放（23-进制反转）——
describe('P1-6 23-进制反转 恢复+倒放链', () => {
  test('rar 修复解出 flag.wav → XOR 0xFF 恢复 RIFF → parseWav → reverseWav 头合法且二次倒放还原', () => {
    let bytes = new Uint8Array(readFileSync(rc('xctf-misc', '23-祥云杯2020-进制反转', '进制反转.rar')));
    const sig = engines.rarInspect.fixRarSignature(bytes);
    if (sig.fixed) bytes = sig.fixed;
    const pseudo = engines.rarInspect.fixRarPseudoEncryption(bytes);
    const working = pseudo.fixed ?? bytes;
    const inspected = engines.rarInspect.inspectRar(working);
    const wavEntry = inspected.entries.find(entry => !entry.isDirectory && !entry.encrypted);
    assert.ok(wavEntry, '未找到 wav 条目');
    const extracted = engines.rarExtract.extractRarEntry(working, wavEntry);
    assert.ok(extracted.bytes?.length, '条目解压失败');
    // XOR 0xFF 还原（头两字节 0x52 0x49 = "RI"）
    const recovered = Uint8Array.from(extracted.bytes, b => b ^ 0xFF);
    assert.equal(recovered[0], 0x52);
    assert.equal(recovered[1], 0x49);
    const parsed = engines.audioStego.parseWav(recovered);
    assert.ok(parsed.info.frames > 100000, '恢复的 wav 应有完整音频帧');
    const reversed = engines.audioStego.reverseWav(recovered);
    const reparsed = engines.audioStego.parseWav(reversed);
    assert.equal(reparsed.info.sampleRate, parsed.info.sampleRate);
    assert.equal(reparsed.info.frames, parsed.info.frames);
  });
});

// —— 执行器 E2E：六题 verdict 门禁（真题文件即黄金向量）——
describe('执行器 E2E（r2 门禁）', () => {
  const cases = [
    ['xctf-misc/07-stegano', { PASS: 2 }],
    ['xctf-misc/10-SimpleRAR', { PASS: 1 }],
    ['xctf-misc/12-功夫再高也怕菜刀', { 'PASS-边界': 1 }],
    ['xctf-misc/15-Aesop_secret', { PASS: 1 }],
    ['xctf-misc/23-祥云杯2020-进制反转', { 'PASS-边界': 1 }],
    ['xctf-misc/25-祥云杯2021-鸣雏恋', { PASS: 1 }],
    ['xctf-misc/22-我们的秘密是绿色的', { 'PASS-边界': 1 }],
    ['xctf-misc/24-祥云杯2020-带音乐家', { 'PASS-边界': 1 }],
    ['08_pdf_cropbox', { 'PASS-边界': 1 }],
  ];
  const outDir = path.join(projectRoot, 'output', 'tmp-r2-e2e');
  mkdirSync(outDir, { recursive: true });
  for (const [dir, expectedSummary] of cases) {
    test(`${dir} → ${JSON.stringify(expectedSummary)}`, () => {
      const outPath = path.join(outDir, dir.replace(/[\\/]/g, '_') + '.json');
      const run = spawnSync(process.execPath, ['scripts/solve-real-challenges.mjs', '--dir', rc(dir), '--out', outPath], {
        cwd: projectRoot, encoding: 'utf8', timeout: 300000,
      });
      assert.equal(run.status, 0, `执行器退出码 ${run.status}: ${run.stderr?.slice(0, 300)}`);
      const report = JSON.parse(readFileSync(outPath, 'utf8'));
      assert.deepEqual(report.summary, expectedSummary, `paths: ${JSON.stringify((report.results[0]?.paths ?? []).slice(0, 8))}`);
    });
  }
});
