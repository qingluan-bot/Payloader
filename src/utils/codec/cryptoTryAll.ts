// 密钥+密文组合枚举尝试器（Lane B）：给定密文与密钥，自动枚举 算法×模式×编码 组合逐个试解打分。
// 算法出处与对拍锚点：
// - AES 模式原语：@noble/ciphers（ecb/cbc/cfb/ctr，纯 JS 审计实现）；OFB 由 SP 800-38A 定义的
//   OFB 流程（O_1 = E_k(IV)，O_j = E_k(O_{j-1})）基于 ecb(disablePadding) 单块原语自造。
//   AES 向量锚点：NIST SP 800-38A F.1.1/F.2.1/F.3.1/F.4.1/F.5.1（key 2b7e151628aed2a6abf7158809cf4f3c）。
// - DES/3DES 原语：crypto-js（FIPS 46-3 / SP 800-67）。向量锚点：FIPS 81 ECB 例
//   （key 0123456789abcdef，明文首块 "Now is t"，密文 3fa40e8a984d4815）。
// - RC4：自写 KSA+PRGA（RSA Labs RC4 规范，对拍锚点：Wikipedia RC4 向量 key="Key"
//   plaintext="Plaintext" → BBF316E8D940AF0AD3）。
// - XOR：重复密钥逐字节异或。
// - 打分：printableRatio − ShannonEntropy/16 + 命中 crib 关键词每个 +0.5；
//   解码结果 U+FFFD 占比 > 10% 判 0 分。
// 全部组合用尽或超上限/超时即护栏报错，绝不静默截断。
import { cbc, cfb, ctr, ecb } from '@noble/ciphers/aes.js';
import { md5 } from '@noble/hashes/legacy.js';

// ---------- 字节/编码小工具（零内部依赖，避免 codec 内环） ----------

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder('utf-8', { fatal: false });

export const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');

export const hexToBytes = (hex: string): Uint8Array => {
  const clean = hex.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  if (clean.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(clean)) throw new Error('不是合法 hex');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
};

export const base64ToBytes = (text: string): Uint8Array => {
  const normalized = text.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  // atob 过于宽松（乱字符可能被吞），先做字符集校验
  if (normalized.length === 0 || normalized.length % 4 === 1 || !/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new Error('不是合法 base64');
  }
  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
};

/** 密文输入解析：hex（含 0x/分隔符）优先，其次 base64。 */
export const parseCipherBytes = (value: string): { bytes: Uint8Array; format: 'hex' | 'base64' } => {
  const text = String(value || '').trim();
  if (!text) throw new Error('密文不能为空');
  const compact = text.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  if (compact.length % 2 === 0 && /^[0-9a-f]+$/i.test(compact) && compact.length >= 2) {
    return { bytes: hexToBytes(compact), format: 'hex' };
  }
  try {
    return { bytes: base64ToBytes(text), format: 'base64' };
  } catch {
    throw new Error('密文既不是合法 hex 也不是合法 base64');
  }
};

// ---------- RC4（自写，RSA Labs 规范） ----------

export const rc4Crypt = (key: Uint8Array, data: Uint8Array): Uint8Array => {
  if (key.length === 0) throw new Error('RC4 密钥不能为空');
  const s = Array.from({ length: 256 }, (_, i) => i);
  let j = 0;
  for (let i = 0; i < 256; i += 1) {
    j = (j + s[i] + key[i % key.length]) & 0xff;
    [s[i], s[j]] = [s[j], s[i]];
  }
  const out = new Uint8Array(data.length);
  let i = 0;
  j = 0;
  for (let index = 0; index < data.length; index += 1) {
    i = (i + 1) & 0xff;
    j = (j + s[i]) & 0xff;
    [s[i], s[j]] = [s[j], s[i]];
    out[index] = data[index] ^ s[(s[i] + s[j]) & 0xff];
  }
  return out;
};

// ---------- XOR（重复密钥） ----------

export const xorRepeatCrypt = (key: Uint8Array, data: Uint8Array): Uint8Array => {
  if (key.length === 0) throw new Error('XOR 密钥不能为空');
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 1) out[i] = data[i] ^ key[i % key.length];
  return out;
};

// ---------- AES-OFB（SP 800-38A：由单块 ECB 原语自造） ----------

const aesOfbDecrypt = (key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array => {
  if (iv.length !== 16) throw new Error('AES-OFB IV 必须 16 字节');
  const blockCipher = ecb(key, { disablePadding: true });
  const out = new Uint8Array(data.length);
  let stream = iv.slice();
  for (let offset = 0; offset < data.length; offset += 16) {
    stream = blockCipher.encrypt(stream);
    const take = Math.min(16, data.length - offset);
    for (let i = 0; i < take; i += 1) out[offset + i] = data[offset + i] ^ stream[i];
  }
  return out;
};

// ---------- 打分 ----------

export interface ScoreDetail {
  printableRatio: number;
  entropy: number;
  replacementRatio: number;
  cribHits: string[];
  score: number;
}

export const scorePlaintextBytes = (bytes: Uint8Array, cribs: string[]): ScoreDetail => {
  if (bytes.length === 0) {
    return { printableRatio: 0, entropy: 0, replacementRatio: 0, cribHits: [], score: 0 };
  }
  let printable = 0;
  const freq = new Map<number, number>();
  for (const byte of bytes) {
    if ((byte >= 0x20 && byte <= 0x7e) || byte === 0x0a || byte === 0x0d || byte === 0x09 || byte >= 0x80) printable += 1;
    freq.set(byte, (freq.get(byte) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / bytes.length;
    entropy -= p * Math.log2(p);
  }
  const printableRatio = printable / bytes.length;
  const text = utf8Decoder.decode(bytes);
  let replacement = 0;
  for (const char of text) {
    if (char === '\uFFFD') replacement += 1;
  }
  const replacementRatio = text.length ? replacement / text.length : 0;
  const lowerText = text.toLowerCase();
  const cribHits = cribs.filter(crib => crib.length > 0 && lowerText.includes(crib.toLowerCase()));
  let score = printableRatio - entropy / 16 + cribHits.length * 0.5;
  if (replacementRatio > 0.1) score = 0;
  return { printableRatio, entropy, replacementRatio, cribHits, score };
};

// ---------- 组合枚举 ----------

export type TryAllAlgorithm = 'aes' | 'des' | '3des' | 'rc4' | 'xor';
export type KeyEncoding = 'utf8' | 'hex' | 'base64' | 'md5';
export type IvEncoding = 'utf8' | 'hex' | 'base64';
/** 流式算法（RC4/XOR）只有一种形态；分组算法支持五种模式 */
export type TryAllMode = 'ECB' | 'CBC' | 'CFB' | 'OFB' | 'CTR' | 'stream';

export interface TryAllOptions {
  algorithms?: TryAllAlgorithm[];
  modes?: TryAllMode[];
  keyEncodings?: KeyEncoding[];
  ivEncodings?: IvEncoding[];
  /** 命中即加分的关键词（如 flag{、CTF），大小写不敏感 */
  cribs?: string[];
  /** 时间预算毫秒，默认 5000，超限抛错 */
  timeBudgetMs?: number;
  /** 组合数上限，默认 4096，超出抛错 */
  maxCombos?: number;
  /** 输出结果条数上限，默认 20 */
  maxResults?: number;
}

export interface TryAllHit {
  algorithm: TryAllAlgorithm | '3des';
  mode: TryAllMode;
  keyEncoding: KeyEncoding;
  /** 无 IV 模式为 'none'；未提供 IV 的分组模式用全零 IV，记 'zeros' */
  ivEncoding: string;
  keyBits: number;
  score: number;
  printableRatio: number;
  entropy: number;
  cribHits: string[];
  plaintext: string;
  plaintextHex: string;
}

export interface TryAllReport {
  hits: TryAllHit[];
  combosEstimated: number;
  combosTried: number;
  elapsedMs: number;
  notes: string[];
}

const MODES_BY_ALGORITHM: Record<TryAllAlgorithm, TryAllMode[]> = {
  aes: ['ECB', 'CBC', 'CFB', 'OFB', 'CTR'],
  des: ['ECB', 'CBC', 'CFB', 'OFB', 'CTR'],
  '3des': ['ECB', 'CBC', 'CFB', 'OFB', 'CTR'],
  rc4: ['stream'],
  xor: ['stream'],
};

const KEY_LENGTHS: Record<TryAllAlgorithm, number[]> = {
  aes: [16, 24, 32],
  des: [8],
  '3des': [16, 24],
  rc4: rangeClosed(5, 64),
  xor: rangeClosed(1, 64),
};

function rangeClosed(from: number, to: number): number[] {
  return Array.from({ length: to - from + 1 }, (_, i) => from + i);
}

const IV_SIZES: Partial<Record<TryAllAlgorithm, number>> = { aes: 16, des: 8, '3des': 8 };

interface KeyCandidate {
  encoding: KeyEncoding;
  bytes: Uint8Array;
}

const buildKeyCandidates = (keyText: string, encodings: KeyEncoding[]): KeyCandidate[] => {
  const candidates: KeyCandidate[] = [];
  const push = (encoding: KeyEncoding, bytes: Uint8Array | null) => {
    if (bytes && bytes.length > 0 && !candidates.some(c => c.encoding === encoding && c.bytes.length === bytes.length)) {
      candidates.push({ encoding, bytes });
    }
  };
  for (const encoding of encodings) {
    try {
      if (encoding === 'utf8') push('utf8', utf8Encoder.encode(keyText));
      else if (encoding === 'hex') push('hex', hexToBytes(keyText));
      else if (encoding === 'base64') push('base64', base64ToBytes(keyText));
      else if (encoding === 'md5') push('md5', md5(utf8Encoder.encode(keyText)));
    } catch {
      // 该编码对给定密钥不合法（如 hex 非偶数长度），跳过
    }
  }
  return candidates;
};

interface IvCandidate {
  encoding: string;
  bytes: Uint8Array | null;
}

const buildIvCandidates = (ivText: string, encodings: IvEncoding[], size: number): IvCandidate[] => {
  const text = String(ivText || '').trim();
  if (!text) return [{ encoding: 'zeros', bytes: new Uint8Array(size) }];
  const candidates: IvCandidate[] = [];
  const tryPush = (encoding: IvEncoding, bytes: Uint8Array) => {
    if (bytes.length === size && !candidates.some(c => c.bytes?.every((b, i) => b === bytes[i]))) {
      candidates.push({ encoding, bytes });
    }
  };
  for (const encoding of encodings) {
    try {
      if (encoding === 'utf8') tryPush('utf8', utf8Encoder.encode(text));
      else if (encoding === 'hex') tryPush('hex', hexToBytes(text));
      else if (encoding === 'base64') tryPush('base64', base64ToBytes(text));
    } catch {
      // 长度/格式不符的编码跳过
    }
  }
  return candidates;
};

const loadCryptoJs = async (): Promise<typeof import('crypto-js')> => (await import('crypto-js')).default;

/**
 * 枚举 {算法}×{模式}×{key 编码}×{IV 编码} 组合逐个试解。
 * - 无 IV 模式（ECB/stream）跳过 IV；提供 IV 编码时只有长度精确匹配的候选参与。
 * - 未提供 IV 的 IV 模式自动使用全零 IV（CTF 常见约定）。
 * - 护栏：组合数超过 maxCombos 或耗时超过 timeBudgetMs 立即抛错。
 */
export const tryAllCryptoDecryptions = async (
  cipherInput: string,
  keyText: string,
  ivText = '',
  options: TryAllOptions = {},
): Promise<TryAllReport> => {
  const startedAt = Date.now();
  if (!String(keyText || '').trim()) throw new Error('密钥不能为空');
  const { bytes: cipherBytes } = parseCipherBytes(cipherInput);
  const algorithms: TryAllAlgorithm[] = options.algorithms && options.algorithms.length ? options.algorithms : ['aes', 'des', '3des', 'rc4', 'xor'];
  const keyEncodings: KeyEncoding[] = options.keyEncodings && options.keyEncodings.length ? options.keyEncodings : ['utf8', 'hex', 'base64', 'md5'];
  const ivEncodings: IvEncoding[] = options.ivEncodings && options.ivEncodings.length ? options.ivEncodings : ['utf8', 'hex', 'base64'];
  const cribs = options.cribs || [];
  const timeBudgetMs = options.timeBudgetMs ?? 5000;
  const maxCombos = options.maxCombos ?? 4096;
  const maxResults = options.maxResults ?? 20;
  if (!keyEncodings.length) throw new Error('keyEncodings 不能为空');

  // 组合数预估与护栏
  const keyCandidates = buildKeyCandidates(String(keyText), keyEncodings);
  if (!keyCandidates.length) throw new Error('密钥在给定的编码（utf8/hex/base64/md5）下都无法解析出非空字节');
  let combosEstimated = 0;
  for (const algorithm of algorithms) {
    const modes = (options.modes && options.modes.length ? options.modes : MODES_BY_ALGORITHM[algorithm])
      .filter(mode => MODES_BY_ALGORITHM[algorithm].includes(mode));
    const ivSizes = IV_SIZES[algorithm];
    const ivVariants = ivSizes
      ? buildIvCandidates(String(ivText || ''), ivEncodings, ivSizes).length
      : 1;
    for (const mode of modes) {
      const needsIv = ivSizes != null && mode !== 'ECB';
      const ivCount = needsIv ? ivVariants : 1;
      for (const key of keyCandidates) {
        if (!KEY_LENGTHS[algorithm].includes(key.bytes.length)) continue;
        combosEstimated += ivCount;
      }
    }
  }
  if (combosEstimated === 0) throw new Error('没有可尝试的组合：密钥长度与所选算法不匹配（AES 16/24/32 字节，DES 8 字节，3DES 16/24 字节）');
  if (combosEstimated > maxCombos) {
    throw new Error(`组合数 ${combosEstimated} 超过上限 ${maxCombos}：请缩小 algorithms/keyEncodings/modes 或调高 maxCombos`);
  }

  const CryptoJS = await loadCryptoJs();
  const hits: TryAllHit[] = [];
  const seenTriples = new Set<string>();
  let combosTried = 0;
  const notes: string[] = [];

  const recordHit = (hit: TryAllHit) => {
    const dedupKey = `${hit.algorithm}|${hit.mode}|${hit.keyEncoding}|${hit.ivEncoding}`;
    if (seenTriples.has(dedupKey)) return;
    seenTriples.add(dedupKey);
    hits.push(hit);
  };

  const timeUp = () => Date.now() - startedAt > timeBudgetMs;

  for (const algorithm of algorithms) {
    if (timeUp()) break;
    const modes = (options.modes && options.modes.length ? options.modes : MODES_BY_ALGORITHM[algorithm])
      .filter(mode => MODES_BY_ALGORITHM[algorithm].includes(mode));
    const ivSize = IV_SIZES[algorithm];
    for (const mode of modes) {
      if (timeUp()) break;
      const needsIv = ivSize != null && mode !== 'ECB';
      const ivCandidates: IvCandidate[] = needsIv
        ? buildIvCandidates(String(ivText || ''), ivEncodings, ivSize as number)
        : [{ encoding: 'none', bytes: null }];
      for (const key of keyCandidates) {
        if (!KEY_LENGTHS[algorithm].includes(key.bytes.length)) continue;
        for (const iv of ivCandidates) {
          if (timeUp()) break;
          combosTried += 1;
          let plainBytes: Uint8Array | null = null;
          try {
            if (algorithm === 'rc4') {
              plainBytes = rc4Crypt(key.bytes, cipherBytes);
            } else if (algorithm === 'xor') {
              plainBytes = xorRepeatCrypt(key.bytes, cipherBytes);
            } else if (algorithm === 'aes') {
              plainBytes = decryptAesNoble(mode, key.bytes, iv.bytes, cipherBytes);
            } else {
              plainBytes = decryptDesCryptoJs(CryptoJS, algorithm === 'des' ? CryptoJS.DES : CryptoJS.TripleDES, mode, key.bytes, iv.bytes, cipherBytes);
            }
          } catch {
            continue; // padding/长度不合法：该组合排除
          }
          if (!plainBytes) continue;
          const detail = scorePlaintextBytes(plainBytes, cribs);
          recordHit({
            algorithm,
            mode,
            keyEncoding: key.encoding,
            ivEncoding: iv.encoding,
            keyBits: key.bytes.length * 8,
            score: detail.score,
            printableRatio: detail.printableRatio,
            entropy: detail.entropy,
            cribHits: detail.cribHits,
            plaintext: utf8Decoder.decode(plainBytes),
            plaintextHex: bytesToHex(plainBytes),
          });
        }
      }
    }
  }
  if (timeUp()) {
    throw new Error(`时间预算 ${timeBudgetMs}ms 已耗尽：已尝试 ${combosTried}/${combosEstimated} 组合，请缩小范围或调高 timeBudgetMs`);
  }
  hits.sort((a, b) => b.score - a.score);
  return {
    hits: hits.slice(0, maxResults),
    combosEstimated,
    combosTried,
    elapsedMs: Date.now() - startedAt,
    notes,
  };
};

const decryptAesNoble = (mode: TryAllMode, key: Uint8Array, iv: Uint8Array | null, data: Uint8Array): Uint8Array => {
  switch (mode) {
    case 'ECB':
      // 先按 PKCS#7 严格解；密文无填充（如 NIST SP 800-38A 裸向量）时回退不剥填充
      try {
        return ecb(key).decrypt(data);
      } catch {
        return ecb(key, { disablePadding: true }).decrypt(data);
      }
    case 'CBC':
      try {
        return cbc(key, iv as Uint8Array).decrypt(data);
      } catch {
        return cbc(key, iv as Uint8Array, { disablePadding: true }).decrypt(data);
      }
    case 'CFB':
      return cfb(key, iv as Uint8Array).decrypt(data);
    case 'CTR':
      return ctr(key, iv as Uint8Array).decrypt(data);
    case 'OFB':
      return aesOfbDecrypt(key, iv as Uint8Array, data);
    default:
      throw new Error(`AES 不支持模式 ${mode}`);
  }
};

const decryptDesCryptoJs = (
  CryptoJS: Awaited<ReturnType<typeof loadCryptoJs>>,
  helper: typeof CryptoJS.DES,
  mode: TryAllMode,
  key: Uint8Array,
  iv: Uint8Array | null,
  data: Uint8Array,
): Uint8Array => {
  if (mode === 'stream') throw new Error('DES 家族不支持 stream 形态');
  const keyHex = bytesToHex(key);
  const config: Record<string, unknown> = mode === 'ECB'
    ? { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }
    : {
      mode: modeMapOf(CryptoJS)[mode],
      // CFB/OFB/CTR 为流式形态，不能盲目剥 PKCS#7 填充
      padding: mode === 'CBC' ? CryptoJS.pad.Pkcs7 : CryptoJS.pad.NoPadding,
      iv: CryptoJS.enc.Hex.parse(bytesToHex(iv as Uint8Array)),
    };
  const params = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Hex.parse(bytesToHex(data)) });
  const decrypted = helper.decrypt(params, CryptoJS.enc.Hex.parse(keyHex), config);
  const plainHex = decrypted.toString(CryptoJS.enc.Hex);
  return hexToBytes(plainHex);
};

const modeMapOf = (CryptoJS: Awaited<ReturnType<typeof loadCryptoJs>>) => ({
  ECB: CryptoJS.mode.ECB,
  CBC: CryptoJS.mode.CBC,
  CFB: CryptoJS.mode.CFB,
  OFB: CryptoJS.mode.OFB,
  CTR: CryptoJS.mode.CTR,
});

/** 文本入口：cipher/key/iv/cribs 字段（key 也可由参数传入），输出 JSON 报告。 */
export const cryptoTryAllSolve = async (value: string, secret = '', options: TryAllOptions = {}): Promise<string> => {
  const text = String(value || '');
  const field = (label: string): string | null => {
    const match = text.match(new RegExp(`(?:^|[\\n;,\\s])${label}\\s*[:=]\\s*([^\\n;]+)`, 'i'));
    return match ? match[1].trim() : null;
  };
  const cipherField = field('cipher') || field('ct') || field('ciphertext');
  if (!cipherField) {
    // 整段文本视为密文（hex/base64），key 走 secret 参数
    if (!secret.trim()) throw new Error('需要 key=<密钥> 字段或密钥参数');
    const cribsField = field('cribs');
    const ivField = field('iv');
    const report = await tryAllCryptoDecryptions(text, secret, ivField || '', {
      ...options,
      cribs: cribsField ? cribsField.split(',').map(item => item.trim()).filter(Boolean) : options.cribs,
    });
    return JSON.stringify(report, null, 2);
  }
  const keyField = field('key') || field('password') || field('passphrase') || secret;
  if (!keyField.trim()) throw new Error('需要 key=<密钥> 字段或密钥参数');
  const ivField = field('iv');
  const cribsField = field('cribs');
  const algosField = field('algos');
  const report = await tryAllCryptoDecryptions(cipherField, keyField, ivField || '', {
    ...options,
    cribs: cribsField ? cribsField.split(',').map(item => item.trim()).filter(Boolean) : options.cribs,
    algorithms: algosField ? (algosField.split(',').map(item => item.trim().toLowerCase()) as TryAllAlgorithm[]) : options.algorithms,
  });
  return JSON.stringify(report, null, 2);
};
