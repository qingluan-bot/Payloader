// TLS 1.2 已知密钥流量解密引擎（流量分析域 B2-6）：NSS keylog + TCP 双向流字节 → 记录层校验 →
// 握手随机数提取 → PRF-SHA256 密钥推导 → AES-GCM 逐记录认证解密。
// 算法出处：
// - 记录层/密钥推导：RFC 5246 §6.2.3.3（AEAD cipher suite 的 nonce = write_IV ‖ explicit_nonce、
//   AAD = seq_num ‖ type ‖ version ‖ length）与 §6.3（key_block 布局：client_write_key、
//   server_write_key、client_write_IV、server_write_IV，AEAD 套件无 MAC 密钥）。
// - TLS PRF：RFC 5246 §5（P_<hash> 迭代 HMAC：A(0)=seed, A(i)=HMAC(secret,A(i-1)),
//   输出 = HMAC(secret, A(i)+seed) 级联）；NSS keylog 格式：
//   "CLIENT_RANDOM <64 hex client_random> <96 hex master_secret>"（Wireshark ssl.log 口径）。
// - 对拍锚点：本机 Node/openssl(≥3.5) SSLKEYLOGFILE 真握手样本（tests/tls-decrypt.test.mjs）
//   与 openssl kdf TLS1-PRF 命令输出交叉验证。
// 只支持 TLS 1.2 + AES-GCM(SHA-256 PRF)；TLS 1.3（HKDF 每记录派生）、CBC、ChaCha20、
// SHA-384 PRF 套件显式拒绝并说明原因，绝不静默输出伪造明文。
// 输入形态：接受"TCP 双向流字节 + keylog 文本"这一最小输入（pcap 层重组由 pcap/analyze.ts
// 的 TcpStream 提供，UI 已把流字节直接喂入），见 decryptTls12Stream。
import { gcm } from '@noble/ciphers/aes.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

// 防御上限：单方向流解析记录数 / 单记录明文上限（防巨型流吃内存）。
export const MAX_TLS_RECORDS = 4096;
const MAX_RECORD_WIRE = 16640; // RFC 5246 上限 2^14+2048，超过即判损坏
const MAX_PLAINTEXT_PER_RECORD = 64 * 1024;

export interface TlsDecryptedRecord {
  direction: 'c2s' | 's2c';
  // 方向内记录序号（从 0 计）。
  index: number;
  // 记录层绝对偏移（方向流内）。
  offset: number;
  type: number;
  typeName: string;
  version: string;
  length: number;
  status: 'decrypted' | 'auth-failed' | 'skipped' | 'handshake';
  plaintext: Uint8Array | null;
  // 明文 latin1 预览（可打印段）。
  preview: string | null;
  note?: string;
}

export interface TlsKeyMaterial {
  clientWriteKey: string;
  serverWriteKey: string;
  clientWriteIv: string;
  serverWriteIv: string;
}

export interface TlsDecryptResult {
  ok: boolean;
  clientRandom: string | null;
  serverRandom: string | null;
  cipherSuite: string | null;
  // keylog 中是否命中 client_random。
  keylogMatched: boolean;
  masterSecret: string | null;
  keys: TlsKeyMaterial | null;
  records: TlsDecryptedRecord[];
  // 解密成功记录数。
  decryptedCount: number;
  // 显式失败原因（错 keylog / 不支持的套件等，永远不静默）。
  failures: string[];
  notes: string[];
}

export const TLS_RECORD_TYPE_NAMES: Record<number, string> = {
  20: 'ChangeCipherSpec',
  21: 'Alert',
  22: 'Handshake',
  23: 'ApplicationData',
};

const toHex = (bytes: Uint8Array): string => {
  let out = '';
  for (let index = 0; index < bytes.length; index += 1) out += bytes[index].toString(16).padStart(2, '0');
  return out;
};

const concatBytes = (parts: Uint8Array[]): Uint8Array => {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

// RFC 5246 §5 P_hash：迭代 HMAC 展开任意长度密钥材料。
export const prfSha256 = (secret: Uint8Array, label: string, seed: Uint8Array, length: number): Uint8Array => {
  const labelBytes = new TextEncoder().encode(label);
  const aSeed = concatBytes([labelBytes, seed]);
  let a = hmac(sha256, secret, aSeed);
  const out = new Uint8Array(length);
  let filled = 0;
  while (filled < length) {
    const chunk = hmac(sha256, secret, concatBytes([a, aSeed]));
    const take = Math.min(chunk.length, length - filled);
    out.set(chunk.subarray(0, take), filled);
    filled += take;
    a = hmac(sha256, secret, a);
  }
  return out;
};

// NSS keylog 解析：返回 client_random hex（小写）→ master_secret hex。
// 只认 CLIENT_RANDOM 行（TLS 1.2 口径）；其余行（V2/V3 客户端随机行、TLS1.3 的
// CLIENT_HANDSHAKE_TRAFFIC_SECRET 等）忽略并计数。
export const parseKeylog = (text: string): { map: Map<string, string>; skippedLines: number } => {
  const map = new Map<string, string>();
  let skippedLines = 0;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#')) continue;
    const parts = line.split(/\s+/);
    if (parts.length !== 3 || parts[0] !== 'CLIENT_RANDOM' || !/^[0-9a-fA-F]{64}$/.test(parts[1]) || !/^[0-9a-fA-F]{96}$/.test(parts[2])) {
      skippedLines += 1;
      continue;
    }
    map.set(parts[1].toLowerCase(), parts[2].toLowerCase());
  }
  return { map, skippedLines };
};

// TLS 密码套件分类：只放行 AES-GCM + SHA-256 PRF 的 TLS 1.2 套件，其余给出拒绝理由。
// 套件号出处：IANA TLS Cipher Suite Registry。
export interface SuiteInfo {
  name: string;
  cipher: 'aes128gcm' | 'aes256gcm-sha384' | 'chacha' | 'cbc' | 'tls13' | 'unknown';
  keyLen: number;
}

export const classifySuite = (suite: number): SuiteInfo => {
  const hex = suite.toString(16).padStart(4, '0');
  const known: Record<number, SuiteInfo> = {
    0x009c: { name: 'TLS_RSA_WITH_AES_128_GCM_SHA256', cipher: 'aes128gcm', keyLen: 16 },
    0x009e: { name: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', cipher: 'aes128gcm', keyLen: 16 },
    0xc02b: { name: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', cipher: 'aes128gcm', keyLen: 16 },
    0xc02f: { name: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', cipher: 'aes128gcm', keyLen: 16 },
    0x009d: { name: 'TLS_RSA_WITH_AES_256_GCM_SHA384', cipher: 'aes256gcm-sha384', keyLen: 32 },
    0x009f: { name: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', cipher: 'aes256gcm-sha384', keyLen: 32 },
    0xc02c: { name: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', cipher: 'aes256gcm-sha384', keyLen: 32 },
    0xc030: { name: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', cipher: 'aes256gcm-sha384', keyLen: 32 },
    0xcca8: { name: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', cipher: 'chacha', keyLen: 32 },
    0xcca9: { name: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', cipher: 'chacha', keyLen: 32 },
    0xcc13: { name: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (draft)', cipher: 'chacha', keyLen: 32 },
    0xcc14: { name: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (draft)', cipher: 'chacha', keyLen: 32 },
    0xcc15: { name: 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (draft)', cipher: 'chacha', keyLen: 32 },
  };
  if (known[suite]) return known[suite];
  if ((suite & 0xff00) === 0x1300) {
    return { name: `TLS 1.3 cipher suite 0x${hex}`, cipher: 'tls13', keyLen: 0 };
  }
  // 未收录套件按族启发式归类（CBC 系 0x00xx 与 ECDHE CBC 系 0xC0xx 占绝大多数）。
  return { name: `cipher suite 0x${hex}`, cipher: 'unknown', keyLen: 0 };
};

export interface HandshakePeek {
  clientRandom: Uint8Array | null;
  serverRandom: Uint8Array | null;
  cipherSuite: number | null;
  tls13Detected: boolean;
  // 是否协商了 extended master secret（RFC 7627，扩展 type 23）。
  extendedMasterSecret: boolean;
  // EMS session_hash 所需的握手转录（CH 起、CKE 止，见下）。
  transcriptUpToClientKeyExchange: Uint8Array | null;
}

// 从两个方向的明文握手记录序列提取 ClientHello/ServerHello 随机数与所选套件。
// 握手消息可能跨记录拼接：把全部 type=22 记录体顺序拼接后再按 4 字节握手头游走。
// 只取各方向 ChangeCipherSpec 之前的握手记录——CCS 之后的 type=22 记录体是加密的
// Finished 密文，混入拼接流会破坏游走（真实握手样本验证发现的坑）。
const EXT_EMS = 23;
const EXT_SUPPORTED_VERSIONS = 43;
const walkHello = (hs: Uint8Array, wantMsg: number, peek: HandshakePeek): void => {
  let pos = 0;
  let guard = 0;
  while (pos + 4 <= hs.length && guard < 64) {
    guard += 1;
    const msgType = hs[pos];
    const len = (hs[pos + 1] << 16) | (hs[pos + 2] << 8) | hs[pos + 3];
    const bodyStart = pos + 4;
    const bodyEnd = Math.min(bodyStart + len, hs.length); // 越出流尾按实际截断
    if (msgType === 1 && bodyEnd - bodyStart >= 34 && !peek.clientRandom) {
      // ClientHello: version(2) random(32)
      peek.clientRandom = hs.slice(bodyStart + 2, bodyStart + 34);
    } else if (msgType === 2 && bodyEnd - bodyStart >= 35 && !peek.serverRandom) {
      // ServerHello: version(2) random(32) session_id_len(1)...
      peek.serverRandom = hs.slice(bodyStart + 2, bodyStart + 34);
      const sidLen = hs[bodyStart + 34];
      const suitePos = bodyStart + 35 + sidLen;
      if (suitePos + 2 <= bodyEnd) peek.cipherSuite = (hs[suitePos] << 8) | hs[suitePos + 1];
      const compLen = hs[suitePos + 2];
      let extPos = suitePos + 3 + compLen;
      if (suitePos + 2 < bodyEnd && extPos + 2 <= bodyEnd) {
        const extTotal = (hs[extPos] << 8) | hs[extPos + 1];
        extPos += 2;
        const extEnd = Math.min(extPos + extTotal, bodyEnd);
        while (extPos + 4 <= extEnd) {
          const extType = (hs[extPos] << 8) | hs[extPos + 1];
          const extLen = (hs[extPos + 2] << 8) | hs[extPos + 3];
          if (extType === EXT_SUPPORTED_VERSIONS) peek.tls13Detected = true;
          if (extType === EXT_EMS) peek.extendedMasterSecret = true;
          extPos += 4 + extLen;
        }
      }
    }
    if (msgType === wantMsg && wantMsg === 2) return; // ServerHello 之后的扩展不再关心
    pos = bodyStart + len;
  }
};

const extractHandshake = (
  clientPlain: Array<{ type: number; body: Uint8Array }>,
  serverPlain: Array<{ type: number; body: Uint8Array }>,
): HandshakePeek => {
  const peek: HandshakePeek = {
    clientRandom: null,
    serverRandom: null,
    cipherSuite: null,
    tls13Detected: false,
    extendedMasterSecret: false,
    transcriptUpToClientKeyExchange: null,
  };
  const plainUntilCcs = (records: Array<{ type: number; body: Uint8Array }>): Uint8Array[] => {
    const parts: Uint8Array[] = [];
    for (const record of records) {
      if (record.type === 20) break; // CCS 之后进入加密区
      if (record.type === 22 && record.body.length >= 4) parts.push(record.body);
    }
    return parts;
  };
  const clientParts = plainUntilCcs(clientPlain);
  const serverParts = plainUntilCcs(serverPlain);
  // ClientHello 只可能来自客户端明文握手，ServerHello 只可能来自服务端明文握手；
  // 各自独立游走（一边被截断不影响另一边提取）。
  const clientHs = concatBytes(clientParts);
  const serverHs = concatBytes(serverParts);
  walkHello(clientHs, 1, peek);
  walkHello(serverHs, 2, peek);
  // EMS session_hash 转录：TLS 1.2 全握手时序为 CH(c2s) → SH..SHD(s2c) → CKE(c2s)，
  // 截取 CH 起到 CKE（含）为止；CKE 是 CCS 前 c2s 握手中的第二条消息（常见拓扑），
  // 未出现 CKE（流被截断）时不做 EMS 派生并给出说明。
  if (peek.extendedMasterSecret) {
    const ckeEnd = (() => {
      let pos = 0;
      let guard = 0;
      while (pos + 4 <= clientHs.length && guard < 64) {
        guard += 1;
        const len = (clientHs[pos + 1] << 16) | (clientHs[pos + 2] << 8) | clientHs[pos + 3];
        const end = pos + 4 + len;
        if (clientHs[pos] === 16) return Math.min(end, clientHs.length); // ClientKeyExchange
        pos = end;
      }
      return -1;
    })();
    if (ckeEnd > 0) {
      // 严格时序重排：CH || s2c 明文握手 || CH 之后的 c2s 明文握手到 CKE（含）。
      // c2s 明文握手只有 CH+CKE（无客户端证书）时 = CH || s2c || CKE，即 EMS 规范形态。
      const chLen = clientHs.length >= 4 ? 4 + ((clientHs[1] << 16) | (clientHs[2] << 8) | clientHs[3]) : 0;
      peek.transcriptUpToClientKeyExchange = concatBytes([
        clientHs.slice(0, Math.min(chLen, ckeEnd)),
        serverHs,
        clientHs.slice(Math.min(chLen, ckeEnd), ckeEnd),
      ]);
    }
  }
  return peek;
};

// 单方向记录切带：校验 type(20-23)/version(0x0300-0x0304)，非法即停在该处并登记。
const sliceRecords = (
  stream: Uint8Array,
  direction: 'c2s' | 's2c',
  failures: string[],
  notes: string[],
): Array<{ type: number; version: number; body: Uint8Array; offset: number }> => {
  const records: Array<{ type: number; version: number; body: Uint8Array; offset: number }> = [];
  let pos = 0;
  while (pos + 5 <= stream.length && records.length < MAX_TLS_RECORDS) {
    const type = stream[pos];
    const version = (stream[pos + 1] << 8) | stream[pos + 2];
    const length = (stream[pos + 3] << 8) | stream[pos + 4];
    if (type < 20 || type > 23) {
      failures.push(`${direction === 'c2s' ? 'C→S' : 'S→C'} 流偏移 ${pos}：记录类型 ${type} 不在 20-23 范围，停止解析（可能不是 TLS 记录流或流已错位）`);
      break;
    }
    if (stream[pos + 1] !== 3 || stream[pos + 2] > 4) {
      failures.push(`${direction === 'c2s' ? 'C→S' : 'S→C'} 流偏移 ${pos}：记录版本 0x${version.toString(16).padStart(4, '0')} 非 SSLv3-TLS1.2 族，停止解析`);
      break;
    }
    if (length > MAX_RECORD_WIRE || pos + 5 + length > stream.length) {
      failures.push(`${direction === 'c2s' ? 'C→S' : 'S→C'} 流偏移 ${pos}：记录长度 ${length} 非法或越过流尾，停止解析`);
      break;
    }
    records.push({ type, version, body: stream.slice(pos + 5, pos + 5 + length), offset: pos });
    pos += 5 + length;
  }
  if (pos < stream.length && records.length < MAX_TLS_RECORDS && pos + 5 > stream.length) {
    notes.push(`${direction === 'c2s' ? 'C→S' : 'S→C'} 流尾部残留 ${stream.length - pos} 字节不足一条完整记录，已忽略`);
  }
  return records;
};

// latin1 可打印预览（控制字符转义，供 UI 直接展示）。
const previewText = (bytes: Uint8Array, maxChars: number): string => {
  let out = '';
  for (let index = 0; index < bytes.length && out.length < maxChars; index += 1) {
    const value = bytes[index];
    out += value === 0x0a || value === 0x0d || (value >= 0x20 && value < 0x7f) ? String.fromCharCode(value) : '.';
  }
  return out;
};

export interface TlsDecryptStreamOptions {
  // 单方向最大记录数（防超大流）。默认 4096。
  maxRecords?: number;
  // 单记录解密明文上限。默认 64KB。
  maxPlaintextPerRecord?: number;
}

// 主入口：TLS 1.2 已知密钥解密。c2s/s2c 为 TCP 流字节（各方向已重组拼接，
// 源自 pcap/analyze.ts 的 TcpStream.bufferAtoB / bufferBtoA 即可），keylog 为
// NSS ssl.log 文本（CLIENT_RANDOM 行）。
export const decryptTls12Stream = (
  c2s: Uint8Array,
  s2c: Uint8Array,
  keylog: string,
  options?: TlsDecryptStreamOptions,
): TlsDecryptResult => {
  const maxRecords = options?.maxRecords ?? MAX_TLS_RECORDS;
  const maxPlain = options?.maxPlaintextPerRecord ?? MAX_PLAINTEXT_PER_RECORD;
  const failures: string[] = [];
  const notes: string[] = [];
  const records: TlsDecryptedRecord[] = [];
  const base: TlsDecryptResult = {
    ok: false,
    clientRandom: null,
    serverRandom: null,
    cipherSuite: null,
    keylogMatched: false,
    masterSecret: null,
    keys: null,
    records,
    decryptedCount: 0,
    failures,
    notes,
  };

  const { map: keylogMap, skippedLines } = parseKeylog(keylog);
  if (skippedLines > 0) notes.push(`keylog 忽略了 ${skippedLines} 行非 CLIENT_RANDOM 行（TLS 1.2 解密只用 CLIENT_RANDOM）`);
  if (keylogMap.size === 0) {
    failures.push('keylog 中没有有效的 CLIENT_RANDOM 行（需要 "CLIENT_RANDOM <64hex> <96hex>" 格式）');
    return base;
  }

  const c2sRecords = sliceRecords(c2s.slice(0, c2s.length), 'c2s', failures, notes);
  const s2cRecords = sliceRecords(s2c, 's2c', failures, notes);
  for (const side of [c2sRecords, s2cRecords]) {
    if (side.length >= maxRecords) notes.push(`单方向记录数达到上限 ${maxRecords}，后续记录未解析`);
  }

  // 握手随机数按方向独立提取（各方向只取 CCS 之前的明文握手记录）。
  const peek = extractHandshake(c2sRecords, s2cRecords);
  if (peek.tls13Detected) {
    failures.push('检测到 TLS 1.3 协商（ServerHello 携带 supported_versions 扩展）：TLS 1.3 使用 HKDF 按阶段派生流量密钥且记录层带内加密，key_block 方案不适用，本引擎显式拒绝');
    return base;
  }
  const clientRandom = peek.clientRandom;
  const serverRandom = peek.serverRandom;
  if (!clientRandom) {
    failures.push('未在 ClientHello 中找到 client_random（流必须从握手开始，且包含完整的 ClientHello 记录）');
    return base;
  }
  if (!serverRandom) {
    failures.push('未在 ServerHello 中找到 server_random（S→C 流必须包含完整的 ServerHello 记录）');
    return base;
  }
  base.clientRandom = toHex(clientRandom);
  base.serverRandom = toHex(serverRandom);

  const suiteValue = peek.cipherSuite;
  const suite = suiteValue === null ? null : classifySuite(suiteValue);
  base.cipherSuite = suite?.name ?? null;
  if (!suiteValue || !suite) {
    failures.push('未读到 ServerHello 所选 cipher suite，无法判断密钥算法');
    return base;
  }
  if (suite.cipher === 'tls13') {
    failures.push(`所选 ${suite.name} 属于 TLS 1.3 套件族：TLS 1.3 密钥调度完全不同（HKDF 派生、记录层早期数据加密），本引擎只支持 TLS 1.2，显式拒绝`);
    return base;
  }
  if (suite.cipher === 'aes256gcm-sha384') {
    failures.push(`所选 ${suite.name} 使用 SHA-384 PRF（key_block 由 PRF-SHA384 展开），本引擎只实现 PRF-SHA256 口径，显式拒绝`);
    return base;
  }
  if (suite.cipher === 'chacha') {
    failures.push(`所选 ${suite.name} 为 ChaCha20-Poly1305 流密码套件：本引擎只实现 AES-GCM 套件解密，显式拒绝`);
    return base;
  }
  if (suite.cipher !== 'aes128gcm') {
    failures.push(`所选 ${suite.name} 不是 AES-GCM 套件（CBC 等传统分组模式的记录体是纯密文 + 独立 MAC，与 AEAD 的 nonce/AAD 口径不同），显式拒绝`);
    return base;
  }

  const masterHex = keylogMap.get(base.clientRandom);
  if (!masterHex) {
    failures.push(`keylog 未命中该会话：没有 CLIENT_RANDOM ${base.clientRandom} 条目（keylog 与抓包不属于同一会话，或抓包被截断丢失了 ClientHello），拒绝解密`);
    return base;
  }
  base.keylogMatched = true;
  base.masterSecret = masterHex;
  const master = new Uint8Array(48);
  for (let index = 0; index < 96; index += 2) master[index / 2] = parseInt(masterHex.slice(index, index + 2), 16);

  // RFC 7627 extended master secret：协商了 EMS（OpenSSL 3.x 默认开启）时，实际派生用的
  // 主密钥 = PRF(keylog 主密钥, "extended master secret", session_hash)，session_hash 为
  // CH 起至 CKE 止的握手转录哈希。keylog 里的 CLIENT_RANDOM 是 EMS 之前的原始主密钥。
  let effectiveMaster: Uint8Array = master;
  if (peek.extendedMasterSecret) {
    if (peek.transcriptUpToClientKeyExchange) {
      const sessionHash = sha256(peek.transcriptUpToClientKeyExchange);
      effectiveMaster = prfSha256(master, 'extended master secret', sessionHash, 48);
      notes.push('会话协商了 extended master secret（RFC 7627）：已按 keylog 主密钥 + 握手转录哈希重算实际主密钥');
    } else {
      failures.push('会话协商了 extended master secret，但握手中未找到完整的 ClientKeyExchange（流可能被截断），无法计算 session_hash，拒绝解密');
      return base;
    }
  }

  // RFC 5246 §6.3：key_block = PRF(master, "key expansion", server_random ‖ client_random)
  // AEAD 套件只需要 client_write_key(16) + server_write_key(16) + client_write_IV(4) + server_write_IV(4)。
  const keyBlock = prfSha256(effectiveMaster, 'key expansion', concatBytes([serverRandom, clientRandom]), 40);
  const c2sKey = keyBlock.slice(0, 16);
  const s2cKey = keyBlock.slice(16, 32);
  const c2sIv = keyBlock.slice(32, 36);
  const s2cIv = keyBlock.slice(36, 40);
  base.keys = {
    clientWriteKey: toHex(c2sKey),
    serverWriteKey: toHex(s2cKey),
    clientWriteIv: toHex(c2sIv),
    serverWriteIv: toHex(s2cIv),
  };

  // 每方向独立 64bit 序号：连接状态激活（ChangeCipherSpec）时归零（RFC 5246 §6.1 "set to
  // zero whenever a connection state is made the active state"），逐记录 +1，供 §6.2.3.3 的
  // AAD/显式 nonce 使用。正向加密闭环测试发现的实现坑：不能按"流内记录序号"计数。
  const seqs: Record<'c2s' | 's2c', number> = { c2s: 0, s2c: 0 };
  const sideDefs: Array<{ direction: 'c2s' | 's2c'; records: typeof c2sRecords; key: Uint8Array; iv: Uint8Array }> = [
    { direction: 'c2s', records: c2sRecords, key: c2sKey, iv: c2sIv },
    { direction: 's2c', records: s2cRecords, key: s2cKey, iv: s2cIv },
  ];
  let sawChangeCipherSpec = false;
  for (const side of sideDefs) {
    for (const [index, record] of side.records.entries()) {
      if (index >= maxRecords) break;
      const seq = seqs[side.direction];
      seqs[side.direction] = record.type === 20 ? 0 : seq + 1;
      const typeName = TLS_RECORD_TYPE_NAMES[record.type] ?? `Type${record.type}`;
      if (record.type === 22) {
        records.push({ direction: side.direction, index, offset: record.offset, type: record.type, typeName, version: `0x${record.version.toString(16).padStart(4, '0')}`, length: record.body.length, status: 'handshake', plaintext: null, preview: null });
        continue;
      }
      if (record.type !== 23) {
        records.push({ direction: side.direction, index, offset: record.offset, type: record.type, typeName, version: `0x${record.version.toString(16).padStart(4, '0')}`, length: record.body.length, status: 'skipped', plaintext: null, preview: null, note: record.type === 20 ? 'ChangeCipherSpec：此后本方向记录切换为加密' : '非应用数据记录，不尝试解密' });
        if (record.type === 20) sawChangeCipherSpec = true;
        continue;
      }
      // 应用数据：nonce = write_IV(4) ‖ explicit_nonce(8，记录体前 8 字节)；体尾 16B 为 GCM tag。
      if (record.body.length < 8 + 16) {
        records.push({ direction: side.direction, index, offset: record.offset, type: record.type, typeName, version: `0x${record.version.toString(16).padStart(4, '0')}`, length: record.body.length, status: 'auth-failed', plaintext: null, preview: null, note: '记录体短于 explicit_nonce+tag，疑似截断' });
        failures.push(`${side.direction === 'c2s' ? 'C→S' : 'S→C'} 记录 #${index}：记录体 ${record.body.length}B 不足 explicit_nonce(8)+tag(16)`);
        continue;
      }
      const explicitNonce = record.body.slice(0, 8);
      const ciphertextWithTag = record.body.slice(8);
      const nonce = concatBytes([side.iv, explicitNonce]);
      const seqBytes = new Uint8Array(8);
      for (let shift = 0; shift < 8; shift += 1) seqBytes[7 - shift] = (seq >>> (8 * shift)) & 0xff;
      // RFC 5246 §6.2.3.3：AAD = seq_num‖type‖version‖TLSCompressed.length（= 明文长度，
      // 不含 explicit nonce 与 tag——正向加密闭环对拍发现的实现坑）。
      const aad = concatBytes([seqBytes, new Uint8Array([record.type]), new Uint8Array([(record.version >> 8) & 0xff, record.version & 0xff]), new Uint8Array([((ciphertextWithTag.length - 16) >> 8) & 0xff, (ciphertextWithTag.length - 16) & 0xff])]);
      try {
        const plain = gcm(side.key, nonce, aad).decrypt(ciphertextWithTag);
        const trimmed = plain.length > maxPlain ? plain.slice(0, maxPlain) : plain;
        if (plain.length > maxPlain) notes.push(`记录 #${index}（${side.direction}）明文 ${plain.length}B 超过单记录上限，截断展示前 ${maxPlain}B`);
        records.push({ direction: side.direction, index, offset: record.offset, type: record.type, typeName, version: `0x${record.version.toString(16).padStart(4, '0')}`, length: record.body.length, status: 'decrypted', plaintext: trimmed, preview: previewText(trimmed, 2048) });
        base.decryptedCount += 1;
      } catch {
        records.push({ direction: side.direction, index, offset: record.offset, type: record.type, typeName, version: `0x${record.version.toString(16).padStart(4, '0')}`, length: record.body.length, status: 'auth-failed', plaintext: null, preview: null, note: 'GCM 认证失败：密钥不匹配或序号/字节错位' });
        failures.push(`${side.direction === 'c2s' ? 'C→S' : 'S→C'} 记录 #${index}：GCM 认证失败（tag 校验不过），未输出任何明文`);
      }
    }
  }

  base.ok = base.decryptedCount > 0;
  if (sawChangeCipherSpec && base.decryptedCount === 0 && failures.length === 0) {
    failures.push('看到了 ChangeCipherSpec 但没有应用数据记录可解密（流中只有握手/控制记录）');
  }
  if (!base.ok && failures.length === 0) {
    failures.push('没有可解密的应用数据记录（流中只有握手/控制记录）');
  }
  return base;
};
