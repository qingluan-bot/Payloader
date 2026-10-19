// WPA2 四次握手校验与 CCMP 解密引擎（流量域 WiFi 解密）。纯函数、输入只读、零浏览器依赖。
// 算法出处与对拍锚点：
//  - PMK = PBKDF2-HMAC-SHA1(口令, SSID, 4096, 32B)（IEEE 802.11i-2004 §H.4 / RFC 2898）
//  - PTK = PRF-512-SHA1(PMK, "Pairwise key expansion", min(AA,SPA)||max(AA,SPA)||ANonce||SNonce)
//    截 48B（KCK16|KEK16|TK16，CCMP 布局）；PRF 迭代式同 §H.4（label||0x00||data||单字节计数）
//  - EAPOL-Key MIC = HMAC-SHA1(KCK, 完整 EAPOL 消息[81..96] 清零) 截 16B（hashcat 22000 同口径）
//  - CCMP 按 RFC 3610 CCM（M=8, L=2）：Nonce(13B)=Priority||A2||PN、AAD(22B)=屏蔽 Flags 后 FC+
//    三地址+SC 低 4bit（802.11-2012 §11.5.4）；先 CTR 解文再对明文 CBC-MAC
//  - 交叉对拍：pycryptodome MODE_CCM 独立加密样本 + scapy rdpcap 容器解析（tests/wpa-decrypt.test.mjs）
// 显式拒绝：WEP（无 ExtIV）、TKIP（描述符版本 1 / 字节形态）、WPA3/PMF（描述符版本 3、仅 SAE AKM）。

import { ctr, ecb } from '@noble/ciphers/aes.js';
import { hmac } from '@noble/hashes/hmac.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha1 } from '@noble/hashes/legacy.js';
import type { ParsedCapture } from './pcap/parser';

// 解密帧数红线：CTF 抓包场景足够大，同时防超大 pcap 拖死 UI。
export const MAX_DECRYPT_FRAMES = 5000;

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

const u16le = (bytes: Uint8Array, offset: number): number => bytes[offset] | (bytes[offset + 1] << 8);

const u16be = (bytes: Uint8Array, offset: number): number => (bytes[offset] << 8) | bytes[offset + 1];

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

export const macToText = (mac: Uint8Array): string =>
  Array.from(mac, byte => byte.toString(16).padStart(2, '0')).join(':');

const bytesEqualConstantTime = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) diff |= left[index] ^ right[index];
  return diff === 0;
};

const isAllZero = (bytes: Uint8Array): boolean => {
  for (let index = 0; index < bytes.length; index += 1) if (bytes[index] !== 0) return false;
  return true;
};

// ---- 802.11 帧头解析 ----

export interface Ieee80211Frame {
  frameIndex: number;
  valid: boolean;
  reason?: string;
  type: number; // 0=管理 1=控制 2=数据
  subtype: number;
  toDS: boolean;
  fromDS: boolean;
  protectedFrame: boolean;
  qos: boolean;
  qosTid: number; // QoS Control 低 4 位（非 QoS 帧 = 0）；CCMP nonce 的 Priority 字节
  headerLength: number;
  addr1: Uint8Array; // 接收方
  addr2: Uint8Array; // 发送方（CCMP 的 A2）
  addr3: Uint8Array;
  addr4: Uint8Array; // WDS 四地址时存在，否则空
  sequenceControl: number;
  body: Uint8Array; // 802.11 头（含 QoS/HT 扩展）之后的帧体
}

const invalidFrame = (frameIndex: number, reason: string): Ieee80211Frame => ({
  frameIndex, valid: false, reason, type: -1, subtype: -1, toDS: false, fromDS: false,
  protectedFrame: false, qos: false, qosTid: 0, headerLength: 0, addr1: new Uint8Array(0),
  addr2: new Uint8Array(0), addr3: new Uint8Array(0), addr4: new Uint8Array(0),
  sequenceControl: 0, body: new Uint8Array(0),
});

// radiotap(127) 头只用来跳过（present 位图不参与本引擎判定，头长度字段即全头长）；
// 裸 802.11(105) 从 0 开始。FC 位域：版本(0-1)/类型(2-3)/子类型(4-7)/ToDS(8)/FromDS(9)/
// MoreFrag(10)/Retry(11)/PwrMgmt(12)/MoreData(13)/Protected(14)/Order(15)。
export const parseIeee80211 = (frame: Uint8Array, frameIndex: number, isRadiotap: boolean): Ieee80211Frame => {
  let offset = 0;
  if (isRadiotap) {
    if (frame.length < 8) return invalidFrame(frameIndex, 'radiotap 头残缺');
    if (frame[0] !== 0) return invalidFrame(frameIndex, `radiotap 版本 ${frame[0]} 非法（应为 0）`);
    const radioLength = u16le(frame, 2);
    if (radioLength < 8 || radioLength > frame.length) return invalidFrame(frameIndex, `radiotap 头长度 ${radioLength} 越界`);
    offset = radioLength;
  }
  if (frame.length - offset < 24) return invalidFrame(frameIndex, '802.11 帧头残缺（不足 24 字节）');
  const fc = u16le(frame, offset);
  const protocolVersion = fc & 0x0003;
  if (protocolVersion !== 0) return invalidFrame(frameIndex, `802.11 协议版本 ${protocolVersion} 非法`);
  const type = (fc >> 2) & 0x03;
  const subtype = (fc >> 4) & 0x0f;
  const toDS = (fc & 0x0100) !== 0;
  const fromDS = (fc & 0x0200) !== 0;
  const protectedFrame = (fc & 0x4000) !== 0;
  const orderFlag = (fc & 0x8000) !== 0;
  const qos = type === 2 && (subtype & 0x08) !== 0;
  let headerLength = 24;
  if (toDS && fromDS) headerLength += 6; // addr4（WDS 四地址）
  if (qos) headerLength += 2; // QoS Control
  if (type === 2 && orderFlag) headerLength += 4; // HT Control
  if (frame.length - offset < headerLength) return invalidFrame(frameIndex, `帧长不足以容纳 ${headerLength} 字节头`);
  const base = offset;
  // QoS Control 位于固定头（含 addr4）之后、HT Control（order 位时）之前——偏移不能从
  // headerLength 尾部倒推，否则 QoS+HT 帧会读进 HT Control 的字节。
  const qosOffset = base + 24 + (toDS && fromDS ? 6 : 0);
  return {
    frameIndex,
    valid: true,
    type,
    subtype,
    toDS,
    fromDS,
    protectedFrame,
    qos,
    qosTid: qos ? u16le(frame, qosOffset) & 0x0f : 0,
    headerLength,
    addr1: frame.slice(base + 4, base + 10),
    addr2: frame.slice(base + 10, base + 16),
    addr3: frame.slice(base + 16, base + 22),
    addr4: toDS && fromDS ? frame.slice(base + 24, base + 30) : new Uint8Array(0),
    sequenceControl: u16le(frame, base + 22),
    body: frame.subarray(base + headerLength),
  };
};

// 数据帧方向 → 以太网地址映射（802.11-2012 Table 4-2）：
// ToDS=0/FromDS=1（AP→STA）：DA=addr1, SA=addr3；ToDS=1/FromDS=0（STA→AP）：DA=addr3, SA=addr2；
// ToDS=1/FromDS=1（WDS）：DA=addr3, SA=addr4；Ad-hoc（双 0）：DA=addr1, SA=addr2。
const ethernetAddresses = (frame: Ieee80211Frame): { dst: Uint8Array; src: Uint8Array } => {
  if (frame.toDS && frame.fromDS) return { dst: frame.addr3, src: frame.addr4 };
  if (frame.toDS) return { dst: frame.addr3, src: frame.addr2 };
  if (frame.fromDS) return { dst: frame.addr1, src: frame.addr3 };
  return { dst: frame.addr1, src: frame.addr2 };
};

// ---- LLC/SNAP 与 EAPOL ----

export interface SnapPayload {
  ethertype: number;
  payload: Uint8Array; // SNAP type 字节之后的净载
}

// LLC/SNAP 剥离：AA-AA-03 头 + SNAP（OUI 3B + ethertype 2B）。OUI 00:00:00（RFC 1042）与
// 00:00:F8（802.1H 桥接）的 type 布局相同可直接剥；其余 OUI 无法映射以太网返回 null。
export const stripSnap = (body: Uint8Array): SnapPayload | null => {
  if (body.length < 8) return null;
  if (body[0] !== 0xaa || body[1] !== 0xaa || body[2] !== 0x03) return null;
  const oui = (body[3] << 16) | (body[4] << 8) | body[5];
  if (oui !== 0x000000 && oui !== 0x0000f8) return null;
  return { ethertype: u16be(body, 6), payload: body.subarray(8) };
};

export type WpaKeyMessageKind = 'M1' | 'M2' | 'M3' | 'M4' | 'unknown';

export interface EapolKeyFrame {
  kind: WpaKeyMessageKind;
  frameIndex: number;
  apMac: Uint8Array; // AA：M1/M3（FromDS）取 addr2，M2/M4（ToDS）取 addr1
  staMac: Uint8Array; // SPA：M1/M3 取 addr1，M2/M4 取 addr2
  keyDescriptorVersion: number; // 1=HMAC-MD5/RC4(TKIP) 2=HMAC-SHA1/AES(CCMP) 3=AES-128-CMAC(PMF)
  keyInfo: number;
  replayCounter: Uint8Array;
  nonce: Uint8Array; // 32B
  mic: Uint8Array; // 16B（M1 为全 0 占位）
  keyDataLength: number;
  complete: boolean; // EAPOL Length 域是否完整落在帧内（截断帧 MIC 校验必失败）
  // 完整 EAPOL 消息（含 4B EAPOL 头，长度 = 4 + EAPOL Length 域；帧截断时按实际长度）。
  message: Uint8Array;
}

// EAPOL-Key 判别：Key Information 位 7=KeyAck、位 8=KeyMIC（802.11i-2004 Figure 43h；
// 位 0-2 = 描述符版本）。M1=ack 无 mic / M2=mic 无 ack 且 nonce 非零 / M3=ack+mic /
// M4=mic 无 ack 且 nonce 全零。
export const classifyEapolKey = (keyInfo: number, nonce: Uint8Array): WpaKeyMessageKind => {
  const ack = (keyInfo & 0x0080) !== 0;
  const mic = (keyInfo & 0x0100) !== 0;
  if (ack && !mic) return 'M1';
  if (!ack && mic) return isAllZero(nonce) ? 'M4' : 'M2';
  if (ack && mic) return 'M3';
  return 'unknown';
};

// 从数据帧提取 EAPOL-Key（LLC/SNAP ethertype 0x888E → EAPOL type=3）。
export const parseEapolKey = (frame: Ieee80211Frame, frameIndex: number): EapolKeyFrame | null => {
  if (!frame.valid || frame.type !== 2 || frame.protectedFrame) return null;
  const snap = stripSnap(frame.body);
  if (!snap || snap.ethertype !== 0x888e) return null;
  const message = snap.payload;
  if (message.length < 4 || message[1] !== 3) return null;
  const bodyLength = u16be(message, 2);
  const fullLength = 4 + bodyLength;
  const available = Math.min(fullLength, message.length);
  if (available < 99) return null; // 固定段 95B + Key Data Length 2B + Key Data 起始
  const keyInfo = u16le(message, 5);
  const nonce = message.slice(17, 49);
  return {
    kind: classifyEapolKey(keyInfo, nonce),
    frameIndex,
    apMac: frame.fromDS ? frame.addr2 : frame.addr1,
    staMac: frame.fromDS ? frame.addr1 : frame.addr2,
    keyDescriptorVersion: keyInfo & 0x0007,
    keyInfo,
    replayCounter: message.slice(9, 17),
    nonce,
    mic: message.slice(81, 97),
    keyDataLength: u16le(message, 97),
    complete: message.length >= fullLength,
    message: message.subarray(0, available),
  };
};

// ---- 密钥派生 ----

// PMK = PBKDF2-HMAC-SHA1(口令, SSID, 4096 迭代, 32B)。
export const derivePsk = (passphrase: string, ssid: string): Uint8Array =>
  pbkdf2(sha1, utf8(passphrase), utf8(ssid), { c: 4096, dkLen: 32 });

const lexLess = (left: Uint8Array, right: Uint8Array): boolean => {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index];
  }
  return false;
};

// PTK = PRF-512(PMK)：每轮 HMAC-SHA1(pmk, label||0x00||min(AA,SPA)||max(AA,SPA)||ANonce||SNonce||轮次)，
// 首两轮 40B 已覆盖 48B。CCMP 布局：KCK=PTK[0:16]、KEK=PTK[16:32]、TK=PTK[32:48]。
export const derivePtk = (pmk: Uint8Array, aa: Uint8Array, spa: Uint8Array, anonce: Uint8Array, snonce: Uint8Array): Uint8Array => {
  if (pmk.length !== 32) throw new Error(`PMK 必须 32 字节（收到 ${pmk.length}）`);
  if (aa.length !== 6 || spa.length !== 6) throw new Error('AP/客户端 MAC 必须 6 字节');
  if (anonce.length !== 32 || snonce.length !== 32) throw new Error('ANonce/SNonce 必须 32 字节');
  const aaFirst = lexLess(aa, spa);
  const first = aaFirst ? aa : spa;
  const second = aaFirst ? spa : aa;
  const label = utf8('Pairwise key expansion');
  const ptk = new Uint8Array(48);
  let filled = 0;
  for (let round = 0; filled < 48; round += 1) {
    const block = hmac(sha1, pmk, concatBytes([
      label, new Uint8Array([0]), first, second, anonce, snonce, new Uint8Array([round]),
    ]));
    const take = Math.min(20, 48 - filled);
    ptk.set(block.subarray(0, take), filled);
    filled += take;
  }
  return ptk;
};

// KCK MIC 校验：完整 EAPOL 消息字节 [81..96] 清零后 HMAC-SHA1 截 16B 常时比对。
export const verifyEapolMic = (kck: Uint8Array, eapolMessage: Uint8Array): boolean => {
  if (eapolMessage.length < 97) return false;
  const work = eapolMessage.slice();
  work.fill(0, 81, 97);
  const expected = hmac(sha1, kck, work).subarray(0, 16);
  return bytesEqualConstantTime(expected, eapolMessage.subarray(81, 97));
};

// ---- CCMP（RFC 3610 CCM，M=8 / L=2） ----

// B0/计数块 Flags：MAC 起始块 = 0x40(Adata) | ((M−2)/2)<<3(=0x18) | (L−1)(=0x01) = 0x59；
// 密钥流/S0 计数块 Flags 仅 L−1 = 0x01。
const CCM_MAC_FLAGS = 0x59;
const CCM_CTR_FLAGS = 0x01;
const MIC_LENGTH = 8;

const ccmCounterBlock = (nonce: Uint8Array, counter: number): Uint8Array => {
  const block = new Uint8Array(16);
  block[0] = CCM_CTR_FLAGS;
  block.set(nonce, 1);
  block[14] = (counter >> 8) & 0xff;
  block[15] = counter & 0xff;
  return block;
};

const xorBytes = (target: Uint8Array, mask: Uint8Array): void => {
  for (let index = 0; index < target.length; index += 1) target[index] ^= mask[index];
};

// 单块 AES（CBC-MAC 链与 S0 共用）：noble ecb 关闭填充后对 16B 输入即裸块加密。
const aesBlock = (key: Uint8Array, block: Uint8Array): Uint8Array => ecb(key, { disablePadding: true }).encrypt(block);

// CBC-MAC 单块链自实现：X = AES(X ⊕ block)，初值 X = AES(B0)。formatted 需按 16B 对齐补零。
const cbcMac = (key: Uint8Array, b0: Uint8Array, formatted: Uint8Array): Uint8Array => {
  let x = aesBlock(key, b0);
  for (let offset = 0; offset < formatted.length; offset += 16) {
    xorBytes(x, formatted.subarray(offset, offset + 16));
    x = aesBlock(key, x);
  }
  return x.slice(0, MIC_LENGTH);
};

export interface CcmpParts {
  nonce: Uint8Array; // 13B = Priority(1)||A2(6)||PN(6)
  aad: Uint8Array; // 22B = 屏蔽 FC(2)||addr1(6)||addr2(6)||addr3(6)||SC 低 4bit(2)
  key: Uint8Array; // TK（PTK[32:48]）
}

// RFC 3610 CCM 解密 + 认证：先 CTR（计数从 1 起）解文，再对 (B0||带长前缀 AAD||明文) 做
// CBC-MAC，与包尾 8B MIC 异或 MSB8(S0) 后比对；不匹配抛中文错误（确定性认证失败）。
// 密钥流由 @noble/ciphers ctr 生成（初始块 A1；noble 按整 16B 块递增，与 CCM 的 2 字节尾
// 计数在 ≤65535 块内逐位等价——以太网 MTU 场景远达不到）。
export const ccmpDecrypt = (parts: CcmpParts, cipherWithMic: Uint8Array): Uint8Array => {
  const { nonce, aad, key } = parts;
  if (nonce.length !== 13) throw new Error(`CCMP nonce 必须 13 字节（收到 ${nonce.length}）`);
  if (aad.length !== 22) throw new Error(`CCMP AAD 必须 22 字节（收到 ${aad.length}）`);
  if (key.length !== 16) throw new Error(`CCMP 密钥必须 16 字节（收到 ${key.length}）`);
  if (cipherWithMic.length < MIC_LENGTH) throw new Error('CCMP 载荷不足 8 字节 MIC');
  const cipher = cipherWithMic.subarray(0, cipherWithMic.length - MIC_LENGTH);
  const micFromPacket = cipherWithMic.subarray(cipherWithMic.length - MIC_LENGTH);
  const keystream = ctr(key, ccmCounterBlock(nonce, 1)).encrypt(new Uint8Array(cipher.length));
  const plaintext = cipher.slice();
  xorBytes(plaintext, keystream);
  const b0 = new Uint8Array(16);
  b0[0] = CCM_MAC_FLAGS;
  b0.set(nonce, 1);
  b0[14] = (plaintext.length >> 8) & 0xff;
  b0[15] = plaintext.length & 0xff;
  // RFC 3610 关联数据格式：2B 大端长度 + AAD，整体补零到 16B 对齐；明文随后同样对齐
  const aadBlockLength = Math.ceil((2 + aad.length) / 16) * 16;
  const formatted = new Uint8Array(aadBlockLength + Math.ceil(plaintext.length / 16) * 16);
  formatted[0] = (aad.length >> 8) & 0xff;
  formatted[1] = aad.length & 0xff;
  formatted.set(aad, 2);
  formatted.set(plaintext, aadBlockLength);
  const computed = cbcMac(key, b0, formatted);
  // MIC 校验值 = CBC-MAC ⊕ MSB8(S0)，S0 = AES(0x01||nonce||0)
  xorBytes(computed, aesBlock(key, ccmCounterBlock(nonce, 0)).subarray(0, MIC_LENGTH));
  if (!bytesEqualConstantTime(computed, micFromPacket)) {
    throw new Error('CCMP MIC 校验失败（密钥不匹配或帧损坏）');
  }
  return plaintext;
};

// ---- CCMP 头形态判别与要素提取 ----

export type ProtectedCipher = 'ccmp' | 'tkip' | 'wep';

// 受保护数据帧的加密形态判定（CCMP 头 8B / TKIP 头 8B / WEP IV 4B）：
//   CCMP：字节 2 = KeyID(0-1)|ExtIV(bit5)，字节 3 全 0；
//   TKIP：ExtIV 出现在字节 3（TSC 布局）；
//   WEP：两处都无 ExtIV（4 字节 IV 头，字节 3 = 6bit 零填充 + KeyID 高 2 位）。
// 注：WEP 的随机 IV2 小概率撞上 ExtIV 位且 KeyID=0（字节 3=0）时会误判 CCMP——此时解密
// 认证必失败并按帧拒绝，不产生假明文。
export const classifyProtectedBody = (body: Uint8Array): { cipher: ProtectedCipher; headerLength: number; reason?: string } => {
  if (body.length < 5) return { cipher: 'wep', headerLength: 4, reason: '帧体过短' };
  if ((body[3] & 0x20) !== 0) return { cipher: 'tkip', headerLength: 8, reason: 'ExtIV 位于字节 3（TKIP TSC 布局）' };
  if ((body[2] & 0x20) !== 0 && body[3] === 0) return { cipher: 'ccmp', headerLength: 8 };
  return { cipher: 'wep', headerLength: 4, reason: '无 ExtIV 标志（WEP 4 字节 IV 头）' };
};

// CCMP 三要素：nonce = qosTid||addr2||PN（802.11-2012 §11.5.4：PN 字段为 6B 大端，
// 从 8B 头的小端散布位 [PN0,PN1,PN4,PN5,PN6,PN7] 反序拼回）；
// aad = (FC & 0xC70F 小端)||addr1||addr2||addr3||(SC & 0x000F 小端)。
export const extractCcmpParts = (frame: Ieee80211Frame):
  { nonce: Uint8Array; aad: Uint8Array; pnText: string; ciphertext: Uint8Array } => {
  const body = frame.body;
  const pnBe = [body[7], body[6], body[5], body[4], body[1], body[0]]; // 大端 PN（nonce/pnText 口径）
  const nonce = new Uint8Array(13);
  nonce[0] = frame.qosTid & 0x0f;
  nonce.set(frame.addr2, 1);
  nonce.set(pnBe, 7);
  let fc = (frame.type & 3) << 2 | (frame.subtype & 0xf) << 4;
  if (frame.toDS) fc |= 0x0100;
  if (frame.fromDS) fc |= 0x0200;
  if (frame.protectedFrame) fc |= 0x4000;
  fc &= 0xc70f; // 屏蔽 subtype/retry/pwrmgmt/moredata，留 type/ToDS/FromDS/MoreFrag/Protected/Order
  const aad = new Uint8Array(22);
  aad[0] = fc & 0xff;
  aad[1] = (fc >> 8) & 0xff;
  aad.set(frame.addr1, 2);
  aad.set(frame.addr2, 8);
  aad.set(frame.addr3, 14);
  aad[20] = frame.sequenceControl & 0x0f;
  const pnText = pnBe.map(byte => byte.toString(16).padStart(2, '0')).join('');
  return { nonce, aad, pnText, ciphertext: body.subarray(8) };
};

// ---- 管理帧（Beacon/Probe Response）：SSID 与 RSN IE ----

export interface WifiNetworkMeta {
  ssidCandidates: string[];
  pairwiseCiphers: string[];
  akmSuites: string[];
}

// RSN IE 密码套件类型（00-0F-AC 后第 4 字节）。
const RSN_CIPHER_NAMES: Record<number, string> = {
  1: 'WEP-40', 2: 'TKIP', 3: 'WRAP', 4: 'CCMP-128', 5: 'WEP-104', 6: 'GCMP-128', 7: 'GCMP-256', 8: 'CCMP-256',
};
const RSN_AKM_NAMES: Record<number, string> = {
  1: '802.1X', 2: 'PSK', 3: 'FT-802.1X', 4: 'FT-PSK', 5: '802.1X-SHA256', 6: 'PSK-SHA256',
  8: 'SAE', 12: 'SWE', 24: 'FT-SAE',
};

// 解析 Beacon(subtype 8) / Probe Response(subtype 5) 的 tagged IE：tag 0 = SSID、
// tag 48 = RSN（版本+组密码+对密码清单+AKM 清单）。畸形 IE 按边界截断不抛错。
export const parseManagementMeta = (frame: Ieee80211Frame): { ssid?: string; pairwise: string[]; akm: string[] } => {
  const empty = { pairwise: [] as string[], akm: [] as string[] };
  if (!frame.valid || frame.type !== 0 || (frame.subtype !== 8 && frame.subtype !== 5)) return empty;
  const body = frame.body;
  if (body.length < 12) return empty; // timestamp 8 + beacon interval 2 + capability 2
  let offset = 12;
  let ssid: string | undefined;
  const pairwise: string[] = [];
  const akm: string[] = [];
  const readSuites = (position: number, count: number): { suites: string[]; next: number } => {
    const suites: string[] = [];
    let cursor = position;
    for (let index = 0; index < count && cursor + 4 <= body.length; index += 1) {
      if (body[cursor] === 0 && body[cursor + 1] === 0x0f && body[cursor + 2] === 0xac) {
        suites.push(body[cursor + 3].toString());
      }
      cursor += 4;
    }
    return { suites, next: cursor };
  };
  while (offset + 2 <= body.length) {
    const tag = body[offset];
    const length = body[offset + 1];
    const valueStart = offset + 2;
    if (valueStart + length > body.length) break;
    if (tag === 0) {
      ssid = new TextDecoder('utf-8', { fatal: false }).decode(body.subarray(valueStart, valueStart + length));
    } else if (tag === 48 && length >= 4) {
      const version = u16le(body, valueStart);
      if (version === 1) {
        // RSN IE 布局：版本(2) + 组密码套件(4) + 对密码清单计数(2) + 清单 + AKM 计数(2) + 清单
        const pairwiseCountOffset = valueStart + 6; // 版本 2B + 组密码 4B 之后才是计数
        const pairwiseCount = Math.min(u16le(body, pairwiseCountOffset), 8);
        const parsedPairwise = readSuites(pairwiseCountOffset + 2, pairwiseCount);
        pairwise.push(...parsedPairwise.suites.map(type => RSN_CIPHER_NAMES[Number(type)] ?? `rsn:${type}`));
        const akmCount = Math.min(u16le(body, parsedPairwise.next), 8);
        const parsedAkm = readSuites(parsedPairwise.next + 2, akmCount);
        akm.push(...parsedAkm.suites.map(type => RSN_AKM_NAMES[Number(type)] ?? `akm:${type}`));
      }
    }
    offset = valueStart + length;
  }
  return { ssid, pairwise, akm };
};

// ---- 抓包级分析（无需口令的结构预扫描，供 UI 卡片先展示元信息） ----

export interface WpaCaptureAnalysis {
  eapolCount: number;
  messages: EapolKeyFrame[];
  hasHandshake: boolean; // 至少拿到 ANonce（M1/M3）与 SNonce（M2/M4）
  keyDescriptorVersion: number | null;
  ssidCandidates: string[];
  pairwiseCiphers: string[];
  akmSuites: string[];
  protectedDataFrames: number;
  // 抓包级拒绝原因（非 null 时 decryptWpaCapture 直接抛同文案错误）
  rejection: string | null;
}

export const analyzeWpaCapture = (capture: ParsedCapture): WpaCaptureAnalysis => {
  if (capture.linkType !== 105 && capture.linkType !== 127) {
    throw new Error(`链路层类型 ${capture.linkType} 不是 802.11（105 裸帧 / 127 radiotap），无法做 WiFi 解密`);
  }
  const isRadiotap = capture.linkType === 127;
  const messages: EapolKeyFrame[] = [];
  const ssidCandidates: string[] = [];
  const pairwiseCiphers: string[] = [];
  const akmSuites: string[] = [];
  let protectedDataFrames = 0;
  let keyDescriptorVersion: number | null = null;
  for (const packet of capture.packets) {
    const frame = parseIeee80211(packet.data, packet.index, isRadiotap);
    if (!frame.valid) continue;
    const eapol = parseEapolKey(frame, packet.index);
    if (eapol) {
      messages.push(eapol);
      if (keyDescriptorVersion === null || eapol.keyDescriptorVersion !== 2) keyDescriptorVersion = eapol.keyDescriptorVersion;
      continue;
    }
    const meta = parseManagementMeta(frame);
    if (meta.ssid !== undefined && !ssidCandidates.includes(meta.ssid)) ssidCandidates.push(meta.ssid);
    for (const cipher of meta.pairwise) if (!pairwiseCiphers.includes(cipher)) pairwiseCiphers.push(cipher);
    for (const akm of meta.akm) if (!akmSuites.includes(akm)) akmSuites.push(akm);
    if (frame.type === 2 && frame.protectedFrame) protectedDataFrames += 1;
  }
  let anonce: Uint8Array | null = null;
  let snonce: Uint8Array | null = null;
  for (const message of messages) {
    if ((message.kind === 'M1' || message.kind === 'M3') && !anonce) anonce = message.nonce;
    if ((message.kind === 'M2' || message.kind === 'M4') && !snonce) snonce = message.nonce;
  }
  let rejection: string | null = null;
  if (keyDescriptorVersion === 1) rejection = '握手密钥描述符版本 1（TKIP/HMAC-MD5/RC4，WPA1）：本引擎仅支持 CCMP（WPA2-AES）';
  else if (keyDescriptorVersion === 3) rejection = '握手密钥描述符版本 3（802.11w PMF / AES-128-CMAC，常见于 WPA3）：本引擎仅支持版本 2（CCMP）';
  else if (pairwiseCiphers.includes('TKIP') && !pairwiseCiphers.includes('CCMP-128')) rejection = 'RSN IE 显示对密码套件为 TKIP（WPA1）：本引擎仅支持 CCMP';
  else if (pairwiseCiphers.some(cipher => cipher.startsWith('GCMP'))) rejection = `RSN IE 显示 GCMP 套件（${pairwiseCiphers.filter(cipher => cipher.startsWith('GCMP')).join('/')}）：本引擎仅支持 CCMP`;
  else if (akmSuites.includes('SAE') && !akmSuites.includes('PSK') && !akmSuites.includes('802.1X')) rejection = 'RSN IE 显示 AKM 仅 SAE（WPA3-Personal）：PMK 来自 SAE 握手而非口令 PBKDF2，本引擎不支持';
  else if (!anonce || !snonce) rejection = '未找到完整四次握手（需要 M1/M3 的 ANonce 与 M2/M4 的 SNonce）';
  else if (protectedDataFrames === 0) rejection = '没有受 CCMP 保护的 data 帧，无需解密';
  return {
    eapolCount: messages.length,
    messages,
    hasHandshake: Boolean(anonce && snonce),
    keyDescriptorVersion,
    ssidCandidates,
    pairwiseCiphers,
    akmSuites,
    protectedDataFrames,
    rejection,
  };
};

// ---- 解密主入口 ----

export interface WpaDecryptOptions {
  passphrase: string;
  ssid: string;
}

export interface WpaDecryptedFrame {
  frameIndex: number;
  dst: string;
  src: string;
  ethertype: number;
  pnText: string;
  payload: Uint8Array; // 以太网净载（14B 帧头之后）
}

export interface WpaRejectedFrame {
  frameIndex: number;
  reason: string;
}

export interface WpaDecryptResult {
  ssid: string;
  pmk: Uint8Array;
  ptk: Uint8Array;
  kck: Uint8Array;
  tk: Uint8Array;
  anonce: Uint8Array;
  snonce: Uint8Array;
  messages: EapolKeyFrame[];
  // 已校验 MIC 的消息数与是否全部通过；authFailure = 有 MIC 消息且全部失败（错口令/SSID 确定性拒绝）
  micCheckedCount: number;
  micVerified: boolean;
  authFailure: boolean;
  decrypted: WpaDecryptedFrame[];
  rejected: WpaRejectedFrame[];
  // 重建的 Ethernet pcap（linktype 1，保持原包时间戳与顺序），可直接回灌流量域/丢给 Wireshark
  ethernetPcap: Uint8Array;
  fcsTrimmed: number; // 帧尾按 FCS 假设裁 4B 后才通过认证的帧数（抓包带 FCS 时出现）
}

const writeU32le = (out: Uint8Array, offset: number, value: number): void => {
  out[offset] = value & 0xff;
  out[offset + 1] = (value >>> 8) & 0xff;
  out[offset + 2] = (value >>> 16) & 0xff;
  out[offset + 3] = (value >>> 24) & 0xff;
};

// 重建 Ethernet pcap（linktype 1）：24B 全局头（小端微秒）+ 16B 记录头 + 帧。
const buildEthernetPcap = (records: Array<{ tsSeconds: number; frame: Uint8Array }>): Uint8Array => {
  let total = 24;
  for (const record of records) total += 16 + record.frame.length;
  const out = new Uint8Array(total);
  out[0] = 0xd4; out[1] = 0xc3; out[2] = 0xb2; out[3] = 0xa1; // pcap 小端微秒 magic
  out[4] = 2; out[6] = 4; // version 2.4
  writeU32le(out, 16, 262144); // snaplen
  writeU32le(out, 20, 1); // linktype = Ethernet
  let offset = 24;
  for (const record of records) {
    const seconds = Number.isFinite(record.tsSeconds) && record.tsSeconds > 0 ? Math.floor(record.tsSeconds) : 0;
    const micros = Number.isFinite(record.tsSeconds) && record.tsSeconds > 0
      ? Math.min(999999, Math.round((record.tsSeconds - seconds) * 1e6)) : 0;
    writeU32le(out, offset, seconds);
    writeU32le(out, offset + 4, micros);
    writeU32le(out, offset + 8, record.frame.length);
    writeU32le(out, offset + 12, record.frame.length);
    out.set(record.frame, offset + 16);
    offset += 16 + record.frame.length;
  }
  return out;
};

// 单帧 CCMP 解密 + 以太网翻译：SNAP ethertype < 0x0600（802.3 长度域）或未识别 OUI 拒绝。
// 帧尾按 FCS 假设重试一次（真实抓包常带 4B FCS；CTF 自造帧通常没有）。
const decryptFrameToEthernet = (frame: Ieee80211Frame, tk: Uint8Array):
  { payload: Uint8Array; dst: Uint8Array; src: Uint8Array; ethertype: number; pnText: string; fcsTrimmed: boolean } => {
  const parts = extractCcmpParts(frame);
  const addresses = ethernetAddresses(frame);
  const attempt = (ciphertext: Uint8Array): Uint8Array =>
    ccmpDecrypt({ nonce: parts.nonce, aad: parts.aad, key: tk }, ciphertext);
  let plaintext: Uint8Array;
  let fcsTrimmed = false;
  try {
    plaintext = attempt(parts.ciphertext);
  } catch (error) {
    if (parts.ciphertext.length >= 12) {
      plaintext = attempt(parts.ciphertext.subarray(0, parts.ciphertext.length - 4));
      fcsTrimmed = true;
    } else {
      throw error;
    }
  }
  const snap = stripSnap(plaintext);
  if (!snap) throw new Error('解密后的帧体不是 LLC/SNAP 封装，无法映射以太网');
  if (snap.ethertype < 0x0600) throw new Error(`SNAP type 0x${snap.ethertype.toString(16)} 是 802.3 长度域封装，不支持`);
  const ethernetPayload = snap.payload.slice();
  return { payload: ethernetPayload, dst: addresses.dst, src: addresses.src, ethertype: snap.ethertype, pnText: parts.pnText, fcsTrimmed };
};

// WPA2 抓包解密主入口：结构预扫描 → 口令派生 → MIC 校验门 → 逐帧 CCMP 解密 →
// 重建 Ethernet pcap。结构问题（非 802.11、TKIP、WPA3、无握手）抛中文错误；
// 口令/SSID 错误返回 authFailure=true 的结果（不抛异常，属确定性预期输出）。
export const decryptWpaCapture = (capture: ParsedCapture, options: WpaDecryptOptions): WpaDecryptResult => {
  if (!options.passphrase) throw new Error('口令为空：WPA2-Personal 需要 PSK 口令');
  if (!options.ssid) throw new Error('SSID 为空：PBKDF2 派生需要网络名');
  const analysis = analyzeWpaCapture(capture);
  if (analysis.rejection) throw new Error(analysis.rejection);
  const isRadiotap = capture.linkType === 127;
  const { passphrase, ssid } = options;
  const pmk = derivePsk(passphrase, ssid);
  const m1 = analysis.messages.find(message => message.kind === 'M1')
    ?? analysis.messages.find(message => message.kind === 'M3');
  const m2 = analysis.messages.find(message => message.kind === 'M2')
    ?? analysis.messages.find(message => message.kind === 'M4');
  const anonce = m1!.nonce;
  const snonce = m2!.nonce;
  const apMac = m1 ? m1.apMac : m2!.apMac;
  const staMac = m2 ? m2.staMac : m1!.staMac;
  const ptk = derivePtk(pmk, apMac, staMac, anonce, snonce);
  const kck = ptk.subarray(0, 16);
  const tk = ptk.subarray(32, 48);
  // MIC 校验门：M2/M3/M4 全部可用 MIC 消息（M1 无 MIC）逐条校验
  let micCheckedCount = 0;
  let micPassed = 0;
  for (const message of analysis.messages) {
    if (message.kind === 'M1' || message.kind === 'unknown') continue;
    micCheckedCount += 1;
    if (verifyEapolMic(kck, message.message)) micPassed += 1;
  }
  const authFailure = micCheckedCount > 0 && micPassed === 0;
  const decrypted: WpaDecryptedFrame[] = [];
  const rejected: WpaRejectedFrame[] = [];
  const pcapRecords: Array<{ tsSeconds: number; frame: Uint8Array }> = [];
  let fcsTrimmed = 0;
  if (!authFailure) {
    for (const packet of capture.packets) {
      if (decrypted.length >= MAX_DECRYPT_FRAMES) break;
      const frame = parseIeee80211(packet.data, packet.index, isRadiotap);
      if (!frame.valid || frame.type !== 2 || !frame.protectedFrame) continue;
      const shape = classifyProtectedBody(frame.body);
      if (shape.cipher !== 'ccmp') {
        rejected.push({ frameIndex: packet.index, reason: shape.cipher === 'wep'
          ? `WEP 形态受保护帧（${shape.reason ?? '无 ExtIV'}）：本引擎仅支持 CCMP`
          : `TKIP 形态受保护帧（${shape.reason ?? ''}）：本引擎仅支持 CCMP` });
        continue;
      }
      try {
        const result = decryptFrameToEthernet(frame, tk);
        if (result.fcsTrimmed) fcsTrimmed += 1;
        decrypted.push({
          frameIndex: packet.index,
          dst: macToText(result.dst),
          src: macToText(result.src),
          ethertype: result.ethertype,
          pnText: result.pnText,
          payload: result.payload,
        });
        pcapRecords.push({
          tsSeconds: packet.tsSeconds,
          frame: concatBytes([result.dst, result.src,
            new Uint8Array([result.ethertype >> 8, result.ethertype & 0xff]), result.payload]),
        });
      } catch (error) {
        rejected.push({
          frameIndex: packet.index,
          reason: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }
  return {
    ssid,
    pmk,
    ptk,
    kck,
    tk,
    anonce,
    snonce,
    messages: analysis.messages,
    micCheckedCount,
    micVerified: micCheckedCount > 0 && micPassed === micCheckedCount,
    authFailure,
    decrypted,
    rejected,
    ethernetPcap: buildEthernetPcap(pcapRecords),
    fcsTrimmed,
  };
};
