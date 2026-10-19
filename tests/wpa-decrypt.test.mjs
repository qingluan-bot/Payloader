// WPA2 四次握手校验与 CCMP 解密测试（B2-12）。
// 黄金向量由独立 Python 实现（gen_wpa_golden.py，hashlib.pbkdf2_hmac + hmac + pycryptodome
// MODE_CCM + 手写 802.11/EAPOL/IPv4/TCP 字节）生成，scapy rdpcap/Dot11 交叉验证容器与帧结构；
// 值嵌入下方 GOLDEN 常量，TS 引擎零共享代码。
// 覆盖：802.11/radiotap 解析、M1-M4 判别、PMK/PTK 派生、M2/M3/M4 MIC、CCMP 解密（QoS 与非
// QoS、两种方向）、WEP 形态拒绝、错口令/错 SSID 确定性拒绝、TKIP/PMF(v3)/WPA3(SAE) 抓包级
// 拒绝、Ethernet pcap 重建 → 既有流量链（parseCapture/buildPacketViews/analyzeCapture flag 命中）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const parser = loadModule(path.join(srcDir, 'utils', 'ctf', 'pcap', 'parser.ts'));
const protocols = loadModule(path.join(srcDir, 'utils', 'ctf', 'pcap', 'protocols.ts'));
const analyze = loadModule(path.join(srcDir, 'utils', 'ctf', 'pcap', 'analyze.ts'));
const wpa = loadModule(path.join(srcDir, 'utils', 'ctf', 'wpaDecrypt.ts'));

// ---- Python 黄金向量（独立权威；生成脚本含 scapy 交叉验证）----
const GOLDEN = {
  ssid: 'labnet',
  password: 'password123',
  pmk: 'fb7410e5f04128bdc1277a2acce9728f18da66033a1002a2bb811914bacb1d32',
  ptk: 'd3330b82ce72f45a1661e1057db93442a18a53f4083173885b710eda521b05a10a4514e70dfd73bf405906ee46421dcc',
  m1Frame: '0802000066778899aabb0211223344550211223344550100aaaa03000000888e0203005ffe8a001000000000000000000111223344556677889900aabbccddeeff00112233445566778899aabbccddeeff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
  m2Frame: '0801000002112233445566778899aabb0211223344550200aaaa03000000888e0203005ffe0a0110000000000000000002a1b2c3d4e5f60718293a4b5c6d7e8f9011aa22bb33cc44dd55ee66ff0077889900000000000000000000000000000000000000000000000000000000000000006b8f5d9efb1322c07274e3059ff707970000',
  m3Frame: '0802000066778899aabb0211223344550211223344550300aaaa03000000888e0203006ffeca131000000000000000000311223344556677889900aabbccddeeff00112233445566778899aabbccddeeff000000000000000000000000000000000000000000000000000000000000000002dc2359039b792b85fe8718696d124d100000000000000000000000000000000000',
  m4Frame: '0801000002112233445566778899aabb0211223344550400aaaa03000000888e0203005ffe0a031000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c7f2f515a3cce15caa24286a25554dd50000',
  frameA: '8841000002112233445566778899aabb0211223344550a0005000100200000000000d329eadc6270a4b215637e2193344abd03306b865d9ee1a45798ccf7305aae0caf3ef60e8625f376d37de15e75f25a24d2a72d6d702c2a0aa1dbb0bc338a5891d283247f7b046ea0e7ffd2262be5e69e9f632f2b2d8d1e959e8aaee8bc59739979555868e5446aaf8ea1175a13d89478852217495236c69d074b22e1e3cac6f2318df39f8bcafb',
  frameB: '0842000066778899aabb0211223344550211223344550b000200200000000000af0a7c6013c16e73e7984bda09e0adf3a6802cc9ad3fbc09b38873216ce411797eba0554c76049beef079c151fb2e6b6143e5ac03a942484c76dbf2c6ca56a27cff85e2a674a220814f478f7d077acbb94e2423a66c1a6b6a663214fe5457b43b1a09c592e9ec72b2a54f575c4652c368188cf62bfea86df8995',
  frameC: '0841000002112233445566778899aabb0211223344550c0011223340deadbeefdeadbeefdeadbeefdeadbeef',
  beaconFrame: '80000000ffffffffffff021122334455021122334455000000000000000000006400110400066c61626e657430120100000fac040100000fac040100000fac02',
  nonceA: '0566778899aabb000000000001',
  nonceB: '00021122334455000000000002',
  aadA: '084102112233445566778899aabb0211223344550a00',
  aadB: '084266778899aabb0211223344550211223344550b00',
};

const fromHex = hex => Uint8Array.from(Buffer.from(hex, 'hex'));
const bytesToHex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');

// 帧类 golden 一次性转字节（GOLDEN 里的 16 进制串仅作展示，运行时全用 F.* 字节；
// 直接把 hex 串喂给帧解析会被 Uint8Array.set 按字符静默转成数字字节，是必踩的坑）。
const F = {
  beacon: fromHex(GOLDEN.beaconFrame),
  m1: fromHex(GOLDEN.m1Frame),
  m2: fromHex(GOLDEN.m2Frame),
  m3: fromHex(GOLDEN.m3Frame),
  m4: fromHex(GOLDEN.m4Frame),
  frameA: fromHex(GOLDEN.frameA),
  frameB: fromHex(GOLDEN.frameB),
  frameC: fromHex(GOLDEN.frameC),
};

const concat = parts => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

const u16le = value => Uint8Array.from([value & 0xff, (value >>> 8) & 0xff]);
const u32le = value => Uint8Array.from([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]);

// pcap 容器（小端微秒 + 指定链路层类型）+ 记录序列。
const pcapFromRecords = (records, { linkType = 127 } = {}) => concat([
  concat([Uint8Array.from([0xd4, 0xc3, 0xb2, 0xa1]), u16le(2), u16le(4), u32le(0), u32le(0), u32le(262144), u32le(linkType)]),
  ...records.map(record => concat([u32le(1700000000), u32le(record.usec ?? 0), u32le(record.data.length), u32le(record.data.length), record.data])),
]);

// 最小 radiotap 头（8B：version 0 / pad 0 / len 8 / present 0）。
const radiotapWrap = frame => concat([Uint8Array.from([0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]), frame]);

const framesToCapture = (frames, linkType) => {
  const wireFrames = linkType === 127 ? frames.map(radiotapWrap) : frames;
  return parser.parseCapture(pcapFromRecords(wireFrames.map((data, index) => ({ data, usec: index })), { linkType }));
};

const fullCapture = linkType => framesToCapture(
  [F.beacon, F.m1, F.m2, F.m3, F.m4, F.frameA, F.frameB, F.frameC],
  linkType,
);

const latin1 = bytes => {
  let out = '';
  for (let index = 0; index < bytes.length; index += 1) out += String.fromCharCode(bytes[index]);
  return out;
};

// ---- 密钥派生（PBKDF2/PRF 与 hashlib/hmac 对拍）----

test('derivePsk：PBKDF2-HMAC-SHA1(口令,SSID,4096) 与 Python hashlib 黄金一致', () => {
  assert.equal(bytesToHex(wpa.derivePsk(GOLDEN.password, GOLDEN.ssid)), GOLDEN.pmk);
});

test('derivePtk：PRF-512 48B 与 Python 黄金一致（KCK/TK 切片正确）', () => {
  const pmk = wpa.derivePsk(GOLDEN.password, GOLDEN.ssid);
  const ptk = wpa.derivePtk(
    pmk,
    Uint8Array.from(Buffer.from('021122334455', 'hex')),
    Uint8Array.from(Buffer.from('66778899aabb', 'hex')),
    Uint8Array.from(Buffer.from('11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff', 'hex')),
    Uint8Array.from(Buffer.from('a1b2c3d4e5f60718293a4b5c6d7e8f9011aa22bb33cc44dd55ee66ff00778899', 'hex')),
  );
  assert.equal(bytesToHex(ptk), GOLDEN.ptk);
  // MAC 顺序无关性：交换 AA/SPA 参数位得到同一 PTK（引擎内部按字典序排序）
  const ptkSwapped = wpa.derivePtk(pmk,
    Uint8Array.from(Buffer.from('66778899aabb', 'hex')),
    Uint8Array.from(Buffer.from('021122334455', 'hex')),
    Uint8Array.from(Buffer.from('11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff', 'hex')),
    Uint8Array.from(Buffer.from('a1b2c3d4e5f60718293a4b5c6d7e8f9011aa22bb33cc44dd55ee66ff00778899', 'hex')));
  assert.equal(bytesToHex(ptkSwapped), GOLDEN.ptk);
});

// ---- 802.11 帧解析与 EAPOL 判别 ----

test('parseIeee80211：radiotap 跳过、FC 位域、QoS 头长与 TID 回填', () => {
  const frame = wpa.parseIeee80211(radiotapWrap(F.frameA), 0, true);
  assert.equal(frame.valid, true);
  assert.equal(frame.type, 2);
  assert.equal(frame.subtype, 8);
  assert.equal(frame.toDS, true);
  assert.equal(frame.fromDS, false);
  assert.equal(frame.protectedFrame, true);
  assert.equal(frame.qos, true);
  assert.equal(frame.headerLength, 26); // 24 + QoS Control 2
  assert.equal(frame.qosTid, 5);
  assert.equal(bytesToHex(frame.addr2), '66778899aabb');
  // 裸 802.11（105）同一帧
  const raw = wpa.parseIeee80211(F.frameA, 1, false);
  assert.equal(raw.valid, true);
  assert.equal(raw.headerLength, frame.headerLength);
  // 非法输入
  assert.equal(wpa.parseIeee80211(new Uint8Array(10), 2, true).valid, false);
  assert.equal(wpa.parseIeee80211(radiotapWrap(new Uint8Array(20)), 3, true).valid, false);
});

test('classifyEapolKey：M1-M4 判据（ack/mic/nonce）', () => {
  const zero32 = new Uint8Array(32);
  const nonce = Uint8Array.from(Buffer.from('a1b2c3d4', 'hex')); // 非零占位
  assert.equal(wpa.classifyEapolKey(0x008a, nonce), 'M1'); // ack 无 mic
  assert.equal(wpa.classifyEapolKey(0x010a, nonce), 'M2'); // mic 无 ack 且 nonce 非零
  assert.equal(wpa.classifyEapolKey(0x13ca, nonce), 'M3'); // ack+mic
  assert.equal(wpa.classifyEapolKey(0x030a, zero32), 'M4'); // mic 无 ack 且 nonce 全零
  assert.equal(wpa.classifyEapolKey(0x0000, nonce), 'unknown');
});

test('parseEapolKey：golden M2 帧 → kind/keyDescriptorVersion/MIC 域提取', () => {
  const capture = framesToCapture([F.m2], 105);
  const frame = wpa.parseIeee80211(capture.packets[0].data, 0, false);
  const eapol = wpa.parseEapolKey(frame, 0);
  assert.ok(eapol);
  assert.equal(eapol.kind, 'M2');
  assert.equal(eapol.keyDescriptorVersion, 2);
  assert.equal(eapol.keyInfo, 0x010a);
  assert.equal(bytesToHex(eapol.mic), '6b8f5d9efb1322c07274e3059ff70797');
  assert.equal(bytesToHex(eapol.apMac), '021122334455');
  assert.equal(bytesToHex(eapol.staMac), '66778899aabb');
  assert.equal(eapol.complete, true);
});

// ---- MIC 校验 ----

test('verifyEapolMic：golden KCK 下 M2/M3/M4 全部通过，篡改即失败', () => {
  const kck = Uint8Array.from(Buffer.from(GOLDEN.ptk.slice(0, 32), 'hex'));
  const loadEapol = frameHex => {
    const capture = framesToCapture([frameHex], 105);
    const frame = wpa.parseIeee80211(capture.packets[0].data, 0, false);
    return wpa.parseEapolKey(frame, 0).message;
  };
  assert.equal(wpa.verifyEapolMic(kck, loadEapol(F.m2)), true);
  assert.equal(wpa.verifyEapolMic(kck, loadEapol(F.m3)), true);
  assert.equal(wpa.verifyEapolMic(kck, loadEapol(F.m4)), true);
  const tampered = loadEapol(F.m2).slice();
  tampered[50] ^= 0x01;
  assert.equal(wpa.verifyEapolMic(kck, tampered), false);
  // 错 KCK 确定性失败
  const wrongKck = kck.slice();
  wrongKck[0] ^= 0xff;
  assert.equal(wpa.verifyEapolMic(wrongKck, loadEapol(F.m2)), false);
});

// ---- CCMP 单元（nonce/AAD 与 Python 对拍 + 解密回明文）----

test('extractCcmpParts：QoS tid 进 nonce、AAD 屏蔽 Flags 后 FC+三地址+SC 低 4bit（golden 对拍）', () => {
  const loadFrame = frameHex => {
    const capture = framesToCapture([frameHex], 105);
    return wpa.parseIeee80211(capture.packets[0].data, 0, false);
  };
  const partsA = wpa.extractCcmpParts(loadFrame(F.frameA));
  assert.equal(bytesToHex(partsA.nonce), GOLDEN.nonceA);
  assert.equal(bytesToHex(partsA.aad), GOLDEN.aadA);
  const partsB = wpa.extractCcmpParts(loadFrame(F.frameB));
  assert.equal(bytesToHex(partsB.nonce), GOLDEN.nonceB);
  assert.equal(bytesToHex(partsB.aad), GOLDEN.aadB);
});

test('ccmpDecrypt：golden 密文解回 IPv4+TCP 明文（pycryptodome MODE_CCM 加密对拍）', () => {
  const tk = Uint8Array.from(Buffer.from(GOLDEN.ptk.slice(64, 96), 'hex'));
  const partsA = { nonce: fromHex(GOLDEN.nonceA), aad: fromHex(GOLDEN.aadA), key: tk };
  const cipherA = F.frameA.subarray(26 + 8); // QoS 头 26 + CCMP 头 8
  const plaintext = wpa.ccmpDecrypt(partsA, cipherA);
  const expectedA = 'aaaa030000000800450000771234400040068ef9c0a80c02c0a80c01c03a0050000003e8000007d15018faf02f930000474554202f666c61672e74787420485454502f312e310d0a486f73743a206c61622e6c6f63616c0d0a557365722d4167656e743a206374660d0a0d0a666c61677b63636d705f67306c64656e7d0d0a';
  assert.equal(bytesToHex(plaintext), expectedA);
  assert.ok(latin1(plaintext).includes('flag{ccmp_g0lden}'));
  // MIC 被篡改 → 确定性认证失败
  const tampered = cipherA.slice();
  tampered[tampered.length - 1] ^= 0x80;
  assert.throws(() => wpa.ccmpDecrypt(partsA, tampered), /MIC/);
  // 错 TK → 确定性认证失败
  const wrongKey = tk.slice();
  wrongKey[0] ^= 0xff;
  assert.throws(() => wpa.ccmpDecrypt({ ...partsA, key: wrongKey }, cipherA), /MIC/);
});

// ---- analyzeWpaCapture / decryptWpaCapture 全链 ----

test('analyzeWpaCapture：SSID 候选/握手齐全/CCMP 无拒绝（radiotap 127）', () => {
  const capture = fullCapture(127);
  assert.equal(capture.linkType, 127);
  const analysis = wpa.analyzeWpaCapture(capture);
  assert.equal(analysis.eapolCount, 4);
  assert.equal(analysis.hasHandshake, true);
  assert.equal(analysis.keyDescriptorVersion, 2);
  // 沙箱红线：analysis 的数组是 vm realm 的，断言前 Array.from 转主 realm
  assert.deepEqual(Array.from(analysis.ssidCandidates), ['labnet']);
  assert.deepEqual(Array.from(analysis.pairwiseCiphers), ['CCMP-128']);
  assert.deepEqual(Array.from(analysis.akmSuites), ['PSK']);
  assert.equal(analysis.protectedDataFrames, 3);
  assert.equal(analysis.rejection, null);
});

test('decryptWpaCapture：MIC 全过、2 帧解密、WEP 帧拒绝、Ethernet pcap 走通流量链', () => {
  const capture = fullCapture(127);
  const result = wpa.decryptWpaCapture(capture, { passphrase: GOLDEN.password, ssid: GOLDEN.ssid });
  assert.equal(result.authFailure, false);
  assert.equal(result.micCheckedCount, 3); // M2/M3/M4
  assert.equal(result.micVerified, true);
  assert.equal(result.decrypted.length, 2);
  assert.equal(result.fcsTrimmed, 0);
  // 帧 A（STA→AP ToDS）：以太网 dst=AP src=STA，净载为完整 IPv4 包
  const frameA = result.decrypted[0];
  assert.equal(frameA.dst, '02:11:22:33:44:55');
  assert.equal(frameA.src, '66:77:88:99:aa:bb');
  assert.equal(frameA.ethertype, 0x0800);
  assert.ok(latin1(frameA.payload).includes('flag{ccmp_g0lden}'));
  // 帧 B（AP→STA FromDS）：方向翻转
  const frameB = result.decrypted[1];
  assert.equal(frameB.dst, '66:77:88:99:aa:bb');
  assert.equal(frameB.src, '02:11:22:33:44:55');
  assert.ok(latin1(frameB.payload).includes('flag{wpa2_g0lden_v3c}'));
  // WEP 形态帧 C 进 rejected
  assert.equal(result.rejected.length, 1);
  assert.match(result.rejected[0].reason, /WEP/);
  assert.equal(result.rejected[0].frameIndex, 7);
  // PMK/PTK 与黄金一致
  assert.equal(bytesToHex(result.pmk), GOLDEN.pmk);
  assert.equal(bytesToHex(result.ptk), GOLDEN.ptk);
  // 重建 Ethernet pcap → 既有流量链：parseCapture → buildPacketViews → analyzeCapture flag 命中
  const rebuilt = parser.parseCapture(result.ethernetPcap);
  assert.equal(rebuilt.linkType, 1);
  assert.equal(rebuilt.packets.length, 2);
  const views = protocols.buildPacketViews(rebuilt);
  const analysis = analyze.analyzeCapture(views);
  const flagSamples = analysis.flags.map(hit => hit.sample);
  assert.ok(flagSamples.includes('flag{ccmp_g0lden}'), `flags=${JSON.stringify(flagSamples)}`);
  assert.ok(flagSamples.includes('flag{wpa2_g0lden_v3c}'), `flags=${JSON.stringify(flagSamples)}`);
  assert.equal(analysis.streamTotal, 1); // 请求/响应归并同一条 TCP 流
});

test('decryptWpaCapture：裸 802.11（linktype 105）同样全链成立', () => {
  const capture = fullCapture(105);
  const result = wpa.decryptWpaCapture(capture, { passphrase: GOLDEN.password, ssid: GOLDEN.ssid });
  assert.equal(result.micVerified, true);
  assert.equal(result.decrypted.length, 2);
  const rebuilt = parser.parseCapture(result.ethernetPcap);
  const analysis = analyze.analyzeCapture(protocols.buildPacketViews(rebuilt));
  assert.ok(analysis.flags.some(hit => hit.sample === 'flag{ccmp_g0lden}'));
});

test('decryptWpaCapture：错口令确定性拒绝（authFailure，零解密，可复现）', () => {
  const capture = fullCapture(105);
  const first = wpa.decryptWpaCapture(capture, { passphrase: 'wrong-password', ssid: GOLDEN.ssid });
  const second = wpa.decryptWpaCapture(capture, { passphrase: 'wrong-password', ssid: GOLDEN.ssid });
  assert.equal(first.authFailure, true);
  assert.equal(first.micVerified, false);
  assert.equal(first.micCheckedCount, 3);
  assert.equal(first.decrypted.length, 0);
  assert.deepEqual(Array.from(first.ethernetPcap), Array.from(second.ethernetPcap));
});

test('decryptWpaCapture：错 SSID 确定性拒绝', () => {
  const capture = fullCapture(105);
  const result = wpa.decryptWpaCapture(capture, { passphrase: GOLDEN.password, ssid: 'notlabnet' });
  assert.equal(result.authFailure, true);
  assert.equal(result.decrypted.length, 0);
});

// ---- 抓包级显式拒绝 ----

const patchedFrame = (frameBytes, byteOffset, value) => {
  const bytes = frameBytes.slice();
  bytes[byteOffset] = value;
  return bytes;
};

test('TKIP（描述符版本 1）抓包级拒绝', () => {
  // M2 帧 KeyInfo 在 EAPOL 偏移 5 = 帧偏移 24+8+5 = 37；版本 1 + pairwise + mic = 0x0109
  const tkipM2 = patchedFrame(F.m2, 37, 0x09);
  const capture = framesToCapture([F.beacon, F.m1, tkipM2], 105);
  assert.throws(() => wpa.decryptWpaCapture(capture, { passphrase: GOLDEN.password, ssid: GOLDEN.ssid }), /TKIP/);
});

test('PMF/描述符版本 3 抓包级拒绝', () => {
  const v3M2 = patchedFrame(F.m2, 37, 0x0b); // 版本 3 + pairwise + mic = 0x010B
  const capture = framesToCapture([F.m1, v3M2], 105);
  assert.throws(() => wpa.decryptWpaCapture(capture, { passphrase: GOLDEN.password, ssid: GOLDEN.ssid }), /版本 3/);
});

test('WPA3（SAE-only AKM beacon）抓包级拒绝', () => {
  // beacon 最后一字节为 AKM 套件类型 02(PSK) → 08(SAE)
  const saeBeacon = patchedFrame(F.beacon, F.beacon.length - 1, 0x08);
  const capture = framesToCapture([saeBeacon, F.m1, F.m2], 105);
  assert.throws(() => wpa.decryptWpaCapture(capture, { passphrase: GOLDEN.password, ssid: GOLDEN.ssid }), /SAE|WPA3/);
});

test('无握手 / 无受保护数据帧 / Ethernet 链路层类型拒绝', () => {
  const beaconOnly = framesToCapture([F.beacon], 105);
  assert.throws(() => wpa.decryptWpaCapture(beaconOnly, { passphrase: GOLDEN.password, ssid: GOLDEN.ssid }), /握手/);
  const handshakeOnly = framesToCapture([F.m1, F.m2], 105);
  assert.throws(() => wpa.decryptWpaCapture(handshakeOnly, { passphrase: GOLDEN.password, ssid: GOLDEN.ssid }), /CCMP 保护的 data 帧/);
  assert.throws(() => {
    const ethBytes = pcapFromRecords([{ data: new Uint8Array(60) }], { linkType: 1 });
    wpa.decryptWpaCapture(parser.parseCapture(ethBytes), { passphrase: 'x'.repeat(8), ssid: 's' });
  }, /链路层/);
});

test('口令/SSID 为空参数拒绝', () => {
  const capture = fullCapture(105);
  assert.throws(() => wpa.decryptWpaCapture(capture, { passphrase: '', ssid: GOLDEN.ssid }), /口令/);
  assert.throws(() => wpa.decryptWpaCapture(capture, { passphrase: GOLDEN.password, ssid: '' }), /SSID/);
});
