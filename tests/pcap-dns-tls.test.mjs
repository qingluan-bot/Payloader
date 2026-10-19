// 批次二 Lane J：DNS 报文全量解析（RFC 1035）与 TLS ClientHello/ServerHello 提取（RFC 5246/6066）。
// 样本三种来源、全部独立可复核：
//   ① dnspython（权威实现）生成的 wire 字节（开发期双向对拍，向量以 hex 内嵌，见 SAMPLE_*_HEX 出处注释）；
//   ② 按 RFC 逐字段手算的字节（注释含偏移推演）；
//   ③ 程序化构造 pcap（复用 pcap-analysis.test.mjs 的帧构造风格）。
// 加载方式统一走 tests/helpers/compileTsModule.mjs（T4 测试基建收敛）。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import ts from 'typescript';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const protocols = loadModule(path.join(srcDir, 'utils', 'ctf', 'pcap', 'protocols.ts'));
const analyze = loadModule(path.join(srcDir, 'utils', 'ctf', 'pcap', 'analyze.ts'));
const parser = loadModule(path.join(srcDir, 'utils', 'ctf', 'pcap', 'parser.ts'));

// ---- 字节构造工具（与 pcap-analysis.test.mjs 同风格，测试本地自持） ----

const u16be = value => Uint8Array.from([(value >> 8) & 0xff, value & 0xff]);
const u24be = value => Uint8Array.from([(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]);
const u32be = value => Uint8Array.from([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
const u16le = value => Uint8Array.from([value & 0xff, (value >>> 8) & 0xff]);
const u32le = value => Uint8Array.from([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]);
const ipToBytes = dotted => Uint8Array.from(dotted.split('.').map(Number));
const ascii = text => Uint8Array.from(Buffer.from(text, 'latin1'));
const hex = text => Uint8Array.from(text.match(/../g).map(pair => parseInt(pair, 16)));
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
const bytesHex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');

const MAC = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const ethFrame = (payload, ethertype = 0x0800) => concat([Uint8Array.from(MAC), Uint8Array.from(MAC, byte => byte + 1), u16be(ethertype), payload]);
const ipv4Packet = (protocol, srcIp, dstIp, payload, ident = 1) => concat([
  Uint8Array.from([0x45, 0x00]),
  u16be(20 + payload.length),
  u16be(ident),
  u16be(0x4000),
  Uint8Array.from([64, protocol, 0, 0]),
  ipToBytes(srcIp),
  ipToBytes(dstIp),
  payload,
]);
const tcpSegment = (seq, ack, flags, sport, dport, payload) => concat([
  u16be(sport), u16be(dport), u32be(seq), u32be(ack),
  Uint8Array.from([0x50, flags]), u16be(0x2000), u16be(0), u16be(0), payload,
]);
const udpDatagram = (sport, dport, payload) => concat([u16be(sport), u16be(dport), u16be(8 + payload.length), u16be(0), payload]);

const u16 = (value, little) => (little ? u16le(value) : u16be(value));
const u32 = (value, little) => (little ? u32le(value) : u32be(value));
const pcapFromFrames = (frames, { little = true, tsSec = 1700000000, tsFrac = 0 } = {}) => {
  const header = concat([
    Uint8Array.from(little ? [0xd4, 0xc3, 0xb2, 0xa1] : [0xa1, 0xb2, 0xc3, 0xd4]),
    u16(2, little), u16(4, little), u32(0, little), u32(0, little), u32(262144, little), u32(1, little),
  ]);
  const records = frames.map(frame => concat([u32(tsSec, little), u32(tsFrac, little), u32(frame.length, little), u32(frame.length, little), frame]));
  return concat([header, ...records]);
};

const parseAndAnalyze = bytes => {
  const capture = parser.parseCapture(bytes);
  const views = protocols.buildPacketViews(capture);
  const analysis = analyze.analyzeCapture(views);
  return { capture, views, analysis };
};

// ---- dnspython 权威样本（开发期用 dnspython 2.x 生成并回读校验，hex 原样内嵌） ----
// 生成脚本要点：dns.message.make_query/make_response + to_wire()，dnspython 默认启用名字压缩。

// 样本 A：应答，question=www.flag-hunt.example/A，answer 区三条：
//   CNAME（所有者名是指针 0xC00C 指回 question 名）→ cdn.flag-hunt.example
//   A 203.0.113.7（cdn 名同为指针 0xC033）、AAAA 2001:db8::5。
const SAMPLE_A_HEX = '1234810000010003000000000377777709666c61672d68756e74076578616d706c650000010001c00c000500010000012c00060363646ec010c03300010001000000780004cb007107c033001c000100000078001020010db8000000000000000000000005';
// 样本 B：TXT 多字符串 + authority(NS/SOA) + additional(MX/PTR/SRV)。
const SAMPLE_B_HEX = '123481000001000100020003047a6f6e65076578616d706c650000100001c00c001000010000003c002016666c61677b646e73707974686f6e5f616e63686f727d08706172742d74776fc00c00020001000151800006036e7331c00cc00c0006000100000e10001ec0560561646d696ec00c78a3f17500001c2000000e10001275000000012c046d61696cc00c000f0001000002580008000a036d7831c00c013501340133013201300130013001300130013001300130013001300130013001300130013001300130013001300138016201640130013101300130013203697036046172706100000c000100000384000704686f7374c00c045f736970045f746370c00c002100010000012c00180005001413c403736970047a6f6e65076578616d706c6500';
// 样本 C：查询报文（QR=0，RD=1），question=ctf.example/AAAA。
const SAMPLE_C_HEX = 'beef0100000100000000000003637466076578616d706c6500001c0001';

// ---- DNS：dnspython 样本逐字段对拍 ----

test('dnspython 样本 A：应答头字段与 CNAME 压缩指针链', () => {
  const message = protocols.parseDnsMessage(hex(SAMPLE_A_HEX));
  assert.ok(message);
  assert.equal(message.id, 0x1234);
  assert.equal(message.isResponse, true);
  assert.equal(message.opcode, 0);
  assert.equal(message.opcodeText, 'QUERY');
  assert.equal(message.rcode, 0);
  assert.equal(message.rcodeText, 'NOERROR');
  assert.equal(message.parseError, null);
  // 跨 realm 数组不用 deepStrictEqual（vm 沙箱原型不同），统一 Array.from 转换后比较。
  assert.deepEqual(Array.from(message.questions, q => `${q.name}|${q.typeText}|${q.classText}`), ['www.flag-hunt.example|A|IN']);
  const answers = Array.from(message.records, r => `${r.section}|${r.name}|${r.typeText}|${r.ttl}|${r.value}`);
  assert.deepEqual(answers, [
    'answer|www.flag-hunt.example|CNAME|300|cdn.flag-hunt.example',
    'answer|cdn.flag-hunt.example|A|120|203.0.113.7',
    'answer|cdn.flag-hunt.example|AAAA|120|2001:db8::5',
  ]);
});

test('dnspython 样本 B：TXT 逐段拼接与 NS/SOA/MX/PTR/SRV 全类型', () => {
  const message = protocols.parseDnsMessage(hex(SAMPLE_B_HEX));
  assert.ok(message);
  assert.equal(message.parseError, null);
  const txt = message.records.find(record => record.typeText === 'TXT');
  assert.ok(txt, 'TXT 记录必须存在');
  // 逐值断言：两个 character-string（RFC 1035 §3.3.14），拼接值 == 串接。
  assert.deepEqual(Array.from(txt.values), ['flag{dnspython_anchor}', 'part-two']);
  assert.equal(txt.value, 'flag{dnspython_anchor}part-two');
  assert.equal(txt.ttl, 60);
  const byType = typeText => Array.from(message.records.filter(record => record.typeText === typeText), r => `${r.name}|${r.ttl}|${r.value}`);
  assert.deepEqual(byType('NS'), ['zone.example|86400|ns1.zone.example']);
  assert.deepEqual(byType('SOA'), ['zone.example|3600|ns1.zone.example admin.zone.example 2024010101 7200 3600 1209600 300']);
  assert.deepEqual(byType('MX'), ['mail.zone.example|600|10 mx1.zone.example']);
  // 反解 PTR 名（权威口径：dnspython from_wire 回读本样本同字节，5.4.3.2 后跟 19 个零标签）。
  const ptrName = `5.4.3.2.${'0.'.repeat(19)}8.b.d.0.1.0.0.2.ip6.arpa`;
  assert.deepEqual(byType('PTR'), [`${ptrName}|900|host.zone.example`]);
  assert.deepEqual(byType('SRV'), ['_sip._tcp.zone.example|300|5 20 5060 sip.zone.example']);
  // 三区归属：1 answer（TXT）+ 2 authority（NS/SOA）+ 3 additional（MX/PTR/SRV）。
  assert.equal(message.records.filter(record => record.section === 'answer').length, 1);
  assert.equal(message.records.filter(record => record.section === 'authority').length, 2);
  assert.equal(message.records.filter(record => record.section === 'additional').length, 3);
});

test('dnspython 样本 C：查询报文 QR/RD 位与 question', () => {
  const message = protocols.parseDnsMessage(hex(SAMPLE_C_HEX));
  assert.ok(message);
  assert.equal(message.id, 0xbeef);
  assert.equal(message.isResponse, false);
  assert.equal(message.recursionDesired, true);
  assert.deepEqual(Array.from(message.questions, q => `${q.name}|${q.typeText}|${q.classText}`), ['ctf.example|AAAA|IN']);
  assert.equal(message.records.length, 0);
});

// ---- DNS：手算字节（RFC 1035 §4.1 逐偏移推演，注释即权威依据） ----

test('手算样本：两层压缩指针链（answer 名 → rdata 名 → question 名）', () => {
  // 偏移推演：头 0-11；QNAME 12-21（01 'a' 01 'b' 04 'test' 00）；qtype/qclass 22-25；
  // answer 所有者名 26-27 = C0 0C（→12）；type/class 28-31（CNAME/IN）；
  // ttl 32-35 = 60；rdlength 36-37 = 2；rdata 38-39 = C0 1A（→26，链式再经 26 的 C0 0C 到 12）。
  const bytes = concat([
    hex('dead81800001000100000000'),
    ascii('\x01a\x01b\x04test\x00'), u16be(1), u16be(1),
    hex('c00c'), u16be(5), u16be(1), u32be(60), u16be(2), hex('c01a'),
  ]);
  const message = protocols.parseDnsMessage(bytes);
  assert.ok(message);
  assert.equal(message.parseError, null);
  assert.equal(message.records.length, 1);
  assert.equal(message.records[0].name, 'a.b.test');
  assert.equal(message.records[0].typeText, 'CNAME');
  assert.equal(message.records[0].value, 'a.b.test');
  assert.equal(message.records[0].ttl, 60);
});

test('手算样本：自指指针被拒、前向指针被拒、过短报文返回 null', () => {
  const build = answerName => concat([
    hex('dead81800001000100000000'),
    ascii('\x01a\x01b\x04test\x00'), u16be(1), u16be(1),
    answerName, u16be(5), u16be(1), u32be(60), u16be(2), hex('c00c'),
  ]);
  // 自指：指针位于偏移 26，指向 26 自己 → 拒绝，报文保留已解出的 question。
  const selfLoop = protocols.parseDnsMessage(build(hex('c01a')));
  assert.ok(selfLoop);
  assert.match(selfLoop.parseError ?? '', /回答区/);
  assert.equal(selfLoop.records.length, 0);
  assert.equal(selfLoop.questions.length, 1);
  // 前向：指针指向未写区域（0x40 = 64 > 报文长）→ 同样拒绝。
  const forward = protocols.parseDnsMessage(build(hex('c040')));
  assert.ok(forward);
  assert.match(forward.parseError ?? '', /回答区/);
  // 过短：不足 12 字节头直接 null。
  assert.equal(protocols.parseDnsMessage(Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8])), null);
});

// ---- DNS：UDP 通道进问答表 + TXT flag 扫描 ----

const UDP_TXT_FLAG_MESSAGE = concat([
  hex('abcd81800001000100000000'),
  // QNAME x.example（12-22），qtype/qclass TXT/IN（23-26）。
  ascii('\x01x\x07example\x00'), u16be(16), u16be(1),
  // answer：名 C0 0C（→12）、TXT/IN、ttl 60、rdlength 19、rdata = 长度 18 + 'flag{dns_txt_leak}'。
  hex('c00c'), u16be(16), u16be(1), u32be(60), u16be(19), ascii('\x12flag{dns_txt_leak}'),
]);

test('UDP 53：TXT 应答进问答表，flag 自动扫描命中', () => {
  const frame = ethFrame(ipv4Packet(17, '10.0.0.1', '10.0.0.2', udpDatagram(40000, 53, UDP_TXT_FLAG_MESSAGE)));
  const { views, analysis } = parseAndAnalyze(pcapFromFrames([frame]));
  assert.equal(views[0].isDns, true);
  assert.equal(analysis.dnsTotal, 1);
  const exchange = analysis.dnsExchanges[0];
  assert.equal(exchange.transport, 'UDP');
  assert.equal(exchange.packetIndex, 0);
  assert.equal(exchange.streamId, null);
  assert.equal(exchange.isResponse, true);
  assert.equal(exchange.rcodeText, 'NOERROR');
  assert.equal(exchange.hasFlag, true);
  assert.equal(exchange.parseError, null);
  // 问答表携带完整记录：TXT values 逐值 + TTL。
  const txt = exchange.records.find(record => record.typeText === 'TXT');
  assert.deepEqual(Array.from(txt.values), ['flag{dns_txt_leak}']);
  assert.equal(txt.ttl, 60);
  // flag 汇总面板命中，来源标注 DNS TXT。
  const hit = analysis.flags.find(candidate => candidate.sample === 'flag{dns_txt_leak}');
  assert.ok(hit);
  assert.match(hit.source, /DNS TXT · x\.example/);
});

test('UDP 53：查询与应答成对进表，统计口径 DNS=2', () => {
  const query = ethFrame(ipv4Packet(17, '10.0.0.1', '10.0.0.2', udpDatagram(40000, 53, hex(SAMPLE_C_HEX))));
  const response = ethFrame(ipv4Packet(17, '10.0.0.2', '10.0.0.1', udpDatagram(53, 40000, hex(SAMPLE_A_HEX))));
  const { analysis } = parseAndAnalyze(pcapFromFrames([query, response]));
  assert.equal(analysis.dnsTotal, 2);
  assert.equal(analysis.dnsExchanges[0].isResponse, false);
  assert.equal(analysis.dnsExchanges[0].id, 0xbeef);
  assert.equal(analysis.dnsExchanges[1].isResponse, true);
  assert.equal(analysis.dnsExchanges[1].records.length, 3);
  const statMap = Object.fromEntries(analysis.stats.map(row => [row.key, row.count]));
  assert.equal(statMap.DNS, 2);
  assert.equal(statMap.UDP, 2);
});

// ---- DNS over TCP（RFC 1035 §4.2.2 两字节长度前缀） ----

const dnsTcpFrame = (message, seq, sport, dport) => ethFrame(ipv4Packet(6, sport === 40001 ? '10.0.0.1' : '10.0.0.2', sport === 40001 ? '10.0.0.2' : '10.0.0.1', tcpSegment(seq, 0, 0x18, sport, dport, concat([u16be(message.length), message]))));

test('TCP 53：流重组后按长度前缀成帧，查询/应答/管线化四报文', () => {
  // 客户端两包三查询（首包单条 + 次包管线化两条，前缀+报文连排），服务器一包一条应答。
  const queryMessage = hex(SAMPLE_C_HEX);
  const pipelined = concat([u16be(queryMessage.length), queryMessage, u16be(queryMessage.length), queryMessage]);
  const frames = [
    dnsTcpFrame(queryMessage, 1000, 40001, 53),
    ethFrame(ipv4Packet(6, '10.0.0.1', '10.0.0.2', tcpSegment(1000 + 2 + queryMessage.length, 0, 0x18, 40001, 53, pipelined))),
    ethFrame(ipv4Packet(6, '10.0.0.2', '10.0.0.1', tcpSegment(5000, 0, 0x18, 53, 40001, concat([u16be(hex(SAMPLE_A_HEX).length), hex(SAMPLE_A_HEX)])))),
  ];
  const { analysis } = parseAndAnalyze(pcapFromFrames(frames));
  const tcpDns = analysis.dnsExchanges.filter(exchange => exchange.transport === 'TCP');
  assert.equal(tcpDns.length, 4);
  assert.ok(tcpDns.every(exchange => exchange.streamId === 0));
  assert.equal(tcpDns.filter(exchange => exchange.isResponse).length, 1);
  assert.equal(tcpDns.filter(exchange => !exchange.isResponse).length, 3);
  assert.equal(tcpDns.filter(exchange => exchange.isResponse)[0].records.length, 3);
  const statMap = Object.fromEntries(analysis.stats.map(row => [row.key, row.count]));
  // 统计口径按包计数（3 个 TCP 53 数据包），问答表按报文计数（4 条，管线化展开）。
  assert.equal(statMap.DNS, 3);
  assert.equal(statMap.TCP, 3);
});

test('TCP 53：非 DNS 端口流不进问答表（隔离性）', () => {
  const httpFrame = ethFrame(ipv4Packet(6, '10.0.0.9', '10.0.0.8', tcpSegment(1, 2, 0x18, 5000, 80, ascii('GET / HTTP/1.1\r\nHost: x\r\n\r\n'))));
  const { analysis } = parseAndAnalyze(pcapFromFrames([httpFrame]));
  assert.equal(analysis.dnsTotal, 0);
  assert.equal(analysis.dnsExchanges.length, 0);
});

// ---- TLS：手算 ClientHello / ServerHello（RFC 5246 §7.4.1.2 + RFC 6066 §3 结构） ----

const buildClientHelloRecord = ({ sniHost, withSessionId = true }) => {
  const random = Uint8Array.from({ length: 32 }, (_, index) => index);
  const sessionId = withSessionId ? Uint8Array.from({ length: 32 }, (_, index) => 0xa0 + index) : new Uint8Array(0);
  const hostBytes = ascii(sniHost);
  // SNI 扩展数据（RFC 6066 §3）：server_name_list_length(2) + [name_type(1)=host_name + length(2) + host]。
  const sniList = concat([u16be(3 + hostBytes.length), Uint8Array.from([0]), u16be(hostBytes.length), hostBytes]);
  // 第二个扩展（extended_master_secret 0x0017，空数据）验证扩展遍历不早退。
  const extensions = concat([u16be(0x0000), u16be(sniList.length), sniList, u16be(0x0017), u16be(0)]);
  const body = concat([
    u16be(0x0303),            // ClientHello.legacy_version
    random,
    Uint8Array.from([sessionId.length]), sessionId,
    u16be(2), u16be(0x1301),  // cipher_suites：1 个 TLS_AES_128_GCM_SHA256
    Uint8Array.from([1, 0]),  // compression_methods：null
    u16be(extensions.length), extensions,
  ]);
  const handshake = concat([Uint8Array.from([0x01]), u24be(body.length), body]);
  return concat([Uint8Array.from([0x16, 0x03, 0x01]), u16be(handshake.length), handshake]);
};

test('TLS ClientHello：SNI/random/session_id 提取一致', () => {
  const record = buildClientHelloRecord({ sniHost: 'flag-server.example', withSessionId: true });
  const handshakes = protocols.parseTlsHandshakes(record);
  assert.equal(handshakes.length, 1);
  const hello = handshakes[0];
  assert.equal(hello.kind, 'client');
  assert.equal(hello.recordVersion, 'TLS 1.0');
  assert.equal(hello.handshakeVersion, 'TLS 1.2');
  assert.equal(hello.sni, 'flag-server.example');
  assert.deepEqual(Array.from(hello.serverNames), ['flag-server.example']);
  // random 是 0x00..0x1f 的 32 字节；session_id 是 0xa0..0xbf 的 32 字节。
  assert.equal(hello.random.length, 32);
  assert.equal(bytesHex(hello.random), Array.from({ length: 32 }, (_, index) => index.toString(16).padStart(2, '0')).join(''));
  assert.equal(hello.sessionId.length, 32);
  assert.equal(bytesHex(hello.sessionId), Array.from({ length: 32 }, (_, index) => (0xa0 + index).toString(16).padStart(2, '0')).join(''));
  assert.equal(hello.truncated, false);
});

test('TLS ClientHello：无 session_id 时透出空值', () => {
  const record = buildClientHelloRecord({ sniHost: 'no-session.example', withSessionId: false });
  const [hello] = protocols.parseTlsHandshakes(record);
  assert.equal(hello.sni, 'no-session.example');
  assert.equal(hello.sessionId.length, 0);
});

test('TLS ServerHello：random/session_id 透出，SNI 为空', () => {
  // 手算：record 16 03 03 + handshake 02 + body（version 0303 + random 0x20..0x3f + sid 0x40..0x5f + cipher 1301 + compression 00）。
  const random = Uint8Array.from({ length: 32 }, (_, index) => 0x20 + index);
  const sessionId = Uint8Array.from({ length: 32 }, (_, index) => 0x40 + index);
  const body = concat([u16be(0x0303), random, Uint8Array.from([32]), sessionId, u16be(0x1301), Uint8Array.from([0])]);
  const handshake = concat([Uint8Array.from([0x02]), u24be(body.length), body]);
  const record = concat([Uint8Array.from([0x16, 0x03, 0x03]), u16be(handshake.length), handshake]);
  const [hello] = protocols.parseTlsHandshakes(record);
  assert.equal(hello.kind, 'server');
  assert.equal(hello.recordVersion, 'TLS 1.2');
  assert.equal(hello.handshakeVersion, 'TLS 1.2');
  assert.equal(hello.sni, null);
  assert.equal(hello.random.length, 32);
  assert.equal(bytesHex(hello.random), Array.from({ length: 32 }, (_, index) => (0x20 + index).toString(16).padStart(2, '0')).join(''));
  assert.equal(bytesHex(hello.sessionId), Array.from({ length: 32 }, (_, index) => (0x40 + index).toString(16).padStart(2, '0')).join(''));
});

test('TLS：握手消息跨 TCP 段重组后仍可提取 SNI', () => {
  const full = buildClientHelloRecord({ sniHost: 'split.example' });
  const splitAt = 20; // record 头 + 部分握手体，强制跨段。
  const frames = [
    ethFrame(ipv4Packet(6, '10.0.0.1', '10.0.0.2', tcpSegment(1000, 0, 0x18, 51000, 443, full.subarray(0, splitAt)))),
    ethFrame(ipv4Packet(6, '10.0.0.1', '10.0.0.2', tcpSegment(1000 + splitAt, 0, 0x18, 51000, 443, full.subarray(splitAt)))),
  ];
  const { analysis } = parseAndAnalyze(pcapFromFrames(frames));
  assert.equal(analysis.streamTotal, 1);
  const stream = analysis.streams[0];
  const handshakes = [...protocols.parseTlsHandshakes(stream.bufferAtoB), ...protocols.parseTlsHandshakes(stream.bufferBtoA)];
  assert.equal(handshakes.length, 1);
  assert.equal(handshakes[0].sni, 'split.example');
});

test('TLS：非 TLS 流与截断 record 容错', () => {
  // 跨 realm 数组不做 deepEqual（vm 沙箱原型不同），统一按长度断言。
  assert.equal(protocols.parseTlsHandshakes(ascii('GET / HTTP/1.1\r\nHost: x\r\n\r\n')).length, 0);
  const full = buildClientHelloRecord({ sniHost: 'x.example' });
  // record 头声明长度超过实际剩余 → 停止，不产出半截握手。
  assert.equal(protocols.parseTlsHandshakes(full.subarray(0, 8)).length, 0);
  assert.equal(protocols.parseTlsHandshakes(new Uint8Array(0)).length, 0);
});

// ---- UI 冒烟：TSX 语法层 transpileModule（类型检查由 npm run typecheck 口径负责） ----

test('UI 冒烟：DnsTlsCard 与 TrafficWorkspace transpileModule 零错误', () => {
  const compilerOptions = { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true };
  for (const relative of ['src/components/ctf/traffic/DnsTlsCard.tsx', 'src/components/ctf/traffic/TrafficWorkspace.tsx']) {
    const source = fs.readFileSync(path.join(projectRoot, relative), 'utf8');
    const { outputText, diagnostics } = ts.transpileModule(source, { compilerOptions, fileName: relative, reportDiagnostics: true });
    const errors = (diagnostics ?? []).filter(diagnostic => diagnostic.category === ts.DiagnosticCategory.Error);
    assert.deepEqual(errors, [], `${relative} 存在转译错误：${errors.map(error => ts.flattenDiagnosticMessageText(error.messageText, '\n')).join('; ')}`);
    assert.ok(outputText.length > 0);
  }
});
