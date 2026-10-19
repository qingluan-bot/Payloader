// 批次二 Lane K 流量分析补强测试：FTP 控制/数据流配对提取（B2-5）、MQTT 流解析与主题表（B2-9）、
// HTTP body 压缩多层解码（B2-10）。全部抓包样本程序化自造（无外部 fixture、无网络依赖）；
// 权威对拍源：SHA-256 用 node:crypto（FIPS 180-4），压缩样本用 node:zlib（gzip/deflate 互为对拍）。
// 加载方式统一走 tests/helpers/compileTsModule.mjs（T4 测试基建收敛）。
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import ts from 'typescript';
import zlib from 'node:zlib';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();

const parser = loadModule(path.join(srcDir, 'utils', 'ctf', 'pcap', 'parser.ts'));
const protocols = loadModule(path.join(srcDir, 'utils', 'ctf', 'pcap', 'protocols.ts'));
const analyze = loadModule(path.join(srcDir, 'utils', 'ctf', 'pcap', 'analyze.ts'));

// ---- 样本构造工具（按规范手工拼字节，与 tests/pcap-analysis.test.mjs 同族） ----

const u16be = value => Uint8Array.from([(value >> 8) & 0xff, value & 0xff]);
const u32be = value => Uint8Array.from([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
const u32le = value => Uint8Array.from([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]);
const u16le = value => Uint8Array.from([value & 0xff, (value >>> 8) & 0xff]);
const ipToBytes = dotted => Uint8Array.from(dotted.split('.').map(Number));
const ascii = text => Uint8Array.from(Buffer.from(text, 'latin1'));
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

const MAC = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

const ethFrame = (payload, ethertype = 0x0800) => concat([Uint8Array.from(MAC), Uint8Array.from(MAC, byte => byte + 1), u16be(ethertype), payload]);

const ipv4Packet = (protocol, srcIp, dstIp, payload, ident = 1) => {
  const header = concat([
    Uint8Array.from([0x45, 0x00]),
    u16be(20 + payload.length),
    u16be(ident),
    u16be(0x4000),
    Uint8Array.from([64, protocol, 0, 0]),
    ipToBytes(srcIp),
    ipToBytes(dstIp),
  ]);
  return concat([header, payload]);
};

const tcpSegment = (seq, ack, flags, sport, dport, payload) => concat([
  u16be(sport),
  u16be(dport),
  u32be(seq),
  u32be(ack),
  Uint8Array.from([0x50, flags]),
  u16be(0x2000),
  u16be(0),
  u16be(0),
  payload,
]);

const pcapFromFrames = (frames, { tsSec = 1700000000, tsFrac = 0 } = {}) => {
  const header = concat([
    Uint8Array.from([0xd4, 0xc3, 0xb2, 0xa1]),
    u16le(2),
    u16le(4),
    u32le(0),
    u32le(0),
    u32le(262144),
    u32le(1),
  ]);
  const records = frames.map(frame => concat([u32le(tsSec), u32le(tsFrac), u32le(frame.length), u32le(frame.length), frame]));
  return concat([header, ...records]);
};

const parseAndAnalyze = bytes => {
  const capture = parser.parseCapture(bytes);
  const views = protocols.buildPacketViews(capture);
  const analysis = analyze.analyzeCapture(views);
  return { capture, views, analysis };
};

const CLIENT = '192.168.1.10';
const SERVER = '93.184.216.34';

// TCP 数据段帧：单段（PSH+ACK），seq 独立以避免与控制流混淆。
const dataSegment = (srcIp, dstIp, sport, dport, seq, payload) =>
  ethFrame(ipv4Packet(6, srcIp, dstIp, tcpSegment(seq, 1, 0x18, sport, dport, payload)));

// 控制流帧构造：事件列表逐条成包，同方向 seq 自动顺次推进（杜绝手工算偏移导致的段重叠）。
const buildControlExchange = (events, { cport, sport = 21 }) => {
  let clientSeq = 1001;
  let serverSeq = 5001;
  return events.map(event => {
    const bytes = ascii(event.text);
    const frame = event.fromClient
      ? dataSegment(CLIENT, SERVER, cport, sport, clientSeq, bytes)
      : dataSegment(SERVER, CLIENT, sport, cport, serverSeq, bytes);
    if (event.fromClient) clientSeq += bytes.length;
    else serverSeq += bytes.length;
    return frame;
  });
};

// ---- SHA-256（FIPS 180-4）：NIST 标准向量 + node:crypto 任意长度对拍 ----

test('sha256Hex：NIST "abc" 向量与 node:crypto 多长度对拍', () => {
  assert.equal(analyze.sha256Hex(ascii('abc')), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(analyze.sha256Hex(new Uint8Array(0)), crypto.createHash('sha256').update(Buffer.alloc(0)).digest('hex'));
  for (const length of [1, 55, 56, 64, 65, 1000]) {
    const bytes = crypto.randomBytes(length);
    assert.equal(analyze.sha256Hex(new Uint8Array(bytes)), crypto.createHash('sha256').update(bytes).digest('hex'), `length=${length}`);
  }
});

// ---- FTP（B2-5）：主动 PORT + RETR 文件下载 ----

const PNG_BYTES = concat([
  Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  Uint8Array.from([0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52]),
  crypto.randomBytes(32),
]);

test('FTP 主动模式：PORT 公告 + RETR，文件字节逐位一致且 SHA-256 正确', () => {
  const control = buildControlExchange([
    { fromClient: true, text: 'USER anonymous\r\nPASS guest@example.com\r\nTYPE I\r\nPORT 192,168,1,10,199,88\r\nRETR secret.png\r\n' },
    { fromClient: false, text: '220 FTP server ready\r\n331 Password required\r\n230 User logged in\r\n200 Type set\r\n200 PORT command successful\r\n150 Opening BINARY mode\r\n226 Transfer complete\r\n' },
  ], { cport: 51000, sport: 21 });
  // 主动模式数据流：服务器 20 端口 → 客户端公告端口 51032（199*256+88）。
  const data = dataSegment(SERVER, CLIENT, 20, 51032, 9001, PNG_BYTES);
  const { analysis } = parseAndAnalyze(pcapFromFrames([...control, data]));
  const sessions = analyze.analyzeFtp(analysis);
  assert.equal(sessions.length, 1);
  const session = sessions[0];
  assert.equal(session.client, `${CLIENT}:51000`);
  assert.equal(session.server, `${SERVER}:21`);
  assert.equal(session.username, 'anonymous');
  assert.equal(session.password, 'guest@example.com');
  assert.equal(session.loggedIn, true);
  assert.equal(session.ftps, false);
  assert.equal(session.transfers.length, 1);
  const transfer = session.transfers[0];
  assert.equal(transfer.command, 'RETR');
  assert.equal(transfer.filename, 'secret.png');
  assert.equal(transfer.mode, 'active');
  assert.equal(transfer.announcedEndpoint, `${CLIENT}:51032`);
  assert.equal(transfer.status, 'ok');
  assert.equal(transfer.direction, 'server-to-client');
  assert.equal(transfer.fallbackMatch, false);
  assert.notEqual(transfer.dataStreamId, null);
  assert.equal(transfer.size, PNG_BYTES.length);
  assert.ok(Buffer.from(transfer.bytes).equals(Buffer.from(PNG_BYTES)), '导出文件字节应逐位一致');
  assert.equal(transfer.sha256, crypto.createHash('sha256').update(PNG_BYTES).digest('hex'));
});

// ---- FTP（B2-5）：被动 PASV + STOR 上传 ----

test('FTP 被动模式：227 公告按包序先于 STOR 配对，客户端→服务器字节导出', () => {
  // 每条命令独立成包，验证跨方向的公告→命令按包序交错配对（227 先到，STOR 后到）。
  const control = buildControlExchange([
    { fromClient: true, text: 'USER ftp\r\nPASS x\r\n' },
    { fromClient: false, text: '220 ready\r\n331 pass\r\n230 ok\r\n' },
    { fromClient: true, text: 'PASV\r\n' },
    { fromClient: false, text: '227 Entering Passive Mode (93,184,216,34,200,15)\r\n' },
    { fromClient: true, text: 'STOR upload.txt\r\n' },
    { fromClient: false, text: '150 ok\r\n226 ok\r\n' },
  ], { cport: 51000, sport: 21 });
  const payload = ascii('flag{ftp_stor_passive}');
  const data = dataSegment(CLIENT, SERVER, 51200, 51215, 7001, payload); // 200*256+15 = 51215
  const { analysis } = parseAndAnalyze(pcapFromFrames([...control, data]));
  const sessions = analyze.analyzeFtp(analysis);
  assert.equal(sessions.length, 1);
  const session = sessions[0];
  assert.equal(session.transfers.length, 1, `transfers=${JSON.stringify(session.transfers.map(t => t.status))}`);
  const transfer = session.transfers[0];
  assert.equal(transfer.command, 'STOR');
  assert.equal(transfer.filename, 'upload.txt');
  assert.equal(transfer.mode, 'passive');
  assert.equal(transfer.announcedEndpoint, `${SERVER}:51215`);
  assert.equal(transfer.status, 'ok');
  assert.equal(transfer.direction, 'client-to-server');
  assert.ok(Buffer.from(transfer.bytes).equals(Buffer.from(payload)));
  assert.equal(transfer.sha256, crypto.createHash('sha256').update(payload).digest('hex'));
});

// ---- FTP（B2-5）：配对冲突如实声明 ----

test('FTP 配对冲突：ok / 无公告 / 数据流已占用 / 公告无数据流 逐一如实声明', () => {
  const control = buildControlExchange([
    { fromClient: true, text: 'PORT 192,168,1,10,200,10\r\nRETR a.bin\r\nRETR b.bin\r\nPORT 192,168,1,10,200,10\r\nRETR dup.bin\r\nPORT 192,168,1,10,200,11\r\nLIST\r\n' },
    { fromClient: false, text: '220 ok\r\n200 ok\r\n150 ok\r\n226 ok\r\n150 ok\r\n226 ok\r\n150 ok\r\n226 ok\r\n' },
  ], { cport: 51001, sport: 21 });
  // 只有 51210（200*256+10）有真实数据流；51211 无数据流。
  const dataA = dataSegment(SERVER, CLIENT, 20, 51210, 9001, ascii('AAA-BIN-CONTENT'));
  const { analysis } = parseAndAnalyze(pcapFromFrames([...control, dataA]));
  const sessions = analyze.analyzeFtp(analysis);
  assert.equal(sessions.length, 1);
  const transfers = sessions[0].transfers;
  // vm 沙箱 realm 的数组 deepEqual 必失败（原型不同），统一 Array.from 转主 realm 再断言。
  assert.deepEqual(Array.from(transfers, transfer => transfer.status), ['ok', 'no-announcement', 'stream-consumed', 'stream-missing']);
  assert.notEqual(transfers[0].dataStreamId, null);
  assert.equal(transfers[1].announcedEndpoint, null);
  assert.match(transfers[1].note, /没有未消费的数据端点公告/);
  assert.match(transfers[2].note, /已被先前传输占用/);
  assert.match(transfers[3].note, /没有匹配到数据流/);
  assert.equal(transfers[3].command, 'LIST');
});

test('FTP NAT 兜底：公告 IP 与抓包不符时按端口+对端 IP 匹配并声明 fallback', () => {
  const control = buildControlExchange([
    { fromClient: true, text: 'USER anon\r\nPORT 10,0,0,99,200,40\r\nRETR natfile.txt\r\n' },
    { fromClient: false, text: '220 ok\r\n331 pass\r\n230 ok\r\n200 ok\r\n150 ok\r\n226 ok\r\n' },
  ], { cport: 51002, sport: 21 });
  // 公告 10.0.0.99:51240（200*256+40），实际抓到的数据流是 192.168.1.10:51240。
  const data = dataSegment(SERVER, CLIENT, 20, 51240, 9001, ascii('NAT-FILE'));
  const { analysis } = parseAndAnalyze(pcapFromFrames([...control, data]));
  const sessions = analyze.analyzeFtp(analysis);
  assert.equal(sessions.length, 1);
  const transfer = sessions[0].transfers[0];
  assert.equal(transfer.status, 'ok');
  assert.equal(transfer.fallbackMatch, true);
  assert.ok(Buffer.from(transfer.bytes).equals(Buffer.from(ascii('NAT-FILE'))));
  assert.ok(sessions[0].notes.some(note => note.includes('兜底匹配')));
});

test('FTPS：AUTH TLS 显式声明不支持解密', () => {
  const control = buildControlExchange([
    { fromClient: true, text: 'AUTH TLS\r\nUSER u\r\nPASS p\r\n' },
    { fromClient: false, text: '234 AUTH TLS successful\r\n331 pass\r\n230 ok\r\n' },
  ], { cport: 51003, sport: 21 });
  const { analysis } = parseAndAnalyze(pcapFromFrames(control));
  const sessions = analyze.analyzeFtp(analysis);
  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].ftps, true);
  assert.ok(sessions[0].notes.some(note => note.includes('FTPS')));
});

test('FTP 非标准端口：2121 上按 USER+三位应答内容特征识别控制流', () => {
  const control = buildControlExchange([
    { fromClient: true, text: 'USER ctfuser\r\nPORT 192,168,1,10,200,50\r\nRETR file.bin\r\n' },
    { fromClient: false, text: '220 content-ftp\r\n331 pass\r\n200 ok\r\n150 ok\r\n226 ok\r\n' },
  ], { cport: 51004, sport: 2121 });
  const data = dataSegment(SERVER, CLIENT, 20, 51250, 9001, ascii('CONTENT-MATCH')); // 200*256+50 = 51250
  const { analysis } = parseAndAnalyze(pcapFromFrames([...control, data]));
  const sessions = analyze.analyzeFtp(analysis);
  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].server, `${SERVER}:2121`);
  assert.equal(sessions[0].username, 'ctfuser');
  assert.equal(sessions[0].transfers[0].status, 'ok');
});

// ---- MQTT（B2-9）：报文构造工具 ----

const mqttString = text => {
  const bytes = Buffer.from(text, 'utf8');
  return concat([u16be(bytes.length), new Uint8Array(bytes)]);
};

// 剩余长度变长编码（spec 2.2.3）：低 7 位数值 + 续位。
const mqttEncodeRemaining = value => {
  const bytes = [];
  let remaining = value;
  do {
    let digit = remaining % 128;
    remaining = Math.floor(remaining / 128);
    if (remaining > 0) digit |= 0x80;
    bytes.push(digit);
  } while (remaining > 0);
  return Uint8Array.from(bytes);
};

const mqttPacket = (typeByte, body) => concat([Uint8Array.from([typeByte]), mqttEncodeRemaining(body.length), body]);

test('MQTT 会话：CONNECT/PUBLISH(QoS0/1)/SUBSCRIBE/PINGREQ 解析与主题表聚合', () => {
  const connectBody = concat([
    mqttString('MQTT'),
    Uint8Array.from([4, 0x02]), // level 4（3.1.1）+ clean session
    u16be(60),
    mqttString('ctf-client'),
  ]);
  const publishQos0 = mqttPacket(0x30, concat([mqttString('ctf/status'), ascii('flag{mqtt_plain}')]));
  const pngPayload = PNG_BYTES.subarray(0, 8);
  const publishQos1 = mqttPacket(0x32, concat([mqttString('ctf/bin'), u16be(1), pngPayload]));
  const subscribe = mqttPacket(0x82, concat([u16be(10), mqttString('ctf/#'), Uint8Array.from([1])]));
  const pingreq = mqttPacket(0xc0, new Uint8Array(0));
  const connack = mqttPacket(0x20, Uint8Array.from([0, 0]));
  const frames = [
    dataSegment(CLIENT, SERVER, 51010, 1883, 1001, concat([
      mqttPacket(0x10, connectBody), publishQos0, publishQos1, subscribe, pingreq,
    ])),
    dataSegment(SERVER, CLIENT, 1883, 51010, 5001, connack),
  ];
  const { analysis } = parseAndAnalyze(pcapFromFrames(frames));
  const sessions = analyze.analyzeMqtt(analysis);
  assert.equal(sessions.length, 1);
  const session = sessions[0];
  assert.equal(session.client, `${CLIENT}:51010`);
  assert.equal(session.server, `${SERVER}:1883`);
  assert.equal(session.protocolName, 'MQTT');
  assert.equal(session.protocolLevel, 4);
  assert.equal(session.clientId, 'ctf-client');

  const byType = typeName => session.packets.filter(packet => packet.typeName === typeName);
  assert.deepEqual(byType('CONNECT').length, 1);
  assert.deepEqual(byType('PINGREQ').length, 1);
  assert.deepEqual(byType('CONNACK').length, 1);
  const qos0 = byType('PUBLISH').find(packet => packet.topic === 'ctf/status');
  assert.ok(qos0);
  assert.equal(qos0.qos, 0);
  assert.equal(new TextDecoder('utf-8').decode(qos0.payload), 'flag{mqtt_plain}');
  assert.equal(qos0.hasFlag, true, 'PUBLISH 载荷 flag 扫描应命中');
  assert.ok(qos0.packetIndex >= 0, 'MQTT 报文应定位到具体包');
  const qos1 = byType('PUBLISH').find(packet => packet.topic === 'ctf/bin');
  assert.ok(qos1);
  assert.equal(qos1.qos, 1);
  assert.equal(qos1.packetId, 1, 'QoS1 PUBLISH 应解出包标识符');
  const subscribePacket = byType('SUBSCRIBE')[0];
  assert.deepEqual(Array.from(subscribePacket.topicFilters), ['ctf/#']);
  assert.equal(subscribePacket.packetId, 10);

  // 主题表聚合：topic × 消息数 + 载荷魔数识别（PNG 魔数）+ flag。
  assert.equal(session.topics.length, 2);
  const statusRow = session.topics.find(row => row.topic === 'ctf/status');
  assert.equal(statusRow.count, 1);
  assert.equal(statusRow.hasFlag, true);
  const binRow = session.topics.find(row => row.topic === 'ctf/bin');
  assert.equal(binRow.magic, 'PNG image');
  assert.deepEqual(Array.from(binRow.qosLevels), [1]);
});

test('MQTT 剩余长度多字节：0xAC 0x02 = 300 字节形态正确解码', () => {
  // topic 't' 占 3 字节（2 长度 + 1 内容），payload 297 字节 → 剩余长度 300。
  const payload = crypto.randomBytes(297);
  const body = concat([mqttString('t'), payload]);
  assert.equal(body.length, 300);
  const packet300 = concat([Uint8Array.from([0x30]), Uint8Array.from([0xac, 0x02]), body]);
  assert.deepEqual(Array.from(packet300.subarray(1, 3)), [0xac, 0x02], '编码形态必须是 0xAC 0x02');
  const frames = [
    dataSegment(CLIENT, SERVER, 51011, 1883, 1001, concat([
      mqttPacket(0x10, concat([mqttString('MQTT'), Uint8Array.from([4, 0x02]), u16be(60), mqttString('cid')])),
      packet300,
    ])),
  ];
  const { analysis } = parseAndAnalyze(pcapFromFrames(frames));
  const sessions = analyze.analyzeMqtt(analysis);
  assert.equal(sessions.length, 1);
  const publishes = sessions[0].packets.filter(packet => packet.typeName === 'PUBLISH');
  assert.equal(publishes.length, 1);
  assert.equal(publishes[0].topic, 't');
  assert.equal(publishes[0].payload.length, 297);
  assert.ok(Buffer.from(publishes[0].payload).equals(Buffer.from(payload)));
});

test('MQTT QoS2：PUBLISH 包标识符与 PUBACK 回执标识符解析', () => {
  const publishQos2 = mqttPacket(0x34, concat([mqttString('q2/topic'), u16be(0xbeef), ascii('payload')]));
  const puback = mqttPacket(0x40, u16be(0xbeef));
  const frames = [
    dataSegment(CLIENT, SERVER, 51012, 1883, 1001, concat([
      mqttPacket(0x10, concat([mqttString('MQTT'), Uint8Array.from([4, 0x02]), u16be(60), mqttString('cid2')])),
      publishQos2,
    ])),
    dataSegment(SERVER, CLIENT, 1883, 51012, 5001, puback),
  ];
  const { analysis } = parseAndAnalyze(pcapFromFrames(frames));
  const sessions = analyze.analyzeMqtt(analysis);
  assert.equal(sessions.length, 1);
  const publish = sessions[0].packets.find(packet => packet.typeName === 'PUBLISH');
  assert.equal(publish.qos, 2);
  assert.equal(publish.packetId, 0xbeef);
  const ack = sessions[0].packets.find(packet => packet.typeName === 'PUBACK');
  assert.equal(ack.packetId, 0xbeef);
  const row = sessions[0].topics.find(entry => entry.topic === 'q2/topic');
  assert.deepEqual(Array.from(row.qosLevels), [2]);
});

test('MQTT 中途抓包：无 CONNECT 但端口 1883 时按内容兜底接受', () => {
  const publish = mqttPacket(0x30, concat([mqttString('mid/topic'), ascii('mid-data')]));
  const frames = [dataSegment(CLIENT, SERVER, 40000, 1883, 1001, publish)];
  const { analysis } = parseAndAnalyze(pcapFromFrames(frames));
  const sessions = analyze.analyzeMqtt(analysis);
  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].clientId, null);
  assert.ok(sessions[0].notes.some(note => note.includes('CONNECT')));
  assert.equal(sessions[0].topics[0].topic, 'mid/topic');
});

// ---- HTTP body 多层解压（B2-10） ----

let httpPort = 52000;
const httpTransactionFrames = (responseHead, responseBodyBytes) => {
  httpPort += 1;
  const request = ascii('GET /file HTTP/1.1\r\nHost: ctf.example\r\n\r\n');
  const response = concat([ascii(responseHead), responseBodyBytes]);
  return [
    dataSegment(CLIENT, SERVER, httpPort, 80, 1001, request),
    dataSegment(SERVER, CLIENT, 80, httpPort, 5001, response),
  ];
};

test('HTTP gzip→base64→文本三层样本逐层还原', async () => {
  const finalText = 'flag{http_layers_3}';
  const base64Layer = Buffer.from(finalText, 'utf8').toString('base64');
  const gzipBody = zlib.gzipSync(Buffer.from(base64Layer, 'latin1'));
  const head = `HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Encoding: gzip\r\nContent-Length: ${gzipBody.length}\r\n\r\n`;
  const { analysis } = parseAndAnalyze(pcapFromFrames(httpTransactionFrames(head, gzipBody)));
  const decoded = await analyze.decodeHttpTransactionBodies(analysis.transactions);
  assert.equal(decoded.length, 1);
  const result = decoded[0];
  assert.equal(result.direction, 'res');
  assert.equal(result.contentEncoding, 'gzip');
  assert.equal(result.error, null);
  // vm 沙箱 realm 的数组 deepEqual 必失败（原型不同），统一 Array.from 转主 realm 再断言。
  assert.deepEqual(Array.from(result.layers, layer => layer.kind), ['原始 body', 'gzip 解压', 'base64 解码']);
  assert.equal(result.layers[0].byteLength, gzipBody.length);
  assert.equal(result.layers[1].byteLength, base64Layer.length);
  assert.equal(result.layers[2].byteLength, finalText.length);
  assert.equal(result.finalText, finalText);
  assert.ok(Buffer.from(result.finalBytes).equals(Buffer.from(finalText, 'utf8')));
});

test('HTTP deflate（789c 魔数）：单层解压还原', async () => {
  const text = 'flag{deflate_direct}';
  const deflateBody = zlib.deflateSync(Buffer.from(text, 'latin1'));
  assert.equal(deflateBody[0], 0x78, 'zlib 头 CMF 应为 0x78');
  const head = `HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\nContent-Length: ${deflateBody.length}\r\n\r\n`;
  const { analysis } = parseAndAnalyze(pcapFromFrames(httpTransactionFrames(head, deflateBody)));
  const decoded = await analyze.decodeHttpTransactionBodies(analysis.transactions);
  assert.equal(decoded.length, 1);
  assert.deepEqual(Array.from(decoded[0].layers, layer => layer.kind), ['原始 body', 'deflate 解压']);
  assert.equal(decoded[0].finalText, text);
  assert.equal(decoded[0].error, null);
});

test('HTTP 非压缩 body：不产生任何解压条目（零行为变化）', async () => {
  const head = 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\n';
  const { analysis } = parseAndAnalyze(pcapFromFrames(httpTransactionFrames(head, ascii('plain text!'))));
  const decoded = await analyze.decodeHttpTransactionBodies(analysis.transactions);
  assert.equal(decoded.length, 0);
});

test('HTTP 层深上限：gzip→base64→gzip→base64 解到 3 层后如实声明', async () => {
  const innermost = 'flag{deep}';
  const b1 = Buffer.from(innermost, 'utf8').toString('base64');
  const g1 = zlib.gzipSync(Buffer.from(b1, 'latin1'));
  const b2 = Buffer.from(g1).toString('base64');
  const g2 = zlib.gzipSync(Buffer.from(b2, 'latin1'));
  const head = `HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: ${g2.length}\r\n\r\n`;
  const { analysis } = parseAndAnalyze(pcapFromFrames(httpTransactionFrames(head, g2)));
  const decoded = await analyze.decodeHttpTransactionBodies(analysis.transactions);
  assert.equal(decoded.length, 1);
  const result = decoded[0];
  assert.deepEqual(Array.from(result.layers, layer => layer.kind), ['原始 body', 'gzip 解压', 'base64 解码', 'gzip 解压']);
  assert.notEqual(result.error, null);
  assert.match(result.error, /层深上限/);
  assert.equal(result.finalText, b1, '第 3 层产物（仍是 base64 文本）应如实呈现');
});

test('HTTP 内嵌 HTTP：gzip 产物是完整 HTTP 报文时提取其 body', async () => {
  const innerBody = 'flag{inner_http}';
  const inner = `HTTP/1.1 200 OK\r\nContent-Length: ${innerBody.length}\r\n\r\n${innerBody}`;
  const gzipBody = zlib.gzipSync(Buffer.from(inner, 'latin1'));
  const head = `HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: ${gzipBody.length}\r\n\r\n`;
  const { analysis } = parseAndAnalyze(pcapFromFrames(httpTransactionFrames(head, gzipBody)));
  const decoded = await analyze.decodeHttpTransactionBodies(analysis.transactions);
  assert.equal(decoded.length, 1);
  const result = decoded[0];
  assert.deepEqual(Array.from(result.layers, layer => layer.kind), ['原始 body', 'gzip 解压', '内嵌 HTTP body']);
  assert.equal(result.layers[2].byteLength, innerBody.length);
  assert.equal(result.finalText, innerBody);
  assert.equal(result.error, null);
});

// ---- UI 冒烟：TSX 经 ts.transpileModule（jsx: ReactJSX）零诊断 ----

test('TSX 冒烟：流量域 UI 改动文件转译零诊断', () => {
  const files = [
    'src/components/ctf/traffic/FtpCard.tsx',
    'src/components/ctf/traffic/MqttCard.tsx',
    'src/components/ctf/traffic/TrafficWorkspace.tsx',
    'src/components/ctf/traffic/HttpObjects.tsx',
  ];
  for (const relative of files) {
    const source = fs.readFileSync(path.join(projectRoot, relative), 'utf8');
    const result = ts.transpileModule(source, {
      compilerOptions: { target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
      fileName: relative,
      reportDiagnostics: true,
    });
    assert.deepEqual(result.diagnostics ?? [], [], `${relative} 应无转译诊断`);
  }
});
