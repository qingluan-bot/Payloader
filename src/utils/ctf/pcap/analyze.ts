// 流量分析（批次 L）：TCP 流重组、HTTP 报文级解析（Content-Length / chunked / 读到流尾）、
// 请求-响应配对、协议统计与 flag 定位扫描（复用智能解码 flag 格式清单）。
// 批次二补强（Lane K）：FTP 控制/数据流配对提取（RFC 959）、MQTT 3.1.1/5.0 流解析与主题表、
// HTTP body 压缩多层解码（RFC 7231 Content-Encoding + 魔数双判据，DecompressionStream）。
// 批次二补强（Lane J）：DNS 问答表——UDP 53 逐包 + TCP 53 流重组（RFC 1035 §4.2.2 两字节长度
// 前缀成帧）双通道合流，TXT 载荷自动过 flag 扫描。
// 输入只读；输出中的字节均为切片/拷贝，组件层可直接持有。
import { detectFlagFormats } from '../../codec/smartDecode';
import { detectFileTypes } from '../fileDetect';
import { parseDnsMessage, type DnsMessage, type DnsQuestion, type DnsRecord } from './protocols';
import type { PacketView } from './protocols';

// 单方向流拼接上限：超过即丢弃越界段并标记 truncated（防超大流吃内存）。
export const MAX_STREAM_BYTES = 2 * 1024 * 1024;
const MAX_HTTP_MESSAGES_PER_DIRECTION = 200;
const MAX_STREAMS = 500;
const MAX_HEADER_BYTES = 64 * 1024;

export interface FlagHit {
  prefix: string;
  sample: string;
  source: string;
}

export interface HttpHeader {
  name: string;
  value: string;
}

export interface HttpMessage {
  direction: 'req' | 'res';
  streamId: number;
  packetIndex: number;
  startLine: string;
  method: string;
  path: string;
  query: Array<[string, string]>;
  status: number | null;
  headers: HttpHeader[];
  bodyBytes: Uint8Array;
  bodyText: string;
  bodyTruncated: boolean;
  hasFlag: boolean;
}

export interface HttpTransaction {
  streamId: number;
  request: HttpMessage | null;
  response: HttpMessage | null;
}

export interface TcpStream {
  id: number;
  endpointA: string;
  endpointB: string;
  packetCount: number;
  byteCount: number;
  bufferAtoB: Uint8Array;
  bufferBtoA: Uint8Array;
  // 方向内"段起始偏移 → 包序号"映射（批次二 Lane K 增补）：FTP/MQTT 按行/报文定位归属包。
  offsetsAtoB: Array<{ start: number; packetIndex: number }>;
  offsetsBtoA: Array<{ start: number; packetIndex: number }>;
  truncated: boolean;
  hasFlag: boolean;
  packetIndexes: number[];
}

export interface CaptureAnalysis {
  stats: Array<{ key: string; count: number }>;
  streams: TcpStream[];
  streamTotal: number;
  transactions: HttpTransaction[];
  httpTotal: number;
  flags: FlagHit[];
  // DNS 问答表（Lane J）：UDP 53 与 TCP 53 双通道合流，按出现顺序排列。
  dnsExchanges: DnsExchange[];
  dnsTotal: number;
}

// DNS 问答表行（Lane J）：一条 DNS 报文一行，questions/records 携带域名/类型/值/TTL。
export interface DnsExchange {
  transport: 'UDP' | 'TCP';
  // UDP 为承载包的序号；TCP 重组后无单一归属包，取该流第一个数据包序号。
  packetIndex: number;
  streamId: number | null;
  id: number;
  isResponse: boolean;
  opcode: number;
  opcodeText: string;
  rcode: number;
  rcodeText: string;
  questions: DnsQuestion[];
  records: DnsRecord[];
  hasFlag: boolean;
  parseError: string | null;
}

// DNS 解析限量（Lane J）：问答表条数上限 + TCP 流单方向 DNS 报文数上限。
const MAX_DNS_EXCHANGES = 500;
const MAX_TCP_DNS_MESSAGES = 200;

interface StreamSide {
  segments: Array<{ rawSeq: number; length: number; packetIndex: number; bytes: Uint8Array }>;
}

const endpointOf = (view: PacketView, side: 'src' | 'dst'): string => {
  const ip = side === 'src' ? view.src : view.dst;
  const port = side === 'src' ? view.srcPort : view.dstPort;
  return port === null ? ip : `${ip}:${port}`;
};

// 相对 seq：以方向最小 seq 为基线（无符号差值）。乱序到达时"首个到达的包"未必 seq 最小，
// 因此基线在重组阶段统一取最小值；跨回绕窗口的极端场景会产生巨大相对值并被上限丢弃（标记 truncated）。
const relativeSeq = (seq: number, base: number): number => (seq - base) >>> 0;

interface DirectionBuffer {
  buffer: Uint8Array;
  offsets: Array<{ start: number; packetIndex: number }>;
  truncated: boolean;
}

const reassembleDirection = (side: StreamSide): DirectionBuffer => {
  const sorted = [...side.segments].sort((left, right) => left.rawSeq - right.rawSeq);
  const baseSeq = sorted.length ? sorted[0].rawSeq : 0;
  const ordered = sorted
    .map(segment => ({ relSeq: relativeSeq(segment.rawSeq, baseSeq), length: segment.length, packetIndex: segment.packetIndex, bytes: segment.bytes }))
    .sort((left, right) => left.relSeq - right.relSeq);
  let end = 0;
  for (const segment of ordered) {
    if (segment.relSeq >= MAX_STREAM_BYTES) continue;
    end = Math.max(end, Math.min(segment.relSeq + segment.length, MAX_STREAM_BYTES));
  }
  const buffer = new Uint8Array(end);
  const offsets: Array<{ start: number; packetIndex: number }> = [];
  const written = new Set<number>();
  let truncated = false;
  for (const segment of ordered) {
    if (segment.relSeq >= MAX_STREAM_BYTES) {
      truncated = true;
      continue;
    }
    if (segment.relSeq + segment.length > MAX_STREAM_BYTES) truncated = true;
    const copyLength = Math.min(segment.length, MAX_STREAM_BYTES - segment.relSeq);
    buffer.set(segment.bytes.subarray(0, copyLength), segment.relSeq);
    if (!written.has(segment.relSeq)) {
      offsets.push({ start: segment.relSeq, packetIndex: segment.packetIndex });
      written.add(segment.relSeq);
    }
  }
  offsets.sort((left, right) => left.start - right.start);
  return { buffer, offsets, truncated };
};

const packetIndexOf = (offsets: Array<{ start: number; packetIndex: number }>, offset: number): number => {
  let best = 0;
  for (const entry of offsets) {
    if (entry.start <= offset) best = entry.packetIndex;
    else break;
  }
  return best;
};

const REQUEST_LINE_STICKY = /([A-Za-z]{3,10}) ([^ \r\n]+) HTTP\/1\.[01]\r\n/y;
const STATUS_LINE_STICKY = /HTTP\/1\.[01] (\d{3})[^\r\n]*\r\n/y;
const NEXT_MESSAGE = /\r\n(?=(?:[A-Za-z]{3,10} [^ \r\n]+ HTTP\/1\.[01]\r\n)|(?:HTTP\/1\.[01] \d{3}\r\n))/g;

interface HttpHeaderPair {
  name: string;
  value: string;
}

interface RawHttpMessage {
  direction: 'req' | 'res';
  offset: number;
  bodyStart: number;
  bodyEnd: number;
  chunkedText: string | null;
  method: string;
  path: string;
  status: number | null;
  startLine: string;
  headers: HttpHeaderPair[];
}

const parseHeaderBlock = (text: string, cursor: number): { headers: HttpHeaderPair[]; end: number } | null => {
  const headers: HttpHeaderPair[] = [];
  let position = cursor;
  for (let guard = 0; guard < 128; guard += 1) {
    const lineEnd = text.indexOf('\r\n', position);
    if (lineEnd < 0 || lineEnd > position + MAX_HEADER_BYTES) return null;
    if (lineEnd === position) return { headers, end: position + 2 };
    const line = text.slice(position, lineEnd);
    const colon = line.indexOf(':');
    if (colon > 0) headers.push({ name: line.slice(0, colon).trim().toLowerCase(), value: line.slice(colon + 1).trim() });
    position = lineEnd + 2;
  }
  return null;
};

// chunked 解码：返回 [结束偏移, 解码文本]；结构非法时结束偏移为 -1。
const decodeChunkedBody = (text: string, start: number): [number, string] => {
  let position = start;
  const parts: string[] = [];
  for (let guard = 0; guard < 4096; guard += 1) {
    const lineEnd = text.indexOf('\r\n', position);
    if (lineEnd < 0) return [-1, ''];
    const size = parseInt(text.slice(position, lineEnd).split(';')[0].trim(), 16);
    if (!Number.isFinite(size) || size < 0) return [-1, ''];
    if (size === 0) return [lineEnd + 2, parts.join('')];
    const dataStart = lineEnd + 2;
    if (dataStart + size + 2 > text.length) return [-1, ''];
    parts.push(text.slice(dataStart, dataStart + size));
    position = dataStart + size + 2;
  }
  return [-1, ''];
};

const findNextMessageOffset = (text: string, from: number): number => {
  NEXT_MESSAGE.lastIndex = from;
  const match = NEXT_MESSAGE.exec(text);
  return match ? match.index + 2 : text.length;
};

const parseHttpDirection = (text: string): RawHttpMessage[] => {
  const messages: RawHttpMessage[] = [];
  let position = 0;
  while (messages.length < MAX_HTTP_MESSAGES_PER_DIRECTION) {
    const beforeSkip = position;
    let found: { direction: 'req' | 'res'; method: string; path: string; status: number | null; startLine: string; headerStart: number } | null = null;
    // 报文起点前允许有限行的前置噪声（重传尾巴、banner）：最多跳 16 行。
    for (let skip = 0; skip < 16 && !found; skip += 1) {
      REQUEST_LINE_STICKY.lastIndex = position;
      const requestMatch = REQUEST_LINE_STICKY.exec(text);
      if (requestMatch) {
        found = { direction: 'req', method: requestMatch[1].toUpperCase(), path: requestMatch[2], status: null, startLine: requestMatch[0].trim(), headerStart: REQUEST_LINE_STICKY.lastIndex };
        break;
      }
      STATUS_LINE_STICKY.lastIndex = position;
      const statusMatch = STATUS_LINE_STICKY.exec(text);
      if (statusMatch) {
        found = { direction: 'res', method: '', path: '', status: Number(statusMatch[1]), startLine: statusMatch[0].trim(), headerStart: STATUS_LINE_STICKY.lastIndex };
        break;
      }
      const nextNewline = text.indexOf('\n', position);
      if (nextNewline < 0) break;
      position = nextNewline + 1;
    }
    if (!found) break;
    const headerBlock = parseHeaderBlock(text, found.headerStart);
    if (!headerBlock) break;
    const headerMap = new Map(headerBlock.headers.map(header => [header.name, header.value]));
    const transferEncoding = headerMap.get('transfer-encoding') ?? '';
    const contentLength = headerMap.get('content-length');
    const bodyStart = headerBlock.end;
    let bodyEnd = bodyStart;
    let chunkedText: string | null = null;
    if (/chunked/i.test(transferEncoding)) {
      const [consumed, decoded] = decodeChunkedBody(text, bodyStart);
      if (consumed >= 0) {
        bodyEnd = consumed;
        chunkedText = decoded;
      } else {
        bodyEnd = text.length;
      }
    } else if (contentLength !== undefined) {
      const length = parseInt(contentLength, 10);
      bodyEnd = Number.isFinite(length) && length >= 0 ? Math.min(text.length, bodyStart + length) : text.length;
    } else if (found.direction === 'res') {
      bodyEnd = findNextMessageOffset(text, bodyStart);
    }
    messages.push({ ...found, offset: beforeSkip, bodyStart, bodyEnd, chunkedText, headers: headerBlock.headers });
    if (bodyEnd <= position && chunkedText === null && bodyEnd <= found.headerStart) break;
    position = Math.max(bodyEnd, found.headerStart);
  }
  return messages;
};

const decodeQuery = (path: string): Array<[string, string]> => {
  const questionMark = path.indexOf('?');
  if (questionMark < 0) return [];
  const params = new URLSearchParams(path.slice(questionMark + 1));
  const pairs: Array<[string, string]> = [];
  for (const [key, value] of params) {
    pairs.push([key, value]);
    if (pairs.length >= 64) break;
  }
  return pairs;
};

const latin1Encode = (text: string): Uint8Array => {
  const bytes = new Uint8Array(text.length);
  for (let index = 0; index < text.length; index += 1) bytes[index] = text.charCodeAt(index) & 0xff;
  return bytes;
};

export const analyzeCapture = (views: PacketView[]): CaptureAnalysis => {
  // ---- 协议统计（HTTP/DNS 作为 TCP/UDP 内的细分标签，允许重叠计数） ----
  const statOrder = ['TCP', 'HTTP', 'UDP', 'DNS', 'ICMP', 'ICMPv6', 'ARP', 'other'] as const;
  const statCounts = new Map<string, number>();
  for (const view of views) {
    const keys: string[] = [];
    if (view.proto === 'TCP') {
      keys.push('TCP');
      if (view.isHttpRequest || view.isHttpResponse) keys.push('HTTP');
      // 批次二（Lane J）：TCP 53 的包也计入 DNS 细分（UDP 53 分支同口径）。
      if (view.isDns) keys.push('DNS');
    } else if (view.proto === 'UDP') {
      keys.push('UDP');
      if (view.isDns) keys.push('DNS');
    } else if (view.proto === 'ICMP') keys.push('ICMP');
    else if (view.proto === 'ICMPv6') keys.push('ICMPv6');
    else if (view.proto === 'ARP') keys.push('ARP');
    else keys.push('other');
    for (const key of keys) statCounts.set(key, (statCounts.get(key) ?? 0) + 1);
  }
  const stats = statOrder.filter(key => (statCounts.get(key) ?? 0) > 0).map(key => ({ key, count: statCounts.get(key) ?? 0 }));

  // ---- TCP 流分组 ----
  const groups = new Map<string, { endpoints: [string, string]; sides: [StreamSide, StreamSide]; packetIndexes: Set<number>; byteCount: number }>();
  for (const view of views) {
    if (view.proto !== 'TCP') continue;
    const endpointSrc = endpointOf(view, 'src');
    const endpointDst = endpointOf(view, 'dst');
    const ordered = endpointSrc <= endpointDst ? [endpointSrc, endpointDst] : [endpointDst, endpointSrc];
    const key = `${ordered[0]}|${ordered[1]}`;
    let group = groups.get(key);
    if (!group) {
      group = { endpoints: [ordered[0], ordered[1]], sides: [{ segments: [] }, { segments: [] }], packetIndexes: new Set(), byteCount: 0 };
      groups.set(key, group);
    }
    // 全部 TCP 包（含握手/挥手）计入流包数；仅数据段参与重组与基线计算。
    group.packetIndexes.add(view.index);
    if (view.payload === null || view.payload.length === 0 || view.tcpSeq === null) continue;
    const forward = endpointSrc === group.endpoints[0];
    const side = group.sides[forward ? 0 : 1];
    side.segments.push({ rawSeq: view.tcpSeq, length: view.payload.length, packetIndex: view.index, bytes: view.payload });
    group.byteCount += view.payload.length;
  }

  // ---- 流重组 + HTTP 解析 + flag 定位 ----
  const sortedGroups = [...groups.values()].sort((left, right) => right.byteCount - left.byteCount);
  const streamTotal = sortedGroups.length;
  const streams: TcpStream[] = [];
  const transactions: HttpTransaction[] = [];
  // 未响应请求按流建栈：响应到达 O(1) 弹出配对（管线化语义 = 最新请求优先应答），
  // 避免"[...transactions].reverse().find()"在大量微报文下的 O(T²) 主线程冻结。
  const openRequests = new Map<number, HttpTransaction[]>();
  const flags: FlagHit[] = [];
  const flagSeen = new Set<string>();
  let httpTotal = 0;

  const pushFlag = (hit: { prefix: string; sample: string }, source: string) => {
    const dedupeKey = `${hit.prefix}|${hit.sample}|${source}`;
    if (flagSeen.has(dedupeKey)) return;
    flagSeen.add(dedupeKey);
    flags.push({ prefix: hit.prefix, sample: hit.sample, source });
  };

  for (const [streamIndex, group] of sortedGroups.entries()) {
    if (streamIndex >= MAX_STREAMS) break;
    const forward = reassembleDirection(group.sides[0]);
    const reverse = reassembleDirection(group.sides[1]);
    const truncated = forward.truncated || reverse.truncated;
    const stream: TcpStream = {
      id: streamIndex,
      endpointA: group.endpoints[0],
      endpointB: group.endpoints[1],
      packetCount: group.packetIndexes.size,
      byteCount: group.byteCount,
      bufferAtoB: forward.buffer,
      bufferBtoA: reverse.buffer,
      offsetsAtoB: forward.offsets,
      offsetsBtoA: reverse.offsets,
      truncated,
      hasFlag: false,
      packetIndexes: [...group.packetIndexes].sort((left, right) => left - right),
    };

    const sideTexts: Array<{ direction: 'req' | 'res'; buffer: Uint8Array; offsets: DirectionBuffer['offsets'] }> = [
      { direction: 'req', buffer: forward.buffer, offsets: forward.offsets },
      { direction: 'res', buffer: reverse.buffer, offsets: reverse.offsets },
    ];

    for (const side of sideTexts) {
      const text = new TextDecoder('latin1').decode(side.buffer);
      const rawMessages = parseHttpDirection(text);
      for (const raw of rawMessages) {
        const bodyText = raw.chunkedText ?? text.slice(raw.bodyStart, raw.bodyEnd);
        const bodyBytes = raw.chunkedText !== null ? latin1Encode(raw.chunkedText) : new Uint8Array(side.buffer.slice(raw.bodyStart, raw.bodyEnd));
        const hits = detectFlagFormats(`${raw.startLine}\n${bodyText}`);
        const message: HttpMessage = {
          direction: raw.direction,
          streamId: stream.id,
          packetIndex: packetIndexOf(side.offsets, raw.offset),
          startLine: raw.startLine,
          method: raw.method,
          path: raw.path,
          query: raw.direction === 'req' ? decodeQuery(raw.path) : [],
          status: raw.status,
          headers: raw.headers,
          bodyBytes,
          bodyText,
          bodyTruncated: raw.bodyEnd - raw.bodyStart > 1024 * 1024,
          hasFlag: hits.length > 0,
        };
        httpTotal += 1;
        for (const hit of hits) pushFlag(hit, `HTTP ${raw.direction === 'req' ? '请求' : '响应'} · 包 #${message.packetIndex}`);
        if (hits.length > 0) stream.hasFlag = true;
        if (raw.direction === 'req') {
          const transaction: HttpTransaction = { streamId: stream.id, request: message, response: null };
          transactions.push(transaction);
          const queue = openRequests.get(stream.id);
          if (queue) queue.push(transaction);
          else openRequests.set(stream.id, [transaction]);
        } else {
          const queue = openRequests.get(stream.id);
          const pending = queue && queue.length > 0 ? queue[queue.length - 1] : undefined;
          if (pending) {
            queue!.pop();
            pending.response = message;
          } else {
            transactions.push({ streamId: stream.id, request: null, response: message });
          }
        }
      }
      const sideHits = detectFlagFormats(text);
      if (sideHits.length > 0) {
        stream.hasFlag = true;
        for (const hit of sideHits) pushFlag(hit, `TCP 流 #${stream.id}（${stream.endpointA} → ${stream.endpointB}，${side.direction === 'req' ? 'A→B' : 'B→A'}）`);
      }
    }
    streams.push(stream);
  }

  // ---- DNS 问答表（Lane J）：UDP 53 逐包 + TCP 53 流重组双通道 ----
  // UDP：每个 53 端口包即一个独立报文；TCP：RFC 1035 §4.2.2——报文前置 2 字节长度，
  // 同方向可管线化多条，按前缀顺序切分。TXT 载荷逐段过 detectFlagFormats（复用 flag 扫描）。
  const dnsExchanges: DnsExchange[] = [];
  const pushDnsExchange = (transport: 'UDP' | 'TCP', packetIndex: number, streamId: number | null, message: DnsMessage) => {
    if (dnsExchanges.length >= MAX_DNS_EXCHANGES) return;
    let hasFlag = false;
    for (const record of message.records) {
      if (record.type !== 16 || !record.values) continue;
      for (const piece of record.values) {
        const hits = detectFlagFormats(piece);
        if (!hits.length) continue;
        hasFlag = true;
        const origin = streamId === null ? `包 #${packetIndex}` : `流 #${streamId}`;
        for (const hit of hits) pushFlag(hit, `DNS TXT · ${record.name}（${transport} ${origin}）`);
      }
    }
    dnsExchanges.push({
      transport,
      packetIndex,
      streamId,
      id: message.id,
      isResponse: message.isResponse,
      opcode: message.opcode,
      opcodeText: message.opcodeText,
      rcode: message.rcode,
      rcodeText: message.rcodeText,
      questions: message.questions,
      records: message.records,
      hasFlag,
      parseError: message.parseError,
    });
  };
  for (const view of views) {
    if (!view.isDns || view.proto !== 'UDP' || !view.payload || view.payload.length === 0) continue;
    const message = parseDnsMessage(view.payload);
    if (message) pushDnsExchange('UDP', view.index, null, message);
  }
  // TCP 53：复用已重组的流缓冲，两方向分别按长度前缀成帧解析。
  const endpointPort = (endpoint: string): number | null => {
    const at = endpoint.lastIndexOf(':');
    return at < 0 ? null : Number(endpoint.slice(at + 1));
  };
  for (const stream of streams) {
    if (endpointPort(stream.endpointA) !== 53 && endpointPort(stream.endpointB) !== 53) continue;
    const anchorPacket = stream.packetIndexes.length > 0 ? stream.packetIndexes[0] : 0;
    for (const buffer of [stream.bufferAtoB, stream.bufferBtoA]) {
      let cursor = 0;
      let messageCount = 0;
      while (cursor + 2 <= buffer.length && messageCount < MAX_TCP_DNS_MESSAGES) {
        const messageLength = (buffer[cursor] << 8) | buffer[cursor + 1];
        // 长度前缀非法（小于头部 12 字节）或越界：帧结构已不可信，停止该方向。
        if (messageLength < 12 || cursor + 2 + messageLength > buffer.length) break;
        const message = parseDnsMessage(buffer.subarray(cursor + 2, cursor + 2 + messageLength));
        if (!message) break;
        pushDnsExchange('TCP', anchorPacket, stream.id, message);
        cursor += 2 + messageLength;
        messageCount += 1;
      }
    }
  }

  return { stats, streams, streamTotal, transactions, httpTotal, flags, dnsExchanges, dnsTotal: dnsExchanges.length };
};

// ICMP 数据外带拼合（真题套路：flag 分片藏在一串 echo data 里，整包扫描被 pcap 头打断拼不上）。
// 按包序拼合全部 ICMP 载荷（请求+响应都算），供可疑扫描与拼合预览消费。
export const assembleIcmpData = (views: PacketView[]): { text: string; packetCount: number } | null => {
  const parts: Uint8Array[] = [];
  for (const view of views) {
    if ((view.proto !== 'ICMP' && view.proto !== 'ICMPv6') || !view.payload || view.payload.length === 0) continue;
    parts.push(view.payload);
  }
  if (!parts.length) return null;
  let total = 0;
  for (const part of parts) total += part.length;
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return { text: new TextDecoder('latin1').decode(joined), packetCount: parts.length };
};

// =====================================================================
// 批次二补强（Lane K）：共享工具 —— SHA-256、字节拼合、端点拆解
// =====================================================================

// SHA-256（FIPS 180-4）纯函数：FTP 导出文件的完整性指纹在引擎内同步算出，不引入 crypto.subtle
// 异步链。对拍锚点：NIST 样本 "abc" → ba7816bf…15ad；测试侧另用 node:crypto 对任意长度逐位对拍。
const SHA256_H0 = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export const sha256Hex = (data: Uint8Array): string => {
  const bitLength = data.length * 8;
  // 填充：原文 + 0x80 + 零 + 64 位大端比特长度，总长为 64 的倍数。
  const padded = new Uint8Array(((data.length + 9) + 63) & ~63);
  padded.set(data);
  padded[data.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(bitLength / 0x100000000));
  view.setUint32(padded.length - 4, bitLength >>> 0);
  const hash = new Uint32Array(SHA256_H0);
  const words = new Uint32Array(64);
  const rotr = (value: number, bits: number): number => ((value >>> bits) | (value << (32 - bits))) >>> 0;
  for (let block = 0; block < padded.length; block += 64) {
    for (let t = 0; t < 16; t += 1) words[t] = view.getUint32(block + t * 4);
    for (let t = 16; t < 64; t += 1) {
      const s0 = rotr(words[t - 15], 7) ^ rotr(words[t - 15], 18) ^ (words[t - 15] >>> 3);
      const s1 = rotr(words[t - 2], 17) ^ rotr(words[t - 2], 19) ^ (words[t - 2] >>> 10);
      words[t] = (words[t - 16] + s0 + words[t - 7] + s1) >>> 0;
    }
    let a = hash[0], b = hash[1], c = hash[2], d = hash[3], e = hash[4], f = hash[5], g = hash[6], h = hash[7];
    for (let t = 0; t < 64; t += 1) {
      const bigS1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const choice = (e & f) ^ (~e & g);
      const temp1 = (h + bigS1 + choice + SHA256_K[t] + words[t]) >>> 0;
      const bigS0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (bigS0 + majority) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    hash[0] = (hash[0] + a) >>> 0; hash[1] = (hash[1] + b) >>> 0; hash[2] = (hash[2] + c) >>> 0; hash[3] = (hash[3] + d) >>> 0;
    hash[4] = (hash[4] + e) >>> 0; hash[5] = (hash[5] + f) >>> 0; hash[6] = (hash[6] + g) >>> 0; hash[7] = (hash[7] + h) >>> 0;
  }
  return Array.from(hash, value => value.toString(16).padStart(8, '0')).join('');
};

const concatBytes = (parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

// 端点字符串形如 "ip:port"（IPv6 也是 ip:port 拼接，取最后一个冒号即可拆开）。
const ipOfEndpoint = (endpoint: string): string => endpoint.slice(0, endpoint.lastIndexOf(':'));
const portOfEndpoint = (endpoint: string): number => Number(endpoint.slice(endpoint.lastIndexOf(':') + 1));

const latin1Head = (buffer: Uint8Array, maxBytes: number): string =>
  new TextDecoder('latin1').decode(buffer.subarray(0, Math.min(buffer.length, maxBytes)));

// =====================================================================
// FTP 控制/数据流配对提取（B2-5，RFC 959）
// 控制流识别：端口 21 优先，否则按 USER 命令 + 三位数字应答的内容特征兜底；
// 行解析抽 USER/PASS/TYPE/PORT/PASV/EPSV/EPRT/RETR/STOR/LIST/NLST；
// 数据端点公告与传输命令按流内顺序配对；5 元组匹配数据流且每流只消费一次；
// RETR=服务器→客户端、STOR=客户端→服务器导出原文件字节（附 SHA-256 与大小）；
// FTPS（AUTH TLS/SSL）显式报不支持。交错不可恢复时如实记入 unmatched/notes。
// =====================================================================

export interface FtpCommandRecord {
  fromClient: boolean;
  command: string;
  argument: string;
  replyCode: number | null;
  packetIndex: number;
}

export type FtpTransferStatus = 'ok' | 'no-announcement' | 'stream-missing' | 'stream-consumed' | 'empty-data';

export interface FtpTransfer {
  command: 'RETR' | 'STOR' | 'LIST' | 'NLST';
  filename: string | null;
  mode: 'active' | 'passive';
  announcedEndpoint: string | null;
  dataStreamId: number | null;
  fallbackMatch: boolean;
  direction: 'server-to-client' | 'client-to-server';
  bytes: Uint8Array | null;
  size: number;
  sha256: string;
  commandPacketIndex: number;
  status: FtpTransferStatus;
  note: string;
}

export interface FtpSession {
  streamId: number;
  client: string;
  server: string;
  username: string | null;
  password: string | null;
  loggedIn: boolean | null;
  commands: FtpCommandRecord[];
  transfers: FtpTransfer[];
  unmatched: string[];
  ftps: boolean;
  notes: string[];
}

const FTP_MAX_SESSIONS = 32;
const FTP_MAX_LINES_PER_DIRECTION = 1000;
const FTP_MAX_LINE_CHARS = 512;
const FTP_MAX_COMMAND_RECORDS = 200;

const FTP_CLIENT_COMMANDS = new Set(['USER', 'PASS', 'TYPE', 'PORT', 'PASV', 'EPSV', 'EPRT', 'RETR', 'STOR', 'LIST', 'NLST', 'AUTH']);
const FTP_TRANSFER_COMMANDS = new Set(['RETR', 'STOR', 'LIST', 'NLST']);

interface FtpLine {
  text: string;
  offset: number;
}

const splitFtpLines = (text: string): FtpLine[] => {
  const lines: FtpLine[] = [];
  let position = 0;
  while (lines.length < FTP_MAX_LINES_PER_DIRECTION && position < text.length) {
    const newline = text.indexOf('\n', position);
    const end = newline < 0 ? text.length : newline;
    const lineEnd = end > position && text[end - 1] === '\r' ? end - 1 : end;
    if (lineEnd > position) {
      const raw = text.slice(position, lineEnd);
      lines.push({ text: raw.length > FTP_MAX_LINE_CHARS ? raw.slice(0, FTP_MAX_LINE_CHARS) : raw, offset: position });
    }
    if (newline < 0) break;
    position = newline + 1;
  }
  return lines;
};

// PORT a1,a2,a3,a4,p1,p2（RFC 959 4.1.2.6）与 EPRT |1|ip|port|（RFC 2428）→ 数据端点。
const parseFtpPortArgs = (argument: string): { ip: string; port: number } | null => {
  const commaMatch = /^(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})/.exec(argument);
  if (commaMatch) {
    const octets = commaMatch.slice(1, 5).map(Number);
    if (octets.every(value => value >= 0 && value <= 255)) {
      return { ip: octets.join('.'), port: Number(commaMatch[5]) * 256 + Number(commaMatch[6]) };
    }
  }
  const eprtMatch = /^\|(\d)\|([^|\s]+)\|(\d+)\|/.exec(argument);
  if (eprtMatch && eprtMatch[1] === '1') return { ip: eprtMatch[2], port: Number(eprtMatch[3]) };
  return null;
};

// 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)（RFC 959）与 229 (|||port|)（RFC 2428）。
const parseFtpPasvReply = (text: string): { ip: string | null; port: number } | null => {
  const commaMatch = /(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})/.exec(text);
  if (commaMatch) {
    const octets = commaMatch.slice(1, 5).map(Number);
    if (octets.every(value => value >= 0 && value <= 255)) {
      return { ip: octets.join('.'), port: Number(commaMatch[5]) * 256 + Number(commaMatch[6]) };
    }
  }
  const epsvMatch = /\(\|\|\|(\d+)\|\)/.exec(text);
  if (epsvMatch) return { ip: null, port: Number(epsvMatch[1]) };
  return null;
};

const analyzeFtpSession = (stream: TcpStream, analysis: CaptureAnalysis, consumedDataStreams: Set<number>): FtpSession | null => {
  const portA = portOfEndpoint(stream.endpointA);
  const portB = portOfEndpoint(stream.endpointB);
  // 控制流识别：任一侧端口 21 即控制流；无 21 时按 USER 命令 + 三位数字应答的内容特征兜底。
  const forwardHead = latin1Head(stream.bufferAtoB, 1024);
  const reverseHead = latin1Head(stream.bufferBtoA, 1024);
  const forwardHasUser = /(?:^|\r?\n)USER [^\r\n]*\r?/.test(forwardHead);
  const reverseHasUser = /(?:^|\r?\n)USER [^\r\n]*\r?/.test(reverseHead);
  const forwardHasReply = /(?:^|\r?\n)\d{3}[ -]/.test(forwardHead);
  const reverseHasReply = /(?:^|\r?\n)\d{3}[ -]/.test(reverseHead);
  let clientIsA: boolean;
  if (portA === 21) clientIsA = false; // A 侧端口 21 → A 是服务器
  else if (portB === 21) clientIsA = true;
  else if (forwardHasUser && reverseHasReply) clientIsA = true;
  else if (reverseHasUser && forwardHasReply) clientIsA = false;
  else return null;

  const client = clientIsA ? stream.endpointA : stream.endpointB;
  const server = clientIsA ? stream.endpointB : stream.endpointA;
  const serverIp = ipOfEndpoint(server);
  const clientIp = ipOfEndpoint(client);
  const clientOffsets = clientIsA ? stream.offsetsAtoB : stream.offsetsBtoA;
  const serverOffsets = clientIsA ? stream.offsetsBtoA : stream.offsetsAtoB;

  const session: FtpSession = {
    streamId: stream.id,
    client,
    server,
    username: null,
    password: null,
    loggedIn: null,
    commands: [],
    transfers: [],
    unmatched: [],
    ftps: false,
    notes: [],
  };

  // 统一时间线：PASV 场景里服务端 227 公告先于客户端 RETR 到达（不同包），必须按包序交错
  // 走时间线才能正确配对；同一包内的行必属同一方向，稳定排序后行内顺序天然保序。
  // 跨方向同包序不可恢复的极端交错按 no-announcement 如实声明（见 handleTransferCommand）。
  interface FtpTimelineEntry {
    packetIndex: number;
    fromClient: boolean;
    line: FtpLine;
  }
  const clientLines = splitFtpLines(new TextDecoder('latin1').decode(clientIsA ? stream.bufferAtoB : stream.bufferBtoA));
  const serverLines = splitFtpLines(new TextDecoder('latin1').decode(clientIsA ? stream.bufferBtoA : stream.bufferAtoB));
  const timeline: FtpTimelineEntry[] = [
    ...clientLines.map(line => ({ packetIndex: packetIndexOf(clientOffsets, line.offset), fromClient: true, line })),
    ...serverLines.map(line => ({ packetIndex: packetIndexOf(serverOffsets, line.offset), fromClient: false, line })),
  ];
  timeline.sort((left, right) => left.packetIndex - right.packetIndex);

  const recordCommand = (fromClient: boolean, command: string, argument: string, replyCode: number | null, packetIndex: number) => {
    if (session.commands.length >= FTP_MAX_COMMAND_RECORDS) return;
    session.commands.push({ fromClient, command, argument, replyCode, packetIndex });
  };

  let pending: { mode: 'active' | 'passive'; endpoint: string } | null = null;

  const handleTransferCommand = (transferCommand: 'RETR' | 'STOR' | 'LIST' | 'NLST', argument: string, packetIndex: number) => {
    const filename = argument || null;
    if (!pending) {
      session.transfers.push({
        command: transferCommand, filename, mode: 'active', announcedEndpoint: null, dataStreamId: null,
        fallbackMatch: false, direction: transferCommand === 'STOR' ? 'client-to-server' : 'server-to-client',
        bytes: null, size: 0, sha256: sha256Hex(new Uint8Array(0)), commandPacketIndex: packetIndex,
        status: 'no-announcement',
        note: `${transferCommand} 之前没有未消费的数据端点公告（RFC 959 要求先 PORT/PASV 再传输；交错不可恢复时按此口径如实声明）`,
      });
      return;
    }
    const announcement = pending;
    pending = null;
    const announcedIp = ipOfEndpoint(announcement.endpoint);
    const announcedPort = portOfEndpoint(announcement.endpoint);
    // 数据流另一侧应是对端：被动公告=服务器侧端点 → 另一侧是客户端 IP；主动公告反之。
    const counterpartIp = announcement.mode === 'passive' ? clientIp : serverIp;
    const matchesStream = (candidate: TcpStream) =>
      candidate.id !== stream.id && (
        (candidate.endpointA === announcement.endpoint && ipOfEndpoint(candidate.endpointB) === counterpartIp) ||
        (candidate.endpointB === announcement.endpoint && ipOfEndpoint(candidate.endpointA) === counterpartIp));
    const portOnlyMatches = (candidate: TcpStream) =>
      candidate.id !== stream.id && announcedPort !== 21 && (
        (portOfEndpoint(candidate.endpointA) === announcedPort && ipOfEndpoint(candidate.endpointB) === counterpartIp) ||
        (portOfEndpoint(candidate.endpointB) === announcedPort && ipOfEndpoint(candidate.endpointA) === counterpartIp));
    let matched = analysis.streams.find(candidate => !consumedDataStreams.has(candidate.id) && matchesStream(candidate));
    let fallback = false;
    if (!matched) {
      matched = analysis.streams.find(candidate => !consumedDataStreams.has(candidate.id) && portOnlyMatches(candidate));
      fallback = matched !== undefined;
    }
    if (!matched) {
      const consumedElsewhere = analysis.streams.some(candidate => consumedDataStreams.has(candidate.id) && matchesStream(candidate));
      session.transfers.push({
        command: transferCommand, filename, mode: announcement.mode, announcedEndpoint: announcement.endpoint,
        dataStreamId: null, fallbackMatch: false,
        direction: transferCommand === 'STOR' ? 'client-to-server' : 'server-to-client',
        bytes: null, size: 0, sha256: sha256Hex(new Uint8Array(0)), commandPacketIndex: packetIndex,
        status: consumedElsewhere ? 'stream-consumed' : 'stream-missing',
        note: consumedElsewhere
          ? `公告端点 ${announcement.endpoint} 对应的数据流已被先前传输占用（每条数据流只消费一次）`
          : `公告端点 ${announcement.endpoint} 没有匹配到数据流（抓包缺段或连接未建立）`,
      });
      return;
    }
    consumedDataStreams.add(matched.id);
    const serverIsA = ipOfEndpoint(matched.endpointA) === serverIp;
    const serverToClient = serverIsA ? matched.bufferAtoB : matched.bufferBtoA;
    const clientToServer = serverIsA ? matched.bufferBtoA : matched.bufferAtoB;
    const wantsServerToClient = transferCommand !== 'STOR';
    const bytes = wantsServerToClient ? serverToClient : clientToServer;
    session.transfers.push({
      command: transferCommand, filename, mode: announcement.mode,
      announcedEndpoint: announcedIp === '0.0.0.0' ? `${serverIp}:${announcedPort}` : announcement.endpoint,
      dataStreamId: matched.id, fallbackMatch: fallback,
      direction: wantsServerToClient ? 'server-to-client' : 'client-to-server',
      bytes: bytes.length > 0 ? bytes : null,
      size: bytes.length,
      sha256: sha256Hex(bytes),
      commandPacketIndex: packetIndex,
      status: bytes.length > 0 ? 'ok' : 'empty-data',
      note: bytes.length > 0
        ? (fallback ? '端点 IP 精确匹配失败，按"端口+对端 IP"兜底匹配' : '')
        : `数据流 #${matched.id} 预期方向无数据字节`,
    });
  };

  // 按包序走统一时间线：公告（PORT/EPRT 客户端命令、227/229 服务端应答）写入单槽 pending，
  // 遇传输命令即消费该槽；登录态（230/530）与 FTPS（AUTH TLS/SSL）顺路记录。
  for (const entry of timeline) {
    if (entry.fromClient) {
      const spaceIndex = entry.line.text.indexOf(' ');
      const command = (spaceIndex < 0 ? entry.line.text : entry.line.text.slice(0, spaceIndex)).toUpperCase();
      const argument = spaceIndex < 0 ? '' : entry.line.text.slice(spaceIndex + 1).trim();
      if (!FTP_CLIENT_COMMANDS.has(command)) continue;
      recordCommand(true, command, argument, null, entry.packetIndex);
      if (command === 'USER') session.username = argument || null;
      else if (command === 'PASS') session.password = argument || null;
      else if (command === 'PORT' || command === 'EPRT') {
        const endpoint = parseFtpPortArgs(argument);
        pending = endpoint ? { mode: 'active', endpoint: `${endpoint.ip}:${endpoint.port}` } : null;
      } else if (command === 'AUTH' && /SSL|TLS/i.test(argument)) {
        session.ftps = true;
      } else if (FTP_TRANSFER_COMMANDS.has(command)) {
        handleTransferCommand(command as 'RETR' | 'STOR' | 'LIST' | 'NLST', argument, entry.packetIndex);
      }
    } else {
      const replyMatch = /^(\d{3})([ -])(.*)$/.exec(entry.line.text);
      if (!replyMatch) continue;
      const replyCode = Number(replyMatch[1]);
      const replyText = replyMatch[3];
      recordCommand(false, 'reply', replyText, replyCode, entry.packetIndex);
      if (replyCode === 230) session.loggedIn = true;
      else if (replyCode === 530) session.loggedIn = false;
      else if (replyCode === 227 || replyCode === 229) {
        const parsed = parseFtpPasvReply(replyText);
        if (parsed) {
          // 227 里 IP 为 0.0.0.0（NAT 后写法）时回退用控制流服务器 IP。
          const ip = parsed.ip && parsed.ip !== '0.0.0.0' ? parsed.ip : serverIp;
          pending = { mode: 'passive', endpoint: `${ip}:${parsed.port}` };
        }
      }
    }
  }
  if (pending) {
    session.unmatched.push(`数据端点公告 ${pending.endpoint}（${pending.mode === 'passive' ? '被动' : '主动'}）未对应任何传输命令`);
  }
  if (session.ftps) session.notes.push('检测到显式 FTPS（AUTH TLS/SSL）：控制与数据通道已加密，本工具不做解密，提取结果可能不完整。');
  if (session.transfers.some(transfer => transfer.fallbackMatch)) {
    session.notes.push('部分数据流按"端口+对端 IP"兜底匹配（公告 IP 与实际抓包不一致，常见于 NAT 环境）。');
  }
  return session.commands.length > 0 || session.transfers.length > 0 ? session : null;
};

export const analyzeFtp = (analysis: CaptureAnalysis): FtpSession[] => {
  const sessions: FtpSession[] = [];
  const consumedDataStreams = new Set<number>();
  for (const stream of analysis.streams) {
    if (sessions.length >= FTP_MAX_SESSIONS) break;
    const session = analyzeFtpSession(stream, analysis, consumedDataStreams);
    if (session) sessions.push(session);
  }
  return sessions;
};

// =====================================================================
// MQTT 流解析与主题表（B2-9，MQTT 3.1.1 / 5.0）
// TCP 流重组后按固定头（1 字节类型/标志 + 剩余长度变长编码，spec 2.2 节）逐包解
// CONNECT（clientId）/PUBLISH（topic+payload，QoS 判定）/SUBSCRIBE 等；
// 输出主题表（topic × 消息数 + 载荷魔数识别）与载荷导出；flag 扫描复用 detectFlagFormats。
// 对拍锚点：剩余长度 300 → 0xAC 0x02（spec 2.2.3 变长编码同族示例）；测试用手工构造字节流验证。
// =====================================================================

export interface MqttPacket {
  streamId: number;
  // 客户端/服务器语义（c2s = 客户端→服务器），由 CONNECT 发起方判定后重映射。
  direction: 'c2s' | 's2c';
  packetIndex: number;
  type: number;
  typeName: string;
  qos: number;
  dup: boolean;
  retain: boolean;
  topic: string | null;
  topicFilters: string[];
  packetId: number | null;
  clientId: string | null;
  protocolName: string | null;
  protocolLevel: number | null;
  payload: Uint8Array | null;
  payloadTruncated: boolean;
  hasFlag: boolean;
}

export interface MqttTopicRow {
  topic: string;
  count: number;
  totalPayloadBytes: number;
  magic: string | null;
  hasFlag: boolean;
  qosLevels: number[];
}

export interface MqttSession {
  streamId: number;
  client: string;
  server: string;
  protocolName: string | null;
  protocolLevel: number | null;
  clientId: string | null;
  packets: MqttPacket[];
  topics: MqttTopicRow[];
  notes: string[];
}

const MQTT_MAX_SESSIONS = 32;
const MQTT_MAX_PACKETS_PER_DIRECTION = 1000;
const MQTT_MAX_PAYLOAD_KEEP = 256 * 1024;
const MQTT_TYPE_NAMES: Record<number, string> = {
  1: 'CONNECT', 2: 'CONNACK', 3: 'PUBLISH', 4: 'PUBACK', 5: 'PUBREC', 6: 'PUBREL', 7: 'PUBCOMP',
  8: 'SUBSCRIBE', 9: 'SUBACK', 10: 'UNSUBSCRIBE', 11: 'UNSUBACK', 12: 'PINGREQ', 13: 'PINGRESP',
  14: 'DISCONNECT', 15: 'AUTH',
};

interface MqttFixedHeader {
  type: number;
  flags: number;
  bodyStart: number;
  bodyEnd: number;
  offset: number;
}

// 剩余长度变长编码（spec 2.2.3）：每字节低 7 位参与数值、最高位为续位，最多 4 字节。
// 例：300 = 0b100101100 → 首字节 0x2C|0x80=0xAC，次字节 0x02。
const readMqttFixedHeader = (buffer: Uint8Array, offset: number): MqttFixedHeader | null => {
  if (offset + 2 > buffer.length) return null;
  const first = buffer[offset];
  let position = offset + 1;
  let remaining = 0;
  let multiplier = 1;
  for (let count = 0; count < 4; count += 1) {
    if (position >= buffer.length) return null;
    const byte = buffer[position];
    position += 1;
    remaining += (byte & 0x7f) * multiplier;
    multiplier *= 128;
    if ((byte & 0x80) === 0) {
      const bodyStart = position;
      const bodyEnd = bodyStart + remaining;
      if (bodyEnd > buffer.length) return null; // 包体截断：如实停在已解析部分
      return { type: first >> 4, flags: first & 0x0f, bodyStart, bodyEnd, offset };
    }
  }
  return null; // 4 字节后仍有续位：非法编码
};

const readMqttString = (buffer: Uint8Array, position: number): { value: string; next: number } | null => {
  if (position + 2 > buffer.length) return null;
  const length = (buffer[position] << 8) | buffer[position + 1];
  const end = position + 2 + length;
  if (end > buffer.length) return null;
  return { value: new TextDecoder('utf-8', { fatal: false }).decode(buffer.subarray(position + 2, end)), next: end };
};

const readMqttU16 = (buffer: Uint8Array, position: number): { value: number; next: number } | null => {
  if (position + 2 > buffer.length) return null;
  return { value: (buffer[position] << 8) | buffer[position + 1], next: position + 2 };
};

// MQTT 5.0 属性段：变长长度前缀 + 内容，整段跳过（本工具只做展示级解析）。
const skipMqttProperties = (buffer: Uint8Array, position: number): number | null => {
  let value = 0;
  let multiplier = 1;
  for (let count = 0; count < 4; count += 1) {
    if (position >= buffer.length) return null;
    const byte = buffer[position];
    position += 1;
    value += (byte & 0x7f) * multiplier;
    multiplier *= 128;
    if ((byte & 0x80) === 0) {
      return position + value <= buffer.length ? position + value : null;
    }
  }
  return null;
};

interface MqttBodyFields {
  topic: string | null;
  topicFilters: string[];
  packetId: number | null;
  clientId: string | null;
  protocolName: string | null;
  protocolLevel: number | null;
  payloadStart: number;
}

const parseMqttBody = (buffer: Uint8Array, header: MqttFixedHeader, protocolLevel: number | null): MqttBodyFields | null => {
  const fields: MqttBodyFields = { topic: null, topicFilters: [], packetId: null, clientId: null, protocolName: null, protocolLevel: null, payloadStart: header.bodyEnd };
  let position = header.bodyStart;
  switch (header.type) {
    case 1: { // CONNECT：协议名(2+len) + level + flags + keepalive(2) + [v5 属性] + clientId
      const name = readMqttString(buffer, position);
      if (!name) return null;
      fields.protocolName = name.value;
      position = name.next;
      if (position + 2 > buffer.length) return null;
      const level = buffer[position];
      const connectFlags = buffer[position + 1];
      fields.protocolLevel = level;
      position += 4; // level + flags + keepalive
      if (level >= 5) {
        const afterProperties = skipMqttProperties(buffer, position);
        if (afterProperties === null) return null;
        position = afterProperties;
      }
      // 3.1.1：clean session 位（0x02）置位则 payload 以 clientId 开头；MQIsdp(3.1) 恒有。
      if ((connectFlags & 0x02) !== 0 || level === 3) {
        const clientId = readMqttString(buffer, position);
        if (clientId) {
          fields.clientId = clientId.value;
          position = clientId.next;
        }
      }
      fields.payloadStart = header.bodyEnd;
      return fields;
    }
    case 3: { // PUBLISH：topic(2+len) + [packetId(QoS>0)] + [v5 属性] + payload
      if (((header.flags >> 1) & 3) === 3) return null; // QoS 3 保留值：非法
      const topic = readMqttString(buffer, position);
      if (!topic) return null;
      fields.topic = topic.value;
      position = topic.next;
      const qos = (header.flags >> 1) & 3;
      if (qos > 0) {
        const packetId = readMqttU16(buffer, position);
        if (!packetId) return null;
        fields.packetId = packetId.value;
        position = packetId.next;
      }
      if (protocolLevel !== null && protocolLevel >= 5) {
        const afterProperties = skipMqttProperties(buffer, position);
        if (afterProperties !== null) position = afterProperties;
      }
      fields.payloadStart = position;
      return fields;
    }
    case 8: { // SUBSCRIBE：固定头标志必须 0b0010（spec 3.8.1）；packetId + [v5 属性] + (filter + 选项)*
      if (header.flags !== 0x02) return null;
      const packetId = readMqttU16(buffer, position);
      if (!packetId) return null;
      fields.packetId = packetId.value;
      position = packetId.next;
      if (protocolLevel !== null && protocolLevel >= 5) {
        const afterProperties = skipMqttProperties(buffer, position);
        if (afterProperties !== null) position = afterProperties;
      }
      while (position < header.bodyEnd) {
        const filter = readMqttString(buffer, position);
        if (!filter) return null;
        fields.topicFilters.push(filter.value);
        position = filter.next + 1; // 订阅选项 1 字节
      }
      fields.payloadStart = header.bodyEnd;
      return fields;
    }
    case 4: case 5: case 6: case 7: case 9: case 10: case 11: { // ACK 家族：packetId 起始
      const packetId = readMqttU16(buffer, position);
      if (packetId) fields.packetId = packetId.value;
      fields.payloadStart = header.bodyEnd;
      return fields;
    }
    default:
      fields.payloadStart = header.bodyEnd;
      return fields;
  }
};

const mqttPayloadText = (payload: Uint8Array): string =>
  new TextDecoder('utf-8', { fatal: false }).decode(payload.subarray(0, Math.min(payload.length, 64 * 1024)));

const parseMqttDirection = (
  buffer: Uint8Array,
  offsets: Array<{ start: number; packetIndex: number }>,
  direction: 'c2s' | 's2c',
  streamId: number,
  protocolLevel: number | null,
): MqttPacket[] => {
  const packets: MqttPacket[] = [];
  let position = 0;
  while (position + 2 <= buffer.length && packets.length < MQTT_MAX_PACKETS_PER_DIRECTION) {
    const header = readMqttFixedHeader(buffer, position);
    if (!header || header.type === 0) break;
    const fields = parseMqttBody(buffer, header, protocolLevel);
    if (!fields) break;
    const qos = header.type === 3 ? (header.flags >> 1) & 3 : 0;
    const rawPayload = header.type === 3 && fields.payloadStart < header.bodyEnd ? buffer.subarray(fields.payloadStart, header.bodyEnd) : null;
    const truncatedPayload = rawPayload !== null && rawPayload.length > MQTT_MAX_PAYLOAD_KEEP;
    const payload = rawPayload === null ? null : (truncatedPayload ? rawPayload.subarray(0, MQTT_MAX_PAYLOAD_KEEP) : rawPayload);
    const flagHits = payload ? detectFlagFormats(mqttPayloadText(payload)) : [];
    packets.push({
      streamId,
      direction,
      packetIndex: packetIndexOf(offsets, header.offset),
      type: header.type,
      typeName: MQTT_TYPE_NAMES[header.type] ?? `type ${header.type}`,
      qos,
      dup: header.type === 3 && ((header.flags >> 3) & 1) === 1,
      retain: header.type === 3 && (header.flags & 1) === 1,
      topic: fields.topic,
      topicFilters: fields.topicFilters,
      packetId: fields.packetId,
      clientId: fields.clientId,
      protocolName: fields.protocolName,
      protocolLevel: fields.protocolLevel,
      payload,
      payloadTruncated: truncatedPayload,
      hasFlag: flagHits.length > 0,
    });
    position = header.bodyEnd;
  }
  return packets;
};

const analyzeMqttStream = (stream: TcpStream): MqttSession | null => {
  // 方向判定：CONNECT 发起方即客户端。先按 A→B 为客户端试探，再试反方向；
  // 两向都无 CONNECT 时，仅当流涉及 1883/8883 端口才按"抓包从中途开始"口径接受。
  const attemptOrientation = (clientIsA: boolean): { clientPackets: MqttPacket[]; serverPackets: MqttPacket[]; level: number | null } | null => {
    const clientBuffer = clientIsA ? stream.bufferAtoB : stream.bufferBtoA;
    const clientOffsets = clientIsA ? stream.offsetsAtoB : stream.offsetsBtoA;
    const serverBuffer = clientIsA ? stream.bufferBtoA : stream.bufferAtoB;
    const serverOffsets = clientIsA ? stream.offsetsBtoA : stream.offsetsAtoB;
    const firstPass = parseMqttDirection(clientBuffer, clientOffsets, 'c2s', stream.id, null);
    const connect = firstPass.find(packet => packet.type === 1);
    if (!connect || (connect.protocolName !== 'MQTT' && connect.protocolName !== 'MQIsdp')) return null;
    const level = connect.protocolLevel;
    return {
      clientPackets: parseMqttDirection(clientBuffer, clientOffsets, 'c2s', stream.id, level),
      serverPackets: parseMqttDirection(serverBuffer, serverOffsets, 's2c', stream.id, level),
      level,
    };
  };

  let parsed = attemptOrientation(true);
  let clientIsA = true;
  if (!parsed) {
    parsed = attemptOrientation(false);
    clientIsA = false;
  }
  if (!parsed) {
    const portA = portOfEndpoint(stream.endpointA);
    const portB = portOfEndpoint(stream.endpointB);
    const mqttSide = portA === 1883 || portA === 8883 ? 'a' : portB === 1883 || portB === 8883 ? 'b' : null;
    if (!mqttSide) return null;
    clientIsA = mqttSide === 'a' ? false : true; // 1883/8883 所在一侧是服务器
    const forwardOffsets = clientIsA ? stream.offsetsAtoB : stream.offsetsBtoA;
    const reverseOffsets = clientIsA ? stream.offsetsBtoA : stream.offsetsAtoB;
    const forward = parseMqttDirection(stream.bufferAtoB, forwardOffsets, clientIsA ? 'c2s' : 's2c', stream.id, null);
    const reverse = parseMqttDirection(stream.bufferBtoA, reverseOffsets, clientIsA ? 's2c' : 'c2s', stream.id, null);
    if (forward.length === 0 && reverse.length === 0) return null;
    parsed = { clientPackets: clientIsA ? forward : reverse, serverPackets: clientIsA ? reverse : forward, level: null };
  }

  const clientPackets = parsed.clientPackets;
  const serverPackets = parsed.serverPackets;
  if (clientPackets.length === 0 && serverPackets.length === 0) return null;
  const connect = clientPackets.find(packet => packet.type === 1) ?? null;
  const notes: string[] = [];
  if (!connect) notes.push('未捕获 CONNECT 报文（抓包从中途开始），客户端身份未知。');
  const truncatedCount = [...clientPackets, ...serverPackets].filter(packet => packet.payloadTruncated).length;
  if (truncatedCount > 0) notes.push(`${truncatedCount} 个 PUBLISH 载荷超过保留上限（各保前 256KB），仅作预览与魔数识别。`);

  // 主题表：按 topic 聚合 PUBLISH——消息数、载荷总字节、魔数（任一消息命中即登记）、flag。
  const topicMap = new Map<string, MqttTopicRow>();
  for (const packet of [...clientPackets, ...serverPackets]) {
    if (packet.type !== 3 || packet.topic === null) continue;
    let row = topicMap.get(packet.topic);
    if (!row) {
      row = { topic: packet.topic, count: 0, totalPayloadBytes: 0, magic: null, hasFlag: false, qosLevels: [] };
      topicMap.set(packet.topic, row);
    }
    row.count += 1;
    row.totalPayloadBytes += packet.payload?.length ?? 0;
    if (!row.magic && packet.payload && packet.payload.length > 0) {
      row.magic = detectFileTypes(packet.payload)[0]?.name ?? null;
    }
    if (packet.hasFlag) row.hasFlag = true;
    if (!row.qosLevels.includes(packet.qos)) row.qosLevels.push(packet.qos);
  }
  const topics = [...topicMap.values()].sort((left, right) => right.count - left.count || left.topic.localeCompare(right.topic));
  for (const row of topics) row.qosLevels.sort((left, right) => left - right);

  const packets = [...clientPackets, ...serverPackets].sort((left, right) => left.packetIndex - right.packetIndex);

  return {
    streamId: stream.id,
    client: clientIsA ? stream.endpointA : stream.endpointB,
    server: clientIsA ? stream.endpointB : stream.endpointA,
    protocolName: connect?.protocolName ?? null,
    protocolLevel: connect?.protocolLevel ?? parsed.level,
    clientId: connect?.clientId ?? null,
    packets,
    topics,
    notes,
  };
};

export const analyzeMqtt = (analysis: CaptureAnalysis): MqttSession[] => {
  const sessions: MqttSession[] = [];
  for (const stream of analysis.streams) {
    if (sessions.length >= MQTT_MAX_SESSIONS) break;
    const session = analyzeMqttStream(stream);
    if (session) sessions.push(session);
  }
  return sessions;
};

// =====================================================================
// HTTP body 压缩多层解码（B2-10，RFC 7231 Content-Encoding + RFC 7230 报文结构）
// 双判据：Content-Encoding 头（gzip/deflate）与魔数（1f8b / 789c / 78da / 785e / 7890 / 7801）；
// DecompressionStream('gzip'|'deflate') 解压；解压产物仍是 base64/HTTP 时递归再解（层深 ≤3）；
// 每层记录类型与字节数。非压缩 body 零行为变化（不产生任何结果条目）。
// =====================================================================

export interface HttpBodyLayer {
  kind: string;
  byteLength: number;
  preview: string;
}

export interface HttpBodyDecodeResult {
  transactionIndex: number;
  direction: 'req' | 'res';
  startLine: string;
  contentEncoding: string | null;
  layers: HttpBodyLayer[];
  finalText: string | null;
  finalBytes: Uint8Array | null;
  error: string | null;
}

const MAX_DECODE_LAYERS = 3;
const MAX_DECODE_OUTPUT_BYTES = 8 * 1024 * 1024;

const layerPreview = (bytes: Uint8Array): string => {
  const decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, 256));
  let out = '';
  for (const ch of decoded) {
    const code = ch.codePointAt(0) ?? 0;
    const printable = code === 9 || code === 10 || code === 13 || code >= 32;
    out += printable ? ch : '·';
  }
  return out;
};

const isGzipMagic = (bytes: Uint8Array): boolean => bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
// zlib 头：CMF=0x78 + FLG（789c/78da/785e/7890/7801 为常见变体，按题面清单全收）。
const isZlibMagic = (bytes: Uint8Array): boolean =>
  bytes.length >= 2 && bytes[0] === 0x78 && (bytes[1] === 0x9c || bytes[1] === 0xda || bytes[1] === 0x5e || bytes[1] === 0x90 || bytes[1] === 0x01);

// DecompressionStream 管道：writer 单次写入 + reader 循环读出（兼容 vm 沙箱无 Response 的环境）。
const inflateWithStream = async (data: Uint8Array, format: 'gzip' | 'deflate'): Promise<Uint8Array | null> => {
  if (typeof DecompressionStream === 'undefined') return null;
  let overflow = false;
  try {
    const decompressor = new DecompressionStream(format);
    const writer = decompressor.writable.getWriter();
    const reader = decompressor.readable.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    // 写入前拷贝到自有 ArrayBuffer（write 的 BufferSource 形参要求非 SharedArrayBuffer 视图）。
    const settle = writer.write(new Uint8Array(data)).then(() => writer.close(), () => undefined);
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
      if (total > MAX_DECODE_OUTPUT_BYTES) {
        overflow = true;
        void reader.cancel();
        void writer.abort('size limit').catch(() => undefined);
        break;
      }
    }
    await settle;
    if (overflow) return null;
    return concatBytes(chunks);
  } catch {
    return null;
  }
};

const BASE64_CHARSET = /^[A-Za-z0-9+/=\s]+$/;
const BASE64_TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const looksLikeBase64 = (bytes: Uint8Array): boolean => {
  if (bytes.length < 8 || bytes.length % 4 !== 0) return false;
  const text = new TextDecoder('latin1').decode(bytes);
  if (!BASE64_CHARSET.test(text)) return false;
  const compact = text.replace(/\s+/g, '');
  return compact.length >= 8 && compact.length % 4 === 0;
};

const base64DecodeBytes = (bytes: Uint8Array): Uint8Array | null => {
  const compact = new TextDecoder('latin1').decode(bytes).replace(/\s+/g, '').replace(/=+$/, '');
  const out = new Uint8Array(Math.floor((compact.length * 3) / 4));
  let accumulator = 0;
  let bits = 0;
  let offset = 0;
  for (let index = 0; index < compact.length; index += 1) {
    const value = BASE64_TABLE.indexOf(compact[index]);
    if (value < 0) return null;
    accumulator = ((accumulator << 6) | value) >>> 0;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[offset] = (accumulator >>> bits) & 0xff;
      offset += 1;
    }
  }
  return out.subarray(0, offset);
};

// 状态行含原因短语（'HTTP/1.1 200 OK'），\d{3} 后允许任意非换行字符再接 CRLF。
const HTTP_RESPONSE_HEAD = /^HTTP\/1\.[01] \d{3}[^\r\n]*\r\n/;
const HTTP_REQUEST_HEAD = /^[A-Za-z]{3,10} [^ \r\n]+ HTTP\/1\.[01]\r\n/;

// 解压产物内嵌 HTTP 报文时提取其 body（Content-Length / chunked / 余量）。
const extractEmbeddedHttpBody = (bytes: Uint8Array): Uint8Array | null => {
  const text = new TextDecoder('latin1').decode(bytes);
  const isResponse = HTTP_RESPONSE_HEAD.test(text);
  const isRequest = HTTP_REQUEST_HEAD.test(text);
  if (!isResponse && !isRequest) return null;
  const firstLineEnd = text.indexOf('\r\n');
  if (firstLineEnd < 0) return null;
  const headerBlock = parseHeaderBlock(text, firstLineEnd + 2);
  const headerMap = new Map((headerBlock?.headers ?? []).map(header => [header.name, header.value]));
  const bodyStart = headerBlock ? headerBlock.end : text.indexOf('\r\n\r\n') + 4;
  if (bodyStart >= bytes.length) return new Uint8Array(0);
  const transferEncoding = headerMap.get('transfer-encoding') ?? '';
  if (/chunked/i.test(transferEncoding)) {
    const [consumed, decoded] = decodeChunkedBody(text, bodyStart);
    return consumed >= 0 ? latin1Encode(decoded) : bytes.subarray(bodyStart);
  }
  const contentLength = headerMap.get('content-length');
  if (contentLength !== undefined) {
    const length = parseInt(contentLength, 10);
    if (Number.isFinite(length) && length >= 0) {
      return bytes.subarray(bodyStart, Math.min(bytes.length, bodyStart + length));
    }
  }
  return bytes.subarray(bodyStart);
};

const decodeHttpBodyLayers = async (
  transactionIndex: number,
  message: HttpMessage,
): Promise<HttpBodyDecodeResult> => {
  const encodingHeader = message.headers.find(header => header.name === 'content-encoding')?.value.toLowerCase() ?? null;
  const layers: HttpBodyLayer[] = [{ kind: '原始 body', byteLength: message.bodyBytes.length, preview: layerPreview(message.bodyBytes) }];
  let current = message.bodyBytes;
  let error: string | null = null;
  let decodedAny = false;
  for (let depth = 0; depth < MAX_DECODE_LAYERS; depth += 1) {
    const encoding = depth === 0 ? encodingHeader : null;
    if (isGzipMagic(current) || (encoding !== null && encoding.includes('gzip'))) {
      const inflated = await inflateWithStream(current, 'gzip');
      if (!inflated) {
        error = 'gzip 解压失败（数据损坏、非 gzip 数据或超过 8MB 输出上限）';
        break;
      }
      current = inflated;
      layers.push({ kind: 'gzip 解压', byteLength: current.length, preview: layerPreview(current) });
      decodedAny = true;
      continue;
    }
    if (isZlibMagic(current) || (encoding !== null && encoding.includes('deflate'))) {
      const inflated = await inflateWithStream(current, 'deflate');
      if (!inflated) {
        error = 'deflate 解压失败（数据损坏、非 zlib 数据或超过 8MB 输出上限）';
        break;
      }
      current = inflated;
      layers.push({ kind: 'deflate 解压', byteLength: current.length, preview: layerPreview(current) });
      decodedAny = true;
      continue;
    }
    if (looksLikeBase64(current)) {
      const decoded = base64DecodeBytes(current);
      if (decoded !== null && decoded.length > 0) {
        current = decoded;
        layers.push({ kind: 'base64 解码', byteLength: current.length, preview: layerPreview(current) });
        decodedAny = true;
        continue;
      }
    }
    const headText = new TextDecoder('latin1').decode(current.subarray(0, 128));
    if (HTTP_RESPONSE_HEAD.test(headText) || HTTP_REQUEST_HEAD.test(headText)) {
      const embedded = extractEmbeddedHttpBody(current);
      if (embedded !== null) {
        current = embedded;
        layers.push({ kind: '内嵌 HTTP body', byteLength: current.length, preview: layerPreview(current) });
        decodedAny = true;
        continue;
      }
    }
    break;
  }
  if (error === null && decodedAny) {
    // 达到层深上限且当前层仍可继续解时，如实声明剩余层未解。
    const stillDecodable = isGzipMagic(current) || isZlibMagic(current) || looksLikeBase64(current);
    if (stillDecodable) error = `已解 ${MAX_DECODE_LAYERS} 层仍未到终态，更深层未继续（层深上限 ${MAX_DECODE_LAYERS}）`;
  }
  return {
    transactionIndex,
    direction: message.direction,
    startLine: message.startLine,
    contentEncoding: encodingHeader,
    layers,
    finalText: decodedAny ? new TextDecoder('utf-8', { fatal: false }).decode(current.subarray(0, 1024 * 1024)) : null,
    finalBytes: decodedAny ? current : null,
    error,
  };
};

// 逐事务解压请求/响应 body。只有"声明过压缩（头或魔数）"或真实解出 ≥1 层的 body 才产生条目；
// 纯文本 body 不产生任何条目（零行为变化）。
export const decodeHttpTransactionBodies = async (transactions: HttpTransaction[]): Promise<HttpBodyDecodeResult[]> => {
  const results: HttpBodyDecodeResult[] = [];
  for (let index = 0; index < transactions.length; index += 1) {
    const transaction = transactions[index];
    for (const message of [transaction.request, transaction.response]) {
      if (!message || message.bodyBytes.length === 0) continue;
      const claimedCompression =
        message.headers.some(header => header.name === 'content-encoding' && /gzip|deflate/i.test(header.value)) ||
        isGzipMagic(message.bodyBytes) ||
        isZlibMagic(message.bodyBytes);
      if (!claimedCompression && !looksLikeBase64(message.bodyBytes)) continue;
      const result = await decodeHttpBodyLayers(index, message);
      if (result.layers.length > 1 || result.error !== null) results.push(result);
    }
  }
  return results;
};
