// 协议剥离（批次 L）：Ethernet/VLAN → IPv4/IPv6（含基础扩展头）→ TCP/UDP/ICMP。
// 输入为 parser.ts 的 ParsedCapture，输出只读的包视图；payload 是帧内 subarray 引用。
// 批次二补强：DNS 报文全量解析（RFC 1035，UDP/TCP 53 双通道）、TLS 握手提取（RFC 5246/6066 SNI）。
import type { ParsedCapture } from './parser';

export type PacketProto = 'TCP' | 'UDP' | 'ICMP' | 'ICMPv6' | 'ARP' | 'IPv6' | 'other';

export interface PacketView {
  index: number;
  tsSeconds: number;
  linkType: number;
  linkSupported: boolean;
  proto: PacketProto;
  src: string;
  dst: string;
  srcPort: number | null;
  dstPort: number | null;
  length: number;
  info: string;
  isHttpRequest: boolean;
  isHttpResponse: boolean;
  isDns: boolean;
  // TCP/UDP 载荷（帧内偏移切片）；无载荷为 null。
  payload: Uint8Array | null;
  tcpFlags: number | null;
  tcpSeq: number | null;
  // 整帧字节（原文件内 subarray 引用），供 hexdump 详情。
  frame: Uint8Array;
}

const LINK_ETHERNET = 1;
const ETH_TYPE_IPV4 = 0x0800;
const ETH_TYPE_IPV6 = 0x86dd;
const ETH_TYPE_ARP = 0x0806;
const ETH_TYPE_VLAN = 0x8100;
const ETH_TYPE_QINQ = 0x88a8;

const IP_PROTO_ICMP = 1;
const IP_PROTO_TCP = 6;
const IP_PROTO_UDP = 17;
const IP_PROTO_ICMPV6 = 58;

const TCP_FLAG_NAMES: Array<[number, string]> = [
  [0x02, 'SYN'], [0x10, 'ACK'], [0x01, 'FIN'], [0x04, 'RST'], [0x08, 'PSH'], [0x20, 'URG'],
];

const TCP_METHOD_PATTERN = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) /;
const HTTP_STATUS_PATTERN = /^HTTP\/1\.[01] \d{3}/;

const formatMac = (bytes: Uint8Array, offset: number): string =>
  Array.from(bytes.subarray(offset, offset + 6), byte => byte.toString(16).padStart(2, '0')).join(':');

const formatIpv4 = (bytes: Uint8Array, offset: number): string =>
  Array.from(bytes.subarray(offset, offset + 4), byte => String(byte)).join('.');

const formatIpv6 = (bytes: Uint8Array, offset: number): string => {
  const groups: string[] = [];
  for (let index = 0; index < 8; index += 1) {
    groups.push(((bytes[offset + index * 2] << 8) | bytes[offset + index * 2 + 1]).toString(16));
  }
  // RFC 5952：最长全零段压缩为 ::（仅压缩一段，避免歧义）。
  let bestStart = -1;
  let bestLength = 0;
  let runStart = -1;
  for (let index = 0; index <= groups.length; index += 1) {
    if (index < groups.length && groups[index] === '0') {
      if (runStart < 0) runStart = index;
    } else if (runStart >= 0) {
      if (index - runStart > bestLength) {
        bestLength = index - runStart;
        bestStart = runStart;
      }
      runStart = -1;
    }
  }
  if (bestLength >= 2) {
    groups.splice(bestStart, bestLength, ':');
  }
  return groups.join(':').replace(/:::/, '::').replace(/^:($|:)/, '::');
};

const tcpFlagsText = (flags: number): string =>
  TCP_FLAG_NAMES.filter(([bit]) => (flags & bit) !== 0).map(([, name]) => name).join(', ') || '-';

const icmpSummary = (type: number, code: number): string => {
  if (type === 8 && code === 0) return 'Echo (ping) request';
  if (type === 0 && code === 0) return 'Echo (ping) reply';
  if (type === 3) return 'Destination unreachable';
  if (type === 11) return 'Time exceeded';
  return `type=${type} code=${code}`;
};

// 以 IP 头声明的总长收尾，避免以太网 padding 被当作载荷。
const trimPayloadByIpTotal = (data: Uint8Array, l4Offset: number, ipTotalLength: number, ipHeaderLength: number): Uint8Array => {
  const end = Math.min(data.length, l4Offset + Math.max(0, ipTotalLength - ipHeaderLength));
  return end > l4Offset ? data.subarray(l4Offset, end) : data.subarray(l4Offset, l4Offset);
};

// IPv6 扩展头跳过：hop-by-hop/routing/dest opts 长度 = 8 + hdr_ext_len*8，AH = 4*(len+2)，fragment 固定 8。
const ipv6NextHeader = (data: Uint8Array, offset: number, initial: number, limit: number): { proto: number; l4Offset: number } => {
  let proto = initial;
  let cursor = offset;
  for (let hop = 0; hop < 8; hop += 1) {
    if (proto === 0 || proto === 60 || proto === 43) {
      if (cursor + 2 > limit) return { proto: -1, l4Offset: cursor };
      proto = data[cursor];
      cursor += 8 + data[cursor + 1] * 8;
    } else if (proto === 51) {
      if (cursor + 2 > limit) return { proto: -1, l4Offset: cursor };
      proto = data[cursor];
      cursor += (data[cursor + 1] + 2) * 4;
    } else if (proto === 44) {
      if (cursor + 8 > limit) return { proto: -1, l4Offset: cursor };
      proto = data[cursor];
      cursor += 8;
    } else {
      return { proto, l4Offset: cursor };
    }
  }
  return { proto: -1, l4Offset: cursor };
};

interface BuildOutcome {
  proto: PacketProto;
  src: string;
  dst: string;
  srcPort: number | null;
  dstPort: number | null;
  info: string;
  payload: Uint8Array | null;
  tcpFlags: number | null;
  tcpSeq: number | null;
  isHttpRequest: boolean;
  isHttpResponse: boolean;
}

const none: BuildOutcome = {
  proto: 'other', src: '-', dst: '-', srcPort: null, dstPort: null,
  info: '', payload: null, tcpFlags: null, tcpSeq: null, isHttpRequest: false, isHttpResponse: false,
};

const decodeHead = (payload: Uint8Array, maxBytes: number): string =>
  new TextDecoder('latin1').decode(payload.subarray(0, Math.min(payload.length, maxBytes)));

const firstLine = (payload: Uint8Array): string => {
  const text = decodeHead(payload, 96);
  const lineEnd = text.indexOf('\r');
  return (lineEnd > 0 ? text.slice(0, lineEnd) : text).slice(0, 72);
};

const parseFrame = (data: Uint8Array): BuildOutcome => {
  if (data.length < 14) return { ...none, info: data.length ? `过短帧（${data.length} 字节）` : '空帧' };
  let ethertype = (data[12] << 8) | data[13];
  let cursor = 14;
  for (let vlan = 0; vlan < 2 && (ethertype === ETH_TYPE_VLAN || ethertype === ETH_TYPE_QINQ); vlan += 1) {
    if (cursor + 4 > data.length) return { ...none, info: 'VLAN 头截断' };
    ethertype = (data[cursor + 2] << 8) | data[cursor + 3];
    cursor += 4;
  }
  if (ethertype === ETH_TYPE_ARP) {
    return { ...none, proto: 'ARP', src: formatMac(data, 6), dst: formatMac(data, 0), info: data.length >= cursor + 28 ? 'ARP' : 'ARP（截断）' };
  }
  if (ethertype !== ETH_TYPE_IPV4 && ethertype !== ETH_TYPE_IPV6) {
    return { ...none, src: formatMac(data, 6), dst: formatMac(data, 0), info: `EtherType 0x${ethertype.toString(16).padStart(4, '0')}` };
  }
  if (ethertype === ETH_TYPE_IPV4) {
    if (cursor + 20 > data.length) return { ...none, src: formatMac(data, 6), dst: formatMac(data, 0), info: 'IPv4 头截断' };
    const ihl = (data[cursor] & 0x0f) * 4;
    if (ihl < 20) return { ...none, src: formatMac(data, 6), dst: formatMac(data, 0), info: `IPv4 IHL 非法（${ihl}）` };
    const totalLength = (data[cursor + 2] << 8) | data[cursor + 3];
    const fragmentOffset = ((data[cursor + 6] << 8) | data[cursor + 7]) & 0x1fff;
    const protocol = data[cursor + 9];
    const srcIp = formatIpv4(data, cursor + 12);
    const dstIp = formatIpv4(data, cursor + 16);
    const l4 = cursor + ihl;
    const base = { src: srcIp, dst: dstIp, srcPort: null as number | null, dstPort: null as number | null, tcpFlags: null as number | null };
    if (fragmentOffset > 0) {
      return { ...none, ...base, proto: 'other', info: `IPv4 分片 offset=${fragmentOffset * 8}（不重组）` };
    }
    if (protocol === IP_PROTO_TCP && l4 + 20 <= data.length) {
      const srcPort = (data[l4] << 8) | data[l4 + 1];
      const dstPort = (data[l4 + 2] << 8) | data[l4 + 3];
      const seq = ((data[l4 + 4] << 24) | (data[l4 + 5] << 16) | (data[l4 + 6] << 8) | data[l4 + 7]) >>> 0;
      const flags = data[l4 + 13];
      const headerLength = ((data[l4 + 12] >> 4) & 0x0f) * 4;
      const payloadStart = headerLength >= 20 ? l4 + headerLength : l4 + 20;
      const trimmed = trimPayloadByIpTotal(data, payloadStart, totalLength || data.length, ihl + (headerLength >= 20 ? headerLength : 20));
      // 无数据包（SYN/纯 ACK）载荷置 null：流重组与 HTTP 解析都据此跳过。
      const payload = trimmed.length > 0 ? trimmed : null;
      const head = payload ? decodeHead(payload, 16) : '';
      const isHttpRequest = head.length >= 4 && TCP_METHOD_PATTERN.test(head);
      const isHttpResponse = head.length >= 12 && HTTP_STATUS_PATTERN.test(head);
      const info = payload && (isHttpRequest || isHttpResponse) ? firstLine(payload) : `${tcpFlagsText(flags)}, seq ${seq}`;
      return { ...none, ...base, srcPort, dstPort, proto: 'TCP', info, payload, tcpFlags: flags, tcpSeq: seq, isHttpRequest, isHttpResponse };
    }
    if (protocol === IP_PROTO_UDP && l4 + 8 <= data.length) {
      const srcPort = (data[l4] << 8) | data[l4 + 1];
      const dstPort = (data[l4 + 2] << 8) | data[l4 + 3];
      const payload = trimPayloadByIpTotal(data, l4 + 8, totalLength || data.length, ihl + 8);
      return {
        ...none, ...base, srcPort, dstPort, proto: 'UDP', payload,
        info: srcPort === 53 || dstPort === 53 ? 'DNS' : `${payload.length} 字节载荷`,
      };
    }
    if (protocol === IP_PROTO_ICMP && l4 + 4 <= data.length) {
      // echo request/reply（type 0/8）载荷在 8 字节 ICMP 头之后——数据外带题常把 flag 分片藏在 echo data 里。
      const icmpType = data[l4];
      const icmpHeader = icmpType === 0 || icmpType === 8 ? 8 : 4;
      const icmpPayload = data.length > l4 + icmpHeader ? data.subarray(l4 + icmpHeader) : null;
      return { ...none, ...base, proto: 'ICMP', info: icmpSummary(icmpType, data[l4 + 1]), payload: icmpPayload };
    }
    return { ...none, ...base, proto: 'other', info: `IPv4 协议号 ${protocol}` };
  }
  // IPv6
  if (cursor + 40 > data.length) return { ...none, src: formatMac(data, 6), dst: formatMac(data, 0), info: 'IPv6 头截断' };
  const nextHeader = data[cursor + 6];
  const payloadLength = (data[cursor + 4] << 8) | data[cursor + 5];
  const srcIp = formatIpv6(data, cursor + 8);
  const dstIp = formatIpv6(data, cursor + 24);
  const limit = payloadLength > 0 ? Math.min(data.length, cursor + 40 + payloadLength) : data.length;
  const base = { src: srcIp, dst: dstIp, srcPort: null as number | null, dstPort: null as number | null, tcpFlags: null as number | null };
  const { proto, l4Offset } = ipv6NextHeader(data, cursor + 40, nextHeader, limit);
  if (proto === IP_PROTO_TCP && l4Offset + 20 <= data.length) {
    const srcPort = (data[l4Offset] << 8) | data[l4Offset + 1];
    const dstPort = (data[l4Offset + 2] << 8) | data[l4Offset + 3];
    const seq = ((data[l4Offset + 4] << 24) | (data[l4Offset + 5] << 16) | (data[l4Offset + 6] << 8) | data[l4Offset + 7]) >>> 0;
    const flags = data[l4Offset + 13];
    const headerLength = ((data[l4Offset + 12] >> 4) & 0x0f) * 4;
    const payloadStart = headerLength >= 20 ? l4Offset + headerLength : l4Offset + 20;
    const trimmedV6 = data.subarray(payloadStart, limit);
    const payload = trimmedV6.length > 0 ? trimmedV6 : null;
    const headV6 = payload ? decodeHead(payload, 16) : '';
    const isHttpRequestV6 = headV6.length >= 4 && TCP_METHOD_PATTERN.test(headV6);
    const isHttpResponseV6 = headV6.length >= 12 && HTTP_STATUS_PATTERN.test(headV6);
    const infoV6 = isHttpRequestV6 || isHttpResponseV6 ? firstLine(payload!) : `${tcpFlagsText(flags)}, seq ${seq}`;
    return { ...none, ...base, srcPort, dstPort, proto: 'TCP', payload, tcpFlags: flags, tcpSeq: seq, info: infoV6, isHttpRequest: isHttpRequestV6, isHttpResponse: isHttpResponseV6 };
  }
  if (proto === IP_PROTO_UDP && l4Offset + 8 <= data.length) {
    const srcPort = (data[l4Offset] << 8) | data[l4Offset + 1];
    const dstPort = (data[l4Offset + 2] << 8) | data[l4Offset + 3];
    return { ...none, ...base, srcPort, dstPort, proto: 'UDP', payload: data.subarray(l4Offset + 8, limit), info: 'UDPv6' };
  }
  if (proto === IP_PROTO_ICMPV6 && l4Offset + 4 <= data.length) {
    return { ...none, ...base, proto: 'ICMPv6', info: icmpSummary(data[l4Offset], data[l4Offset + 1]) };
  }
  return { ...none, ...base, proto: 'IPv6', info: `IPv6 next header ${nextHeader}` };
};

export const buildPacketViews = (capture: ParsedCapture): PacketView[] => {
  return capture.packets.map(packet => {
    const supported = packet.linkType === LINK_ETHERNET;
    const decoded = supported && packet.capturedLen > 0 ? parseFrame(packet.data) : null;
    return {
      index: packet.index,
      tsSeconds: packet.tsSeconds,
      linkType: packet.linkType,
      linkSupported: supported,
      proto: decoded?.proto ?? 'other',
      src: decoded?.src ?? '-',
      dst: decoded?.dst ?? '-',
      srcPort: decoded?.srcPort ?? null,
      dstPort: decoded?.dstPort ?? null,
      length: packet.originalLen,
      info: supported
        ? decoded?.info || ''
        : `链路层类型 ${packet.linkType}（仅支持 Ethernet，未解析）`,
      isHttpRequest: decoded?.isHttpRequest ?? false,
      isHttpResponse: decoded?.isHttpResponse ?? false,
      // DNS 口径（批次二起含 TCP 53）：UDP 53 逐包即报文；TCP 53 需流重组后按两字节长度前缀成帧。
      isDns: (decoded?.proto === 'UDP' || decoded?.proto === 'TCP') && (decoded?.srcPort === 53 || decoded?.dstPort === 53),
      payload: decoded?.payload ?? null,
      tcpFlags: decoded?.tcpFlags ?? null,
      tcpSeq: decoded?.tcpSeq ?? null,
      frame: packet.data,
    };
  });
};

// ===== DNS 报文全量解析（批次二 B2-3） =====
// 算法出处：RFC 1035 §4（报文格式）与 §4.1.4（名字压缩指针）、§3.3.14（TXT character-string）；
// 术语与字段名对照 RFC 8499。对拍锚点：tests/pcap-dns-tls.test.mjs 内嵌 dnspython 生成的
// wire 样本（SAMPLE_A/B/C_HEX，开发期双向对拍：dnspython 生成 → 本解析器读出同值）。

export interface DnsQuestion {
  name: string;
  type: number;
  typeText: string;
  classText: string;
}

export interface DnsRecord {
  name: string;
  type: number;
  typeText: string;
  classText: string;
  ttl: number;
  // 展示值：A/AAAA 点分、域名类为名字、MX「优先级 交换机」、SOA 七元组、SRV「优先级 权重 端口 目标」、其余十六进制。
  value: string;
  // TXT 专供：逐段 character-string 原文（RFC 1035 §3.3.14 允许多段）；其他类型为 null。
  values: string[] | null;
  section: 'answer' | 'authority' | 'additional';
}

export interface DnsMessage {
  id: number;
  isResponse: boolean;
  opcode: number;
  opcodeText: string;
  authoritative: boolean;
  truncated: boolean;
  recursionDesired: boolean;
  rcode: number;
  rcodeText: string;
  questions: DnsQuestion[];
  records: DnsRecord[];
  // 结构性解析失败的原因（名字指针非法、RR 越界等）；整体报文仍尽量保留已解出部分。
  parseError: string | null;
}

const DNS_HEADER_BYTES = 12;
// RFC 1035 §2.3.4：域名全长上限 255 字节、标签上限 63；防御上限另加指针跳数与 RR 总量。
const MAX_DNS_NAME_BYTES = 255;
const MAX_DNS_LABELS = 128;
const MAX_DNS_POINTER_JUMPS = 64;
const MAX_DNS_QUESTIONS = 32;
const MAX_DNS_RECORDS = 512;

const DNS_TYPE_TEXT: Record<number, string> = {
  1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV',
};
const DNS_CLASS_TEXT: Record<number, string> = { 1: 'IN', 3: 'CH', 4: 'HS' };
const DNS_OPCODE_TEXT: Record<number, string> = { 0: 'QUERY', 1: 'IQUERY', 2: 'STATUS', 4: 'NOTIFY', 5: 'UPDATE' };
const DNS_RCODE_TEXT: Record<number, string> = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' };

const dnsTypeText = (type: number): string => DNS_TYPE_TEXT[type] ?? `TYPE${type}`;
const dnsClassText = (klass: number): string => DNS_CLASS_TEXT[klass] ?? `CLASS${klass}`;

const readU16At = (bytes: Uint8Array, offset: number): number => (bytes[offset] << 8) | bytes[offset + 1];
const readU32At = (bytes: Uint8Array, offset: number): number =>
  ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');

const latin1At = (bytes: Uint8Array, start: number, end: number): string =>
  new TextDecoder('latin1').decode(bytes.subarray(start, end));

// 名字解压（含压缩指针递归）：返回解出的名字与「首个非指针字节的后一位置」。
// 防环双重护栏：①指针只许指向前方（target < 指针自身位置，RFC 1035 压缩语义必然如此，
// 严格递减即不可能成环）；②visited 集合 + 跳数上限兜底防御畸形报文。
const readDnsName = (bytes: Uint8Array, offset: number): { name: string; next: number } | null => {
  const labels: string[] = [];
  const visited = new Set<number>();
  let cursor = offset;
  let next = -1;
  let totalLength = 0;
  for (;;) {
    if (cursor >= bytes.length) return null;
    const length = bytes[cursor];
    if (length === 0) {
      if (next < 0) next = cursor + 1;
      break;
    }
    if ((length & 0xc0) === 0xc0) {
      if (cursor + 1 >= bytes.length) return null;
      const target = ((length & 0x3f) << 8) | bytes[cursor + 1];
      if (target >= cursor || visited.has(target) || visited.size >= MAX_DNS_POINTER_JUMPS) return null;
      visited.add(cursor);
      if (next < 0) next = cursor + 2;
      cursor = target;
      continue;
    }
    // 0x40/0x80 开头是 EDNS0 位图等保留标签类型（RFC 1035 §4.1.4 未定义），按非法处理。
    if ((length & 0xc0) !== 0) return null;
    if (cursor + 1 + length > bytes.length) return null;
    totalLength += length + 1;
    if (totalLength > MAX_DNS_NAME_BYTES || labels.length >= MAX_DNS_LABELS) return null;
    labels.push(latin1At(bytes, cursor + 1, cursor + 1 + length));
    cursor += 1 + length;
  }
  return { name: labels.join('.'), next };
};

const DNS_SECTION_LABEL: Record<DnsRecord['section'], string> = {
  answer: '回答', authority: '授权', additional: '附加',
};

// 单条 RR 解析：游标处为所有者名字，随后 type(2)/class(2)/ttl(4)/rdlength(2)/rdata。
const parseDnsRecord = (bytes: Uint8Array, cursor: number, section: DnsRecord['section']): { record: DnsRecord; next: number } | null => {
  const owner = readDnsName(bytes, cursor);
  if (!owner || owner.next + 10 > bytes.length) return null;
  const type = readU16At(bytes, owner.next);
  const klass = readU16At(bytes, owner.next + 2);
  const ttl = readU32At(bytes, owner.next + 4);
  const rdLength = readU16At(bytes, owner.next + 8);
  const rdataStart = owner.next + 10;
  const rdataEnd = rdataStart + rdLength;
  if (rdataEnd > bytes.length) return null;
  let value = '';
  let values: string[] | null = null;
  if (type === 1 && rdLength === 4) {
    value = formatIpv4(bytes, rdataStart);
  } else if (type === 28 && rdLength === 16) {
    value = formatIpv6(bytes, rdataStart);
  } else if (type === 2 || type === 5 || type === 12) {
    // NS/CNAME/PTR：RDATA 即域名（指针可指回报文其他区域）。
    const target = readDnsName(bytes, rdataStart);
    value = target ? target.name : toHex(bytes.subarray(rdataStart, rdataEnd));
  } else if (type === 15 && rdLength >= 3) {
    // MX：preference(2) + exchange 名字。
    const exchange = readDnsName(bytes, rdataStart + 2);
    value = exchange ? `${readU16At(bytes, rdataStart)} ${exchange.name}` : toHex(bytes.subarray(rdataStart, rdataEnd));
  } else if (type === 16) {
    // TXT：一至多个 character-string（长度前缀 1 字节，串内无转义）。
    values = [];
    let piece = rdataStart;
    while (piece < rdataEnd) {
      const pieceLength = bytes[piece];
      if (piece + 1 + pieceLength > rdataEnd) break;
      values.push(latin1At(bytes, piece + 1, piece + 1 + pieceLength));
      piece += 1 + pieceLength;
    }
    value = values.join('');
  } else if (type === 6 && rdLength >= 20) {
    // SOA：mname rname + serial/refresh/retry/expire/minimum 五个 32 位整数。
    const mname = readDnsName(bytes, rdataStart);
    if (mname && mname.next + 20 <= rdataEnd) {
      const rname = readDnsName(bytes, mname.next);
      if (rname && rname.next + 20 <= rdataEnd) {
        const numbers = [0, 4, 8, 12, 16].map(step => readU32At(bytes, rname.next + step));
        value = `${mname.name} ${rname.name} ${numbers.join(' ')}`;
      }
    }
    if (!value) value = toHex(bytes.subarray(rdataStart, rdataEnd));
  } else if (type === 33 && rdLength >= 7) {
    // SRV（RFC 2782）：priority(2) weight(2) port(2) + target 名字。
    const target = readDnsName(bytes, rdataStart + 6);
    value = target
      ? `${readU16At(bytes, rdataStart)} ${readU16At(bytes, rdataStart + 2)} ${readU16At(bytes, rdataStart + 4)} ${target.name}`
      : toHex(bytes.subarray(rdataStart, rdataEnd));
  } else {
    // 未覆盖类型：十六进制兜底（CTF 里 UNKNOWN/TYPE999 藏线索时仍可读）。
    value = toHex(bytes.subarray(rdataStart, rdataEnd));
  }
  return {
    record: { name: owner.name, type, typeText: dnsTypeText(type), classText: dnsClassText(klass), ttl, value, values, section },
    next: rdataEnd,
  };
};

// DNS 报文解析主入口：bytes 为单个 DNS 报文（UDP 53 载荷，或 TCP 流里两字节长度前缀框出的分段）。
// 结构非法（<12 字节头部）返回 null；局部畸形返回 message 并在 parseError 注明。
export const parseDnsMessage = (bytes: Uint8Array): DnsMessage | null => {
  if (bytes.length < DNS_HEADER_BYTES) return null;
  const flags = readU16At(bytes, 2);
  const questionCount = readU16At(bytes, 4);
  const answerCount = readU16At(bytes, 6);
  const authorityCount = readU16At(bytes, 8);
  const additionalCount = readU16At(bytes, 10);
  const opcode = (flags >> 11) & 0x0f;
  const rcode = flags & 0x000f;
  const message: DnsMessage = {
    id: readU16At(bytes, 0),
    isResponse: (flags & 0x8000) !== 0,
    opcode,
    opcodeText: DNS_OPCODE_TEXT[opcode] ?? `OPCODE${opcode}`,
    authoritative: (flags & 0x0400) !== 0,
    truncated: (flags & 0x0200) !== 0,
    recursionDesired: (flags & 0x0100) !== 0,
    rcode,
    rcodeText: DNS_RCODE_TEXT[rcode] ?? `RCODE${rcode}`,
    questions: [],
    records: [],
    parseError: null,
  };
  let cursor = DNS_HEADER_BYTES;
  let error: string | null = null;
  if (questionCount > MAX_DNS_QUESTIONS) error = `Question 数 ${questionCount} 超过防御上限`;
  for (let index = 0; index < questionCount && !error; index += 1) {
    const name = readDnsName(bytes, cursor);
    if (!name || name.next + 4 > bytes.length) {
      error = `Question 区第 ${index + 1} 条解析失败`;
      break;
    }
    const type = readU16At(bytes, name.next);
    const klass = readU16At(bytes, name.next + 2);
    message.questions.push({ name: name.name, type, typeText: dnsTypeText(type), classText: dnsClassText(klass) });
    cursor = name.next + 4;
  }
  const sections: Array<[number, DnsRecord['section']]> = [
    [answerCount, 'answer'], [authorityCount, 'authority'], [additionalCount, 'additional'],
  ];
  let recordBudget = MAX_DNS_RECORDS;
  for (const [count, section] of sections) {
    for (let index = 0; index < count && !error; index += 1) {
      if (recordBudget <= 0) {
        error = 'RR 数量超过防御上限，已截断';
        break;
      }
      const parsed = parseDnsRecord(bytes, cursor, section);
      if (!parsed) {
        error = `${DNS_SECTION_LABEL[section]}区第 ${index + 1} 条 RR 解析失败`;
        break;
      }
      message.records.push(parsed.record);
      cursor = parsed.next;
      recordBudget -= 1;
    }
    if (error) break;
  }
  message.parseError = error;
  return message;
};

// ===== TLS 握手提取（批次二 B2-4） =====
// 算法出处：RFC 5246 §6.2.1（record 层：type/version/length）与 §7.4（handshake 消息结构）、
// SNI 扩展 RFC 6066 §3（server_name_list → host_name）。对拍锚点：
// tests/pcap-dns-tls.test.mjs 手算 ClientHello/ServerHello 字节（注释含逐字段偏移），
// 并覆盖跨 TCP 段重组后的流式输入。random/session_id 全量透出，为后续 keylog 匹配（B2-6）留口。

export interface TlsHandshake {
  kind: 'client' | 'server';
  // record 层版本（0x0301 → 'TLS 1.0'）与握手消息内版本，两者在真实抓包中常不一致。
  recordVersion: string;
  handshakeVersion: string;
  // 32 字节 random（ClientHello/ServerHello 各一），TLS 1.2 及以下 keylog 派生的输入之一。
  random: Uint8Array;
  sessionId: Uint8Array;
  // SNI host_name（仅 ClientHello 携带；无 SNI 扩展为 null）。
  sni: string | null;
  serverNames: string[];
  // 解析中途越界（畸形或截断）时置位，已解出的字段仍保留。
  truncated: boolean;
}

const TLS_CONTENT_HANDSHAKE = 22;
const TLS_HANDSHAKE_CLIENT_HELLO = 0x01;
const TLS_HANDSHAKE_SERVER_HELLO = 0x02;
const TLS_SNI_EXTENSION = 0x0000;
const TLS_HANDSHAKE_HEADER_BYTES = 4;
// record 层 5 字节头 + 聚合握手缓冲防御上限（正常 ClientHello 数百字节）。
const MAX_TLS_HANDSHAKE_BUFFER = 512 * 1024;
const MAX_TLS_HANDSHAKES = 16;

const tlsVersionText = (version: number): string => {
  const known: Record<number, string> = { 0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };
  return known[version] ?? `0x${version.toString(16).padStart(4, '0')}`;
};

// 解析 ClientHello/ServerHello 消息体（不含 4 字节 handshake 头）。
const parseHelloBody = (kind: 'client' | 'server', body: Uint8Array, recordVersion: number): TlsHandshake => {
  const base: TlsHandshake = {
    kind,
    recordVersion: tlsVersionText(recordVersion),
    handshakeVersion: '-',
    random: new Uint8Array(0),
    sessionId: new Uint8Array(0),
    sni: null,
    serverNames: [],
    truncated: true,
  };
  // version(2) random(32) session_id_len(1)：公共前缀。
  if (body.length < 35) return base;
  const handshakeVersion = readU16At(body, 0);
  const random = body.slice(2, 34);
  const sessionIdLength = body[34];
  let cursor = 35;
  if (cursor + sessionIdLength > body.length) return base;
  const sessionId = body.slice(cursor, cursor + sessionIdLength);
  cursor += sessionIdLength;
  const hello: TlsHandshake = { ...base, handshakeVersion: tlsVersionText(handshakeVersion), random, sessionId, truncated: false };
  if (kind === 'client') {
    // ClientHello：cipher_suites<2..2^16-2> + compression_methods<1..255> + extensions。
    if (cursor + 2 > body.length) return { ...hello, truncated: true };
    cursor += 2 + readU16At(body, cursor);
    if (cursor + 1 > body.length) return { ...hello, truncated: true };
    cursor += 1 + body[cursor];
    if (cursor + 2 > body.length) return { ...hello, truncated: true };
    const extensionsEnd = Math.min(body.length, cursor + 2 + readU16At(body, cursor));
    cursor += 2;
    while (cursor + 4 <= extensionsEnd) {
      const extensionType = readU16At(body, cursor);
      const extensionLength = readU16At(body, cursor + 2);
      cursor += 4;
      if (cursor + extensionLength > extensionsEnd) return { ...hello, truncated: true };
      if (extensionType === TLS_SNI_EXTENSION && extensionLength >= 2) {
        // RFC 6066 §3：server_name_list_length(2) + 若干 (name_type 1 + length 2 + host)。
        let entry = cursor + 2;
        const listEnd = cursor + extensionLength;
        while (entry + 3 <= listEnd) {
          const nameType = body[entry];
          const nameLength = readU16At(body, entry + 1);
          entry += 3;
          if (entry + nameLength > listEnd) return { ...hello, truncated: true };
          if (nameType === 0) {
            const host = latin1At(body, entry, entry + nameLength);
            hello.serverNames.push(host);
            if (hello.sni === null) hello.sni = host;
          }
          entry += nameLength;
        }
      }
      cursor += extensionLength;
    }
  } else {
    // ServerHello：cipher_suite(2) + compression_method(1)；extensions 可选，不展开。
    if (cursor + 3 > body.length) return { ...hello, truncated: true };
  }
  return hello;
};

// 从重组后的 TCP 流字节中提取全部 ClientHello/ServerHello。
// record 逐个走（type 20-23 才像 TLS），type 22 的载荷聚合后按 handshake 消息切分——
// 一条握手消息允许跨多个 record（RFC 5246 §6.2.1），故先拼接再解析。
export const parseTlsHandshakes = (stream: Uint8Array, options?: { maxHandshakes?: number }): TlsHandshake[] => {
  const maxHandshakes = options?.maxHandshakes ?? MAX_TLS_HANDSHAKES;
  const chunks: Uint8Array[] = [];
  let handshakeBytes = 0;
  let recordVersionSeen = 0x0300;
  let cursor = 0;
  while (cursor + 5 <= stream.length) {
    const contentType = stream[cursor];
    const recordVersion = readU16At(stream, cursor + 1);
    const recordLength = readU16At(stream, cursor + 3);
    // 非 TLS record（content type 越界）或版本不像 SSL3.0-TLS1.3：认为流不是 TLS，停止。
    if (contentType < 20 || contentType > 23) break;
    if ((recordVersion >> 8) !== 0x03 || (recordVersion & 0xff) > 0x04) break;
    const bodyStart = cursor + 5;
    if (bodyStart + recordLength > stream.length) break;
    if (contentType === TLS_CONTENT_HANDSHAKE) {
      chunks.push(stream.subarray(bodyStart, bodyStart + recordLength));
      handshakeBytes += recordLength;
      if (recordVersionSeen === 0x0300) recordVersionSeen = recordVersion;
      if (handshakeBytes > MAX_TLS_HANDSHAKE_BUFFER) break;
    }
    cursor = bodyStart + recordLength;
  }
  const handshakes: TlsHandshake[] = [];
  let position = 0;
  // 聚合缓冲：握手消息按 type(1)+length(3) 顺序排布。
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.length;
  }
  while (position + TLS_HANDSHAKE_HEADER_BYTES <= joined.length && handshakes.length < maxHandshakes) {
    const handshakeType = joined[position];
    const bodyLength = (joined[position + 1] << 16) | (joined[position + 2] << 8) | joined[position + 3];
    const bodyStart = position + TLS_HANDSHAKE_HEADER_BYTES;
    if (bodyStart + bodyLength > joined.length) break;
    if (handshakeType === TLS_HANDSHAKE_CLIENT_HELLO || handshakeType === TLS_HANDSHAKE_SERVER_HELLO) {
      handshakes.push(parseHelloBody(
        handshakeType === TLS_HANDSHAKE_CLIENT_HELLO ? 'client' : 'server',
        joined.subarray(bodyStart, bodyStart + bodyLength),
        recordVersionSeen,
      ));
    }
    position = bodyStart + bodyLength;
  }
  return handshakes;
};
