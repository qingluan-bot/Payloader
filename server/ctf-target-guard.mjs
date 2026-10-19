// CTF 目标防护（SSRF 缓解，环境感知）：本机回环自用形态默认放行（题目靶机场景完整保留），
// 非回环监听（0.0.0.0/对外地址）默认拦截回环/内网/链路本地目标；PAYLOADER_CTF_TARGET_POLICY
// 可显式指定 off|protected 覆盖自动判定。域名目标经 DNS 预解析后逐地址校验，解析失败即拒绝。
// 残余风险：预解析与实际连接之间存在 DNS rebinding 窗口，本防护目标是公网滥用缓解而非 APT 防御。

import { lookup } from 'node:dns/promises';

const loopbackListenHosts = new Set(['127.0.0.1', '::1', 'localhost']);
const dnsCacheTtlMs = 60_000;
const dnsCacheLimit = 512;

// IPv4 阻断段（网络字节序前缀比较）：0/8（本网络）、10/8、100.64/10（CGNAT）、
// 127/8（回环）、169.254/16（链路本地/云 metadata）、172.16/12、192.168/16、198.18/15（基准测试）、240/4（保留）
const blockedV4Prefixes = [
  { bytes: [0], length: 8 },
  { bytes: [10], length: 8 },
  { bytes: [100, 64], length: 10 },
  { bytes: [127], length: 8 },
  { bytes: [169, 254], length: 16 },
  { bytes: [172, 16], length: 12 },
  { bytes: [192, 168], length: 16 },
  { bytes: [198, 18], length: 15 },
  { bytes: [240], length: 4 },
];

// IPv6 阻断段：::（未指定）、::1（回环）、::ffff:0:0/96（v4 映射，展开后按 v4 规则判定）、
// fc00::/7（ULA 内网）、fe80::/10（链路本地）
const blockedV6Prefixes = [
  { bytes: [], length: 0, exactUnspecified: true },
  { bytes: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], length: 128 },
  { bytes: [0xfc], length: 7 },
  { bytes: [0xfe, 0x80], length: 10 },
];

const matchesPrefix = (bytes, prefix) => {
  if (prefix.exactUnspecified) return bytes.every(byte => byte === 0);
  const byteLength = Math.ceil(prefix.length / 8);
  for (let index = 0; index < byteLength; index += 1) {
    const bitsInByte = Math.min(8, prefix.length - index * 8);
    if (bitsInByte === 8) {
      if (bytes[index] !== prefix.bytes[index]) return false;
    } else {
      const mask = (0xff << (8 - bitsInByte)) & 0xff;
      if ((bytes[index] & mask) !== (prefix.bytes[index] & mask)) return false;
    }
  }
  return true;
};

export const parseIpv4 = value => {
  const text = String(value || '').trim();
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  const bytes = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const number_ = Number(part);
    if (number_ > 255) return null;
    bytes.push(number_);
  }
  return bytes;
};

export const parseIpv6 = value => {
  const text = String(value || '').trim().replace(/^\[/, '').replace(/\]$/, '');
  if (!text.includes(':')) return null;
  // 含点的组（嵌入式 v4，如 ::ffff:a.b.c.d）先展开为两个十六进制组，统一按 8 组处理
  const expandGroups = raw => {
    const groups = [];
    for (const group of raw.split(':').filter(Boolean)) {
      if (!group.includes('.')) {
        groups.push(group);
        continue;
      }
      const v4 = parseIpv4(group);
      if (!v4) return null;
      groups.push(((v4[0] << 8) | v4[1]).toString(16), ((v4[2] << 8) | v4[3]).toString(16));
    }
    return groups;
  };
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? expandGroups(halves[0]) : [];
  const tail = halves.length === 2 && halves[1] ? expandGroups(halves[1]) : [];
  if (!head || !tail) return null;
  let groups;
  if (halves.length === 2) {
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups = [...head, ...Array(missing).fill('0'), ...tail];
  } else {
    if (head.length !== 8) return null;
    groups = head;
  }
  const bytes = [];
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    const value16 = Number.parseInt(group, 16);
    bytes.push(value16 >> 8, value16 & 0xff);
  }
  return bytes.length === 16 ? bytes : null;
};

export const isBlockedAddress = value => {
  const v4 = parseIpv4(value);
  if (v4) return blockedV4Prefixes.some(prefix => matchesPrefix(v4, prefix));
  const v6 = parseIpv6(value);
  if (!v6) return true; // 无法解析的地址一律视为阻断（fail closed）
  // ::ffff:a.b.c.d 映射地址按 v4 规则判定
  if (v6.slice(0, 10).every(byte => byte === 0) && v6[10] === 0xff && v6[11] === 0xff) {
    return blockedV4Prefixes.some(prefix => matchesPrefix(v6.slice(12), prefix));
  }
  // NAT64（64:ff9b::/96）与 6to4（2002::/16）低 32 位是嵌入式 v4，按 v4 规则判定
  if (v6[0] === 0x00 && v6[1] === 0x64 && v6[2] === 0xff && v6[3] === 0x9b
    && v6.slice(4, 12).every(byte => byte === 0)) {
    return blockedV4Prefixes.some(prefix => matchesPrefix(v6.slice(12), prefix));
  }
  if (v6[0] === 0x20 && v6[1] === 0x02) {
    // 6to4：2002::/16 前缀后紧跟的 4 字节（下标 2-5）是嵌入式 IPv4
    return blockedV4Prefixes.some(prefix => matchesPrefix(v6.slice(2, 6), prefix));
  }
  return blockedV6Prefixes.some(prefix => matchesPrefix(v6, prefix));
};

export const resolveCtfTargetPolicy = ({ serverHost }) => {
  const raw = String(process.env.PAYLOADER_CTF_TARGET_POLICY || '').trim().toLowerCase();
  if (raw === 'off' || raw === 'open') return 'open';
  if (raw === 'protected' || raw === 'strict') return 'protected';
  return loopbackListenHosts.has(String(serverHost || '').trim().toLowerCase()) ? 'open' : 'protected';
};

const blockedMessage = '目标地址被 SSRF 防护拦截：当前服务以非本机监听部署，禁止访问回环、内网或链路本地地址。如确需访问内网题目靶机，请设置环境变量 PAYLOADER_CTF_TARGET_POLICY=off 后重启服务。';

export const createCtfTargetGuard = ({ policy } = {}) => {
  // 非空但非法的策略值直接抛错，防手误静默放行
  if (policy !== undefined && policy !== 'open' && policy !== 'protected') {
    throw new Error(`Unknown CTF target guard policy: ${String(policy)}`);
  }
  const mode = policy === 'protected' ? 'protected' : 'open';
  const dnsCache = new Map();
  const lookupTimeoutMs = 5_000;

  const rememberLookup = (host, entry) => {
    if (dnsCache.size >= dnsCacheLimit) {
      const oldest = dnsCache.keys().next().value;
      if (oldest !== undefined) dnsCache.delete(oldest);
    }
    // 成功 60s；失败负缓存 5s——慢速/失败解析不应逐请求重放 DNS 查询
    const ttl = entry.addresses ? dnsCacheTtlMs : 5_000;
    dnsCache.set(host, { at: Date.now(), ...entry, ttl });
  };

  const resolveHostAddresses = async host => {
    const cached = dnsCache.get(host);
    if (cached && Date.now() - cached.at < cached.ttl) {
      if (cached.addresses) return cached.addresses;
      throw new Error('Recent DNS lookup failure');
    }
    let addresses;
    try {
      // lookup 无内建超时：慢解析以超时收口，超时按失败处理（fail closed）
      let timeoutRef;
      try {
        const records = await Promise.race([
          lookup(host, { all: true, verbatim: true }),
          new Promise((_, reject) => {
            timeoutRef = setTimeout(() => reject(new Error('DNS lookup timeout')), lookupTimeoutMs);
          }),
        ]);
        addresses = records.map(record => record.address);
      } finally {
        clearTimeout(timeoutRef);
      }
    } catch (error) {
      rememberLookup(host, { addresses: null });
      throw error;
    }
    rememberLookup(host, { addresses });
    return addresses;
  };

  if (mode === 'open') {
    return {
      policy: mode,
      checkTarget: async () => ({ allowed: true }),
    };
  }

  return {
    policy: mode,
    // target 接受完整 URL（proxy）或裸主机名（portscan），仅提取 hostname 校验
    checkTarget: async target => {
      const text = String(target || '').trim();
      let host = text;
      try {
        if (/^https?:\/\//i.test(text)) {
          host = new URL(text).hostname;
        } else if (text.includes('/')) {
          host = new URL(text).hostname;
        }
      } catch {
        return { allowed: false, message: '目标 URL 无法解析。' };
      }
      host = host.replace(/^\[|\]$/g, '');
      if (!host) return { allowed: false, message: '目标缺少主机名。' };
      // IP 字面量直接判定；域名先 DNS 解析再逐地址判定（预解析防域名绕过，解析失败 fail closed）
      let addresses;
      try {
        addresses = [host];
        if (!parseIpv4(host) && !parseIpv6(host)) {
          addresses = await resolveHostAddresses(host);
        }
      } catch {
        return { allowed: false, message: blockedMessage };
      }
      if (!addresses.length) return { allowed: false, message: blockedMessage };
      for (const address of addresses) {
        if (isBlockedAddress(address)) return { allowed: false, message: blockedMessage };
      }
      return { allowed: true };
    },
  };
};

// 路由工厂缺省值：不显式注入 guard 的调用方（单测/既有集成）保持全放行行为
export const openCtfTargetGuard = createCtfTargetGuard({ policy: 'open' });
