// ULID 生成器（EXP 条目稳定 ID 用）：Crockford Base32，48bit 毫秒时间戳 + 80bit 随机。
// 无外部依赖；256 = 8×32 使 bytes[i] % 32 无取模偏差，同毫秒唯一性由 80bit 随机空间保证
//（生成频率低，无需单调序列）。本模块仅服务端使用。

import { webcrypto as crypto } from 'node:crypto';

const encoding = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const timeLength = 10;
const randomLength = 16;

const encodeTime = milliseconds => {
  let remaining = milliseconds;
  let encoded = '';
  for (let i = 0; i < timeLength; i += 1) {
    const mod = remaining % 32;
    encoded = encoding[mod] + encoded;
    remaining = (remaining - mod) / 32;
  }
  return encoded;
};

const encodeRandom = () => {
  const bytes = crypto.getRandomValues(new Uint8Array(randomLength));
  let encoded = '';
  for (let i = 0; i < randomLength; i += 1) {
    encoded += encoding[bytes[i] % 32];
  }
  return encoded;
};

export const createUlid = (now = Date.now()) => {
  const time = typeof now === 'number' && Number.isFinite(now) && now >= 0 ? Math.floor(now) : Date.now();
  return encodeTime(time) + encodeRandom();
};

// 校验（导入/入库前的 ID 形状门）：26 位 Crockford Base32。
export const isUlidShape = value => {
  const candidate = String(value ?? '');
  if (candidate.length !== timeLength + randomLength) return false;
  for (const char of candidate) {
    if (!encoding.includes(char)) return false;
  }
  return true;
};

export const ulidTimestamp = value => {
  const candidate = String(value ?? '');
  if (!isUlidShape(candidate)) return null;
  let milliseconds = 0;
  for (let i = 0; i < timeLength; i += 1) {
    const index = encoding.indexOf(candidate[i]);
    if (index < 0) return null;
    milliseconds = milliseconds * 32 + index;
  }
  return milliseconds;
};
