// 管理后台登录图形验证码服务：svg-captcha 生成 + 服务端单次有效存储。
// 安全要点：答案永不出库（测试回显仅凭 PAYLOADER_CAPTCHA_ECHO_ANSWER=1 显式开启）、
// 5 分钟 TTL、验证即焚（对错都只可用一次）、容量上限防灌爆、timingSafeEqual 恒时比较。

import { randomBytes, timingSafeEqual } from 'node:crypto';
import svgCaptcha from 'svg-captcha';

const captchaTtlMs = 5 * 60_000;
const maxStoredCaptchas = 512;

const constantTimeEquals = (actual, expected) => {
  const left = Buffer.from(String(actual), 'utf8');
  const right = Buffer.from(String(expected), 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
};

export const createCaptchaService = () => {
  const store = new Map();

  const purgeExpired = now => {
    for (const [token, entry] of store) {
      if (entry.expiresAt <= now) store.delete(token);
    }
  };

  const issue = () => {
    const now = Date.now();
    purgeExpired(now);
    if (store.size >= maxStoredCaptchas) {
      let oldestToken = null;
      let oldestExpiresAt = Infinity;
      for (const [token, entry] of store) {
        if (entry.expiresAt < oldestExpiresAt) {
          oldestToken = token;
          oldestExpiresAt = entry.expiresAt;
        }
      }
      if (oldestToken !== null) store.delete(oldestToken);
    }
    const captcha = svgCaptcha.create({
      size: 4,
      noise: 2,
      color: true,
      background: '#f4f6f8',
      width: 128,
      height: 46,
      fontSize: 44,
      ignoreChars: '0o1ilI',
    });
    const token = randomBytes(24).toString('base64url');
    store.set(token, { answer: captcha.text.toLowerCase(), expiresAt: now + captchaTtlMs });
    const payload = {
      token,
      svg: captcha.data,
      expiresInSeconds: Math.floor(captchaTtlMs / 1000),
    };
    if (process.env.PAYLOADER_CAPTCHA_ECHO_ANSWER === '1') {
      payload.answer = captcha.text;
    }
    return payload;
  };

  const verify = (token, answer) => {
    if (typeof token !== 'string' || typeof answer !== 'string' || !token || !answer) return false;
    const entry = store.get(token);
    store.delete(token);
    if (!entry || entry.expiresAt <= Date.now()) return false;
    return constantTimeEquals(answer.trim().toLowerCase(), entry.answer);
  };

  return { issue, verify };
};
