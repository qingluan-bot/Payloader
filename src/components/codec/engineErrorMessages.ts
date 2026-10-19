// 引擎异常渲染层映射（F-07）：不改引擎契约，只在 UI 侧把"原始异常文本"翻译成面向解题者的中文提示。
// 规则：
// - 引擎已给中文文案的（古典密码/中国密码等）原样展示，不包 details；
// - 已知英文异常模式（JSON.parse / WebCrypto OperationError / TypeError 取字段）映射为可行动的中文提示，
//   原始文本收进可展开 <details>「详情」；
// - 其余无汉字的未知异常兜底一句中文 + details。
export interface EngineErrorCopy {
  zh: string;
  en: string;
}

export interface DescribedEngineError {
  // 展示用提示（已按语言取值的职责在渲染层：label(hint, language)）
  hint: EngineErrorCopy;
  // 原始异常文本；null = 提示本身就是原文（引擎中文文案），无需 details
  detail: string | null;
  // 因参数缺失报错（F-11）：宿主据此自动展开参数面板并红描边提示
  missingParam: boolean;
}

// 参数缺失类：引擎文案（HMAC 需要填写密钥 / AES-CBC 需要填写 IV / OpenSSL enc 需要填写 passphrase /
// XX 不能为空）以及英文 is required。注意 "requires a 12-byte nonce" 是长度不符，不算缺失。
const MISSING_PARAM_PATTERN = /需要填写|需要密钥|不能为空|\bis required\b/i;

const containsChinese = (text: string): boolean => /[\u4e00-\u9fff]/.test(text);

const jsonCiphertextHint: EngineErrorCopy = {
  zh: '需要 JSON 格式密文（{salt, iv, ct}）——可先在『加密』方向生成一次，再把输出粘贴回输入框解密。',
  en: 'Ciphertext must be JSON ({salt, iv, ct}) — run Encode once and paste its output back to decode.',
};

const keyMismatchHint: EngineErrorCopy = {
  zh: '解密失败：密钥（或口令）与密文不匹配，或密文已损坏、被篡改。',
  en: 'Decryption failed: the key or passphrase does not match this ciphertext, or the data is corrupted.',
};

const incompletePayloadHint: EngineErrorCopy = {
  zh: '密文结构不完整：缺少必需字段（如 salt / iv / ct），无法完成解析。',
  en: 'Ciphertext payload is incomplete: required fields (salt / iv / ct) are missing.',
};

const fallbackHint: EngineErrorCopy = {
  zh: '执行失败：请检查输入内容与当前参数是否匹配，再重试。',
  en: 'Operation failed: check that the input matches the current parameters, then retry.',
};

export const describeEngineError = (raw: string): DescribedEngineError => {
  // 引擎中文文案（含参数缺失类）：已是面向用户的提示，原样展示
  if (containsChinese(raw)) {
    return { hint: { zh: raw, en: raw }, detail: null, missingParam: MISSING_PARAM_PATTERN.test(raw) };
  }

  if (/unexpected token|unexpected end of json|not valid json|in json at position|json\.parse/i.test(raw)) {
    return { hint: jsonCiphertextHint, detail: raw, missingParam: false };
  }
  if (/operationerror|domexception|the operation failed|operation is not supported/i.test(raw)) {
    return { hint: keyMismatchHint, detail: raw, missingParam: false };
  }
  if (/cannot read propert(y|ies) of (null|undefined)|cannot destructure/i.test(raw)) {
    return { hint: incompletePayloadHint, detail: raw, missingParam: false };
  }

  return { hint: fallbackHint, detail: raw, missingParam: MISSING_PARAM_PATTERN.test(raw) };
};
