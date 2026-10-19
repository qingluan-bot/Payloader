// 执行器文本链纯函数库：摩尔斯（含 AB/点划别名）与连续 AB 串歧义分割。
// 独立成模块的动机：执行器（scripts/solve-real-challenges.mjs）与黄金向量回归测试必须
// 消费同一份实现，禁止测试侧复制粘贴产生镜像漂移。
// 点划别名映射口径：A=. B=-、_=-、其余按标准摩尔斯表。

export const MORSE_TABLE: Record<string, string> = {
  '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
  '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
  '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
  '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
  '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9', '-..-.': '/', '.-.-.-': '.',
  '--..--': ',', '..--..': '?', '-.-.--': '!', '.----.': "'", '---...': ':', '-....-': '-', '.-.-.': '+',
};

// 反查表：连续 AB 串歧义分割 DFS 用。
export const MORSE_REV: Record<string, string> = Object.fromEntries(
  Object.entries(MORSE_TABLE).map(([code, char]) => [code, char]),
);

// 文本摩尔斯解码：/ 或多空格为字母间界；_ 按划别名归一。
export const decodeMorseText = (text: string): string => {
  const tokens = text.trim().split(/\s*\/\s*|\s{2,}|\s+/);
  const parts: string[] = [];
  for (const token of tokens) {
    if (token === '/') { parts.push(' '); continue; }
    const char = MORSE_TABLE[token.replace(/[._]/g, m => (m === '_' ? '-' : '.'))];
    if (char) parts.push(char);
  }
  return parts.join('');
};

// 连续 AB 串（PDF 文本层提取丢空格形态）的摩尔斯歧义分割：DFS 前缀枚举，优先产出含
// FLAG/CTF 的解；辅音 4 连剪枝砍掉无锚乱码解；步数护栏防病态输入爆炸。
export const decodeAbContinuous = (dots: string): string[] => {
  const flagSols: string[] = [];
  const plainSols: string[] = [];
  const path: string[] = [];
  let steps = 0;
  const dfs = (pos: number) => {
    if (flagSols.length >= 3 || steps > 500000) return;
    steps += 1;
    if (pos === dots.length) {
      const text = path.join('');
      if (/[A-Z0-9]{4}/.test(text)) (text.includes('FLAG') || text.includes('CTF') ? flagSols : plainSols).push(text);
      return;
    }
    for (let len = 1; len <= 5 && pos + len <= dots.length; len += 1) {
      const char = MORSE_REV[dots.slice(pos, pos + len)];
      if (!char) continue;
      path.push(char);
      if (path.length >= 4 && /^[^AEIOUY]{4}$/.test(path.slice(-4).join(''))) path.pop();
      else { dfs(pos + len); path.pop(); }
    }
  };
  dfs(0);
  return [...flagSols, ...plainSols].slice(0, 6);
};

// AB 串摩尔斯统一入口：带空格按字母边界分词，连续串走歧义分割（只采纳含 FLAG/CTF 的解）；
// 每个命中经 onDecoded 回调抛给调用方。
export const collectAbMorse = (text: string, onDecoded: (decoded: string) => void): void => {
  for (const line of String(text).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!/^[BA][BA\s]{29,}$/.test(trimmed)) continue;
    const dots = trimmed.replace(/A/g, '.').replace(/B/g, '-');
    if (/\s/.test(trimmed)) {
      const decoded = decodeMorseText(dots);
      if (/[A-Z0-9]{4}/.test(decoded)) onDecoded(decoded);
    } else {
      for (const abMorse of decodeAbContinuous(dots)) {
        if (abMorse.includes('FLAG') || abMorse.includes('CTF')) onDecoded(abMorse);
      }
    }
  }
};
