import type { Direction } from './types';

// 批次三 · Lane H：七族符号密码（Z408 黄道十二宫杀手 / 和文摩尔斯 / 古文明数字 / 天体符号 / 骰面骨牌 / 三元与单双元 / 圣书体单辅音）。
// 码表出处与对拍锚点（逐项核实）：
// - Zodiac Z408：54 符号同音替换已破子集键表。符号表示采用 Oranchak webtoy ASCII 记法（zodiackillerciphers.com
//   webtoy zodiac.js 的 alphabet[1] = "ABDEFGHIJKLMNOPQRSTUVWXYZ56789cdefjklpqrtz!#%()=+/@\^_"，研究界事实标准、
//   azdecrypt 兼容），逐符号明文键取自 webtoy 内置 "The correct one" decoder 串；另以 nibzard/zodiac 仓库收录的
//   Harden 解密明文逐位交叉验证（前 390 位 385/390 一致，5 处分歧为 Zodiac 本人编码串组错位，文献有载）。
//   对拍锚点：密文首行 "9%P/Z/UB%kOR=pX=B"（17 符号）→ 明文 "ilikekillingpeopl"。
//   J/Q/Z 三字母在键表中无符号（Harden 明文未出现），编码如实报错；组容量 e=7、t/a/o/i/n/s=4、r/l=3，与文献一致。
// - Wabun 和文摩尔斯：JA Wikipedia「モールス符号」現行和文表（基于総務省令 無線局運用規則別表第1号，48 假名 +
//   濁点/半濁点，另收長音「ー」= .--.-、区切点「、」= .-.-.-）。对拍锚点：条文原文"和文モールス符号で（・）と（－）
//   が意味するのはそれぞれ「ヘ」と「ム」"（ヘ=.、ム=-）；ヌ=....、キ=-.-..、ヱ=.--..（与英文维基旧转写分歧处以
//   日文原文为准）。
// - 古文明数字：Unicode 官方码位（UnicodeData.txt 核实）：楔形竖楔 DIS=U+12079、横楔 U(U2)=U+12311、楔形数字块
//   U+12400-1247F；玛雅数字块 U+1D2E0-1D2F3（零=贝壳 𝋠）；埃及圣书体 7 幂符号 Z001=U+133E4(1)、V020=U+13386(10)、
//   V001=U+13362(100)、M012=U+131BC(1000)、D050=U+130AD(10000)、I008=U+13190(100000)、C011=U+13068(1000000)。
//   巴比伦为 60 进制位值制（无零号，此处以"·"占位并文档化）；玛雅按纯 20 进制（历法 18×20 变体不支持，dCode 同口径）；
//   埃及为加法记数（7 幂降幂规范形，每位 1-9 个符号，无零号）。
// - 天体符号：Unicode U+2609 太阳、U+263D/U+263E 月、U+263F-2647 行星（水金地火木土天海冥）、U+2648-2653 黄道十二宫；
//   地球 ⊕/♁、月 ☽/☾、天王星 ♅/⛢(U+26E2) 变体归一到主名。
// - 骰面/骨牌：U+2680-2685 骰面 1-6；骨牌块 U+1F031 起 49 个横排有序对（a|b，a 左 b 右）、U+1F063 起 49 个竖排
//   （UnicodeData.txt 核实 DOMINO TILE HORIZONTAL-00-00=1F031 … HORIZONTAL-06-06=1F061，VERTICAL 同布局 +0x32），
//   西式 28 张为 a≤b 子集，此处按 49 有序对全保序编码。
// - Trilitère 三元：dCode Triliteral Cipher Base 3 规范（对拍锚点：DCODE → "ABA AAC BBC ABA ABB"）：
//   默认变体 space=CCC（a=AAA…z=CCB、空格=CCC），备选变体 space=AAA（空格=AAA、a=AAB…z=CCC）；解码兼容 1/2/3 数字集。
// - Monome-Binome：dCode 3×10 变体 1 规范（首行无行键 A-H 于 10 列中占 8 格，第 3/7 行为行键，共 28 字符位）。
//   对拍锚点：MONOME → "34 36 35 36 34 5"；4303536345 → DINOME（dCode 官方两例）。
// - 圣书体单辅音符：Gardiner 编号单辅音符号（Unicode 埃及圣书体块 U+13000-1342F，码位逐项核实），按埃及学转写惯例
//   归一到 20 个无 C/E/J/O/U/V 的英文字母（ꜣ/ʿ→A、ḥ→H、ḏ→D、š→S、ṯ→T、ḫ/ẖ→X、z(S29)→Z 等变体归一）；
//   C/E/J/O/U/V 无单辅音字形，编码如实报错。码表按公开埃及学资料整理，个别字母的变体归一口径存在流派差异。
// 全部表驱动、纯函数；字符串遍历一律按码点（[...str]），骨牌区 U+1F031 为代理对不可按 UTF-16 索引；
// 各族解码对未知符号容错计数（不抛异常），结果尾部以 "[未知符号xN]" 注明。

const unknownSuffix = (count: number): string => (count > 0 ? `[未知符号x${count}]` : '');

// ---- 1. Zodiac Z408：54 符号同音替换（Oranchak webtoy ASCII 记法 + Harden 键） ----
export const Z408_SYMBOLS = 'ABDEFGHIJKLMNOPQRSTUVWXYZ56789cdefjklpqrtz!#%()=+/@\\^_';
// 逐符号明文键：与 Z408_SYMBOLS 等长按位配对（webtoy "The correct one" decoder）。
const Z408_KEY_PLAINTEXT = 'wlnesattfsthenifgaoibeouetesaivocdxiaemrrdollnhpeksrny';

const z408BySymbol = new Map<string, string>([...Z408_SYMBOLS].map((symbol, index) => [symbol, Z408_KEY_PLAINTEXT[index] ?? '']));
// 字母 → 该字母的同音符号组（保持符号表顺序，供 cycle/primary 两档取用）
export const z408Homophones = new Map<string, string[]>();
for (const [symbol, letter] of z408BySymbol) {
  const list = z408Homophones.get(letter) ?? [];
  list.push(symbol);
  z408Homophones.set(letter, list);
}

export const zodiac408Encode = (input: string, variant: string): string => {
  const cycle = variant !== 'primary';
  const counters = new Map<string, number>();
  return [...input]
    .map(char => {
      if (/\s/.test(char)) return char;
      const lower = char.toLowerCase();
      if (lower < 'a' || lower > 'z') throw new Error(`Zodiac Z408 编码仅支持字母与空白，遇到 "${char}"`);
      if ('jqz'.includes(lower)) throw new Error(`Zodiac Z408 键表无字母 "${char.toUpperCase()}" 的符号（Harden 解密明文未出现 J/Q/Z）`);
      const homophones = z408Homophones.get(lower) ?? [];
      const position = cycle ? counters.get(lower) ?? 0 : 0;
      counters.set(lower, position + 1);
      return homophones[position % homophones.length] ?? '';
    })
    .join('');
};

export const zodiac408Decode = (input: string): string => {
  let unknown = 0;
  const output = [...input]
    .map(symbol => {
      const letter = z408BySymbol.get(symbol);
      if (letter !== undefined) return letter;
      if (!/\s/.test(symbol)) unknown += 1;
      return symbol;
    })
    .join('');
  return output + unknownSuffix(unknown);
};

// ---- 2. Wabun 和文摩尔斯：片假名 ↔ 点划（JA Wikipedia 現行和文表） ----
const WABUN_TABLE: Array<[string, string]> = [
  ['イ', '.-'], ['ロ', '.-.-'], ['ハ', '-...'], ['ニ', '-.-.'], ['ホ', '-..'], ['ヘ', '.'],
  ['ト', '..-..'], ['チ', '..-.'], ['リ', '--.'], ['ヌ', '....'], ['ル', '-.--.'], ['ヲ', '.---'],
  ['ワ', '-.-'], ['カ', '.-..'], ['ヨ', '--'], ['タ', '-.'], ['レ', '---'], ['ソ', '---.'],
  ['ツ', '.--.'], ['ネ', '--.-'], ['ナ', '.-.'], ['ラ', '...'], ['ム', '-'], ['ウ', '..-'],
  ['ヰ', '.-..-'], ['ノ', '..--'], ['オ', '.-...'], ['ク', '...-'], ['ヤ', '.--'], ['マ', '-..-'],
  ['ケ', '-.--'], ['フ', '--..'], ['コ', '----'], ['エ', '-....'], ['テ', '.-.--'], ['ア', '--.--'],
  ['サ', '-.-.-'], ['キ', '-.-..'], ['ユ', '-..--'], ['メ', '-...-'], ['ミ', '..-.-'], ['シ', '--.-.'],
  ['ヱ', '.--..'], ['ヒ', '--..-'], ['モ', '-..-.'], ['セ', '.---.'], ['ス', '---.-'], ['ン', '.-.-.'],
  [String.fromCodePoint(0x309b), '..'], [String.fromCodePoint(0x309c), '..--.'],
  ['ー', '.--.-'], ['、', '.-.-.-'],
];
const wabunByKana = new Map(WABUN_TABLE);
const wabunByCode = new Map(WABUN_TABLE.map(([kana, code]) => [code, kana]));
// 小书字归一（和文摩尔斯无小书字规定，按常规转大字）
const WABUN_SMALL_TO_BASE = new Map([...'ァィゥェォッャュョヮ'].map((char, index) => [char, ['ア', 'イ', 'ウ', 'エ', 'オ', 'ツ', 'ヤ', 'ユ', 'ヨ', 'ワ'][index] ?? char]));
const WABUN_DAKUTEN = String.fromCodePoint(0x309b); // 独立濁点 ゛
const WABUN_HANDAKUTEN = String.fromCodePoint(0x309c); // 独立半濁点 ゜
const WABUN_COMBINING_DAKUTEN = String.fromCodePoint(0x3099);
const WABUN_COMBINING_HANDAKUTEN = String.fromCodePoint(0x309a);

const wabunNormalizeChar = (char: string): string => {
  const code = char.codePointAt(0) ?? 0;
  if (code >= 0x3041 && code <= 0x3096) return String.fromCodePoint(code + 0x60); // 平假名 → 片假名
  if (code === 0x3099) return WABUN_DAKUTEN;
  if (code === 0x309a) return WABUN_HANDAKUTEN;
  return WABUN_SMALL_TO_BASE.get(char) ?? char;
};

export const wabunEncode = (input: string): string => [...input.normalize('NFD')]
  .map(raw => {
    if (/\s/.test(raw)) return '/';
    const char = wabunNormalizeChar(raw);
    return wabunByKana.get(char) ?? raw;
  })
  .join(' ');

export const wabunDecode = (input: string): string => {
  let unknown = 0;
  const text = input
    .replace(/・/gu, '.')
    .replace(/－|—|−/gu, '-')
    .split(/\s+/)
    .filter(Boolean)
    .map(token => {
      if (token === '/') return ' ';
      const kana = wabunByCode.get(token);
      if (kana !== undefined) return kana;
      unknown += 1;
      return token;
    })
    .join('');
  // 独立濁点/半濁点转组合记号后 NFC 合成（か+゛ → が）
  const composed = text
    .replaceAll(WABUN_DAKUTEN, WABUN_COMBINING_DAKUTEN)
    .replaceAll(WABUN_HANDAKUTEN, WABUN_COMBINING_HANDAKUTEN)
    .normalize('NFC');
  return composed + unknownSuffix(unknown);
};

// ---- 3a. 巴比伦 60 进制楔形数字（竖楔 DIS / 横楔 U，位间空格，零位"·"占位） ----
const BABYLONIAN_ONE = String.fromCodePoint(0x12079); // U+12079 CUNEIFORM SIGN DIS（竖楔 = 1）
const BABYLONIAN_TEN = String.fromCodePoint(0x12311); // U+12311 CUNEIFORM SIGN U2（横楔 = 10）
const babylonianRenderDigit = (digit: number, variant: string): string => {
  if (digit === 0) return variant === 'ascii' ? '.' : '·';
  const tens = Math.floor(digit / 10);
  const units = digit % 10;
  const tenGlyph = variant === 'ascii' ? '-' : BABYLONIAN_TEN;
  const unitGlyph = variant === 'ascii' ? '|' : BABYLONIAN_ONE;
  return tenGlyph.repeat(tens) + unitGlyph.repeat(units);
};

export const babylonianEncode = (input: string, variant: string): string => {
  const text = input.trim();
  if (!/^\d+$/.test(text)) throw new Error(`巴比伦数字仅支持非负十进制整数，遇到 "${input}"`);
  let value = BigInt(text);
  if (value === 0n) return babylonianRenderDigit(0, variant);
  const places: number[] = [];
  while (value > 0n) {
    places.push(Number(value % 60n));
    value /= 60n;
  }
  return places.reverse().map(digit => babylonianRenderDigit(digit, variant)).join(' ');
};

export const babylonianDecode = (input: string): string => {
  let unknown = 0;
  const digits: number[] = [];
  for (const group of input.trim().split(/\s+/).filter(Boolean)) {
    let tens = 0;
    let units = 0;
    let zero = false;
    for (const char of [...group]) {
      if (char === BABYLONIAN_TEN || char === '-') tens += 1;
      else if (char === BABYLONIAN_ONE || char === '|') units += 1;
      else if (char === '·' || char === '.') zero = true;
      else unknown += 1;
    }
    const value = tens * 10 + units;
    if (tens === 0 && units === 0 && !zero) continue; // 纯未知符号组
    if (value > 59) throw new Error(`巴比伦 60 进制单个位值 ${value} 超过 59（规范形每位最多 5 横楔 + 9 竖楔）`);
    digits.push(value);
  }
  if (digits.length === 0) throw new Error('巴比伦数字无法解析：未找到楔形数字符号');
  const value = digits.reduce((acc, digit) => acc * 60n + BigInt(digit), 0n);
  return value.toString() + unknownSuffix(unknown);
};

// ---- 3b. 玛雅 20 进制数字（Unicode 玛雅数字块 / 点杠 ASCII 双档，点=1 杠=5，零=贝壳） ----
const mayanGlyph = (digit: number): string => String.fromCodePoint(0x1d2e0 + digit);
const MAYAN_ASCII_ZERO = '0';

const mayanRenderDigit = (digit: number, variant: string): string => {
  if (variant === 'ascii') {
    if (digit === 0) return MAYAN_ASCII_ZERO;
    return '.'.repeat(digit % 5) + '-'.repeat(Math.floor(digit / 5));
  }
  return mayanGlyph(digit);
};

export const mayanEncode = (input: string, variant: string): string => {
  const text = input.trim();
  if (!/^\d+$/.test(text)) throw new Error(`玛雅数字仅支持非负十进制整数，遇到 "${input}"`);
  let value = BigInt(text);
  if (value === 0n) return mayanRenderDigit(0, variant);
  const places: number[] = [];
  while (value > 0n) {
    places.push(Number(value % 20n));
    value /= 20n;
  }
  return places.reverse().map(digit => mayanRenderDigit(digit, variant)).join(' ');
};

export const mayanDecode = (input: string): string => {
  let unknown = 0;
  const digits: number[] = [];
  for (const group of input.trim().split(/\s+/).filter(Boolean)) {
    let value = 0;
    let seen = false;
    for (const char of [...group]) {
      const code = char.codePointAt(0) ?? 0;
      if (code >= 0x1d2e0 && code <= 0x1d2f3) {
        value += code - 0x1d2e0;
        seen = true;
      } else if (char === '.') {
        value += 1;
        seen = true;
      } else if (char === '-') {
        value += 5;
        seen = true;
      } else if (char === MAYAN_ASCII_ZERO) {
        seen = true;
      } else {
        unknown += 1;
      }
    }
    if (!seen) continue;
    if (value > 19) throw new Error(`玛雅 20 进制单个位值 ${value} 超过 19（规范形每位最多 4 点 + 3 杠）`);
    digits.push(value);
  }
  if (digits.length === 0) throw new Error('玛雅数字无法解析：未找到点杠或数字符号');
  const value = digits.reduce((acc, digit) => acc * 20n + BigInt(digit), 0n);
  return value.toString() + unknownSuffix(unknown);
};

// ---- 3c. 埃及加法十进制（7 幂降幂规范形，Unicode 埃及圣书体数字符号） ----
const EGYPTIAN_POWERS: Array<[bigint, number, string]> = [
  [1000000n, 0x13068, 'C011 何何神（百万）'],
  [100000n, 0x13190, 'I008 蝌蚪（十万）'],
  [10000n, 0x130ad, 'D050 指号（万）'],
  [1000n, 0x131bc, 'M012 莲花（千）'],
  [100n, 0x13362, 'V001 绳卷（百）'],
  [10n, 0x13386, 'V20 牛轭（十）'],
  [1n, 0x133e4, 'Z1 单笔画（一）'],
];
const egyptianByGlyph = new Map(EGYPTIAN_POWERS.map(([power, code]) => [String.fromCodePoint(code), power]));

export const egyptianEncode = (input: string): string => {
  const text = input.trim();
  if (!/^\d+$/.test(text)) throw new Error(`埃及数字仅支持非负十进制整数，遇到 "${input}"`);
  let value = BigInt(text);
  if (value === 0n) throw new Error('埃及加法记数没有零号，无法编码 0');
  let output = '';
  for (const [power, code, label] of EGYPTIAN_POWERS) {
    const count = value / power;
    value %= power;
    if (count > 9n) throw new Error(`埃及数字规范形每位最多 9 个符号，${label} 位出现 ${count} 个`);
    output += String.fromCodePoint(code).repeat(Number(count));
  }
  return output;
};

export const egyptianDecode = (input: string): string => {
  let unknown = 0;
  let value = 0n;
  for (const char of [...input]) {
    const power = egyptianByGlyph.get(char);
    if (power === undefined) {
      if (!/\s/.test(char)) unknown += 1;
      continue;
    }
    value += power;
  }
  return value.toString() + unknownSuffix(unknown);
};

// ---- 4. 天体符号：行星（11）+ 黄道十二宫（12）名称 ↔ Unicode 天体符号 ----
const ASTRO_TABLE: Array<[string, number, number[]]> = [
  ['sun', 0x2609, []],
  ['moon', 0x263d, [0x263e]],
  ['mercury', 0x263f, []],
  ['venus', 0x2640, []],
  ['earth', 0x2295, [0x2641]],
  ['mars', 0x2642, []],
  ['jupiter', 0x2643, []],
  ['saturn', 0x2644, []],
  ['uranus', 0x2645, [0x26e2]],
  ['neptune', 0x2646, []],
  ['pluto', 0x2647, []],
  ['aries', 0x2648, []],
  ['taurus', 0x2649, []],
  ['gemini', 0x264a, []],
  ['cancer', 0x264b, []],
  ['leo', 0x264c, []],
  ['virgo', 0x264d, []],
  ['libra', 0x264e, []],
  ['scorpio', 0x264f, []],
  ['sagittarius', 0x2650, []],
  ['capricorn', 0x2651, []],
  ['aquarius', 0x2652, []],
  ['pisces', 0x2653, []],
];
const astroBySymbol = new Map<string, string>();
for (const [name, primary, variants] of ASTRO_TABLE) {
  astroBySymbol.set(String.fromCodePoint(primary), name);
  for (const variant of variants) astroBySymbol.set(String.fromCodePoint(variant), name);
}

export const astroEncode = (input: string): string => input
  .trim()
  .split(/\s+/)
  .filter(Boolean)
  .map(token => {
    const entry = ASTRO_TABLE.find(([name]) => name === token.toLowerCase());
    if (!entry) throw new Error(`天体符号表无名称 "${token}"（支持 ${ASTRO_TABLE.map(([name]) => name).join(' ')}）`);
    return String.fromCodePoint(entry[1]);
  })
  .join('');

export const astroDecode = (input: string): string => {
  let unknown = 0;
  const names = [...input]
    .map(symbol => {
      const name = astroBySymbol.get(symbol);
      if (name !== undefined) return name;
      if (!/\s/.test(symbol)) unknown += 1;
      return symbol;
    })
    .join(' ')
    .split(/\s+/)
    .filter(Boolean)
    .join(' ');
  return names + unknownSuffix(unknown);
};

// ---- 5a. 骰面：数字 1-6 ↔ U+2680-2685 ----
export const diceEncode = (input: string): string => [...input]
  .map(char => {
    if (/\s/.test(char)) return char;
    if (char < '1' || char > '6') throw new Error(`骰面密码仅支持数字 1-6，遇到 "${char}"`);
    return String.fromCodePoint(0x2680 + Number(char) - 1);
  })
  .join('');

export const diceDecode = (input: string): string => {
  let unknown = 0;
  const output = [...input]
    .map(char => {
      const code = char.codePointAt(0) ?? 0;
      if (code >= 0x2680 && code <= 0x2685) return String(code - 0x2680 + 1);
      if (/\s/.test(char)) return char;
      unknown += 1;
      return char;
    })
    .join('');
  return output + unknownSuffix(unknown);
};

// ---- 5b. 骨牌：两位数对 [a|b]（0-6）↔ U+1F031 起（横排）/ U+1F063 起（竖排）49 有序对 ----
const DOMINO_HORIZONTAL_BASE = 0x1f031; // DOMINO TILE HORIZONTAL-00-00，行 a 列 b：+a*7+b
const DOMINO_VERTICAL_BASE = 0x1f063; // DOMINO TILE VERTICAL-00-00

export const dominoEncode = (input: string, variant: string): string => {
  const base = variant === 'vertical' ? DOMINO_VERTICAL_BASE : DOMINO_HORIZONTAL_BASE;
  return input
    .split(/[\s,;]+/)
    .filter(Boolean)
    .map(group => {
      if (!/^[0-6]{2}$/.test(group)) throw new Error(`骨牌数对必须是两位 0-6 数字（如 "35"），遇到 "${group}"`);
      return String.fromCodePoint(base + Number(group[0]) * 7 + Number(group[1]));
    })
    .join(' ');
};

export const dominoDecode = (input: string): string => {
  let unknown = 0;
  const parts = [...input]
    .map(char => {
      const code = char.codePointAt(0) ?? 0;
      if (code >= DOMINO_HORIZONTAL_BASE && code < DOMINO_HORIZONTAL_BASE + 49) {
        const offset = code - DOMINO_HORIZONTAL_BASE;
        return `${Math.floor(offset / 7)}${offset % 7} `;
      }
      if (code >= DOMINO_VERTICAL_BASE && code < DOMINO_VERTICAL_BASE + 49) {
        const offset = code - DOMINO_VERTICAL_BASE;
        return `${Math.floor(offset / 7)}${offset % 7} `;
      }
      if (/\s/.test(char)) return ' ';
      unknown += 1;
      return char;
    })
    .join('');
  return parts.split(/\s+/).filter(Boolean).join(' ') + unknownSuffix(unknown);
};

// ---- 6a. Trilitère 三元：A/B/C 三进制三元组（dCode Base 3 双变体） ----
const TRILITERATE_DIGITS = 'ABC';
const triliterateTriplet = (index: number): string => `${TRILITERATE_DIGITS[Math.floor(index / 9) % 3]}${TRILITERATE_DIGITS[Math.floor(index / 3) % 3]}${TRILITERATE_DIGITS[index % 3]}`;

export const trilitereEncode = (input: string, variant: string): string => {
  const spaceAtZero = variant === 'aaa';
  return [...input.toLowerCase()]
    .map(char => {
      const index = char === ' ' ? (spaceAtZero ? 0 : 26)
        : char >= 'a' && char <= 'z' ? char.charCodeAt(0) - 97 + (spaceAtZero ? 1 : 0)
        : -1;
      if (index < 0) throw new Error(`Trilitère 三元密码仅支持字母与空格，遇到 "${char}"`);
      return triliterateTriplet(index);
    })
    .join(' ');
};

export const trilitereDecode = (input: string, variant: string): string => {
  const spaceAtZero = variant === 'aaa';
  const compact = input.toUpperCase().replace(/[^A-C1-3]/gu, '');
  const normalized = [...compact]
    .map(char => (char === '1' ? 'A' : char === '2' ? 'B' : char === '3' ? 'C' : char))
    .join('');
  if (normalized.length % 3 !== 0) throw new Error(`Trilitère 三元组符号数必须是 3 的倍数，当前 ${normalized.length} 个`);
  let output = '';
  for (let index = 0; index < normalized.length; index += 3) {
    const value = [...normalized.slice(index, index + 3)]
      .reduce((acc, char) => acc * 3 + TRILITERATE_DIGITS.indexOf(char), 0);
    output += spaceAtZero
      ? value === 0 ? ' ' : String.fromCharCode(96 + value)
      : value === 26 ? ' ' : String.fromCharCode(97 + value);
  }
  return output;
};

// ---- 6b. Monome-Binome：3×10 网格（首行无行键，行键 3/7），首行单数字、其余行双数字 ----
const MB_HEADER_ROW = ['A', 'B', 'C', '', 'D', 'E', 'F', '', 'G', 'H'];
const MB_ROW_THREE = 'IJKLMNOPQR';
const MB_ROW_SEVEN = 'STUVWXYZ *';

export const monomeBinomeEncode = (input: string): string => [...input.toUpperCase()]
  .map(char => {
    if (char === ' ') return '78';
    if (char === '*') return '79';
    const headerColumn = MB_HEADER_ROW.indexOf(char);
    if (headerColumn >= 0) return String(headerColumn);
    const rowThree = MB_ROW_THREE.indexOf(char);
    if (rowThree >= 0) return `3${rowThree}`;
    const rowSeven = MB_ROW_SEVEN.indexOf(char);
    if (rowSeven >= 0) return `7${rowSeven}`;
    throw new Error(`Monome-Binome 网格仅支持 A-Z、空格与 "*"，遇到 "${char}"`);
  })
  .join(' ');

export const monomeBinomeDecode = (input: string): string => {
  let unknown = 0;
  let output = '';
  const chars = [...input];
  let index = 0;
  while (index < chars.length) {
    const char = chars[index] ?? '';
    if (!/[0-9]/.test(char)) {
      if (!/\s/.test(char)) unknown += 1;
      index += 1;
      continue;
    }
    if (char === '3' || char === '7') {
      // 行键：必为双数字（行+列），dCode 官方解码规则
      const column = chars[index + 1] ?? '';
      if (!/[0-9]/.test(column)) throw new Error(`Monome-Binome 行键 ${char} 后缺少列号数字`);
      const row = char === '3' ? MB_ROW_THREE : MB_ROW_SEVEN;
      output += row[Number(column)] ?? '';
      index += 2;
      continue;
    }
    const header = MB_HEADER_ROW[Number(char)];
    if (header === undefined || header === '') {
      unknown += 1; // 首行 3/7 列为空位（保留作行键命名）
    } else {
      output += header;
    }
    index += 1;
  }
  return output + unknownSuffix(unknown);
};

// ---- 7. 圣书体单辅音符：20 字母编码 / 25 字形解码（变体归一大写） ----
const HIEROGLYPH_TABLE: Array<[string, Array<[string, number]>]> = [
  ['A', [['G1 秃鹫（ꜣ）', 0x1313f], ['D36 手臂（ʿ）', 0x1309d]]],
  ['B', [['D58 脚', 0x130c0]]],
  ['D', [['D46 手', 0x130a7], ['I10 眼镜蛇（ḏ）', 0x13193]]],
  ['F', [['I9 角蝰', 0x13191]]],
  ['G', [['W11 罐架', 0x133bc]]],
  ['H', [['O4 庭院', 0x13254], ['V28 灯芯（ḥ）', 0x1339b]]],
  ['I', [['M17 芦苇（i/j）', 0x131cb]]],
  ['K', [['V31 篮', 0x133a1]]],
  ['L', [['E23 狮子', 0x130ed]]],
  ['M', [['G17 猫头鹰', 0x13153]]],
  ['N', [['N35 水', 0x13216]]],
  ['P', [['Q3 凳', 0x132aa]]],
  ['Q', [['T14 山坡（ḳ）', 0x13319]]],
  ['R', [['D21 嘴', 0x1308b]]],
  ['S', [['O34 门闩', 0x13283], ['N37 池（š）', 0x13219]]],
  ['T', [['X1 面包', 0x133cf], ['V13 缰绳（ṯ）', 0x1337f]]],
  ['W', [['G43 鹌鹑雏', 0x13171]]],
  ['X', [['Aa1 胎盘（ḫ）', 0x1340d], ['F40 动物肚（ẖ）', 0x1312b]]],
  ['Y', [['M18 双芦苇', 0x131cd]]],
  ['Z', [['S29 折布（古埃及 z）', 0x132f4]]],
];
const hieroglyphPrimary = new Map(HIEROGLYPH_TABLE.map(([letter, glyphs]) => [letter, String.fromCodePoint(glyphs[0]?.[1] ?? 0)]));
const hieroglyphByGlyph = new Map(HIEROGLYPH_TABLE.flatMap(([letter, glyphs]) => glyphs.map(([, code]) => [String.fromCodePoint(code), letter])));
const HIEROGLYPH_MISSING = 'CEJOUV';

export const hieroglyphEncode = (input: string): string => [...input.toUpperCase()]
  .map(char => {
    if (/\s/.test(char)) return char;
    const glyph = hieroglyphPrimary.get(char);
    if (glyph === undefined) {
      if (HIEROGLYPH_MISSING.includes(char)) throw new Error(`圣书体单辅音符无字母 "${char}" 的字形（C/E/J/O/U/V 历史上无单辅音符号）`);
      throw new Error(`圣书体单辅音符仅支持 20 个字母（无 C/E/J/O/U/V），遇到 "${char}"`);
    }
    return glyph;
  })
  .join('');

export const hieroglyphDecode = (input: string): string => {
  let unknown = 0;
  const output = [...input]
    .map(char => {
      const letter = hieroglyphByGlyph.get(char);
      if (letter !== undefined) return letter;
      if (!/\s/.test(char)) unknown += 1;
      return char;
    })
    .join('');
  return output + unknownSuffix(unknown);
};

// ---- 操作元数据（主控挂载后 id 收编进 OperationId 联合类型） ----
export interface SymbolCipherOperationMeta {
  id: string;
  category: 'crypto' | 'text';
  name: { zh: string; en: string };
  summary: { zh: string; en: string };
  params?: string[];
  supportsEncode?: boolean;
  supportsDecode?: boolean;
}

export const symbolCiphersOperations: SymbolCipherOperationMeta[] = [
  {
    id: 'zodiac-408',
    category: 'crypto',
    name: { zh: 'Zodiac Z408 黄道杀手密码', en: 'Zodiac Z408 Cipher' },
    summary: { zh: '黄道十二宫杀手 1969 年 408 字符同音替换密文的已破子集键表（54 符号 → 23 字母，Harden 解，Oranchak webtoy 记法）：编码按同音符号轮转/首选两档，J/Q/Z 无符号报错；解码逐符号查表。', en: 'Solved key of the Zodiac Killer 408 homophonic cipher (54 symbols to 23 letters, Harden solution, webtoy notation): encode cycles or pins homophones, J/Q/Z error; decode maps symbol by symbol.' },
    params: ['variant'],
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'wabun',
    category: 'crypto',
    name: { zh: '和文摩尔斯（Wabun）', en: 'Wabun Code' },
    summary: { zh: '和文モールス符号（総務省規則表）：片假名 ↔ 点划，平假名/小书字归一片假名，NFD 分解濁点半濁点（が=か+・・），词间 "/"；含長音「ー」与区切点「、」。', en: 'Japanese Wabun Morse (MIC table): katakana to/from dots and dashes; hiragana and small kana normalized, dakuten/handakuten split via NFD, "/" separates words; includes chōonpu and comma.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'babylonian',
    category: 'text',
    name: { zh: '巴比伦楔形数字', en: 'Babylonian Numerals' },
    summary: { zh: '巴比伦 60 进制位值记数（竖楔𒁹=1、横楔𒌋=10，位间空格，零位"·"占位）：支持任意大小整数（BigInt）；ASCII 双档用 -/|。单位值上限 59，超出报错。', en: 'Babylonian base-60 positional numerals (vertical wedge = 1, horizontal = 10, space between places, dot placeholder for zero): arbitrary-size integers via BigInt; ASCII variant uses - and |.' },
    params: ['variant'],
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'mayan',
    category: 'text',
    name: { zh: '玛雅数字', en: 'Mayan Numerals' },
    summary: { zh: '玛雅 20 进制记数（Unicode 玛雅数字块 𝋠-𝋿 或点杠 ASCII 双档，点=1 杠=5，零=贝壳）：支持任意大小整数（BigInt）；纯 20 进制口径，历法 18×20 变体不支持。', en: 'Mayan vigesimal numerals (Unicode Mayan block or dot-bar ASCII variant, dot = 1, bar = 5, shell = zero): arbitrary-size integers via BigInt; pure base 20, calendar 18x20 variant not supported.' },
    params: ['variant'],
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'egyptian-numerals',
    category: 'text',
    name: { zh: '古埃及数字', en: 'Egyptian Numerals' },
    summary: { zh: '古埃及加法十进制（7 幂符号降幂规范形，Unicode 圣书体数字区：单笔画/牛轭/绳卷/莲花/指号/蝌蚪/何何神）：每位 1-9 个符号，无零号，编码 0 或超 9999999 报错。', en: 'Egyptian additive decimal (seven power glyphs in canonical descending form, Unicode hieroglyph numerals): 1-9 symbols per power, no zero; encoding 0 or values over 9999999 errors.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'astro-symbols',
    category: 'text',
    name: { zh: '天体符号表', en: 'Astro Symbols' },
    summary: { zh: '行星（日月至冥王 11 个）与黄道十二宫名称 ↔ Unicode 天体符号（U+2609/U+2648 区，共 23 项）：名称以空格分隔连写输出符号；☾/♁/⛢ 等变体解码归一到主名。', en: 'Planet (Sun through Pluto, 11) and zodiac names to/from Unicode astro symbols (U+2609/U+2648 ranges, 23 entries): space-separated names; variants like ☾/♁/♅ normalize to primary names.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'dice',
    category: 'text',
    name: { zh: '骰面密码', en: 'Dice Cipher' },
    summary: { zh: '数字 1-6 ↔ Unicode 骰面 ⚀-⚅（U+2680-2685）：逐位替换，其余数字报错；解码对非骰面字符容错计数。', en: 'Digits 1-6 to/from Unicode die faces (U+2680-2685): per-digit substitution, other digits error; decode tolerates and counts unknown symbols.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'dominoes',
    category: 'text',
    name: { zh: '骨牌密码', en: 'Domino Cipher' },
    summary: { zh: '两位数对 [a|b]（0-6）↔ Unicode 骨牌（横排 U+1F031 起 / 竖排 U+1F063 起，49 有序对保序，西式 28 张为 a≤b 子集）：输入两位一组以空白分隔；解码兼容横竖排。', en: 'Two-digit pairs [a|b] (0-6) to/from Unicode domino tiles (horizontal U+1F031+ or vertical U+1F063+, 49 ordered pairs; the 28-tile western set is the a<=b subset): pairs grouped by whitespace; decode accepts both orientations.' },
    params: ['variant'],
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'trilitere',
    category: 'crypto',
    name: { zh: 'Trilitère 三元密码', en: 'Triliteral Cipher' },
    summary: { zh: 'Trilitère 三元替换（dCode Base 3 规范）：字母 → A/B/C 三进制三元组（a=AAA…z=CCB、空格=CCC；aaa 变体空格=AAA、a=AAB…z=CCC）；解码兼容 1/2/3 数字集，长度须为 3 的倍数。', en: 'Triliteral substitution (dCode Base 3): letters to A/B/C ternary triplets (a=AAA...z=CCB, space=CCC; aaa variant pins space=AAA, a=AAB...z=CCC); decode accepts 1/2/3 digit sets, length must be a multiple of 3.' },
    params: ['variant'],
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'monome-binome',
    category: 'crypto',
    name: { zh: 'Monome-Binome 单双元密码', en: 'Monome-Binome Cipher' },
    summary: { zh: 'Monome-Binome 单双元替换（dCode 3×10 网格变体 1，行键 3/7）：首行 8 字母按列号单数字编码，第 3/7 行 28 字符位（含空格与 *）按行+列双数字编码；解码对连续数字串自拆分。', en: 'Monome-binome substitution (dCode 3x10 grid variant 1, row keys 3/7): header-row letters encode as one digit, rows 3/7 (28 slots incl. space and *) as row+column pairs; decode splits continuous digit streams.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'hieroglyph-single',
    category: 'text',
    name: { zh: '圣书体单辅音符', en: 'Hieroglyph Uniliterals' },
    summary: { zh: '古埃及圣书体单辅音字母表（Gardiner 编号，Unicode 圣书体块）：20 字母编码为单辅音字形，25 字形解码变体归一大写（ꜣ/ʿ→A、ḥ→H、ḏ→D 等）；C/E/J/O/U/V 无字形如实报错。', en: 'Egyptian hieroglyphic uniliteral alphabet (Gardiner codes, Unicode hieroglyph block): 20 letters encode to glyphs, 25 glyph variants normalize to uppercase on decode; C/E/J/O/U/V have no glyphs and error.' },
    supportsEncode: true,
    supportsDecode: true,
  },
];

// 各操作 variant 默认档（主控挂载时可作 params 缺省）
export const symbolCiphersDefaultParams: Record<string, string> = {
  'zodiac-408': 'cycle',
  babylonian: 'cuneiform',
  mayan: 'mayan',
  dominoes: 'horizontal',
  trilitere: 'ccc',
};

export async function symbolCiphersTransform(id: string, direction: Direction, input: string, params: Record<string, string>): Promise<string> {
  if (input === '') return '';
  const encode = direction === 'encode';
  const variant = params.variant ?? symbolCiphersDefaultParams[id] ?? '';
  switch (id) {
    case 'zodiac-408':
      return encode ? zodiac408Encode(input, variant) : zodiac408Decode(input);
    case 'wabun':
      return encode ? wabunEncode(input) : wabunDecode(input);
    case 'babylonian':
      return encode ? babylonianEncode(input, variant) : babylonianDecode(input);
    case 'mayan':
      return encode ? mayanEncode(input, variant) : mayanDecode(input);
    case 'egyptian-numerals':
      return encode ? egyptianEncode(input) : egyptianDecode(input);
    case 'astro-symbols':
      return encode ? astroEncode(input) : astroDecode(input);
    case 'dice':
      return encode ? diceEncode(input) : diceDecode(input);
    case 'dominoes':
      return encode ? dominoEncode(input, variant) : dominoDecode(input);
    case 'trilitere':
      return encode ? trilitereEncode(input, variant) : trilitereDecode(input, variant);
    case 'monome-binome':
      return encode ? monomeBinomeEncode(input) : monomeBinomeDecode(input);
    case 'hieroglyph-single':
      return encode ? hieroglyphEncode(input) : hieroglyphDecode(input);
    default:
      throw new Error(`符号密码模块不支持的操作：${id}`);
  }
}
