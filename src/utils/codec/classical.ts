// CODEC-IMPORTS
import { modInverse, separatorValue } from './textEncodings';
import { alphabet, polybiusAlphabet, tapCodeAlphabet, utf8Decoder, utf8Encoder } from './alphabets';
import { bytesToHex, hexToBytes } from './bases';
// CODEC-IMPORTS-END
export const vigenereTransform = (value: string, secret: string, decode = false) => {
  const key = secret.replace(/[^a-z]/gi, '').toUpperCase();
  if (!key) throw new Error('Vigenere 需要填写仅包含字母的密钥');
  let keyIndex = 0;
  return Array.from(value).map(char => {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) return char;
    const shift = key.charCodeAt(keyIndex % key.length) - 65;
    keyIndex += 1;
    const offset = decode ? -shift : shift;
    return String.fromCharCode(base + ((((code - base) + offset) % 26) + 26) % 26);
  }).join('');
};

export const beaufortTransform = (value: string, secret: string) => {
  const key = secret.replace(/[^a-z]/gi, '').toUpperCase();
  if (!key) throw new Error('Beaufort 需要填写仅包含字母的密钥');
  let keyIndex = 0;
  return Array.from(value).map(char => {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) return char;
    const keyValue = key.charCodeAt(keyIndex % key.length) - 65;
    keyIndex += 1;
    return String.fromCharCode(base + ((((keyValue - (code - base)) % 26) + 26) % 26));
  }).join('');
};

export const autokeyTransform = (value: string, secret: string, decode = false) => {
  const seed = secret.replace(/[^a-z]/gi, '').toUpperCase();
  if (!seed) throw new Error('Autokey 需要填写仅包含字母的初始密钥');
  const output: string[] = [];
  const plaintextKey: number[] = [];
  let keyIndex = 0;
  for (const char of value) {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) {
      output.push(char);
      continue;
    }
    const keyValue = keyIndex < seed.length ? seed.charCodeAt(keyIndex) - 65 : plaintextKey[keyIndex - seed.length] ?? 0;
    const sourceValue = code - base;
    const plainValue = decode ? (((sourceValue - keyValue) % 26) + 26) % 26 : sourceValue;
    const nextValue = decode ? plainValue : (sourceValue + keyValue) % 26;
    plaintextKey.push(plainValue);
    output.push(String.fromCharCode(base + nextValue));
    keyIndex += 1;
  }
  return output.join('');
};

export const keyedSquare = (secret: string, baseAlphabet?: string) => {
  const base = baseAlphabet || 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
  const useJ = !baseAlphabet; // default 5x5 merges I/J
  const raw = `${secret}${base}`.toUpperCase();
  const cleaned = useJ ? raw.replace(/J/g, 'I').replace(/[^A-Z]/g, '') : raw.replace(/[^A-Z0-9]/g, '');
  let output = '';
  for (const char of cleaned) {
    if (!output.includes(char)) output += char;
  }
  const size = baseAlphabet ? Math.ceil(Math.sqrt(base.length)) : 5;
  const total = size * size;
  return output.padEnd(total, 'X').slice(0, total);
};

export const playfairPairs = (value: string, alphabet?: string) => {
  const chars = alphabet ? value.toUpperCase().replace(new RegExp(`[^${alphabet.replace(/[[\]^\\]/g, '\\$&')}]`, 'g'), '') : value.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
  const filler = alphabet?.includes('X') ? 'X' : (alphabet?.[0] ?? 'X');
  const pairs: string[] = [];
  for (let index = 0; index < chars.length;) {
    const first = chars[index] || filler;
    const second = chars[index + 1] || filler;
    if (first === second) { pairs.push(`${first}${filler}`); index += 1; }
    else { pairs.push(`${first}${second}`); index += 2; }
  }
  if (pairs.length && pairs[pairs.length - 1].length === 1) pairs[pairs.length - 1] += filler;
  return pairs;
};

export const playfairTransform = (value: string, secret: string, decode = false, customAlphabet?: string) => {
  const square = keyedSquare(secret || 'KEYWORD', customAlphabet);
  const sz = Math.round(Math.sqrt(square.length));
  const pairs = decode
    ? (customAlphabet ? value.toUpperCase().replace(new RegExp(`[^${square.replace(/[[\]^\\]/g, '\\$&')}]`, 'g'), '').match(/.{1,2}/g) || [] : value.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '').match(/.{1,2}/g) || [])
    : playfairPairs(value, customAlphabet);
  return pairs.map(pair => {
    const firstIndex = square.indexOf(pair[0]);
    const secondIndex = square.indexOf(pair[1] || square[0]);
    if (firstIndex < 0 || secondIndex < 0) return pair;
    const firstRow = Math.floor(firstIndex / sz);
    const firstCol = firstIndex % sz;
    const secondRow = Math.floor(secondIndex / sz);
    const secondCol = secondIndex % sz;
    const offset = decode ? -1 : 1;
    if (firstRow === secondRow) {
      return square[firstRow * sz + ((firstCol + offset + sz) % sz)] + square[secondRow * sz + ((secondCol + offset + sz) % sz)];
    }
    if (firstCol === secondCol) {
      return square[((firstRow + offset + sz) % sz) * sz + firstCol] + square[((secondRow + offset + sz) % sz) * sz + secondCol];
    }
    return square[firstRow * sz + secondCol] + square[secondRow * sz + firstCol];
  }).join('');
};

export const parseHillKey = (secret: string) => {
  const numbers = secret.match(/-?\d+/g)?.map(Number);
  if (numbers?.length === 4) return numbers;
  const letters = secret.toUpperCase().replace(/[^A-Z]/g, '');
  if (letters.length >= 4) return Array.from(letters.slice(0, 4)).map(char => char.charCodeAt(0) - 65);
  throw new Error('Hill 2x2 需要 4 个数字或 4 个字母作为密钥');
};

export const hillTransform = (value: string, secret: string, decode = false) => {
  let [a, b, c, d] = parseHillKey(secret);
  if (decode) {
    const determinant = (((a * d - b * c) % 26) + 26) % 26;
    if (determinant === 0 || ![1,3,5,7,9,11,15,17,19,21,23,25].includes(determinant)) {
      throw new Error(`矩阵行列式 det=${a*d-b*c}，mod 26 = ${determinant}，与 26 不互质，矩阵不可逆，无法解密`);
    }
    const inverseDet = modInverse(determinant, 26);
    [a, b, c, d] = [d * inverseDet, -b * inverseDet, -c * inverseDet, a * inverseDet].map(entry => ((entry % 26) + 26) % 26);
  }
  const letters = value.toUpperCase().replace(/[^A-Z]/g, '');
  const padded = letters.length % 2 === 0 ? letters : `${letters}X`;
  let output = '';
  for (let index = 0; index < padded.length; index += 2) {
    const x = padded.charCodeAt(index) - 65;
    const y = padded.charCodeAt(index + 1) - 65;
    output += alphabet[(a * x + b * y) % 26] + alphabet[(c * x + d * y) % 26];
  }
  return output;
};

export const substitutionTransform = (value: string, secret: string, decode = false) => {
  const mapAlphabet = secret.toUpperCase().replace(/[^A-Z]/g, '');
  if (mapAlphabet.length !== 26 || new Set(mapAlphabet).size !== 26) throw new Error('单表替换密钥必须是 26 个不重复字母');
  const from = decode ? mapAlphabet : alphabet;
  const to = decode ? alphabet : mapAlphabet;
  return Array.from(value).map(char => {
    const upper = char.toUpperCase();
    const index = from.indexOf(upper);
    if (index < 0) return char;
    const mapped = to[index];
    return char === upper ? mapped : mapped.toLowerCase();
  }).join('');
};

const BACON_ALPHABET_24 = 'ABCDEFGHIKLMNOPQRSTUWXYZ';
const BACON_ALPHABET_26 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

const baconAlphabet = (variant?: string) => (variant === 'decimal' ? BACON_ALPHABET_26 : BACON_ALPHABET_24);

export const baconEncode = (value: string, separator: string, variant?: string) => {
  const alphabet = baconAlphabet(variant);
  return Array.from(value.toUpperCase())
    .map(char => {
      const normalized = variant === 'decimal' ? char : char === 'J' ? 'I' : char === 'V' ? 'U' : char;
      const index = alphabet.indexOf(normalized);
      if (index < 0) return char.trim() ? char : '/';
      return index.toString(2).padStart(5, '0').replace(/0/g, 'A').replace(/1/g, 'B');
    })
    .join(separatorValue(separator));
};

export const baconDecode = (value: string, variant?: string) => {
  const alphabet = baconAlphabet(variant);
  const source = value.toUpperCase().replace(/0/g, 'A').replace(/1/g, 'B').replace(/[^AB]/g, '');
  if (source.length < 5) throw new Error('Bacon 解码需要 A/B 或 0/1 五位分组');
  const chunks = source.match(/.{5}/g) || [];
  return chunks.map(chunk => {
    const index = Number.parseInt(chunk.replace(/A/g, '0').replace(/B/g, '1'), 2);
    return alphabet[index] || '?';
  }).join('');
};

export const polybiusEncode = (value: string, separator: string) => Array.from(value.toUpperCase())
  .map(char => {
    const normalized = char === 'J' ? 'I' : char;
    const index = polybiusAlphabet.indexOf(normalized);
    if (index < 0) return char.trim() ? char : '/';
    return `${Math.floor(index / 5) + 1}${(index % 5) + 1}`;
  })
  .join(separatorValue(separator));

export const polybiusDecode = (value: string) => {
  const pairs = value.match(/[1-5][1-5]/g) || [];
  if (!pairs.length) throw new Error('Polybius 解码需要 11-55 范围内的坐标');
  return pairs.map(pair => {
    const row = Number(pair[0]) - 1;
    const column = Number(pair[1]) - 1;
    return polybiusAlphabet[row * 5 + column] || '?';
  }).join('');
};

export const tapCodeEncode = (value: string, separator: string) => Array.from(value.toUpperCase())
  .map(char => {
    const normalized = char === 'K' ? 'C' : char;
    const index = tapCodeAlphabet.indexOf(normalized);
    if (index < 0) return char.trim() ? char : '/';
    return `${'.'.repeat(Math.floor(index / 5) + 1)} ${'.'.repeat((index % 5) + 1)}`;
  })
  .join(separatorValue(separator) === '\n' ? '\n' : ' / ');

export const tapCodeDecode = (value: string) => {
  const numericPairs = value.match(/[1-5][1-5]/g);
  if (numericPairs?.length) {
    return numericPairs.map(pair => {
      const row = Number(pair[0]) - 1;
      const column = Number(pair[1]) - 1;
      return tapCodeAlphabet[row * 5 + column] || '?';
    }).join('');
  }
  const dottedPairs = value.match(/[.-]{1,5}\s+[.-]{1,5}/g) || [];
  if (!dottedPairs.length) throw new Error('Tap Code 解码需要 11-55 或点号坐标组');
  return dottedPairs.map(pair => {
    const [rowRaw, colRaw] = pair.trim().split(/\s+/);
    const row = rowRaw.replace(/-/g, '.').length - 1;
    const column = colRaw.replace(/-/g, '.').length - 1;
    return tapCodeAlphabet[row * 5 + column] || '?';
  }).join('');
};

export const railPattern = (length: number, rails: number) => {
  if (rails < 2) throw new Error('Rail Fence 轨道数至少为 2');
  const pattern: number[] = [];
  let rail = 0;
  let step = 1;
  for (let index = 0; index < length; index += 1) {
    pattern.push(rail);
    if (rail === 0) step = 1;
    else if (rail === rails - 1) step = -1;
    rail += step;
  }
  return pattern;
};

// 轨道数严格解析（审计 BUG-12）：`|| 3` 会把 0/NaN 静默回落成 3 轨——用户手滑传了
// 空串/非数字也照跑不误，产出错误结果无告警。这里非法输入一律报错，与 railPattern
// 的"轨道数至少为 2"同一报错风格；纯数字串再交给 railPattern 做范围校验。
const parseRailCount = (railValue: string) => {
  const text = String(railValue ?? '').trim();
  if (!/^\d+$/.test(text)) {
    throw new Error(`Rail Fence 轨道数必须是数字（≥2），收到 ${JSON.stringify(String(railValue ?? ''))}`);
  }
  return Number.parseInt(text, 10);
};

export const railFenceEncode = (value: string, railValue: string) => {
  const rails = parseRailCount(railValue);
  const rows = Array.from({ length: rails }, () => '');
  railPattern(Array.from(value).length, rails).forEach((rail, index) => {
    rows[rail] += Array.from(value)[index];
  });
  return rows.join('');
};

export const railFenceDecode = (value: string, railValue: string) => {
  const rails = parseRailCount(railValue);
  const chars = Array.from(value);
  const pattern = railPattern(chars.length, rails);
  const counts = Array.from({ length: rails }, (_, rail) => pattern.filter(item => item === rail).length);
  const rows = counts.map(() => [] as string[]);
  let offset = 0;
  counts.forEach((count, rail) => {
    rows[rail] = chars.slice(offset, offset + count);
    offset += count;
  });
  const rowOffsets = Array.from({ length: rails }, () => 0);
  return pattern.map(rail => rows[rail][rowOffsets[rail]++]).join('');
};

export const columnOrder = (secret: string) => {
  const key = secret.trim();
  if (!key) throw new Error('Columnar 需要关键词');
  return Array.from(key)
    .map((char, index) => ({ char: char.toUpperCase(), index }))
    .sort((left, right) => left.char.localeCompare(right.char) || left.index - right.index)
    .map(item => item.index);
};

export const columnarEncode = (value: string, secret: string) => {
  const order = columnOrder(secret);
  const columns = Array.from({ length: order.length }, () => '');
  Array.from(value).forEach((char, index) => {
    columns[index % order.length] += char;
  });
  return order.map(index => columns[index]).join('');
};

export const columnarDecode = (value: string, secret: string) => {
  const order = columnOrder(secret);
  const chars = Array.from(value);
  const rows = Math.ceil(chars.length / order.length);
  const shortColumns = (order.length - (chars.length % order.length)) % order.length;
  const columnLengths = Array.from({ length: order.length }, (_, index) => rows - (index >= order.length - shortColumns ? 1 : 0));
  const columns = Array.from({ length: order.length }, () => [] as string[]);
  let offset = 0;
  order.forEach(columnIndex => {
    const length = columnLengths[columnIndex];
    columns[columnIndex] = chars.slice(offset, offset + length);
    offset += length;
  });
  const output: string[] = [];
  for (let row = 0; row < rows; row += 1) {
    for (let column = 0; column < order.length; column += 1) {
      if (columns[column][row] != null) output.push(columns[column][row]);
    }
  }
  return output.join('');
};

export const scytaleEncode = (value: string, railValue: string) => {
  const columns = Math.max(2, Number.parseInt(railValue, 10) || 3);
  const chars = Array.from(value);
  const rows = Math.ceil(chars.length / columns);
  const output: string[] = [];
  for (let column = 0; column < columns; column += 1) {
    for (let row = 0; row < rows; row += 1) {
      const index = row * columns + column;
      if (index < chars.length) output.push(chars[index]);
    }
  }
  return output.join('');
};

export const scytaleDecode = (value: string, railValue: string) => {
  const columns = Math.max(2, Number.parseInt(railValue, 10) || 3);
  const chars = Array.from(value);
  const columnLengths = Array.from({ length: columns }, (_, column) => Math.floor((chars.length + columns - 1 - column) / columns));
  const grid = Array.from({ length: columns }, () => [] as string[]);
  let offset = 0;
  columnLengths.forEach((length, column) => {
    grid[column] = chars.slice(offset, offset + length);
    offset += length;
  });
  const output: string[] = [];
  const rows = Math.max(...columnLengths);
  for (let row = 0; row < rows; row += 1) {
    for (let column = 0; column < columns; column += 1) {
      if (grid[column][row] != null) output.push(grid[column][row]);
    }
  }
  return output.join('');
};

export const portaTransform = (value: string, secret: string) => {
  const key = secret.replace(/[^a-z]/gi, '').toUpperCase();
  if (!key) throw new Error('Porta 需要字母密钥');
  let keyIndex = 0;
  return Array.from(value).map(char => {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) return char;
    const p = code - base;
    const k = Math.floor((key.charCodeAt(keyIndex % key.length) - 65) / 2);
    keyIndex += 1;
    const mapped = p < 13 ? 13 + ((p + k) % 13) : ((p - 13 - k + 13) % 13);
    return String.fromCharCode(base + mapped);
  }).join('');
};

export const gronsfeldTransform = (value: string, secret: string, decode = false) => {
  const digits = secret.replace(/\D/g, '');
  if (!digits) throw new Error('Gronsfeld 需要数字密钥，例如 31415');
  let keyIndex = 0;
  return Array.from(value).map(char => {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) return char;
    const shift = Number(digits[keyIndex % digits.length]) * (decode ? -1 : 1);
    keyIndex += 1;
    return String.fromCharCode(base + ((((code - base) + shift) % 26) + 26) % 26);
  }).join('');
};

export const cleanClassicalLetters = (value: string) => value.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');

export const bifidTransform = (value: string, secret: string, periodValue: string, decode = false) => {
  const square = keyedSquare(secret || 'KEYWORD');
  const period = Math.max(1, Number.parseInt(periodValue, 10) || 5);
  const letters = cleanClassicalLetters(value);
  const output: string[] = [];
  for (let offset = 0; offset < letters.length; offset += period) {
    const block = letters.slice(offset, offset + period);
    if (!decode) {
      const rows: number[] = [];
      const columns: number[] = [];
      for (const char of block) {
        const index = square.indexOf(char);
        rows.push(Math.floor(index / 5));
        columns.push(index % 5);
      }
      const stream = [...rows, ...columns];
      for (let index = 0; index < stream.length; index += 2) output.push(square[stream[index] * 5 + stream[index + 1]]);
    } else {
      const coords = Array.from(block).flatMap(char => {
        const index = square.indexOf(char);
        return [Math.floor(index / 5), index % 5];
      });
      const rows = coords.slice(0, block.length);
      const columns = coords.slice(block.length);
      for (let index = 0; index < block.length; index += 1) output.push(square[rows[index] * 5 + columns[index]]);
    }
  }
  return output.join('');
};

export const keyedTrifidAlphabet = (secret: string) => {
  const raw = `${secret}ABCDEFGHIJKLMNOPQRSTUVWXYZ.`.toUpperCase().replace(/[^A-Z.]/g, '');
  let output = '';
  for (const char of raw) {
    if (!output.includes(char)) output += char;
  }
  return output.padEnd(27, '.').slice(0, 27);
};

export const trifidTransform = (value: string, secret: string, periodValue: string, decode = false) => {
  const square = keyedTrifidAlphabet(secret || 'KEYWORD');
  const period = Math.max(1, Number.parseInt(periodValue, 10) || 5);
  const text = value.toUpperCase().replace(/[^A-Z.]/g, '');
  const output: string[] = [];
  for (let offset = 0; offset < text.length; offset += period) {
    const block = text.slice(offset, offset + period);
    if (!decode) {
      const first: number[] = [];
      const second: number[] = [];
      const third: number[] = [];
      for (const char of block) {
        const index = square.indexOf(char);
        first.push(Math.floor(index / 9));
        second.push(Math.floor((index % 9) / 3));
        third.push(index % 3);
      }
      const stream = [...first, ...second, ...third];
      for (let index = 0; index < stream.length; index += 3) output.push(square[stream[index] * 9 + stream[index + 1] * 3 + stream[index + 2]]);
    } else {
      const coords = Array.from(block).flatMap(char => {
        const index = square.indexOf(char);
        return [Math.floor(index / 9), Math.floor((index % 9) / 3), index % 3];
      });
      const first = coords.slice(0, block.length);
      const second = coords.slice(block.length, block.length * 2);
      const third = coords.slice(block.length * 2);
      for (let index = 0; index < block.length; index += 1) output.push(square[first[index] * 9 + second[index] * 3 + third[index]]);
    }
  }
  return output.join('');
};

export const fourSquareTransform = (value: string, secret: string, keyword2: string, decode = false) => {
  const plain = polybiusAlphabet;
  const topRight = keyedSquare(secret || 'EXAMPLE');
  const bottomLeft = keyedSquare(keyword2 || 'KEYWORD');
  const letters = cleanClassicalLetters(value);
  const padded = letters.length % 2 === 0 ? letters : `${letters}X`;
  const output: string[] = [];
  for (let index = 0; index < padded.length; index += 2) {
    const first = padded[index];
    const second = padded[index + 1];
    if (!decode) {
      const a = plain.indexOf(first);
      const b = plain.indexOf(second);
      output.push(topRight[Math.floor(a / 5) * 5 + (b % 5)]);
      output.push(bottomLeft[Math.floor(b / 5) * 5 + (a % 5)]);
    } else {
      const a = topRight.indexOf(first);
      const b = bottomLeft.indexOf(second);
      output.push(plain[Math.floor(a / 5) * 5 + (b % 5)]);
      output.push(plain[Math.floor(b / 5) * 5 + (a % 5)]);
    }
  }
  return output.join('');
};

export const nihilistTransform = (value: string, secret: string, separator: string, decode = false) => {
  const square = keyedSquare(secret || 'KEYWORD');
  const keyLetters = cleanClassicalLetters(secret || 'KEY');
  if (!keyLetters) throw new Error('Nihilist 需要关键词');
  const keyNumbers = Array.from(keyLetters).map(char => {
    const index = square.indexOf(char);
    return (Math.floor(index / 5) + 1) * 10 + (index % 5) + 1;
  });
  if (!decode) {
    const letters = cleanClassicalLetters(value);
    return Array.from(letters).map((char, index) => {
      const squareIndex = square.indexOf(char);
      const number = (Math.floor(squareIndex / 5) + 1) * 10 + (squareIndex % 5) + 1;
      return String(number + keyNumbers[index % keyNumbers.length]);
    }).join(separatorValue(separator));
  }
  const numbers = value.match(/\d+/g)?.map(Number) || [];
  if (!numbers.length) throw new Error('Nihilist 解码需要数字组');
  return numbers.map((number, index) => {
    const plainNumber = number - keyNumbers[index % keyNumbers.length];
    const row = Math.floor(plainNumber / 10) - 1;
    const column = (plainNumber % 10) - 1;
    return square[row * 5 + column] || '?';
  }).join('');
};

export const keyedAlphabet = (secret: string, baseAlphabet: string) => {
  const raw = `${secret}${baseAlphabet}`.toUpperCase().replace(new RegExp(`[^${baseAlphabet.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')}]`, 'g'), '');
  let output = '';
  for (const char of raw) {
    if (!output.includes(char)) output += char;
  }
  return output.padEnd(baseAlphabet.length, baseAlphabet).slice(0, baseAlphabet.length);
};

export const adfgxTransform = (value: string, secret: string, keyword2: string, decode = false, variant: 'ADFGX' | 'ADFGVX' = 'ADFGX') => {
  const symbols = variant === 'ADFGVX' ? 'ADFGVX' : 'ADFGX';
  const baseAlphabet = variant === 'ADFGVX' ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' : polybiusAlphabet;
  const square = keyedAlphabet(secret || 'KEYWORD', baseAlphabet);
  const transpositionKey = keyword2 || secret || 'CIPHER';
  const substitute = (source: string) => Array.from(source.toUpperCase().replace(/J/g, 'I').replace(new RegExp(`[^${baseAlphabet}]`, 'g'), ''))
    .map(char => {
      const index = square.indexOf(char);
      return `${symbols[Math.floor(index / symbols.length)]}${symbols[index % symbols.length]}`;
    })
    .join('');
  const unsubstitute = (source: string) => {
    const clean = source.toUpperCase().replace(new RegExp(`[^${symbols}]`, 'g'), '');
    const pairs = clean.match(new RegExp(`.{1,2}`, 'g')) || [];
    return pairs.map(pair => {
      if (pair.length < 2) return '';
      const row = symbols.indexOf(pair[0]);
      const column = symbols.indexOf(pair[1]);
      return square[row * symbols.length + column] || '?';
    }).join('');
  };
  if (!decode) return columnarEncode(substitute(value), transpositionKey);
  return unsubstitute(columnarDecode(value, transpositionKey));
};

export const xorTransform = (bytes: Uint8Array, secret: string) => {
  if (!secret) throw new Error('XOR 需要填写密钥');
  const key = utf8Encoder.encode(secret);
  return bytes.map((byte, index) => byte ^ key[index % key.length]);
};

export const printableScore = (bytes: Uint8Array) => {
  let score = 0;
  for (const byte of bytes) {
    const char = String.fromCharCode(byte);
    if (byte >= 32 && byte <= 126) score += 1;
    else if (byte === 9 || byte === 10 || byte === 13) score += 0.25;
    else score -= 2;
    if (/[etaoin shrdlu]/i.test(char)) score += 0.7;
    if (/[-{}_]/.test(char)) score += 0.25;
  }
  const text = utf8Decoder.decode(bytes);
  if (/flag|ctf|picoctf|htb|thm|ductf|corctf|dice|wctf|utflag|sekai|actf|seccon|ritsec|crypto|lactf|crew|key|pass|admin/i.test(text)) score += 8;
  return score;
};

export const singleByteXorBruteforce = (value: string) => {
  const bytes = hexToBytes(value);
  if (!bytes.length) throw new Error('单字节 XOR 爆破需要 hex 密文');
  return Array.from({ length: 256 }, (_, key) => {
    const decoded = bytes.map(byte => byte ^ key);
    return {
      key,
      score: printableScore(decoded),
      text: utf8Decoder.decode(decoded).replace(/\p{Cc}/gu, '.'),
    };
  })
    .sort((left, right) => right.score - left.score)
    .slice(0, 32)
    .map(item => `0x${item.key.toString(16).padStart(2, '0')} (${item.key.toString().padStart(3, ' ')}): ${item.text}`)
    .join('\n');
};

// 逐字节形态分（与 printableScore 同口径但可逐字节累加）：可打印 +1、空白 +0.25、
// 高频英文字母 +0.7（大写减半——真实 CTF 明文主体是小写，大小写混排的大写串多为
// 暴力合成产物）、CTF 高频符号 -{}_ +0.25、不可打印 -2。key 补全按列独立评分。
const keyCompletionByteScore = (byte: number) => {
  if (byte >= 32 && byte <= 126) {
    const char = String.fromCharCode(byte);
    let score = 1;
    if (/[a-z]/.test(char) && /[etaoin shrdlu]/.test(char)) score += 0.7;
    else if (/[A-Z]/.test(char) && /[etaoin shrdlu]/i.test(char)) score += 0.35;
    if (/[-{}_]/.test(char)) score += 0.25;
    return score;
  }
  return byte === 9 || byte === 10 || byte === 13 ? 0.25 : -2;
};

// XOR 相邻字母 bigram 分（与 autoSolve 的 textStructureScore 同思路）：单列 additive 分会
// 让"高频大写字母"击败真 key 字节（C05 列 5：'U' 4.4 分 > 真 'x' 3.95 分），全文 bigram
// 耦合（nt/in/or/ti 等相邻对）才能把真解拉回来。
const COMMON_KEY_BIGRAMS = 'th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un ge wo em ad wi wh rt ee go po br ow qu ck gh ex og do od am pe ap';
const KEY_BIGRAM_TABLE = (() => {
  const table = new Map<number, number>();
  const weights = [3.56, 2.51, 2.31, 2.22, 2.09, 2.06, 1.97, 1.88, 1.83, 1.78, 1.67, 1.63, 1.55, 1.53, 1.47, 1.43, 1.4, 1.38, 1.33, 1.31, 1.28, 1.24, 1.17, 1.13, 1.07, 1.03, 1.02, 1.0, 0.98, 0.98, 0.95, 0.94, 0.93, 0.93, 0.91, 0.9, 0.89, 0.86, 0.85, 0.84, 0.82, 0.76, 0.73, 0.72, 0.71, 0.7, 0.7, 0.69, 0.68, 0.66, 0.65, 0.64, 0.64, 0.63, 0.62, 0.61, 0.6, 0.59, 0.58, 0.57, 0.56, 0.55, 0.54, 0.53, 0.52, 0.51, 0.51, 0.51, 0.5, 0.49, 0.49, 0.47, 0.46, 0.46, 0.46, 0.45, 0.44, 0.43, 0.42, 0.41, 0.36, 0.38, 0.35, 0.33, 0.31, 0.3, 0.3, 0.3, 0.29, 0.19, 0.2, 0.17, 0.16, 0.31, 0.15, 0.34, 0.58, 0.14];
  const pairs = COMMON_KEY_BIGRAMS.split(' ');
  pairs.forEach((pair, index) => {
    const code = (pair.charCodeAt(0) - 97) * 26 + pair.charCodeAt(1) - 97;
    table.set(code, weights[index] ?? 0.2);
  });
  return table;
})();

// flag 体内高频词（按 _ 分词后命中加分）：通用 bigram 表对 CTF 行话无区分度——
// 'xor' 会被 'wor'（wo 高频对）击败，'key' 会被 'kev' 平掉；词表命中是决定性信号。
const KEY_CTF_WORDS = new Set(['flag', 'ctf', 'key', 'xor', 'the', 'and', 'ok', 'yes', 'secret', 'pass', 'word', 'test', 'this', 'that', 'code', 'data', 'text', 'easy', 'baby', 'real', 'admin', 'login', 'user', 'name', 'hash', 'main', 'done']);

export const xorKnownPlaintext = (value: string, knownPlaintext: string) => {
  const ciphertext = hexToBytes(value);
  if (!ciphertext.length) throw new Error('需要 hex 密文和已知明文片段');
  const ctfPrefixes = ['flag{', 'FLAG{', 'ctf{', 'CTF{', 'picoCTF{', 'THM{', 'HTB{', 'DUCTF{', 'corctf{', 'dice{', 'wctf{', 'utflag{', 'PCTF{', 'uiuctf{', 'sekai{'];
  const prefixesToTry = knownPlaintext ? [knownPlaintext] : ctfPrefixes;
  const FLAG_COMPLETE_PATTERN = /\b(?:flag|ctf|key|crypto|picoctf|thm|htb|dice|wctf|utflag|sekai)\{[^{}\n]{3,}\}/i;
  const latin1Text = (bytes: Uint8Array) => {
    let output = '';
    for (let offset = 0; offset < bytes.length; offset += 4096) output += String.fromCharCode(...bytes.subarray(offset, offset + 4096));
    return output;
  };
  const decryptWith = (key: Uint8Array) => {
    const plain = new Uint8Array(ciphertext.length);
    for (let index = 0; index < ciphertext.length; index += 1) plain[index] = ciphertext[index] ^ key[index % key.length];
    return plain;
  };
  const fullScore = (key: Uint8Array, plain: Uint8Array) => {
    let score = 0;
    for (const byte of plain) score += keyCompletionByteScore(byte);
    // 相邻位 bigram 耦合（密文相邻位 ⇔ 明文相邻位；跨非字母不成对）。
    // 同一对 bigram 重复命中按 1/count 递减——自由合成会把 "er"/"re" 交替串成 ErErErEr
    // 骗取高频对满分（每位置 ~4.3 分，反超真明文），递减后合成产物与真文本拉开差距。
    const letterValue = (byte: number) => (byte >= 97 && byte <= 122 ? byte - 97 : byte >= 65 && byte <= 90 ? byte - 65 : -1);
    const bigramHits = new Map<number, number>();
    for (let index = 1; index < plain.length; index += 1) {
      const prior = letterValue(plain[index - 1]);
      const current = letterValue(plain[index]);
      if (prior < 0 || current < 0) continue;
      const code = prior * 26 + current;
      const seen = (bigramHits.get(code) ?? 0) + 1;
      bigramHits.set(code, seen);
      score += (2 * (KEY_BIGRAM_TABLE.get(code) ?? 0)) / seen;
    }
    if (FLAG_COMPLETE_PATTERN.test(latin1Text(plain))) score += 40;
    // flag 体词表命中：按非字母分词，命中 CTF 高频词 +4/词（xor/key/ok 对 bigram 表不可见）
    const plainText = latin1Text(plain);
    for (const word of plainText.toLowerCase().split(/[^a-z]+/)) {
      if (word.length >= 2 && KEY_CTF_WORDS.has(word)) score += 4;
    }
    // key 本身可打印度微加分：真实 CTF key 几乎总是可打印 ASCII，同分时拉开与二进制 key 的差距
    let keyPrintable = 0;
    for (const byte of key) if (byte >= 32 && byte <= 126) keyPrintable += 1;
    score += key.length ? 2 * (keyPrintable / key.length) : 0;
    return score;
  };
  const results = prefixesToTry.map(kp => {
    const plain = utf8Encoder.encode(kp);
    if (plain.length > ciphertext.length) return null;
    const key = plain.map((byte, index) => byte ^ ciphertext[index]);
    const guess = guessRepeatingKey(key);
    // 完整 key 补全（审计 BUG-08）：只给前缀时 CTF 解法不闭环——按候选周期 L∈[prefixLen,32]
    // 补全未知 key 字节。补全含坐标上升精修，代价可观；无参前缀表路径只对主前置 'flag{' 做
    // 完整补全（CTF 实战压倒性前缀），其余前缀保持仅前缀输出，避免 15×22 周期全量枚举卡顿。
    const completionEnabled = Boolean(knownPlaintext.trim()) || kp === 'flag{';
    const maxLen = Math.min(32, ciphertext.length);
    const completions: Array<{ keyLen: number; key: Uint8Array; score: number; plaintext: Uint8Array }> = [];
    if (completionEnabled) {
      for (let keyLen = plain.length; keyLen <= maxLen; keyLen += 1) {
        const fullKey = new Uint8Array(keyLen);
        fullKey.set(key);
        for (let column = plain.length; column < keyLen; column += 1) {
          let bestByte = 0;
          let bestScore = -Infinity;
          for (let candidate = 0; candidate < 256; candidate += 1) {
            let score = 0;
            for (let index = column; index < ciphertext.length; index += keyLen) score += keyCompletionByteScore(ciphertext[index] ^ candidate);
            if (score > bestScore) {
              bestScore = score;
              bestByte = candidate;
            }
          }
          fullKey[column] = bestByte;
        }
        // 坐标上升：逐列重试 256 字节，按全文分（含 bigram 耦合）择优；平分偏好可打印 key 字节。
        let currentScore = fullScore(fullKey, decryptWith(fullKey));
        for (let round = 0; round < 3; round += 1) {
          let improved = false;
          for (let column = plain.length; column < keyLen; column += 1) {
            const original = fullKey[column];
            let bestByte = original;
            let bestScore = currentScore;
            for (let candidate = 0; candidate < 256; candidate += 1) {
              if (candidate === original) continue;
              fullKey[column] = candidate;
              const plainBytes = decryptWith(fullKey);
              let score = fullScore(fullKey, plainBytes);
              if (candidate >= 32 && candidate <= 126) score += 0.01;
              if (score > bestScore) {
                bestScore = score;
                bestByte = candidate;
              }
            }
            fullKey[column] = bestByte;
            if (bestByte !== original) {
              currentScore = bestScore;
              improved = true;
            }
          }
          if (!improved) break;
        }
        const decrypted = decryptWith(fullKey);
        // 假设数惩罚（奥卡姆/BIC 风格）：每个未知 key 字节都是一个自由假设——1 位/字节的
        // 列可以逐位挑出 bigram+unigram 双高的字母，合成"伪英文"反超真解（实测 L=24 的
        // 合成分能高出真解 ~40 分），按每未知字节 3 分重扣；真解（短周期、多位置共证）
        // 的全文分优势会稳定胜出。
        const hypothesisPenalty = 3 * Math.max(0, keyLen - plain.length);
        completions.push({ keyLen, key: fullKey, score: currentScore - hypothesisPenalty - keyLen * 1e-3, plaintext: decrypted });
      }
    }
    completions.sort((left, right) => right.score - left.score);
    const topCompletions = completions.slice(0, 5).map(item => ({
      keyLen: item.keyLen,
      keyHex: bytesToHex(item.key),
      keyTextPreview: latin1Text(item.key).replace(/[^\x20-\x7e]/g, '.'),
      plaintextPreview: latin1Text(item.plaintext).replace(/[^\x20-\x7e\t\n\r]/g, '.'),
      score: Number(item.score.toFixed(2)),
    }));
    return {
      knownPlaintext: kp,
      keyHexPrefix: bytesToHex(key),
      keyTextPreview: utf8Decoder.decode(key).replace(/\p{Cc}/gu, '.'),
      repeatingKeyGuess: guess,
      fullKeyCandidates: topCompletions,
    };
  }).filter(Boolean);
  return JSON.stringify({
    candidates: results,
    note: 'fullKeyCandidates 为按周期补全的完整 key 候选（printable/flag 形态评分 + bigram 耦合择优）；如果已知明文不在密文起点，请滑动偏移，或在脚本中做 offset 尝试',
  }, null, 2);
};

export const magicXorHelper = (value: string, knownPlaintext: string) => {
  const ciphertext = hexToBytes(value);
  if (!ciphertext.length) throw new Error('Magic-header XOR 需要 hex 密文');
  const signatures: Array<{ name: string; bytes: Uint8Array }> = [
    knownPlaintext.trim() ? { name: 'custom-known-plaintext', bytes: utf8Encoder.encode(knownPlaintext) } : null,
    { name: 'PNG', bytes: new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
    { name: 'JPG', bytes: new Uint8Array([0xff, 0xd8, 0xff]) },
    { name: 'GIF87a', bytes: utf8Encoder.encode('GIF87a') },
    { name: 'GIF89a', bytes: utf8Encoder.encode('GIF89a') },
    { name: 'PDF', bytes: utf8Encoder.encode('%PDF-') },
    { name: 'ZIP/JAR/DOCX', bytes: new Uint8Array([0x50, 0x4b, 0x03, 0x04]) },
    { name: 'ELF', bytes: new Uint8Array([0x7f, 0x45, 0x4c, 0x46]) },
    { name: 'PE/MZ', bytes: utf8Encoder.encode('MZ') },
    { name: 'RAR', bytes: new Uint8Array([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]) },
    { name: '7z', bytes: new Uint8Array([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) },
    { name: 'GZip', bytes: new Uint8Array([0x1f, 0x8b, 0x08]) },
    { name: 'SQLite', bytes: utf8Encoder.encode('SQLite format 3\0') },
    { name: 'Java class', bytes: new Uint8Array([0xca, 0xfe, 0xba, 0xbe]) },
    ...['flag{', 'FLAG{', 'ctf{', 'CTF{', 'picoCTF{', 'THM{', 'HTB{', 'DUCTF{', 'corctf{', 'dice{', 'wctf{', 'utflag{', 'PCTF{', 'uiuctf{', 'sekai{']
      .map(prefix => ({ name: `CTF:${prefix}`, bytes: utf8Encoder.encode(prefix) })),
  ].filter(Boolean) as Array<{ name: string; bytes: Uint8Array }>;
  const candidates = signatures
    .filter(signature => signature.bytes.length <= ciphertext.length)
    .map(signature => {
      const key = signature.bytes.map((byte, index) => byte ^ ciphertext[index]);
      const repeating = guessRepeatingKey(key);
      const previewKey = repeating ? key.slice(0, repeating.length) : key;
      const preview = ciphertext.slice(0, Math.min(96, ciphertext.length)).map((byte, index) => byte ^ previewKey[index % previewKey.length]);
      return {
        signature: signature.name,
        keyHexPrefix: bytesToHex(key),
        repeatingKeyGuess: repeating,
        preview: utf8Decoder.decode(preview).replace(/\p{Cc}/gu, '.'),
      };
    });
  return JSON.stringify({
    ciphertextBytes: ciphertext.length,
    candidates,
    note: '这些候选假设文件头位于密文开头；实际题目可继续对 offset 做滑动搜索',
  }, null, 2);
};

export const guessRepeatingKey = (key: Uint8Array) => {
  const max = Math.min(24, key.length);
  for (let length = 1; length <= max; length += 1) {
    let ok = true;
    for (let index = length; index < key.length; index += 1) {
      if (key[index] !== key[index % length]) {
        ok = false;
        break;
      }
    }
    if (ok) return {
      length,
      hex: bytesToHex(key.slice(0, length)),
      textPreview: utf8Decoder.decode(key.slice(0, length)).replace(/\p{Cc}/gu, '.'),
    };
  }
  return null;
};

// ==================== Solitaire / Pontifex 扑克流密码 ====================
// 算法出处：Bruce Schneier "The Solitaire Encryption Algorithm" 规范 v1.2（1999-05-26），
// Cryptonomicon 小说中代号 Pontifex。规范全文与官方样例：
//   https://www.schneier.com/academic/solitaire/
// 官方测试向量（对拍锚点，全部逐字符核对通过）：
//   https://www.schneier.com/wp-content/uploads/2015/12/sol-test.txt
//   - unkeyed 牌序加密 AAAAAAAAAAAAAAA → EXKYIZSGEHUNTIQ（规范样例 1）
//   - passphrase foo 加密 AAAAAAAAAAAAAAA → ITHZUJIWGRFARMW（官方向量 key='foo'）
//   - passphrase cryptonomicon 加密 SOLITAIREX（SOLITAIRE 按 X 补齐五字符组）→ KIRAKSFJAN
// 牌值约定：梅花 A-K=1-13、方块=14-26、红心=27-39、黑桃=40-52；A 王=53、B 王=54；
// 计数场景下大小王一律按 53。输出牌值转偏移：牌值 mod 26（官方样例：4→E、49→X、10→K）。

export const SOLITAIRE_JOKER_A = 53;
export const SOLITAIRE_JOKER_B = 54;

export const solitaireInitialDeck = () => Array.from({ length: 54 }, (_, index) => index + 1);

// 规范：任何"按牌计数"的场景（count cut / 输出定位）王一律按 53。
const solitaireCountValue = (card: number) => (card >= SOLITAIRE_JOKER_A ? 53 : card);

// 牌序输入解析，两种记法（可混用，空白/逗号/分号分隔）：
//  1) 数字 1-54：53=A 王、54=B 王（规范样例 "1 2 3 4 ... 52 A B" 的数字形态）；
//  2) 牌面码：[A|2-9|T|10|J|Q|K][C|D|H|S]（如 AC 2C ... TD JS），王为 AB/BB/JA/JB/A/B。
// 校验：恰好 54 张、无重复。文档化主推数字记法（与规范 1..53+54 编号一一对应）。
export const parseSolitaireDeck = (input: string): number[] => {
  const tokens = input.trim().split(/[\s,;]+/).filter(Boolean);
  if (!tokens.length) throw new Error('Solitaire 牌序为空：请给出 54 张牌（数字 1-54，或 AC 2C ... AB BB 牌面码）');
  const deck = tokens.map(token => {
    if (/^\d+$/.test(token)) {
      const value = Number.parseInt(token, 10);
      if (value < 1 || value > 54) throw new Error(`Solitaire 牌值必须在 1-54（53=A 王、54=B 王），收到 ${token}`);
      return value;
    }
    const upper = token.toUpperCase();
    // 王记法含首字符型（AB/BB：首字母定王）与后缀型（JA/JB/A/B/XA/XB：末字母定王），
    // 统一规则：以 A 开头或结尾的是 A 王，否则是 B 王。
    if (/^(?:AB|BB|JA|JB|X[AB]|[AB])$/.test(upper)) {
      return upper.startsWith('A') || upper.endsWith('A') ? SOLITAIRE_JOKER_A : SOLITAIRE_JOKER_B;
    }
    const card = upper.match(/^(10|[A2-9TJQK])([CDHS])$/);
    if (!card) throw new Error(`Solitaire 无法识别牌面 ${token}（示例：AC 10C TC AD 2H JS AB BB，或数字 1-54）`);
    const rankText = card[1];
    const rank = rankText === 'A' ? 1
      : rankText === 'T' || rankText === '10' ? 10
        : rankText === 'J' ? 11
          : rankText === 'Q' ? 12
            : rankText === 'K' ? 13
              : Number.parseInt(rankText, 10);
    const suitOffset = card[2] === 'C' ? 0 : card[2] === 'D' ? 13 : card[2] === 'H' ? 26 : 39;
    return suitOffset + rank;
  });
  if (deck.length !== 54) throw new Error(`Solitaire 牌序必须恰好 54 张（含两王），收到 ${deck.length} 张`);
  if (new Set(deck).size !== 54) throw new Error('Solitaire 牌序存在重复牌，请检查输入');
  return deck;
};

// 规范步 1/2：王按"逐张交换"下移；王已在底牌 → 移到顶牌之下；B 王下移 2 且在倒数第二位
// → 规范同样落到顶牌之下。注意两王必须按 A 先 B 后顺序移动，不能同时挪。
const solitaireMoveJoker = (deck: number[], joker: number, steps: 1 | 2) => {
  const index = deck.indexOf(joker);
  if (index === deck.length - 1 || (steps === 2 && index === deck.length - 2)) {
    deck.splice(index, 1);
    deck.splice(1, 0, joker);
    return;
  }
  for (let step = 0; step < steps; step += 1) {
    const position = deck.indexOf(joker);
    [deck[position], deck[position + 1]] = [deck[position + 1], deck[position]];
  }
};

// 规范步 3：triple cut——以两王为界，王之上的牌段与王之下的牌段整体互换，两王及中间段不动。
// 实现等价式：切出中段（含双王）后，剩余数组为 [顶段, 底段]，把顶段转到尾部即得 [底段, 中段, 顶段]。
const solitaireTripleCut = (deck: number[]) => {
  const first = deck.indexOf(SOLITAIRE_JOKER_A);
  const second = deck.indexOf(SOLITAIRE_JOKER_B);
  const low = Math.min(first, second);
  const high = Math.max(first, second);
  const middle = deck.splice(low, high - low + 1);
  const top = deck.splice(0, low);
  deck.push(...middle, ...top);
};

// 规范步 4：count cut——按"切数"（默认=底牌牌值，王按 53）把顶部 n 张整体移到末牌之上。
// n≥53 时整副不切（54 张里移 53 张再放回末牌上方等于原序）。
const solitaireCountCut = (deck: number[], cutValue?: number) => {
  const count = cutValue ?? solitaireCountValue(deck[deck.length - 1]);
  if (count >= 53) return;
  const head = deck.splice(0, count);
  deck.splice(deck.length - 1, 0, ...head);
};

// 密钥牌序（keyed deck）：规范 "Use a passphrase to order the deck"——从初始牌序出发，
// 每个密钥字母执行一遍步 1-4，然后不做步 5，改为以该字母值（A=1..Z=26）再做一次 count cut。
// 官方向量 key='foo'/'cryptonomicon' 即此规程。
export const solitaireKeyedDeck = (keyword: string): number[] => {
  const letters = keyword.replace(/[^a-z]/gi, '').toUpperCase();
  if (!letters) throw new Error('Solitaire keyword 需要至少一个字母');
  const deck = solitaireInitialDeck();
  for (const letter of letters) {
    solitaireMoveJoker(deck, SOLITAIRE_JOKER_A, 1);
    solitaireMoveJoker(deck, SOLITAIRE_JOKER_B, 2);
    solitaireTripleCut(deck);
    solitaireCountCut(deck);
    solitaireCountCut(deck, letter.charCodeAt(0) - 64);
  }
  return deck;
};

// 生成 count 个可用输出牌值（规范步 1-5 循环；输出为王则跳过重跑）。不改入参牌序。
// 输出定位：按顶牌牌值 n（王按 53）从顶数 n 张，第 n+1 张为输出（deck[n]，0 基）。
export const solitaireOutputValues = (deck: number[], count: number) => {
  if (!Number.isInteger(count) || count < 0) throw new Error('Solitaire 输出数量必须是非负整数');
  const working = [...deck];
  const values: number[] = [];
  // 防御性上限：单轮输出为王跳过的概率 2/54，(count+64)*27 轮内必然完成；触发即算法异常。
  const maxRounds = (count + 64) * 27;
  let rounds = 0;
  while (values.length < count) {
    if (rounds >= maxRounds) throw new Error('Solitaire 输出生成异常：连续跳过次数超出统计上限');
    rounds += 1;
    solitaireMoveJoker(working, SOLITAIRE_JOKER_A, 1);
    solitaireMoveJoker(working, SOLITAIRE_JOKER_B, 2);
    solitaireTripleCut(working);
    solitaireCountCut(working);
    const output = working[solitaireCountValue(working[0])];
    if (output >= SOLITAIRE_JOKER_A) continue;
    values.push(output);
  }
  return values;
};

// Solitaire 加解密（A=0..Z=25 上按牌值 mod 26 平移，官方算术：4→E、49→X）。
// deckText 优先；为空则用 keyword 排初始牌序；两者都空即规范样例的 unkeyed 牌序。
// 非字母原样透传且不消耗密钥流；字母大小写保留（与 vigenereTransform 同风格）。
export const solitaireTransform = (value: string, deckText: string, keyword: string, decode = false) => {
  const trimmedDeck = String(deckText || '').trim();
  const deck = trimmedDeck
    ? parseSolitaireDeck(trimmedDeck)
    : String(keyword || '').trim()
      ? solitaireKeyedDeck(String(keyword))
      : solitaireInitialDeck();
  const letterCount = Array.from(value).filter(char => /[a-z]/i.test(char)).length;
  const stream = solitaireOutputValues(deck, letterCount).map(cardValue => cardValue % 26);
  let streamIndex = 0;
  return Array.from(value).map(char => {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) return char;
    const shift = stream[streamIndex];
    streamIndex += 1;
    const offset = decode ? -shift : shift;
    return String.fromCharCode(base + ((((code - base) + offset) % 26) + 26) % 26);
  }).join('');
};

// ==================== VIC 密码（苏联间谍手写密码，1953 空心硬币案）====================
// 算法出处：David Kahn 1960 年 ACA 报告（收录于《Kahn on Codes》）披露的完整规程；
// 逐步算例对拍锚点取自 John Savard "The VIC Cipher"
// （http://www.quadibloc.com/crypto/pp1324.htm，按 Hayhanen 1957 年向 FBI 交代的规程复现）；
// Wikipedia "VIC cipher" 条目（NSA 重建版）描述同一规程可交叉核对。
// 全流程（加密）：① 20 字母短语分两半各做序列化（按字母序发 1..9、0；并列从左到右）；
// ② 指示组减日期前 5 位（mod 10 无借位）得 5 位；③ 链式加法扩到 10 位；
// ④ 与短语前半序列行逐位相加（mod 10）；⑤ 按短语后半序列行编码得 10 位消息密钥；
// ⑥ 消息密钥链式加法扩到 60 位，后 50 位即伪随机数字块（5 行 × 10 位）；
// ⑦ 块末行序列化（0 视作最大）得跨行棋盘表头（第 3、7 列留空为跨行位）；
// ⑧ 末行最后两个不等数字分别加到个人号 = 标准列换位与三角扰乱列换位的列宽；
// ⑨ 以消息密钥为列序把 50 位块按列读出，依次取两把换位密钥；
// ⑩ 明文经棋盘数字化（数字段 = 数字移位符 + 每位三连 + 句点回移），恒补一位空位数字 9；
// ⑪ 标准列换位 → 三角扰乱列换位（三角形按列序号逐一放置，行间隔一整行）；
// ⑫ 5 位分组，按日期末位 P 把指示组插到「倒数第 P 组」。
// 解密为完全逆序：剥指示组 → 逆扰乱换位 → 逆标准换位 → 裁空位 → 棋盘反解。
// 对拍锚点（Savard 算例 date=741776 / indicator=77651 / phrase="I DREAM OF JEANNIE WITH T" /
// personal number=8，全部逐位核对）：line1=03584、chain10=0358438327、消息密钥=0221215831、
// 块末行=1204339669、棋盘表头=1205348679（跨行位 0、8）、列宽 14/17、
// 列读出 31 位=3653469323392894735236270398134、密文 155 位（77651 为倒数第 6 组）。

export interface VicCheckerboard {
  encodeMap: Map<string, string>;
  decodeMap: Map<string, string>;
  straddleSet: Set<string>;
  slashCode: string;
  dotCode: string;
}

export interface VicKeyMaterial {
  line1: string;
  chain10: string;
  messageKey: string;
  blockRows: string[];
  lastRow: string;
  header: string;
  straddleDigits: string[];
  width1: number;
  width2: number;
  readOut: string;
  key1: string;
  key2: string;
  keyGroup: string;
  insertionOffset: number;
  board: VicCheckerboard;
}

// VIC 序列化：按 key 升序（并列按位置从左到右）给每个位置发 1..n 的序号；数字序列化时
// 0 视作最大（排序键 10），序号 10 在 10 位行里按惯例记作 0。
const vicSequenceRank = (keys: number[]): number[] => {
  const order = keys.map((key, index) => ({ key, index }))
    .sort((left, right) => left.key - right.key || left.index - right.index);
  const rank = new Array<number>(keys.length).fill(0);
  order.forEach((item, position) => { rank[item.index] = position + 1; });
  return rank;
};

const vicDigitRank = (digits: number[]): number[] => vicSequenceRank(digits.map(digit => (digit === 0 ? 10 : digit)));

// 10 字母半的序列行：序号 1..9、0（第 10 个）。
const vicLetterSequenceRow = (letters: string): number[] =>
  vicSequenceRank(Array.from(letters, char => char.charCodeAt(0))).map(value => (value === 10 ? 0 : value));

// 链式加法（lagged Fibonacci）：不断把当前序列首两位之和（mod 10）追加到尾部。
const vicChainAdd = (seed: number[], targetLength: number): number[] => {
  const digits = [...seed];
  for (let index = 0; digits.length < targetLength; index += 1) {
    digits.push((digits[index] + digits[index + 1]) % 10);
  }
  return digits;
};

const vicAddMod10 = (left: number[], right: number[]): number[] => left.map((digit, index) => (digit + right[index]) % 10);
const vicSubMod10 = (left: number[], right: number[]): number[] => left.map((digit, index) => (((digit - right[index]) % 10) + 10) % 10);

// 按序列行编码：值 v（1-9，0 表示第 10 个）→ codeRow 的第 v 个元素（Savard「1→第 1 个 … 0→第 10 个」）。
const vicEncodeBySequenceRow = (values: number[], codeRow: number[]): number[] =>
  values.map(value => codeRow[value === 0 ? 9 : value - 1]);

// 跨行棋盘：表头 10 位（块末行的序列化）；固定第 3、7 列留空作跨行位（记忆串 AT ONE SIR 的
// 词界），第一行放 8 个高频字母 A T O N E S I R，其余 20 个符号（B-Z 去高频 + . /）按
// Savard 英文示例的行序填满第二、三行，行前缀即两个跨行位数字。
const VIC_ROW1_LETTERS = 'ATONESIR';
const VIC_ROW23_SYMBOLS = 'BCDFGHJKLMPQUVWXYZ./';

const vicBuildCheckerboard = (headerDigits: number[]): VicCheckerboard => {
  const encodeMap = new Map<string, string>();
  const decodeMap = new Map<string, string>();
  const blanks = [2, 6];
  let row1Index = 0;
  for (let column = 0; column < 10; column += 1) {
    if (blanks.includes(column)) continue;
    const letter = VIC_ROW1_LETTERS[row1Index];
    row1Index += 1;
    const code = String(headerDigits[column]);
    encodeMap.set(letter, code);
    decodeMap.set(code, letter);
  }
  const straddleDigits = [String(headerDigits[blanks[0]]), String(headerDigits[blanks[1]])];
  VIC_ROW23_SYMBOLS.split('').forEach((symbol, index) => {
    const code = `${straddleDigits[index < 10 ? 0 : 1]}${headerDigits[index % 10]}`;
    encodeMap.set(symbol, code);
    decodeMap.set(code, symbol);
  });
  return {
    encodeMap,
    decodeMap,
    straddleSet: new Set(straddleDigits),
    slashCode: encodeMap.get('/') ?? '',
    dotCode: encodeMap.get('.') ?? '',
  };
};

export const vicDeriveKeys = (phrase: string, dateValue: string, personalNumberValue: string, keyGroupValue: string): VicKeyMaterial => {
  const letters = phrase.toUpperCase().replace(/[^A-Z]/g, '');
  if (letters.length < 20) throw new Error(`VIC 关键短语需要至少 20 个字母（取前 20 个），实际 ${letters.length} 个`);
  const dateDigits = String(dateValue ?? '').replace(/\D/g, '');
  if (dateDigits.length < 6) throw new Error('VIC 日期需要至少 6 位数字（前 5 位参与减法，末位决定指示组插入位）');
  const personalText = String(personalNumberValue ?? '').trim();
  const personalNumber = Number.parseInt(personalText, 10);
  if (!/^\d$/.test(personalText) || personalNumber < 1 || personalNumber > 9) throw new Error(`VIC 个人号必须是 1-9 的单个数字，收到 ${JSON.stringify(personalText)}`);
  const keyGroupDigits = String(keyGroupValue ?? '').replace(/\D/g, '');
  if (keyGroupDigits.length !== 5) throw new Error(`VIC 密钥组必须是 5 位数字，实际 ${keyGroupDigits.length} 位`);

  const seqRow1 = vicLetterSequenceRow(letters.slice(0, 10));
  const seqRow2 = vicLetterSequenceRow(letters.slice(10, 20));
  const line1 = vicSubMod10(Array.from(keyGroupDigits, Number), Array.from(dateDigits.slice(0, 5), Number));
  const chain10 = vicChainAdd(line1, 10); // 链式加法扩到 10 位（整条即第二行）
  const messageKeyDigits = vicEncodeBySequenceRow(vicAddMod10(seqRow1, chain10), seqRow2);
  const block = vicChainAdd(messageKeyDigits, 60).slice(10); // 50 位伪随机块（5 行 × 10 位）
  const blockRows = [0, 10, 20, 30, 40].map(offset => block.slice(offset, offset + 10).join(''));
  const lastRowDigits = block.slice(40);
  const headerDigits = vicDigitRank(lastRowDigits).map(value => (value === 10 ? 0 : value));
  const board = vicBuildCheckerboard(headerDigits);
  // 末行最后两个不等数字 + 个人号 → 两个换位列宽（Kahn：width = personal number + d）
  const d2 = lastRowDigits[9];
  let d1 = d2;
  for (let index = 8; index >= 0; index -= 1) {
    if (lastRowDigits[index] !== d2) { d1 = lastRowDigits[index]; break; }
  }
  if (d1 === d2) throw new Error('VIC 数字块末行全为同一数字，无法导出换位宽度（概率约 10^-9，请更换日期/密钥组）');
  const width1 = personalNumber + d1;
  const width2 = personalNumber + d2;
  if (width1 < 2 || width2 < 2) throw new Error(`VIC 换位列宽至少为 2（个人号 + 末两位数字得到 ${width1}/${width2}），请更换密钥材料`);
  // 以消息密钥为列序把块按列读出，取前 width1+width2 位作两把换位密钥
  const readOrder = vicDigitRank(messageKeyDigits)
    .map((value, index) => ({ value, index }))
    .sort((left, right) => left.value - right.value)
    .map(item => item.index);
  let readOut = '';
  for (const column of readOrder) {
    for (let row = 0; row < 5; row += 1) readOut += String(block[row * 10 + column]);
  }
  return {
    line1: line1.join(''),
    chain10: chain10.join(''),
    messageKey: messageKeyDigits.join(''),
    blockRows,
    lastRow: lastRowDigits.join(''),
    header: headerDigits.join(''),
    straddleDigits: [...board.straddleSet],
    width1,
    width2,
    readOut,
    key1: readOut.slice(0, width1),
    key2: readOut.slice(width1, width1 + width2),
    keyGroup: keyGroupDigits,
    insertionOffset: Number(dateDigits[dateDigits.length - 1]),
    board,
  };
};

interface VicTransposePlan {
  rows: number;
  width: number;
  lastRowCells: number;
  readOrder: number[];
  triangle: boolean[][];
}

// 换位网格计划：消息按行写入（末行可短），列按密钥序列号 1..n（0 最后）读出。
// disrupted 版按列序号依次放三角扰乱区：三角 k 从「第 k 个被读的列」的顶行开始、
// 每下行一行左边界右移一列，直到缩到最后一列；下一个三角与前一个之间隔一整行
// （Savard「after one space」，与其算例网格行宽 14/15/16/17/5/6/7/8/9 逐位吻合）。
const vicTransposePlan = (length: number, keyDigits: number[], disrupted: boolean): VicTransposePlan => {
  const width = keyDigits.length;
  if (width < 2) throw new Error('VIC 换位列宽至少为 2');
  const rows = Math.max(1, Math.ceil(length / width));
  const lastRowCells = length - (rows - 1) * width;
  const rowLimit = (row: number) => (row === rows - 1 ? lastRowCells : width);
  const readOrder = vicDigitRank(keyDigits)
    .map((value, index) => ({ value, index }))
    .sort((left, right) => left.value - right.value)
    .map(item => item.index);
  const triangle = Array.from({ length: rows }, () => Array<boolean>(width).fill(false));
  if (disrupted) {
    let startRow = 0;
    for (const column of readOrder) {
      const height = width - column;
      for (let step = 0; startRow + step < rows && step < height; step += 1) {
        for (let cell = column + step; cell < rowLimit(startRow + step); cell += 1) {
          triangle[startRow + step][cell] = true;
        }
      }
      startRow += height + 1;
    }
  }
  return { rows, width, lastRowCells, readOrder, triangle };
};

const vicTransposeForward = (digits: string, plan: VicTransposePlan): string => {
  const { rows, width, lastRowCells, readOrder, triangle } = plan;
  const rowLimit = (row: number) => (row === rows - 1 ? lastRowCells : width);
  const grid = Array.from({ length: rows }, (_, row) => Array<string>(rowLimit(row)).fill(''));
  const plainCells: Array<{ row: number; col: number }> = [];
  const triangleCells: Array<{ row: number; col: number }> = [];
  for (let row = 0; row < rows; row += 1) {
    for (let col = 0; col < rowLimit(row); col += 1) {
      (triangle[row][col] ? triangleCells : plainCells).push({ row, col });
    }
  }
  const ordered = [...plainCells, ...triangleCells];
  if (ordered.length !== digits.length) throw new Error(`VIC 换位网格容量 ${ordered.length} 与数字消息长度 ${digits.length} 不一致`);
  ordered.forEach((cell, index) => { grid[cell.row][cell.col] = digits[index]; });
  let output = '';
  for (const column of readOrder) {
    for (let row = 0; row < rows; row += 1) {
      if (column < rowLimit(row)) output += grid[row][column];
    }
  }
  return output;
};

const vicTransposeBackward = (digits: string, plan: VicTransposePlan): string => {
  const { rows, width, lastRowCells, readOrder, triangle } = plan;
  const rowLimit = (row: number) => (row === rows - 1 ? lastRowCells : width);
  const grid = Array.from({ length: rows }, (_, row) => Array<string>(rowLimit(row)).fill(''));
  let offset = 0;
  for (const column of readOrder) {
    for (let row = 0; row < rows; row += 1) {
      if (column < rowLimit(row)) {
        grid[row][column] = digits[offset];
        offset += 1;
      }
    }
  }
  let output = '';
  for (let pass = 0; pass < 2; pass += 1) {
    for (let row = 0; row < rows; row += 1) {
      for (let col = 0; col < rowLimit(row); col += 1) {
        if (triangle[row][col] === (pass === 1)) output += grid[row][col];
      }
    }
  }
  return output;
};

// 棋盘数字化：字母查表；连续数字段 = 数字移位符「/」+ 每位三连 + 句点「.」回移
//（Wikipedia 同款约定：0500 → / 000 555 000 000 .）；其余字符（空格、标点）剔除。
const vicNumericEncode = (message: string, board: VicCheckerboard): string => {
  const cleaned = message.toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (!cleaned) throw new Error('VIC 加密需要可编码的明文（字母与数字）');
  let output = '';
  for (let index = 0; index < cleaned.length;) {
    if (/[0-9]/.test(cleaned[index])) {
      let run = '';
      while (index < cleaned.length && /[0-9]/.test(cleaned[index])) {
        run += cleaned[index] + cleaned[index] + cleaned[index];
        index += 1;
      }
      output += board.slashCode + run + board.dotCode;
      continue;
    }
    const code = board.encodeMap.get(cleaned[index]);
    if (code === undefined) throw new Error(`VIC 内部错误：字符 ${cleaned[index]} 不在棋盘上`);
    output += code;
    index += 1;
  }
  return output;
};

// 贪心解析（跨行位数字必开两位码，其余一位码——棋盘构造保证两者不重叠）。
// 返回 null 表示解析不完整/失败；数字模式中的「.」码是回移控制符，不产出字符。
const vicTokenize = (numeric: string, board: VicCheckerboard): string[] | null => {
  const tokens: string[] = [];
  let index = 0;
  let inDigits = false;
  while (index < numeric.length) {
    if (inDigits) {
      if (numeric.startsWith(board.dotCode, index)) {
        inDigits = false;
        index += board.dotCode.length;
        continue;
      }
      const triplet = numeric.slice(index, index + 3);
      if (triplet.length < 3 || triplet[0] !== triplet[1] || triplet[1] !== triplet[2]) return null;
      tokens.push(triplet[0]);
      index += 3;
      continue;
    }
    const digit = numeric[index];
    if (board.straddleSet.has(digit)) {
      const symbol = board.decodeMap.get(numeric.slice(index, index + 2));
      if (symbol === undefined) return null;
      if (symbol === '/') inDigits = true;
      else tokens.push(symbol);
      index += 2;
      continue;
    }
    const letter = board.decodeMap.get(digit);
    if (letter === undefined) return null;
    tokens.push(letter);
    index += 1;
  }
  return inDigits ? null : tokens;
};

const vicNumericDecode = (numeric: string, board: VicCheckerboard): string => {
  // 空位已由 vicTransform 解密侧恒裁一位（协议恒补一位），这里只做贪心解析。
  const tokens = vicTokenize(numeric, board);
  if (tokens === null) throw new Error('VIC 数字消息解析失败：请确认密钥材料与密文一致');
  return tokens.join('');
};

// VIC 加解密入口：encode 输出 5 位分组、每行 10 组的密文（指示组已插入）；
// decode 接受任意空白分组的数字密文，自动按日期末位剥指示组并校验。
export const vicTransform = (value: string, phrase: string, dateValue: string, personalNumberValue: string, keyGroupValue: string, decode = false): string => {
  const material = vicDeriveKeys(phrase, dateValue, personalNumberValue, keyGroupValue);
  if (!decode) {
    // Kahn 空位数字：恒补恰好一位（算例中 Savard 补的是 9，本实现固定补 9 以复现公开密文；
    // 空位值在规程里由报务员任选，补一位是协议的一部分，与凑不凑得齐 5 的倍数无关）。
    const numeric = `${vicNumericEncode(value, material.board)}9`;
    const plan1 = vicTransposePlan(numeric.length, Array.from(material.key1, Number), false);
    const afterFirst = vicTransposeForward(numeric, plan1);
    const plan2 = vicTransposePlan(afterFirst.length, Array.from(material.key2, Number), true);
    const cipher = vicTransposeForward(afterFirst, plan2);
    const groups = cipher.match(/.{1,5}/g) ?? [];
    // 指示组插到「倒数第 P 组」（P = 日期末位；插入后它距末尾恰 P 组，末组可短于 5 位）；
    // P=0 视作追加在末尾，组数不足时插到开头。
    const insertAt = material.insertionOffset === 0
      ? groups.length
      : Math.max(0, groups.length + 1 - material.insertionOffset);
    groups.splice(insertAt, 0, material.keyGroup);
    const lines: string[] = [];
    for (let index = 0; index < groups.length; index += 10) lines.push(groups.slice(index, index + 10).join(' '));
    return lines.join('\n');
  }
  const digits = value.replace(/\D/g, '');
  if (!digits) throw new Error('VIC 解密需要数字密文（5 位分组，指示组已按日期末位插入）');
  const groups = digits.match(/.{1,5}/g) ?? [];
  const removeAt = material.insertionOffset === 0 ? groups.length - 1 : groups.length - material.insertionOffset;
  if (removeAt < 0 || removeAt >= groups.length) throw new Error(`VIC 密文组数不足以按日期末位剥指示组（需要倒数第 ${material.insertionOffset} 组）`);
  if (groups[removeAt] !== material.keyGroup) {
    throw new Error(`VIC 指示组不匹配：倒数第 ${material.insertionOffset} 组应为 ${material.keyGroup}，实际 ${groups[removeAt]}（请核对密钥组/日期）`);
  }
  const cipher = groups.filter((_, index) => index !== removeAt).join('');
  const plan2 = vicTransposePlan(cipher.length, Array.from(material.key2, Number), true);
  const afterFirst = vicTransposeBackward(cipher, plan2);
  const plan1 = vicTransposePlan(afterFirst.length, Array.from(material.key1, Number), false);
  // 逆标准列换位还原数字消息；Kahn 空位是协议的一部分（恒补一位），解密恒裁掉末位一位。
  const numeric = vicTransposeBackward(afterFirst, plan1).slice(0, -1);
  return vicNumericDecode(numeric, material.board);
};
