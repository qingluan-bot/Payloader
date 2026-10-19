// RAR4 条目解压器（真题缺口：SimpleRAR/进制反转修复头后需要解出条目内容）：
// 与 rarInspect（只读依赖，绝不改动）配套，单条目解出——METHOD 0x30 存储直取；
// 0x31-0x35 走 RAR3（UNP_VER=29）Huffman-LZ 解压。LZ 语义按 unrar unpack30.cpp 的
// 算法结构自写（其许可特殊，禁止逐行翻译），并与 libarchive
// archive_read_support_format_rar.c（BSD-2-Clause）逐条交叉核对：
// 位流 MSB-first；canonical Huffman（码长 1-15，16 位左对齐上限码比较）；表头 2 位
// 标志（PPM 块/沿用旧表）+ 20 个 4 位预表长（0xF 转义零串）+ 404 项主表（值相对上
// 一张表 4 位增量，16/17 重复前值、18/19 零串）；LD 字号 0-255 字面量/256 块结束/
// 257 VM 过滤器/258 复用上次匹配/259-262 老距离/263-270 短距离/271-298 完整匹配；
// 距离槽位表/长度槽位表/低位距离表（LDD，16 为重复哨兵）与两参考一致。
// VM 预处理过滤器（symbol 257）：按 unrar ReadVMCode/AddVMCode 解析过滤器参数与 VM 程序，
// 程序经 XOR 校验和 + 整段 CRC32 识别为标准过滤器后等价直实现 delta/E8/E8E9
// （unrar rarvm.cpp StdList + ExecuteStandardFilter 语义）；非标准程序如实返回 unsupported。
// 单文件顺序解码下过滤器在线性输出坐标上于解码完成后依创建序应用（与 unrar 写出时应用、
// 窗口保留原数据供匹配引用的语义等价；标准过滤器尺寸不变，块坐标账目一致）。
// 范围决策：流内 PPM 块如实返回 unsupported（CTF 文本/flag 文件不用它），
// 旧版 RAR（UNP_VER 15/20/26）压缩流不支持；存储路径不受版本限制。
// 红线：输入只读（输出一律新副本）；解压输出上限 64MB、Huffman 解码步数上限 2^27
// （炸弹流防护，超限抛中文错误）；解压距离不得越过已解码数据（solid 档案或损坏即抛错）；
// 解压后按文件头 FILE_CRC 做 CRC32 校验（头值为 0 时跳过——目录/空文件天然为 0）。

import { RAR4_SIGNATURE, type RarEntry } from './rarInspect';

export interface RarExtractResult {
  name: string;
  bytes: Uint8Array | null;
  method: number;
  unsupported?: string;
}

// 内存与时间预算：超过即抛错（RAR 炸弹防护），测试引用同款常量。
export const RAR_EXTRACT_MAX_OUTPUT = 64 * 1024 * 1024;
export const RAR_EXTRACT_MAX_STEPS = 2 ** 27;

// RAR3（UNP_VER=29）Huffman 表规模（unrar compress.hpp PackDef 口径，两参考一致）。
const NC30 = 299; // LD：字面量 + 长度槽位
const DC30 = 60; // DD：距离槽位
const LDC30 = 17; // LDD：长距离的低位 4 比特（0-15，16=重复哨兵）
const RC30 = 28; // RD：老距离匹配的长度槽位
const BC30 = 20; // 预表（表长编码）字母表
const HUFF_TABLE_SIZE30 = NC30 + DC30 + LDC30 + RC30; // 404
const LOW_DIST_REP_COUNT = 16;

const L_DECODE = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224];
const L_BITS = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5];
const D_DECODE = [
  0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072,
  4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608, 262144, 327680,
  393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040, 1048576, 1310720,
  1572864, 1835008, 2097152, 2359296, 2621440, 2883584, 3145728, 3407872, 3670016, 3932160,
];
const D_BITS = [
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
  14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 18, 18, 18, 18, 18, 18,
  18, 18, 18, 18, 18, 18,
];
const SD_DECODE = [0, 4, 8, 16, 32, 64, 128, 192];
const SD_BITS = [2, 2, 3, 4, 5, 6, 6, 6];

const u16le = (bytes: Uint8Array, offset: number): number => bytes[offset] | (bytes[offset + 1] << 8);

const u32le = (bytes: Uint8Array, offset: number): number =>
  (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;

// 标准 CRC32（多项式 0xEDB88320）——RAR4 FILE_CRC 即解压后数据的 CRC32 低 32 位。
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

const crc32 = (data: Uint8Array): number => {
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i += 1) c = CRC_TABLE[(c ^ data[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};

// canonical Huffman 解码表（与 unrar MakeDecodeTables 等价的自写实现）：
// decodeLen[L] 为码长 L 的左对齐（16 位）上限码，decodePos[L] 为该码长在码表中的起点。
interface HuffTable {
  decodeLen: Uint32Array;
  decodePos: Uint32Array;
  decodeNum: Uint16Array;
  maxNum: number;
}

const buildHuffTable = (lengths: ArrayLike<number>, size: number): HuffTable => {
  const counts = new Uint32Array(16);
  for (let i = 0; i < size; i += 1) counts[lengths[i] & 0xf] += 1;
  counts[0] = 0;
  const decodeLen = new Uint32Array(16);
  const decodePos = new Uint32Array(16);
  const decodeNum = new Uint16Array(size);
  let upper = 0;
  for (let len = 1; len < 16; len += 1) {
    upper += counts[len];
    decodeLen[len] = (upper << (16 - len)) >>> 0;
    upper *= 2;
    decodePos[len] = decodePos[len - 1] + counts[len - 1];
  }
  const cursor = Uint32Array.from(decodePos);
  for (let i = 0; i < size; i += 1) {
    const len = lengths[i] & 0xf;
    if (len !== 0) {
      decodeNum[cursor[len]] = i;
      cursor[len] += 1;
    }
  }
  return { decodeLen, decodePos, decodeNum, maxNum: size };
};

type LzOutcome = { kind: 'ok'; bytes: Uint8Array } | { kind: 'unsupported'; reason: string };

// ---- RAR3 VM 预处理过滤器（symbol 257）：unrar ReadVMCode/AddVMCode/rarvm.cpp 语义等价直实现 ----
// VM 程序经首字节 XOR 校验和 + 整段 CRC32 识别为标准过滤器（rarvm.cpp StdList 同源）后按
// ExecuteStandardFilter 直写执行，六个标准程序全覆盖（音频 wav 常用 AUDIO、exe 常用 E8/E8E9、
// 图像 RGB、arm64 代码 ITANIUM、多声道差分 DELTA）；非标准程序如实返回 unsupported。
type VmStandardType = 'E8' | 'E8E9' | 'DELTA' | 'ITANIUM' | 'RGB' | 'AUDIO';
const VM_STANDARD_FILTERS: ReadonlyArray<{ length: number; crc: number; type: VmStandardType }> = [
  { length: 53, crc: 0xad576887, type: 'E8' },
  { length: 57, crc: 0x3cd7e57e, type: 'E8E9' },
  { length: 120, crc: 0x3769893f, type: 'ITANIUM' },
  { length: 29, crc: 0x0e06077d, type: 'DELTA' },
  { length: 149, crc: 0x1c2c5dc8, type: 'RGB' },
  { length: 216, crc: 0xbc85e701, type: 'AUDIO' },
];
// unrar unpack.hpp：VM 内存 256B KB（VM_MEMSIZE=0x40000）与通道上限
const VM_MEMSIZE = 0x40000;
const VM_MAX3_CHANNELS = 1024;
const VM_MAX3_FILTERS = 8192;

interface VmPendingFilter {
  parentFilter: number;
  type: VmStandardType;
  // 块区间（线性输出绝对坐标；创建时 = 当前解码长度 + ReadData(BlockStart)，bit0x40 时 +258）
  blockStart: number;
  blockLength: number;
  initR: Uint32Array;
}

// ITANIUM 过滤器的位读写（rarvm.cpp FilterItanium_GetBits/SetBits 同语义，base 为当前 16 字节指令束起点）
const itaniumGetBits = (data: Uint8Array, base: number, bitPos: number, bitCount: number): number => {
  const addr = base + (bitPos >> 3);
  const inBit = bitPos & 7;
  let bitField = data[addr];
  bitField = (bitField | (data[addr + 1] << 8) | (data[addr + 2] << 16) | (data[addr + 3] << 24)) >>> 0;
  return (bitField >>> inBit) & (0xffffffff >>> (32 - bitCount));
};

const itaniumSetBits = (data: Uint8Array, base: number, value: number, bitPos: number, bitCount: number): void => {
  const addr = base + (bitPos >> 3);
  const inBit = bitPos & 7;
  let andMask = ((0xffffffff >>> (32 - bitCount)) << inBit) >>> 0;
  andMask = (~andMask) >>> 0;
  let bitField = (value << inBit) >>> 0;
  for (let i = 0; i < 4; i += 1) {
    data[addr + i] = (data[addr + i] & (andMask & 0xff)) | (bitField & 0xff);
    andMask = ((andMask >>> 8) | 0xff000000) >>> 0;
    bitField = bitField >>> 8;
  }
};

// RAR3（UNP_VER=29）LZ 解压：packed 为该条目数据区（UNP_VER/预算已由调用方校验）。
const unpackRar3 = (packed: Uint8Array, unpSize: number): LzOutcome => {
  const limit = packed.length;
  let inAddr = 0;
  let inBit = 0;
  let steps = 0;

  // MSB-first 位读取：越界字节按 0 补齐（与 unrar BitInput::getbits 的 24 位窗口一致）。
  const peek16 = (): number => {
    const b0 = inAddr < limit ? packed[inAddr] : 0;
    const b1 = inAddr + 1 < limit ? packed[inAddr + 1] : 0;
    const b2 = inAddr + 2 < limit ? packed[inAddr + 2] : 0;
    return ((((b0 << 16) | (b1 << 8) | b2) >>> (8 - inBit)) & 0xffff) >>> 0;
  };
  const skip = (bits: number): void => {
    const total = bits + inBit;
    inAddr += total >> 3;
    inBit = total & 7;
  };
  const readBits = (bits: number): number => {
    if (bits === 0) return 0;
    const value = peek16() >>> (16 - bits);
    skip(bits);
    return value;
  };

  const decode = (table: HuffTable): number => {
    steps += 1;
    if (steps > RAR_EXTRACT_MAX_STEPS) {
      throw new Error(`解压步数超出预算上限 ${RAR_EXTRACT_MAX_STEPS}（RAR 炸弹流防护），条目已中止`);
    }
    const bitField = peek16() & 0xfffe;
    let bits = 15;
    for (let len = 1; len < 15; len += 1) {
      if (bitField < table.decodeLen[len]) {
        bits = len;
        break;
      }
    }
    skip(bits);
    const dist = (bitField - table.decodeLen[bits - 1]) >>> (16 - bits);
    const pos = table.decodePos[bits] + dist;
    if (pos >= table.maxNum) {
      throw new Error(`RAR LZ 流损坏：Huffman 解码越界（码长 ${bits}，位置 ${pos} ≥ ${table.maxNum}）`);
    }
    return table.decodeNum[pos];
  };

  let oldTable = new Uint8Array(HUFF_TABLE_SIZE30);
  // 先建空表占位（首次 readTables 之前不会解码，且空表解码会在越界检查处抛错）。
  let ld: HuffTable = buildHuffTable(oldTable.subarray(0, NC30), NC30);
  let dd: HuffTable = buildHuffTable(oldTable.subarray(NC30, NC30 + DC30), DC30);
  let ldd: HuffTable = buildHuffTable(oldTable.subarray(NC30 + DC30, NC30 + DC30 + LDC30), LDC30);
  let rd: HuffTable = buildHuffTable(oldTable.subarray(NC30 + DC30 + LDC30), RC30);
  let prevLowDist = 0;
  let lowDistRepCount = 0;

  const readTables = (): LzOutcome | null => {
    skip((8 - inBit) & 7); // 表头恒按字节对齐
    const bitField = peek16();
    if ((bitField & 0x8000) !== 0) {
      return { kind: 'unsupported', reason: 'PPMd 压缩流（RAR3 -m5 best 常见形态）：本引擎不支持' };
    }
    const keepOld = (bitField & 0x4000) !== 0;
    skip(2);
    prevLowDist = 0;
    lowDistRepCount = 0;
    if (!keepOld) oldTable.fill(0);

    const bitLength = new Uint8Array(BC30);
    let i = 0;
    while (i < BC30) {
      const length = readBits(4);
      if (length !== 15) {
        bitLength[i] = length;
        i += 1;
        continue;
      }
      const zeroCount = readBits(4);
      if (zeroCount === 0) {
        bitLength[i] = 15; // 转义后的字面 15
        i += 1;
      } else {
        for (let k = 0; k < zeroCount + 2 && i < BC30; k += 1) {
          bitLength[i] = 0;
          i += 1;
        }
      }
    }
    const bd = buildHuffTable(bitLength, BC30);

    const table = new Uint8Array(HUFF_TABLE_SIZE30);
    i = 0;
    while (i < HUFF_TABLE_SIZE30) {
      const symbol = decode(bd);
      if (symbol < 16) {
        table[i] = (symbol + oldTable[i]) & 0xf; // 相对上一张表的 4 位增量
        i += 1;
      } else if (symbol < 18) {
        const count = symbol === 16 ? readBits(3) + 3 : readBits(7) + 11;
        if (i === 0) throw new Error('RAR LZ 流损坏：表首部出现重复前值码（16/17）');
        for (let k = 0; k < count && i < HUFF_TABLE_SIZE30; k += 1) {
          table[i] = table[i - 1];
          i += 1;
        }
      } else {
        const count = symbol === 18 ? readBits(3) + 3 : readBits(7) + 11;
        for (let k = 0; k < count && i < HUFF_TABLE_SIZE30; k += 1) {
          table[i] = 0;
          i += 1;
        }
      }
    }
    oldTable = table;
    ld = buildHuffTable(table.subarray(0, NC30), NC30);
    dd = buildHuffTable(table.subarray(NC30, NC30 + DC30), DC30);
    ldd = buildHuffTable(table.subarray(NC30 + DC30, NC30 + DC30 + LDC30), LDC30);
    rd = buildHuffTable(table.subarray(NC30 + DC30 + LDC30), RC30);
    return null;
  };

  const out = new Uint8Array(unpSize);
  let outLen = 0;
  let lastLength = 0;
  const oldDist = [0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff];

  // ---- RAR3 VM 过滤器状态（unrar InitFilters30 口径，单条目解码天然逐条目重置）----
  const vmFilters: VmStandardType[] = [];
  const vmOldFilterLengths: number[] = [];
  let vmLastFilter = 0;
  const vmStack: VmPendingFilter[] = [];

  // symbol 257 处理：ReadVMCode + AddVMCode（unrar unpack30.cpp 语义）。
  // 解出 FirstByte/Length/VM 程序与过滤器参数（块起点/块长/可选寄存器），标准过滤器
  // （delta/E8/E8E9）压入待应用栈；返回 null 表示已入栈可继续解码。
  const readVmCode = (): LzOutcome | null => {
    const firstByte = readBits(8);
    let codeLength = (firstByte & 7) + 1;
    if (codeLength === 7) codeLength = readBits(8) + 7;
    else if (codeLength === 8) codeLength = readBits(16);
    if (codeLength === 0) return { kind: 'unsupported', reason: 'RAR3 VM 过滤器代码长度为 0（流损坏）：无法继续' };
    const code = new Uint8Array(codeLength);
    for (let k = 0; k < codeLength; k += 1) code[k] = readBits(8);

    // AddVMCode 的 VMCodeInp 位读取器（挂在 code 上，语义同主位流：MSB-first、越界补 0）
    let cAddr = 0;
    let cBit = 0;
    const cLimit = code.length;
    const cPeek16 = (): number => {
      const b0 = cAddr < cLimit ? code[cAddr] : 0;
      const b1 = cAddr + 1 < cLimit ? code[cAddr + 1] : 0;
      const b2 = cAddr + 2 < cLimit ? code[cAddr + 2] : 0;
      return ((((b0 << 16) | (b1 << 8) | b2) >>> (8 - cBit)) & 0xffff) >>> 0;
    };
    const cSkip = (bits: number): void => {
      const total = bits + cBit;
      cAddr += total >> 3;
      cBit = total & 7;
    };
    const cReadBits = (bits: number): number => {
      if (bits === 0) return 0;
      const value = cPeek16() >>> (16 - bits);
      cSkip(bits);
      return value;
    };
    // RarVM::ReadData：6/10/14/18/34 位变长编码
    const vmReadData = (): number => {
      const data = cPeek16();
      switch (data & 0xc000) {
        case 0x0000:
          cSkip(6);
          return (data >>> 10) & 0xf;
        case 0x4000:
          if ((data & 0x3c00) === 0) {
            cSkip(14);
            return (0xffffff00 | ((data >>> 2) & 0xff)) >>> 0;
          }
          cSkip(10);
          return (data >>> 6) & 0xff;
        case 0x8000:
          cSkip(2);
          return cReadBits(16);
        default:
          cSkip(2);
          return ((cReadBits(16) << 16) | cReadBits(16)) >>> 0;
      }
    };

    let filtPos: number;
    if ((firstByte & 0x80) !== 0) {
      filtPos = vmReadData();
      if (filtPos === 0) {
        vmFilters.length = 0;
        vmOldFilterLengths.length = 0;
        vmLastFilter = 0;
      } else {
        filtPos -= 1;
      }
    } else {
      filtPos = vmLastFilter;
    }
    if (filtPos > vmFilters.length || filtPos > vmOldFilterLengths.length) {
      return { kind: 'unsupported', reason: `RAR3 VM 过滤器编号越界（${filtPos}）：流损坏` };
    }
    vmLastFilter = filtPos;
    // 读序严格按 unrar AddVMCode：BlockStart → BlockLength → 可选 InitR → （新过滤器时）VM 程序
    let blockStart = vmReadData();
    if ((firstByte & 0x40) !== 0) blockStart += 258;
    let blockLength: number;
    if ((firstByte & 0x20) !== 0) {
      blockLength = vmReadData();
      vmOldFilterLengths[filtPos] = blockLength;
    } else {
      blockLength = filtPos < vmOldFilterLengths.length ? vmOldFilterLengths[filtPos] : 0;
    }
    const initR = new Uint32Array(7);
    initR[4] = blockLength;
    if ((firstByte & 0x10) !== 0) {
      const initMask = cReadBits(7);
      for (let k = 0; k < 7; k += 1) {
        if ((initMask & (1 << k)) !== 0) initR[k] = vmReadData();
      }
    }
    let type: VmStandardType;
    if (filtPos === vmFilters.length) {
      if (filtPos > VM_MAX3_FILTERS) return { kind: 'unsupported', reason: 'RAR3 VM 过滤器数量超出上限：流损坏' };
      const vmCodeSize = vmReadData();
      if (vmCodeSize >= 0x10000 || vmCodeSize === 0 || cAddr + vmCodeSize > cLimit) {
        return { kind: 'unsupported', reason: 'RAR3 VM 程序长度非法：流损坏' };
      }
      const prog = new Uint8Array(vmCodeSize);
      for (let k = 0; k < vmCodeSize; k += 1) prog[k] = cReadBits(8);
      // rarvm.cpp Prepare：首字节为其余字节的 XOR 校验和，整段 CRC32 对表识别标准程序
      let xorSum = 0;
      for (let k = 1; k < vmCodeSize; k += 1) xorSum ^= prog[k];
      if (xorSum !== prog[0]) {
        return { kind: 'unsupported', reason: 'RAR3 VM 程序 XOR 校验失败：流损坏或非标准程序' };
      }
      const standard = VM_STANDARD_FILTERS.find(item => item.length === vmCodeSize && item.crc === crc32(prog));
      if (!standard) {
        return { kind: 'unsupported', reason: 'RAR3 VM 非标准过滤器程序（本引擎仅内置 delta/E8/E8E9 等价直实现；ITANIUM/RGB/AUDIO 与自定义 VM 程序不支持）' };
      }
      type = standard.type;
      vmFilters.push(type);
      vmOldFilterLengths.push(0);
    } else {
      type = vmFilters[filtPos];
    }
    // 线性输出坐标：块绝对起点 = 当前解码长度 + 块起点（单文件顺序解码与 unrar 写出序一致）
    vmStack.push({ parentFilter: filtPos, type, blockStart: outLen + blockStart, blockLength, initR });
    return null;
  };

  const insertOldDist = (distance: number): void => {
    oldDist[3] = oldDist[2];
    oldDist[2] = oldDist[1];
    oldDist[1] = oldDist[0];
    oldDist[0] = distance;
  };

  // 非压缩流（单文件条目）距离只能指向已解码区：越过即 solid 档案或损坏，抛错。
  const copyString = (length: number, distance: number): void => {
    if (distance > outLen) {
      throw new Error(`RAR LZ 流损坏：解压距离 ${distance} 越过已解码的 ${outLen} 字节（solid 档案跨文件引用或数据损坏）`);
    }
    let capped = length;
    if (capped > unpSize - outLen) capped = unpSize - outLen;
    const src = outLen - distance;
    for (let k = 0; k < capped; k += 1) out[outLen + k] = out[src + k];
    outLen += capped;
  };

  const first = readTables();
  if (first !== null) return first;

  while (outLen < unpSize) {
    if (inAddr >= limit) break; // 输入耗尽
    const symbol = decode(ld);

    if (symbol < 256) {
      out[outLen] = symbol;
      outLen += 1;
      continue;
    }
    if (symbol >= 271) {
      let length = L_DECODE[symbol - 271] + 3;
      const lBits = L_BITS[symbol - 271];
      if (lBits > 0) length += readBits(lBits);

      const distSymbol = decode(dd);
      let distance = D_DECODE[distSymbol] + 1;
      const dBits = D_BITS[distSymbol];
      if (dBits > 0) {
        if (distSymbol > 9) {
          if (dBits > 4) distance += readBits(dBits - 4) << 4;
          if (lowDistRepCount > 0) {
            lowDistRepCount -= 1;
            distance += prevLowDist;
          } else {
            const low = decode(ldd);
            if (low === 16) {
              lowDistRepCount = LOW_DIST_REP_COUNT - 1;
              distance += prevLowDist;
            } else {
              distance += low;
              prevLowDist = low;
            }
          }
        } else {
          distance += readBits(dBits);
        }
      }
      if (distance >= 0x2000) length += 1;
      if (distance >= 0x40000) length += 1;
      insertOldDist(distance);
      lastLength = length;
      copyString(length, distance);
      continue;
    }
    if (symbol === 256) {
      const bitField = peek16();
      if ((bitField & 0x8000) !== 0) {
        skip(1); // "1"：本文件内紧跟新表
        const next = readTables();
        if (next !== null) return next;
        continue;
      }
      skip(2); // "00"/"01"：本文件数据结束（第二位是下一文件的表标志，与本文件无关）
      break;
    }
    if (symbol === 257) {
      const vmOutcome = readVmCode();
      if (vmOutcome !== null) return vmOutcome;
      continue;
    }
    if (symbol === 258) {
      if (lastLength !== 0) copyString(lastLength, oldDist[0]);
      continue;
    }
    if (symbol < 263) {
      const distNum = symbol - 259;
      const distance = oldDist[distNum];
      for (let k = distNum; k > 0; k -= 1) oldDist[k] = oldDist[k - 1];
      oldDist[0] = distance;
      const lenSymbol = decode(rd);
      let length = L_DECODE[lenSymbol] + 2;
      const lBits = L_BITS[lenSymbol];
      if (lBits > 0) length += readBits(lBits);
      lastLength = length;
      copyString(length, distance);
      continue;
    }
    const index = symbol - 263; // 263-270：短距离匹配，长度恒为 2
    let distance = SD_DECODE[index] + 1;
    const sBits = SD_BITS[index];
    if (sBits > 0) distance += readBits(sBits);
    insertOldDist(distance);
    lastLength = 2;
    copyString(2, distance);
  }

  if (outLen !== unpSize) {
    throw new Error(`RAR 数据截断：解出 ${outLen}/${unpSize} 字节（数据区不完整）`);
  }
  if (vmStack.length > 0) applyRar3VmFilters(out, vmStack);
  return { kind: 'ok', bytes: out };
};

// 应用挂起的 RAR3 VM 标准过滤器（unrar UnpWriteBuf30/Execute 语义在线性输出上的等价实现）：
// 执行时 R[4]=块长、R[6]=块绝对起点（已写出字节数）；标准过滤器均尺寸不变，直接在输出副本
// 对应区间原地变换（delta 先在 VM 内存后半重构交错，再取回写入）。参数越界时按 unrar
// ExecuteStandardFilter 返回失败的行为保留原始块数据。
const applyRar3VmFilters = (out: Uint8Array, stack: VmPendingFilter[]): void => {
  for (const filter of stack) {
    const start = filter.blockStart;
    const length = filter.blockLength;
    if (length <= 0 || start < 0 || start + length > out.length) continue;
    const block = out.subarray(start, start + length);
    const initR = filter.initR;
    if (filter.type === 'DELTA') {
      const channels = initR[0];
      if (length > VM_MEMSIZE / 2 || channels === 0 || channels > VM_MAX3_CHANNELS) continue;
      const mem = new Uint8Array(length * 2);
      mem.set(block, 0);
      let srcPos = 0;
      for (let channel = 0; channel < channels; channel += 1) {
        let prevByte = 0;
        for (let destPos = length + channel; destPos < length * 2; destPos += channels) {
          prevByte = (prevByte - mem[srcPos]) & 0xff;
          srcPos += 1;
          mem[destPos] = prevByte;
        }
      }
      out.set(mem.subarray(length, length * 2), start);
    } else if (filter.type === 'E8' || filter.type === 'E8E9') {
      // x86 CALL 指令相对地址 → 绝对地址转换（FileSize 常量 0x1000000 同 unrar）
      if (length > VM_MEMSIZE || length < 4) continue;
      const fileSize = 0x1000000;
      const cmpByte2 = filter.type === 'E8E9' ? 0xe9 : 0xe8;
      const fileOffset = start >>> 0;
      let pos = 0;
      let curPos = 0;
      while (curPos < length - 4) {
        const curByte = block[pos];
        pos += 1;
        curPos += 1;
        if (curByte !== 0xe8 && curByte !== cmpByte2) continue;
        const offset = (curPos + fileOffset) >>> 0;
        const addr = (block[pos] | (block[pos + 1] << 8) | (block[pos + 2] << 16) | (block[pos + 3] << 24)) >>> 0;
        let transformed = addr;
        if ((addr & 0x80000000) !== 0) {
          if (((addr + offset) & 0x80000000) === 0) transformed = (addr + fileSize) >>> 0;
        } else if (((addr - fileSize) & 0x80000000) !== 0) {
          transformed = (addr - offset) >>> 0;
        }
        block[pos] = transformed & 0xff;
        block[pos + 1] = (transformed >>> 8) & 0xff;
        block[pos + 2] = (transformed >>> 16) & 0xff;
        block[pos + 3] = (transformed >>> 24) & 0xff;
        pos += 4;
        curPos += 4;
      }
    } else if (filter.type === 'ITANIUM') {
      // Itanium (IA-64) 指令束内 20 位相对地址 → 绝对地址（FileOffset 按 16 字节指令束折算）
      if (length > VM_MEMSIZE || length < 21) continue;
      let fileOffset = start >>> 4;
      let pos = 0;
      let curPos = 0;
      while (curPos < length - 21) {
        const bundleType = (block[pos] & 0x1f) - 0x10;
        if (bundleType >= 0) {
          const cmdMasks = [4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0];
          const cmdMask = cmdMasks[bundleType];
          if (cmdMask !== 0) {
            for (let slot = 0; slot <= 2; slot += 1) {
              if ((cmdMask & (1 << slot)) !== 0) {
                const startPos = slot * 41 + 5;
                if (itaniumGetBits(block, pos, startPos + 37, 4) === 5) {
                  const offset = itaniumGetBits(block, pos, startPos + 13, 20);
                  itaniumSetBits(block, pos, (offset - fileOffset) & 0xfffff, startPos + 13, 20);
                }
              }
            }
          }
        }
        pos += 16;
        curPos += 16;
        fileOffset = (fileOffset + 1) >>> 0;
      }
    } else if (filter.type === 'RGB') {
      // 24 位图像逐字节预测（PrevByte/Upper/UpperLeft 三选一）+ R 通道增量还原
      const width = (initR[0] - 3) >>> 0;
      const posR = initR[1];
      if (length > VM_MEMSIZE / 2 || length < 3 || width > length || posR > 2) continue;
      const dest = new Uint8Array(length);
      let srcPos = 0;
      for (let channel = 0; channel < 3; channel += 1) {
        let prevByte = 0;
        for (let index = channel; index < length; index += 3) {
          let predicted;
          if (index >= width + 3) {
            const upperByte = dest[index - width];
            const upperLeftByte = dest[index - width - 3];
            predicted = (prevByte + upperByte - upperLeftByte) >>> 0;
            const pa = Math.abs((predicted - prevByte) | 0);
            const pb = Math.abs((predicted - upperByte) | 0);
            const pc = Math.abs((predicted - upperLeftByte) | 0);
            if (pa <= pb && pa <= pc) predicted = prevByte;
            else if (pb <= pc) predicted = upperByte;
            else predicted = upperLeftByte;
          } else {
            predicted = prevByte;
          }
          prevByte = dest[index] = (predicted - block[srcPos]) & 0xff;
          srcPos += 1;
        }
      }
      for (let index = posR, border = length - 2; index < border; index += 3) {
        const green = dest[index + 1];
        dest[index] = (dest[index] + green) & 0xff;
        dest[index + 2] = (dest[index + 2] + green) & 0xff;
      }
      out.set(dest, start);
    } else {
      // AUDIO：多声道自适应预测（K1/K2/K3 系数每 32 字节按绝对差最小方向步进）
      const channels = initR[0];
      if (length > VM_MEMSIZE / 2 || channels > 128 || channels === 0) continue;
      const dest = new Uint8Array(length);
      let srcPos = 0;
      for (let channel = 0; channel < channels; channel += 1) {
        let prevByte = 0;
        let prevDelta = 0;
        let d1 = 0;
        let d2 = 0;
        let k1 = 0;
        let k2 = 0;
        let k3 = 0;
        const dif = [0, 0, 0, 0, 0, 0, 0];
        for (let index = channel, byteCount = 0; index < length; index += channels, byteCount += 1) {
          const d3 = d2;
          d2 = prevDelta - d1;
          d1 = prevDelta;
          let predicted = ((8 * prevByte + k1 * d1 + k2 * d2 + k3 * d3) >>> 3) & 0xff;
          const curByte = block[srcPos];
          srcPos += 1;
          predicted = (predicted - curByte) >>> 0;
          dest[index] = predicted & 0xff;
          const predDiff = (predicted - prevByte) & 0xff;
          prevDelta = predDiff < 128 ? predDiff : predDiff - 256; // (signed char) 截断语义
          prevByte = predicted; // unrar 保持 uint 全值（含 2^32 回绕），后续 8*PrevByte 按 uint32 折算一致
          const d = (curByte < 128 ? curByte : curByte - 256) * 8;
          dif[0] += Math.abs(d);
          dif[1] += Math.abs(d - d1);
          dif[2] += Math.abs(d + d1);
          dif[3] += Math.abs(d - d2);
          dif[4] += Math.abs(d + d2);
          dif[5] += Math.abs(d - d3);
          dif[6] += Math.abs(d + d3);
          if ((byteCount & 0x1f) === 0) {
            let minDif = dif[0];
            let numMinDif = 0;
            dif[0] = 0;
            for (let j = 1; j < 7; j += 1) {
              if (dif[j] < minDif) {
                minDif = dif[j];
                numMinDif = j;
              }
              dif[j] = 0;
            }
            if (numMinDif === 1 && k1 >= -16) k1 -= 1;
            else if (numMinDif === 2 && k1 < 16) k1 += 1;
            else if (numMinDif === 3 && k2 >= -16) k2 -= 1;
            else if (numMinDif === 4 && k2 < 16) k2 += 1;
            else if (numMinDif === 5 && k3 >= -16) k3 -= 1;
            else if (numMinDif === 6 && k3 < 16) k3 += 1;
          }
        }
      }
      out.set(dest, start);
    }
  }
};

const verifyCrc = (name: string, bytes: Uint8Array, fileCrc: number): void => {
  if (fileCrc === 0) return;
  const actual = crc32(bytes);
  if (actual !== fileCrc) {
    throw new Error(`条目 "${name}" CRC32 校验失败：文件头 FILE_CRC=0x${fileCrc.toString(16)} ≠ 解出数据 0x${actual.toString(16)}（数据损坏）`);
  }
};

export const extractRarEntry = (bytes: Uint8Array, entry: RarEntry): RarExtractResult => {
  for (let i = 0; i < 7; i += 1) {
    if (bytes[i] !== RAR4_SIGNATURE[i]) {
      throw new Error('不是 RAR4 数据：签名 52 61 72 21 1A 07 00 不完好（RAR5 或签名被改，可先运行 fixRarSignature 修复后重试）');
    }
  }
  const { name, method } = entry;
  if (entry.offset < 0 || entry.offset + 32 > bytes.length) {
    throw new Error(`条目 "${name}" 文件头偏移 ${entry.offset} 越界或头不完整（输入共 ${bytes.length} 字节）`);
  }
  const flags = u16le(bytes, entry.offset + 3);
  const headSize = u16le(bytes, entry.offset + 5);
  if (headSize < 32) {
    throw new Error(`条目 "${name}" 文件头 HEAD_SIZE=${headSize} < 32，字段不完整`);
  }

  if (entry.isDirectory) return { name, bytes: null, method, unsupported: '目录条目：无文件数据' };
  if (entry.encrypted) {
    return { name, bytes: null, method, unsupported: '条目置加密位（0x0004）：需口令才能解压；若为伪加密可先运行 fixRarPseudoEncryption 清位后重试' };
  }
  if ((flags & 0x0003) !== 0) {
    return { name, bytes: null, method, unsupported: '分卷条目（SPLIT 位置位）：跨卷数据在本卷内不完整' };
  }
  if (method < 0x30 || method > 0x35) {
    return { name, bytes: null, method, unsupported: `METHOD=0x${method.toString(16)} 越界（合法 0x30 存储-0x35 最佳）` };
  }

  const unpSize = u32le(bytes, entry.offset + 11) + ((flags & 0x0100) !== 0 ? u32le(bytes, entry.offset + 36) * 0x100000000 : 0);
  if (unpSize > RAR_EXTRACT_MAX_OUTPUT) {
    throw new Error(`解压输出预算超限：UNP_SIZE=${unpSize} > ${RAR_EXTRACT_MAX_OUTPUT}（RAR 炸弹防护）`);
  }
  const fileCrc = u32le(bytes, entry.offset + 16);
  const unpVer = bytes[entry.offset + 24];
  const dataStart = entry.offset + headSize;
  if (dataStart > bytes.length || dataStart + entry.packedSize > bytes.length) {
    throw new Error(`条目 "${name}" 数据区越界：声明 ${entry.packedSize} 字节起于 ${dataStart}，输入仅剩 ${bytes.length - dataStart} 字节（文件截断）`);
  }

  if (method === 0x30) {
    if (entry.packedSize !== unpSize) {
      throw new Error(`条目 "${name}" 存储尺寸不一致：PACK_SIZE=${entry.packedSize} ≠ UNP_SIZE=${unpSize}（头被改动或数据损坏）`);
    }
    const out = bytes.slice(dataStart, dataStart + unpSize);
    verifyCrc(name, out, fileCrc);
    return { name, bytes: out, method };
  }

  if (unpVer !== 29) {
    return { name, bytes: null, method, unsupported: `旧版 RAR 解压流（UNP_VER=${unpVer}）：本引擎仅支持 RAR3 的 29` };
  }
  if (unpSize === 0) return { name, bytes: new Uint8Array(0), method };

  const outcome = unpackRar3(bytes.subarray(dataStart, dataStart + entry.packedSize), unpSize);
  if (outcome.kind === 'unsupported') return { name, bytes: null, method, unsupported: outcome.reason };
  verifyCrc(name, outcome.bytes, fileCrc);
  return { name, bytes: outcome.bytes, method };
};
