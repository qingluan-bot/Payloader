// 最小 ZIP 读取器（无第三方依赖）：解析中央目录 + 本地文件头，
// 支持 store(0) 与 deflate(8) 两种压缩方法——nuclei-templates 拉取专用。

import { inflateRawSync } from 'node:zlib';

const u16 = (buf, offset) => buf.readUInt16LE(offset);
const u32 = (buf, offset) => buf.readUInt32LE(offset);

// 返回 [{ path, data: Buffer }]；传 onEntry 时流式回调（每条解压后立即交出，不攒数组——
// trickest/cve 级别的 zip 有数万条目，全量攒内存会到 GB 级）
export const readZipEntries = (buffer, pathFilter = () => true, onEntry = null) => {
  // 定位 End of Central Directory（签名 0x06054b50，从尾部向前扫描注释区）
  let eocdOffset = -1;
  for (let i = buffer.length - 22; i >= Math.max(0, buffer.length - 22 - 65_536); i -= 1) {
    if (u32(buffer, i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset < 0) throw new Error('ZIP 结构非法：未找到中央目录结尾记录');

  const entryCount = u16(buffer, eocdOffset + 10);
  const cdOffset = u32(buffer, eocdOffset + 16);
  const entries = onEntry ? null : [];
  let cursor = cdOffset;
  for (let index = 0; index < entryCount; index += 1) {
    if (u32(buffer, cursor) !== 0x02014b50) throw new Error(`ZIP 结构非法：中央目录项 ${index} 签名不符`);
    const method = u16(buffer, cursor + 10);
    const compressedSize = u32(buffer, cursor + 20);
    const nameLength = u16(buffer, cursor + 28);
    const extraLength = u16(buffer, cursor + 30);
    const commentLength = u16(buffer, cursor + 32);
    const localHeaderOffset = u32(buffer, cursor + 42);
    const path = buffer.toString('utf8', cursor + 46, cursor + 46 + nameLength);
    cursor += 46 + nameLength + extraLength + commentLength;
    if (!pathFilter(path)) continue;

    // 本地文件头：文件名/extra 长度可能与中央目录不同，必须读本地头的
    if (u32(buffer, localHeaderOffset) !== 0x04034b50) throw new Error(`ZIP 结构非法：本地头签名不符（${path}）`);
    const localNameLength = u16(buffer, localHeaderOffset + 26);
    const localExtraLength = u16(buffer, localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + localNameLength + localExtraLength;
    const raw = buffer.subarray(dataStart, dataStart + compressedSize);
    const data = method === 0 ? Buffer.from(raw) : inflateRawSync(raw);
    if (onEntry) onEntry({ path, data });
    else entries.push({ path, data });
  }
  return entries;
};
