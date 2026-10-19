// USB HID 批次二增强测试（Lane I）：B2-1 组合键权威还原 + 假 flag 防护、B2-2 USBPcap
// linkType=249 权威口径修复。全部 pcap 向量程序化自造，无外部 fixture。
// 对拍锚点：USB HID Usage Tables（usb.org HUT1_12v2/1.5）usage 定义与 boot 协议修饰键位图；
// tcpdump.org link-layer header types 表 LINKTYPE_USBPCAP=249；Ctrl/Alt 组合按 POSIX 终端
// 惯例（console_codes 控制字符表 / readline meta 前缀）。
// 加载走 tests/helpers/compileTsModule.mjs（vm 沙箱）；沙箱 realm 数组一律 Array.from 转主
// realm 后再断言。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const parser = loadModule(path.join(srcDir, 'utils', 'ctf', 'pcap', 'parser.ts'));
const usbHid = loadModule(path.join(srcDir, 'utils', 'ctf', 'usbHid.ts'));

// ---- pcap / usbmon 构造工具（与 tests/usb-hid.test.mjs 同口径） ----

const u16le = value => Uint8Array.from([value & 0xff, (value >>> 8) & 0xff]);
const u32le = value => Uint8Array.from([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]);

const concat = parts => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

// pcap 容器：小端微秒全局头（linkType 默认 220 = LINKTYPE_USB_LINUX_MMAPPED）+ 记录序列。
const pcapFromRecords = (records, { linkType = 220 } = {}) => {
  const header = concat([
    Uint8Array.from([0xd4, 0xc3, 0xb2, 0xa1]),
    u16le(2), u16le(4), u32le(0), u32le(0), u32le(262144), u32le(linkType),
  ]);
  return concat([header, ...records.map(record => concat([u32le(1700000000), u32le(0), u32le(record.length), u32le(record.length), record]))]);
};

// usbmon 64 字节头 + 数据段（默认模拟 IN 端点 0x81 的中断完成事件 'E'）。
const usbmonFrame = (report, { eventType = 0x45, epnum = 0x81, devnum = 3, busnum = 1 } = {}) => {
  const head = Buffer.alloc(64);
  head.writeUInt8(eventType, 8);
  head.writeUInt8(1, 9);
  head.writeUInt8(epnum, 10);
  head.writeUInt8(devnum, 11);
  head.writeUInt16LE(busnum, 12);
  head.writeUInt16LE(report.length, 36); // len_cap
  return concat([head, report]);
};

// 键盘 boot 报文：[modifier, 0, usage, 0,0,0,0,0]。
const keyReport = (usage, modifiers = 0) => Uint8Array.from([modifiers, 0, usage, 0, 0, 0, 0, 0]);
// 修饰键位图（HID boot 协议 bit0..7 = LCtrl/LShift/LAlt/LGUI/RCtrl/RShift/RAlt/RGUI）。
const MOD_LCTRL = 0x01;
const MOD_LSHIFT = 0x02;
const MOD_LALT = 0x04;
const MOD_LGUI = 0x08;
const MOD_RCTRL = 0x10;

const press = (usage, modifiers = 0) => usbmonFrame(keyReport(usage, modifiers));
const release = () => usbmonFrame(keyReport(0x00, 0x00));

const extract = (bytes, options) => usbHid.extractUsbHid(parser.parseCapture(bytes), options);

// USBPcap 27 字节变长头（USBPcap.h USBPCAP_BUFFER_PACKET_HEADER）+ HID 中断 IN 数据段。
const usbPcapFrame = report => {
  const head = Buffer.alloc(27);
  head.writeUInt16LE(27, 0); // headerLen
  // irpId u64@2 恒 0
  head.writeUInt32LE(0, 10); // status = USBD_STATUS_SUCCESS
  head.writeUInt16LE(0x0009, 14); // function = URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER
  head.writeUInt8(0x01, 16); // info bit0 = completion
  head.writeUInt16LE(1, 17); // bus
  head.writeUInt16LE(3, 19); // device
  head.writeUInt8(0x81, 21); // endpoint：IN 端点 1
  head.writeUInt8(0x01, 22); // transfer = Interrupt
  head.writeUInt32LE(report.length, 23); // dataLength
  return concat([head, report]);
};

// 测试侧字符 → (usage, shift) 反查（与引擎 KEYMAP 同口径）。
const charUsage = ch => {
  if (ch >= 'a' && ch <= 'z') return { usage: 0x04 + ch.charCodeAt(0) - 0x61, shift: false };
  if (ch >= 'A' && ch <= 'Z') return { usage: 0x04 + ch.charCodeAt(0) - 0x41, shift: true };
  const symbols = {
    '{': [0x2f, 1], '}': [0x30, 1], '_': [0x2d, 1], '-': [0x2d, 0], '/': [0x38, 0],
    '[': [0x2f, 0], ']': [0x30, 0], '\\': [0x31, 0], '=': [0x2e, 0],
  };
  const entry = symbols[ch];
  if (!entry) throw new Error(`测试字符未映射: ${ch}`);
  return { usage: entry[0], shift: !!entry[1] };
};

// 逐字符 按下+释放 报文序列（真实键盘只在状态变化时上报）。
const typeText = text => {
  const frames = [];
  for (const ch of text) {
    const { usage, shift } = charUsage(ch);
    frames.push(press(usage, shift ? MOD_LSHIFT : 0x00));
    frames.push(release());
  }
  return frames;
};

// ---- B2-2 · 权威常量与判定集合 ----

test('B2-2 常量：USBPCAP_LINKTYPE=249（tcpdump.org 权威），239 保留为兼容旧值，220 不变', () => {
  assert.equal(usbHid.USBPCAP_LINKTYPE, 249);
  assert.equal(usbHid.USBPCAP_LEGACY_LINKTYPE, 239);
  assert.equal(usbHid.USBMON_LINKTYPE, 220);
});

test('B2-2 linkType=249 的 USBPcap 抓包通过过滤并走 27 字节变长头解析路径', () => {
  const records = [usbPcapFrame(keyReport(0x09)), usbPcapFrame(keyReport(0x00))]; // 'f'（usage 0x09）按下 + 释放
  const result = extract(pcapFromRecords(records, { linkType: 249 }));
  assert.equal(result.text, 'f');
  assert.equal(result.dataPackets, 2);
  assert.equal(result.keyboard.length, 1);
  assert.equal(result.keyboard[0].packetIndex, 0);
  // 严格路径命中时不应出现兜底说明。
  assert.ok(!result.notes.some(note => note.includes('兜底')));
  assert.ok(!result.notes.some(note => note.includes('非 USB')));
});

test('B2-2 旧误值 linkType=239 样本仍兼容收录', () => {
  const records = [usbPcapFrame(keyReport(0x09)), usbPcapFrame(keyReport(0x00))];
  const result = extract(pcapFromRecords(records, { linkType: 239 }));
  assert.equal(result.text, 'f');
  assert.equal(result.dataPackets, 2);
});

test('B2-2 非 USB linkType 提示文案更新为"需 usbmon 220 或 USBPcap 249"', () => {
  const records = [usbPcapFrame(keyReport(0x07))];
  const result = extract(pcapFromRecords(records, { linkType: 240 }));
  assert.equal(result.text, '');
  assert.equal(result.dataPackets, 0);
  assert.ok(result.notes.some(note => note.includes('需 usbmon 220 或 USBPcap 249')));
});

// ---- B2-1 · Ctrl 组合 → ASCII 控制字符 ----

test('Ctrl+字母按 usage-0x03 公式：Ctrl+A=\\x01、右Ctrl+C=\\x03、Ctrl+Z=\\x1a', () => {
  const frames = [
    press(0x04, MOD_LCTRL), release(), // Ctrl+A
    press(0x06, MOD_RCTRL), release(), // 右 Ctrl+C
    press(0x1d, MOD_LCTRL), release(), // Ctrl+Z
  ];
  const result = extract(pcapFromRecords(frames));
  assert.equal(result.text, '\x01\x03\x1a');
  assert.equal(result.keyboard[0].ctrl, true);
  assert.equal(result.keyboard[0].key, '\x01');
  assert.equal(result.keyboard[0].combo, 'Ctrl+A → \\x01');
  assert.equal(result.keyboard[1].combo, 'Ctrl+C → \\x03');
  assert.equal(result.keyboard[2].combo, 'Ctrl+Z → \\x1a');
});

test('Ctrl 特例：Enter=\\n、Tab=\\t、Space=NUL、[=ESC、]=GS、\\=FS、-=US、/=DEL', () => {
  const frames = [
    press(0x28, MOD_LCTRL), release(), // Ctrl+Enter → 0x0a
    press(0x2b, MOD_LCTRL), release(), // Ctrl+Tab → 0x09
    press(0x2c, MOD_LCTRL), release(), // Ctrl+Space → 0x00
    press(0x2f, MOD_LCTRL), release(), // Ctrl+[ → 0x1b
    press(0x30, MOD_LCTRL), release(), // Ctrl+] → 0x1d
    press(0x31, MOD_LCTRL), release(), // Ctrl+\ → 0x1c
    press(0x2d, MOD_LCTRL), release(), // Ctrl+- → 0x1f
    press(0x38, MOD_LCTRL), release(), // Ctrl+/ → 0x7f
  ];
  const result = extract(pcapFromRecords(frames));
  assert.equal(result.text, '\n\t\x00\x1b\x1d\x1c\x1f\x7f');
  assert.equal(result.keyboard[3].combo, 'Ctrl+[ → \\x1b');
  assert.equal(result.keyboard[7].combo, 'Ctrl+/ → \\x7f');
});

test('Ctrl 未定义组合（如 Ctrl+1）不产字符但登记还原行', () => {
  const frames = [press(0x1e, MOD_LCTRL), release()]; // Ctrl+1
  const result = extract(pcapFromRecords(frames));
  assert.equal(result.text, '');
  assert.equal(result.keyboard.length, 1);
  assert.equal(result.keyboard[0].key, '');
  assert.equal(result.keyboard[0].combo, 'Ctrl+1 → 未产出字符（未定义组合）');
});

// ---- B2-1 · Alt meta 前缀 ----

test('Alt+x 产出 ESC 前缀 \\x1b+x，Alt+Shift+a 产出 \\x1b+A', () => {
  const frames = [
    press(0x1b, MOD_LALT), release(), // Alt+x（usage 0x1b = x）
    press(0x04, MOD_LALT | MOD_LSHIFT), release(), // Alt+Shift+a
  ];
  const result = extract(pcapFromRecords(frames));
  assert.equal(result.text, '\x1bx\x1bA');
  assert.equal(result.keyboard[0].alt, true);
  assert.equal(result.keyboard[0].key, '\x1bx');
  assert.equal(result.keyboard[0].combo, 'Alt+X → \\x1b+x');
  assert.equal(result.keyboard[1].combo, 'Alt+A → \\x1b+A');
});

// ---- B2-1 · GUI 不产字符 + 优先级 GUI > Alt > Ctrl ----

test('GUI 组合不产字符（系统消费），GUI+Alt+Ctrl 同按 GUI 优先', () => {
  const frames = [
    press(0x04, MOD_LGUI), release(), // GUI+A
    press(0x04, MOD_LGUI | MOD_LALT | MOD_LCTRL), release(), // GUI+Alt+Ctrl+A
  ];
  const result = extract(pcapFromRecords(frames));
  assert.equal(result.text, '');
  assert.equal(result.keyboard.length, 2);
  assert.equal(result.keyboard[0].gui, true);
  assert.equal(result.keyboard[0].key, '');
  assert.equal(result.keyboard[0].combo, 'GUI+A → 未产出字符（系统消费）');
  assert.equal(result.keyboard[1].key, '');
});

// ---- B2-1 · 长按去重 ----

test('长按同一键连续报告只产出一次，释放后再按是新按键', () => {
  const frames = [
    press(0x04), // a 按下
    press(0x04), // 长按重复报告 1
    press(0x04), // 长按重复报告 2
    release(),
    press(0x05), release(), // b
  ];
  const result = extract(pcapFromRecords(frames));
  assert.equal(result.text, 'ab');
  assert.equal(result.keyboard.length, 2);
});

test('交叉滚动（两键同报告）不重复：[a,b] 连续两份同报告只产出 ab', () => {
  const roll = () => usbmonFrame(Uint8Array.from([0x00, 0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00]));
  const frames = [roll(), roll(), release()];
  const result = extract(pcapFromRecords(frames));
  assert.equal(result.text, 'ab');
  assert.equal(result.keyboard.length, 2);
});

// ---- B2-1 · CapsLock：字母大小写 = Shift XOR CapsLock ----

test('CapsLock 0x39 翻转大小写锁，与 Shift 异或决定字母大小写', () => {
  const frames = [
    press(0x39), release(), press(0x04), release(), // caps 开 → 'A'
    press(0x39), release(), press(0x04), release(), // caps 关 → 'a'
    press(0x39), release(), press(0x04, MOD_LSHIFT), release(), // caps 开 + Shift → 'a'（异或抵消）
    press(0x39), release(), press(0x04, MOD_LSHIFT), release(), // caps 关 + Shift → 'A'
  ];
  const result = extract(pcapFromRecords(frames));
  assert.equal(result.text, 'AaaA');
  assert.equal(result.keyboard.length, 4);
  assert.equal(result.keyboard[0].caps, true);
  assert.equal(result.keyboard[1].caps, false);
  assert.equal(result.keyboard[2].caps, true);
  assert.equal(result.keyboard[3].caps, false);
});

// ---- B2-1 · 退格删尾（可切换字面保留） ----

test('退格 0x2a 默认删除重建文本尾字符，Ctrl+H（\\x08）同为退格语义', () => {
  const frames = [
    ...typeText('flag'),
    press(0x2a), release(), // Backspace 删 'g' → 'fla'
    press(0x0a), release(), // 再补 'g' → 'flag'
    press(0x0b, MOD_LCTRL), release(), // Ctrl+H → \x08 删 'g' → 'fla'
  ];
  const result = extract(pcapFromRecords(frames));
  assert.equal(result.text, 'fla');
  assert.equal(result.keyboard.length, 7); // flag 4 键 + 退格 + g + Ctrl+H
  assert.equal(result.keyboard[4].usage, 0x2a);
  assert.equal(result.keyboard[4].combo, 'Backspace → 删除前一字符');
  assert.equal(result.keyboard[6].combo, 'Ctrl+H → \\x08');
});

test('backspace=literal 选项保留字面控制字符', () => {
  const frames = [
    ...typeText('flag'),
    press(0x2a), release(),
    press(0x0a), release(),
    press(0x0b, MOD_LCTRL), release(),
  ];
  const result = extract(pcapFromRecords(frames), { backspace: 'literal' });
  assert.equal(result.text, 'flag\bg\x08');
  assert.equal(result.keyboard[4].combo, 'Backspace → 字面保留 \\b');
});

test('退格删到空不崩溃，事件仍登记', () => {
  const frames = [press(0x2a), release(), press(0x2a), release()];
  const result = extract(pcapFromRecords(frames));
  assert.equal(result.text, '');
  assert.equal(result.keyboard.length, 2);
});

// ---- B2-1 · 假 flag 防护 ----

test('劈开 flag 负样本：f+Ctrl+C+lag{...} 不得产出 lag{...} 候选', () => {
  const frames = [
    ...typeText('f'),
    press(0x06, MOD_LCTRL), release(), // Ctrl+C → \x03 劈进单词
    ...typeText('lag{test_flag}'),
  ];
  const result = extract(pcapFromRecords(frames));
  assert.equal(result.text, 'f\x03lag{test_flag}');
  assert.deepEqual(Array.from(result.flags, flag => flag), []);
  assert.ok(result.notes.some(note => note.includes('拦截')));
});

test('不误杀：控制字节在完好 flag 之前（\\x03flag{...}、\\nflag{...}）照常产出候选', () => {
  const ctrlFirst = extract(pcapFromRecords([
    press(0x06, MOD_LCTRL), release(), // \x03
    ...typeText('flag{real_one}'),
  ]));
  assert.equal(ctrlFirst.text, '\x03flag{real_one}');
  assert.deepEqual(Array.from(ctrlFirst.flags, flag => flag), ['flag{real_one}']);

  const enterFirst = extract(pcapFromRecords([
    press(0x28), release(), // Enter → \n（\t\n\r 不算控制字节）
    ...typeText('flag{real_one}'),
  ]));
  assert.equal(enterFirst.text, '\nflag{real_one}');
  assert.deepEqual(Array.from(enterFirst.flags, flag => flag), ['flag{real_one}']);
});

test('正文判据：flag 正文含控制字节不产出候选', () => {
  const frames = [
    ...typeText('flag{'),
    press(0x06, MOD_LCTRL), release(), // \x03 落进正文
    ...typeText('abcd}'),
  ];
  const result = extract(pcapFromRecords(frames));
  assert.equal(result.text, 'flag{\x03abcd}');
  assert.deepEqual(Array.from(result.flags, flag => flag), []);
});

test('同一候选去重：重复出现的 flag 只产出一份', () => {
  const frames = [
    ...typeText('flag{dup_flag}'),
    press(0x28), release(), // 换行分隔两次输入
    ...typeText('flag{dup_flag}'),
  ];
  const result = extract(pcapFromRecords(frames));
  assert.deepEqual(Array.from(result.flags, flag => flag), ['flag{dup_flag}']);
});
