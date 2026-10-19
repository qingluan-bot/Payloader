// USB HID 击键/鼠标流量恢复（流量取证域，sweep2 缺口 #17；批次二 Lane I 增强）：
// usbmon 抓包（LINKTYPE_USB_LINUX_MMAPPED=220）与 Windows USBPcap 抓包（tcpdump.org
// link-layer header types 表 LINKTYPE_USBPCAP=249，旧实现误写 239 为数字换位，保留兼容）
// 里还原键盘输入文本与鼠标相对位移轨迹。纯函数、只读 ParsedCapture、无 DOM/eval/网络。
// usbmon 头布局按内核 Documentation/usb/usbmon.rst：64 字节固定头，数据在偏移 64 起，
// 长度取 len_cap（偏移 36，u32 小端）。USBPcap 按 USBPcap.h：27 字节变长头，数据起于
// headerLen。键盘按 boot 协议 8 字节报文（[0]=修饰键位图、[1]恒 0、[2..7]=键码槽），
// 鼠标按 boot 布局（[0]=按键位图、[1..2]=int8 位移）。
// 键盘字符还原权威口径：USB HID Usage Tables（usb.org HUT1_12v2/1.5）——usage
// 0x04..0x1d 字母 a-z、0x1e..0x27 数字、0x28 Return、0x2a Backspace、0x2b Tab、
// 0x2c Spacebar、0x39 CapsLock；boot 报文修饰键位图 bit0..7 = LCtrl/LShift/LAlt/LGUI/
// RCtrl/RShift/RAlt/RGUI（对应 usage 0xE0..0xE7）。组合键还原按 POSIX 终端惯例：
// Ctrl+字母 → 控制字符 usage-0x03（Ctrl+A=0x01..Ctrl+Z=0x1a），特例 Enter=0x0a、
// Tab=0x09、Space=0x00、[=0x1b(ESC)、]=0x1d(GS)、\=0x1c(FS)、-=0x1f(US)、/=0x7f(DEL)；
// Alt → ESC（\x1b）前缀（readline meta 惯例）；GUI 被系统消费不产字符；优先级 GUI > Alt > Ctrl。
// 对拍锚点：自造 HID 报文序列 vs 终端 `showkey -a` 回显、man console_codes 控制字符表。
import type { ParsedCapture } from './pcap/parser';

export const USBMON_LINKTYPE = 220;
// USBPcap（Windows）原生链路层类型：tcpdump.org link-layer header types 表
// LINKTYPE_USBPCAP=249（Wireshark 侧 LINKTYPE_USBPCAP1 同值）。USBPcap.h 的
// USBPCAP_BUFFER_PACKET_HEADER 为 27 字节变长头，数据起于 headerLen 而非固定 64。
export const USBPCAP_LINKTYPE = 249;
// 历史误值兼容：旧实现把 249 换位写成 239，个别旧样本/旧管线把 239 写进了 pcap 头，
// 判定集合保留 239 防止旧样本被拒收（249 为权威主口径）。
export const USBPCAP_LEGACY_LINKTYPE = 239;

const isUsbPcapLinkType = (value: number): boolean =>
  value === USBPCAP_LINKTYPE || value === USBPCAP_LEGACY_LINKTYPE;

const USBMON_HEADER_BYTES = 64;
const TRACK_CANVAS = 999; // 轨迹归一化画布坐标上界（0..999）

export interface UsbKeyboardEvent {
  shift: boolean;
  ctrl: boolean;
  alt: boolean;
  // LGUI/RGUI 位图（0x08 | 0x80）——GUI 组合被系统消费，不产字符。
  gui: boolean;
  // 该键产出时刻的 CapsLock 大小写锁状态（按设备独立维护）。
  caps: boolean;
  // HID usage id（键码本体）。
  usage: number;
  // 产出的字符；'' = 该组合不产出字符（仍登记进击键列表）。
  key: string;
  // 组合键还原行：哪个键、组合修饰、产出什么字符；普通单键为 ''。
  combo: string;
  packetIndex: number;
}

export interface UsbMouseSample {
  buttons: number;
  dx: number;
  dy: number;
  packetIndex: number;
}

export interface UsbHidOptions {
  // 退格（0x2a，含 Ctrl+H=0x08）处理：'delete'（缺省）从重建文本删除前一字符，
  // 'literal' 保留字面控制字符 \b（对拍旧口径或需要看原始击键流时用）。
  backspace?: 'delete' | 'literal';
}

export interface UsbHidResult {
  keyboard: UsbKeyboardEvent[];
  text: string;
  // flag 候选（假 flag 防护后）：词{正文} 形态扫描，正文排除控制字节、
  // "控制字节劈开单词后贴合前缀"形态被 lookbehind 拦截。
  flags: string[];
  mouse: UsbMouseSample[];
  mouseTrack: { points: Array<{ x: number; y: number; buttons: number }>; width: number; height: number };
  dataPackets: number;
  notes: string[];
}

// HID Usage ID → [常态字符, Shift 字符]；undefined = 不产生字符（0x00 静默、Esc/F 键/
// 方向键/锁定键等）。F 键与锁定键按任务口径略过；小键盘 0x54-0x63 按 NumLock 开启映射
// （数字串/PIN 码题面不丢字符）。
const KEYMAP: Array<[string, string] | undefined> = (() => {
  const map: Array<[string, string] | undefined> = new Array(256).fill(undefined);
  for (let i = 0; i < 26; i += 1) {
    const lower = String.fromCharCode(0x61 + i);
    map[0x04 + i] = [lower, String.fromCharCode(0x41 + i)];
  }
  const digits: Array<[string, string]> = [
    ['1', '!'], ['2', '@'], ['3', '#'], ['4', '$'], ['5', '%'],
    ['6', '^'], ['7', '&'], ['8', '*'], ['9', '('], ['0', ')'],
  ];
  for (let i = 0; i < 10; i += 1) map[0x1e + i] = digits[i];
  map[0x28] = ['\n', '\n'];
  map[0x2a] = ['\b', '\b'];
  map[0x2b] = ['\t', '\t'];
  map[0x2c] = [' ', ' '];
  map[0x2d] = ['-', '_'];
  map[0x2e] = ['=', '+'];
  map[0x2f] = ['[', '{'];
  map[0x30] = [']', '}'];
  map[0x31] = ['\\', '|'];
  map[0x32] = ['#', '~'];
  map[0x33] = [';', ':'];
  map[0x34] = ["'", '"'];
  map[0x35] = ['`', '~'];
  map[0x36] = [',', '<'];
  map[0x37] = ['.', '>'];
  map[0x38] = ['/', '?'];
  map[0x54] = ['/', '/'];
  map[0x55] = ['*', '*'];
  map[0x56] = ['-', '-'];
  map[0x57] = ['+', '+'];
  map[0x58] = ['\n', '\n'];
  const keypad = '1234567890';
  for (let i = 0; i < 10; i += 1) map[0x59 + i] = [keypad[i], keypad[i]];
  map[0x63] = ['.', '.'];
  return map;
})();

// Ctrl 组合的特例控制字符（usage → charCode）：POSIX 终端惯例。字母走 usage-0x03 公式，
// 此表只收非字母特例；未收录的 usage 在 Ctrl 组合下不产字符（未定义组合）。
const CTRL_SPECIAL_CHARS: ReadonlyMap<number, number> = new Map([
  [0x28, 0x0a], // Ctrl+Enter → \n
  [0x2b, 0x09], // Ctrl+Tab → \t
  [0x2c, 0x00], // Ctrl+Space → NUL
  [0x2d, 0x1f], // Ctrl+- → US
  [0x2f, 0x1b], // Ctrl+[ → ESC
  [0x30, 0x1d], // Ctrl+] → GS
  [0x31, 0x1c], // Ctrl+\ → FS
  [0x38, 0x7f], // Ctrl+/ → DEL
]);

const ctrlCharCode = (usage: number): number | undefined => {
  if (usage >= 0x04 && usage <= 0x1d) return usage - 0x03; // Ctrl+A..Z → 0x01..0x1a
  return CTRL_SPECIAL_CHARS.get(usage);
};

// 组合键还原行的键名（人类可读）：字母大写、数字、命名键、小键盘前缀；未映射键回退 Usage(0xXX)。
const KEY_DISPLAY_NAMES: ReadonlyMap<number, string> = new Map([
  [0x28, 'Enter'], [0x29, 'Esc'], [0x2a, 'Backspace'], [0x2b, 'Tab'], [0x2c, 'Space'],
  [0x2d, '-'], [0x2e, '='], [0x2f, '['], [0x30, ']'], [0x31, '\\'], [0x32, '#'],
  [0x33, ';'], [0x34, "'"], [0x35, '`'], [0x36, ','], [0x37, '.'], [0x38, '/'],
  [0x39, 'CapsLock'],
  [0x54, 'Keypad/'], [0x55, 'Keypad*'], [0x56, 'Keypad-'], [0x57, 'Keypad+'],
  [0x58, 'KeypadEnter'], [0x63, 'Keypad.'],
]);

const keyDisplayName = (usage: number): string => {
  if (usage >= 0x04 && usage <= 0x1d) return String.fromCharCode(0x41 + usage - 0x04); // A..Z
  if (usage >= 0x1e && usage <= 0x26) return String.fromCharCode(0x31 + usage - 0x1e); // 1..9
  if (usage === 0x27) return '0';
  if (usage >= 0x59 && usage <= 0x62) return `Keypad${'1234567890'[usage - 0x59]}`;
  return KEY_DISPLAY_NAMES.get(usage) ?? `Usage(0x${usage.toString(16).padStart(2, '0')})`;
};

// 控制字符的人类可读写法：\n/\t/\r 用助记符，其余 C0/DEL 用 \xNN；普通字符原样。
const describeChar = (ch: string): string => {
  if (ch === '') return '未产出字符';
  if (ch === '\n') return '\\n';
  if (ch === '\t') return '\\t';
  if (ch === '\r') return '\\r';
  const code = ch.charCodeAt(0);
  if (code < 0x20 || code === 0x7f) return `\\x${code.toString(16).padStart(2, '0')}`;
  return ch;
};

// 假 flag 防护（批次二）：控制字节判据 = C0 控制字符 + DEL，\t\n\r 是正常打字空白不算；
// "劈开再贴合"形态（如 f\x03lag{} → lag{...}）：匹配起点向前跨过控制字节连续段后若紧邻
// 单词字符，说明前缀词被控制字节劈开重组，拦截该候选；控制字节在文本开头或空格/非单词
// 字符之前时 flag 本体完好，不误杀真答案。
const isControlByte = (code: number): boolean =>
  (code >= 0x00 && code <= 0x1f && code !== 0x09 && code !== 0x0a && code !== 0x0d) || code === 0x7f;

const isWordChar = (code: number): boolean =>
  (code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x5a)
  || (code >= 0x61 && code <= 0x7a) || code === 0x5f;

const isSplitFusionStart = (text: string, start: number): boolean => {
  let cursor = start - 1;
  let controlRun = 0;
  while (cursor >= 0 && isControlByte(text.charCodeAt(cursor))) {
    controlRun += 1;
    cursor -= 1;
  }
  if (controlRun === 0 || cursor < 0) return false;
  return isWordChar(text.charCodeAt(cursor));
};

// flag 候选扫描：前缀词（字母开头 2..32 位词字符）+ {4+ 位正文}。正文判据排除
// \x00-\x1f\x7f（字符类只收可见 flag 字符，控制字节天然不命中）；同一候选去重。
const flagCandidatePattern = (): RegExp => /[A-Za-z][A-Za-z0-9_]{1,31}\{[A-Za-z0-9_!@#$%^&*.-]{4,}\}/g;

const scanFlagCandidates = (text: string): { flags: string[]; intercepted: number } => {
  const flags: string[] = [];
  let intercepted = 0;
  const pattern = flagCandidatePattern();
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    if (isSplitFusionStart(text, match.index)) {
      intercepted += 1;
      continue;
    }
    if (!flags.includes(match[0])) flags.push(match[0]);
  }
  return { flags, intercepted };
};

const u32le = (bytes: Uint8Array, offset: number): number =>
  bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);

const u16le = (bytes: Uint8Array, offset: number): number => bytes[offset] | (bytes[offset + 1] << 8);

const int8 = (value: number): number => (value >= 128 ? value - 256 : value);

// 键盘 boot 报文形态：8 字节、保留位 [1] 恒 0、六个键码槽全为 0 或落在键区 Usage 范围 0x04..0xE7。
const looksLikeKeyboardReport = (report: Uint8Array): boolean => {
  if (report.length !== 8 || report[1] !== 0) return false;
  for (let slot = 2; slot < 8; slot += 1) {
    const code = report[slot];
    if (code !== 0 && (code < 0x04 || code > 0xe7)) return false;
  }
  return true;
};

// 鼠标报文形态：3..8 字节、[0] 按键位图只占低 5 位（左/右/中 + 两个侧键，标准鼠标不会更高）。
const looksLikeMouseReport = (report: Uint8Array): boolean =>
  report.length >= 3 && report.length <= 8 && (report[0] & 0xe0) === 0;

interface HidCandidate {
  report: Uint8Array;
  packetIndex: number;
  // 严格模式为 "bus:dev:endpoint"；兜底模式无设备身份，统一 '*'（逐报文分流）。
  deviceKey: string;
}

// 键盘解码的设备级状态：长按去重需要上一报告的键码集合；CapsLock 锁按设备独立
//（双键盘/键鼠套装互不串扰）。
interface KeyDecodeState {
  prevUsages: Set<number>;
  capsOn: boolean;
}

// 鼠标轨迹：累计相对位移得原始坐标序列（原点代表抓包起点指针位置，画图从原点起笔），
// 再按每轴 min/max 归一到 0..999；width/height 为画布逻辑尺寸 1000。原始范围写入 notes
// 供渲染层保纵横比参考。零跨度轴上所有点落 0。
const buildMouseTrack = (samples: UsbMouseSample[]): {
  points: Array<{ x: number; y: number; buttons: number }>;
  width: number;
  height: number;
  minX: number; maxX: number; minY: number; maxY: number;
} => {
  if (samples.length === 0) return { points: [], width: TRACK_CANVAS + 1, height: TRACK_CANVAS + 1, minX: 0, maxX: 0, minY: 0, maxY: 0 };
  const raw: Array<{ x: number; y: number; buttons: number }> = [{ x: 0, y: 0, buttons: 0 }];
  let x = 0;
  let y = 0;
  for (const sample of samples) {
    x += sample.dx;
    y += sample.dy;
    raw.push({ x, y, buttons: sample.buttons });
  }
  let minX = 0;
  let maxX = 0;
  let minY = 0;
  let maxY = 0;
  for (const point of raw) {
    if (point.x < minX) minX = point.x;
    if (point.x > maxX) maxX = point.x;
    if (point.y < minY) minY = point.y;
    if (point.y > maxY) maxY = point.y;
  }
  const spanX = maxX - minX;
  const spanY = maxY - minY;
  const points = raw.map(point => ({
    x: spanX > 0 ? Math.round(((point.x - minX) / spanX) * TRACK_CANVAS) : 0,
    y: spanY > 0 ? Math.round(((point.y - minY) / spanY) * TRACK_CANVAS) : 0,
    buttons: point.buttons,
  }));
  return { points, width: TRACK_CANVAS + 1, height: TRACK_CANVAS + 1, minX, maxX, minY, maxY };
};

export const extractUsbHid = (parseResult: ParsedCapture, options: UsbHidOptions = {}): UsbHidResult => {
  const notes: string[] = [];
  const keyboard: UsbKeyboardEvent[] = [];
  const mouse: UsbMouseSample[] = [];
  const emptyResult = (): UsbHidResult => ({
    keyboard,
    text: '',
    flags: [],
    mouse,
    mouseTrack: { points: [], width: TRACK_CANVAS + 1, height: TRACK_CANVAS + 1 },
    dataPackets: 0,
    notes,
  });

  if (parseResult.corrupt) notes.push(`容器解析中止于包 #${parseResult.corrupt.packetIndex}：${parseResult.corrupt.reason}`);
  if (parseResult.truncated) notes.push(`包数达到解析上限 ${parseResult.packetLimit}，其后包未参与恢复`);
  if (parseResult.packets.length === 0) {
    notes.push('未解析到任何数据包');
    return emptyResult();
  }
  const isUsbPcap = isUsbPcapLinkType(parseResult.linkType);
  const usbPackets = parseResult.packets.filter(packet => packet.linkType === USBMON_LINKTYPE || isUsbPcapLinkType(packet.linkType));
  if (usbPackets.length === 0) {
    notes.push(`抓包链路层非 USB（linkType=${parseResult.linkType}，需 usbmon 220 或 USBPcap 249），无法恢复 HID`);
    return emptyResult();
  }
  if (usbPackets.length < parseResult.packets.length) {
    notes.push(`${parseResult.packets.length - usbPackets.length} 包链路层非 USB，已跳过`);
  }

  // USBPcap 头（27 字节中断/批量，变长）：headerLen u16@0 | irpId u64@2 | status u32@10 |
  // function u16@14 | info u8@16（bit0=completion）| bus u16@17 | device u16@19 |
  // endpoint u8@21（bit7=IN）| transfer u8@22 | dataLength u32@23。数据起于 headerLen。
  const readUsbPcapReport = (data: Uint8Array): { report: Uint8Array; deviceKey: string; isHidIn: boolean } | null => {
    if (data.length < 27) return null;
    const headerLen = u16le(data, 0);
    const status = u32le(data, 10);
    const info = data[16];
    const bus = u16le(data, 17);
    const device = u16le(data, 19);
    const endpoint = data[21];
    const transfer = data[22];
    const dataLength = u32le(data, 23);
    if (headerLen < 27 || headerLen > data.length) return null;
    const start = headerLen;
    const end = Math.min(start + dataLength, data.length);
    if (end <= start) return null;
    // HID 中断 IN：中断传输 + URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER + completion + IN 端点 + 成功
    const isHidIn = transfer === 1
      && (u16le(data, 14)) === 0x0009
      && (info & 1) === 1
      && (endpoint & 0x80) !== 0
      && status === 0;
    return { report: data.subarray(start, end), deviceKey: `${bus}:${device}:${endpoint & 0x7f}`, isHidIn };
  };

  const readReport = (data: Uint8Array): Uint8Array | null => {
    if (data.length < USBMON_HEADER_BYTES) return null;
    const lenCap = u32le(data, 36);
    const end = Math.min(USBMON_HEADER_BYTES + lenCap, data.length);
    return data.subarray(USBMON_HEADER_BYTES, end);
  };

  const candidates: HidCandidate[] = [];
  if (isUsbPcap) {
    for (const packet of usbPackets) {
      const parsed = readUsbPcapReport(packet.data);
      if (!parsed || parsed.report.length < 3 || parsed.report.length > 8) continue;
      if (!parsed.isHidIn) continue;
      candidates.push({ report: parsed.report, packetIndex: packet.index, deviceKey: parsed.deviceKey });
    }
    if (candidates.length === 0) {
      // 兜底：USBPcap 头字段被改写时退化为数据段形态校验。
      for (const packet of usbPackets) {
        const parsed = readUsbPcapReport(packet.data);
        if (!parsed) continue;
        if (looksLikeKeyboardReport(parsed.report) || looksLikeMouseReport(parsed.report)) {
          candidates.push({ report: parsed.report, packetIndex: packet.index, deviceKey: '*' });
        }
      }
      if (candidates.length > 0) notes.push('USBPcap 头字段未命中 HID 判据，已按数据段形态启发式兜底提取');
    }
  } else {
    for (const packet of usbPackets) {
      const report = readReport(packet.data);
      if (!report || report.length < 3 || report.length > 8) continue;
      const eventType = packet.data[8];
      const epnum = packet.data[10];
      // 方向判定（关键假设）：只收 IN 方向（epnum bit7）的完成事件 'E'——IN 数据只在完成事件
      // 出现、提交事件 'S' 无数据，两者都收会把每次击键记两遍。不校验 xfer_type：sanitized
      // 抓包常把该字段清零，IN+完成+3..8 字节载荷在 usbmon 里已几乎唯一对应 HID 中断报文。
      if (eventType !== 0x45 || (epnum & 0x80) === 0) continue;
      const deviceKey = `${packet.data[12] | (packet.data[13] << 8)}:${packet.data[11]}:${epnum & 0x7f}`;
      candidates.push({ report, packetIndex: packet.index, deviceKey });
    }

    if (candidates.length === 0) {
      // 兜底口径：usbmon 头事件/方向字段不可信时，退化为"数据段形态合法才收"——
      // 8 字节过键盘校验、3..8 字节过鼠标校验；无设备身份，键鼠逐报文分流。
      for (const packet of usbPackets) {
        const report = readReport(packet.data);
        if (!report) continue;
        if (looksLikeKeyboardReport(report) || looksLikeMouseReport(report)) {
          candidates.push({ report, packetIndex: packet.index, deviceKey: '*' });
        }
      }
      if (candidates.length > 0) notes.push('未识别到 IN 方向完成事件（usbmon 头字段缺失或被改写），已按数据段形态启发式兜底提取');
    }
  }

  // 设备级键/鼠仲裁：8 字节报文在键盘与鼠标间存在逐包歧义（鼠标 [1] 为位移、键盘 [1] 恒 0），
  // 按 (bus,dev,endpoint) 分组投票、多数票整组定性，混合键鼠抓包（无线接收器/键鼠套装）不互串。
  const groups = new Map<string, HidCandidate[]>();
  for (const candidate of candidates) {
    const list = groups.get(candidate.deviceKey);
    if (list) list.push(candidate);
    else groups.set(candidate.deviceKey, [candidate]);
  }
  const keyboardReports: HidCandidate[] = [];
  const mouseReports: HidCandidate[] = [];
  for (const list of groups.values()) {
    if (list[0].deviceKey === '*') {
      for (const candidate of list) (looksLikeKeyboardReport(candidate.report) ? keyboardReports : mouseReports).push(candidate);
      continue;
    }
    let keyboardScore = 0;
    let mouseScore = 0;
    for (const candidate of list) {
      if (looksLikeKeyboardReport(candidate.report)) keyboardScore += 1;
      else if (looksLikeMouseReport(candidate.report)) mouseScore += 1;
    }
    (keyboardScore > mouseScore ? keyboardReports : mouseReports).push(...list);
  }
  // 跨设备统一按抓包顺序输出（分组聚合会打乱到达序）。
  keyboardReports.sort((left, right) => left.packetIndex - right.packetIndex);
  mouseReports.sort((left, right) => left.packetIndex - right.packetIndex);

  // 键盘解码（批次二增强）：长按去重（同键连续报告只出一次，按上一报告键码集合对比）、
  // CapsLock 0x39 按下沿翻转大小写锁（字母大小写 = Shift XOR CapsLock）、组合键权威还原
  // （优先级 GUI > Alt > Ctrl）、退格 0x2a 默认删尾（options.backspace='literal' 保留字面）。
  const backspaceLiteral = options.backspace === 'literal';
  const decodeStates = new Map<string, KeyDecodeState>();
  let text = '';
  for (const { report, packetIndex, deviceKey } of keyboardReports) {
    let state = decodeStates.get(deviceKey);
    if (!state) {
      state = { prevUsages: new Set<number>(), capsOn: false };
      decodeStates.set(deviceKey, state);
    }
    const modifiers = report[0];
    const shift = (modifiers & 0x22) !== 0; // LShift 0x02 | RShift 0x20
    const ctrl = (modifiers & 0x11) !== 0; // LCtrl 0x01 | RCtrl 0x10
    const alt = (modifiers & 0x44) !== 0; // LAlt 0x04 | RAlt 0x40
    const gui = (modifiers & 0x88) !== 0; // LGUI 0x08 | RGUI 0x80
    const currentUsages = new Set<number>();
    for (let slot = 2; slot < report.length; slot += 1) {
      if (report[slot] !== 0) currentUsages.add(report[slot]);
    }
    // CapsLock（0x39）按下沿：本次报告新出现且上一报告键码集合没有 → 翻转大小写锁
    //（键码集合随释放报告自动清空，天然自恢复）。0x39 不在 KEYMAP，不产字符/事件。
    if (currentUsages.has(0x39) && !state.prevUsages.has(0x39)) state.capsOn = !state.capsOn;
    for (const usage of currentUsages) {
      if (state.prevUsages.has(usage)) continue; // 长按去重：同键连续报告只产出一次
      const entry = KEYMAP[usage];
      if (!entry) continue; // 0x00 静默与未映射键（Esc/F 键/方向键/锁定键）不产生字符
      const isLetterUsage = usage >= 0x04 && usage <= 0x1d;
      // 字母大小写 = Shift XOR CapsLock；非字母键（符号/数字）CapsLock 不参与。
      const shifted = isLetterUsage ? shift !== state.capsOn : shift;
      const base = entry[shifted ? 1 : 0];
      let key = '';
      let combo = '';
      if (gui) {
        // 优先级 GUI > Alt > Ctrl：GUI 组合被系统消费，不产字符（仍登记进击键列表）。
        combo = `GUI+${keyDisplayName(usage)} → 未产出字符（系统消费）`;
      } else if (alt) {
        // Alt 组合：POSIX meta 前缀 ESC + 底层字符（Shift/CapsLock 大小写规则照常生效）。
        key = `\x1b${base}`;
        combo = `Alt+${keyDisplayName(usage)} → \\x1b+${describeChar(base)}`;
      } else if (ctrl) {
        // Ctrl 组合：字母 usage-0x03 公式 + 特例表；未定义组合不产字符但登记还原行。
        const code = ctrlCharCode(usage);
        if (code === undefined) {
          combo = `Ctrl+${keyDisplayName(usage)} → 未产出字符（未定义组合）`;
        } else {
          key = String.fromCharCode(code);
          combo = `Ctrl+${keyDisplayName(usage)} → ${describeChar(key)}`;
        }
      } else {
        key = base;
      }
      if (usage === 0x2a && combo === '') {
        combo = backspaceLiteral ? 'Backspace → 字面保留 \\b' : 'Backspace → 删除前一字符';
      }
      keyboard.push({ shift, ctrl, alt, gui, caps: state.capsOn, usage, key, combo, packetIndex });
      // 退格删尾：0x2a 的 \b 与 Ctrl+H 的 \x08 同为退格语义；delete 模式删重建文本尾字符
      //（删到空为止），literal 模式照旧拼接字面控制字符。
      if (!backspaceLiteral && key.includes('\b')) {
        if (text.length > 0) text = text.slice(0, text.length - 1);
      } else {
        text += key;
      }
    }
    state.prevUsages = currentUsages;
  }

  for (const { report, packetIndex } of mouseReports) {
    const buttons = report[0]; // 位图原样传递：bit0 左 / bit1 右 / bit2 中 / bit3-4 侧键
    const dx = int8(report[1]);
    const dy = int8(report[2]);
    if (buttons === 0 && dx === 0 && dy === 0) continue; // 纯空闲报文无信息量
    mouse.push({ buttons, dx, dy, packetIndex });
  }

  const track = buildMouseTrack(mouse);
  // flag 候选（假 flag 防护见 scanFlagCandidates）。
  const { flags, intercepted } = scanFlagCandidates(text);
  if (flags.length > 0) notes.push(`识别 flag 候选 ${flags.length} 个（假 flag 防护：正文排除控制字节，劈开重组形态已拦截）`);
  if (intercepted > 0) notes.push(`拦截 ${intercepted} 个"控制字节劈开单词后贴合前缀"的假 flag 候选（lookbehind 保护）`);
  if (candidates.length === 0) {
    notes.push('未找到可识别的 HID 中断报文（usbmon 数据段无 3..8 字节载荷）');
  } else {
    notes.push(`识别 HID 报文 ${candidates.length} 个（键盘 ${keyboardReports.length} / 鼠标 ${mouseReports.length}）`);
  }
  if (mouse.length > 0) {
    notes.push(`鼠标位移原始范围 X ${track.minX}..${track.maxX} / Y ${track.minY}..${track.maxY}（相对位移单位；轨迹已按每轴 min/max 归一到 0..${TRACK_CANVAS}）`);
  }

  return {
    keyboard,
    text,
    flags,
    mouse,
    mouseTrack: { points: track.points, width: track.width, height: track.height },
    dataPackets: candidates.length,
    notes,
  };
};
