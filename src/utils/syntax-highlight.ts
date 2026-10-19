// 轻量代码高亮（展示级）：bash / python / yaml / http 四语逐行 token 化。
// 纯正则规则，不引入编辑器依赖；未知语言整行 plain。配色走 --code-* token。

export type CodeTokenType = 'plain' | 'comment' | 'string' | 'keyword' | 'number' | 'url' | 'meta';

export interface CodeToken {
  text: string;
  type: CodeTokenType;
}

interface Rule {
  re: RegExp;
  type: CodeTokenType;
}

const BASH_KEYWORDS = [
  'sudo', 'curl', 'wget', 'nc', 'ncat', 'nmap', 'bash', 'sh', 'zsh', 'echo', 'cat', 'grep',
  'awk', 'sed', 'cut', 'tr', 'sort', 'uniq', 'head', 'tail', 'find', 'xargs', 'chmod', 'chown',
  'python', 'python3', 'pip', 'pip3', 'node', 'npm', 'git', 'docker', 'ssh', 'scp', 'openssl',
  'base64', 'tar', 'unzip', 'gzip', 'zip', 'kill', 'ps', 'ls', 'cd', 'pwd', 'mv', 'cp', 'rm',
  'mkdir', 'touch', 'whoami', 'id', 'uname', 'ifconfig', 'ip', 'netstat', 'ss', 'systemctl',
  'service', 'apt', 'apt-get', 'yum', 'brew', 'export', 'source', 'alias', 'read', 'eval',
  'exec', 'set', 'unset', 'printf', 'tee', 'sleep', 'env', 'sqlmap', 'nikto', 'hydra', 'john',
  'hashcat', 'gobuster', 'ffuf', 'wfuzz', 'msfconsole', 'certutil', 'bitsadmin', 'powershell',
  'if', 'then', 'else', 'elif', 'fi', 'for', 'while', 'do', 'done', 'case', 'esac', 'return',
  'exit', 'function', 'local', 'in',
];

const PY_KEYWORDS = [
  'def', 'class', 'import', 'from', 'return', 'if', 'elif', 'else', 'for', 'while', 'try',
  'except', 'finally', 'with', 'as', 'lambda', 'print', 'True', 'False', 'None', 'and', 'or',
  'not', 'in', 'is', 'raise', 'yield', 'pass', 'break', 'continue', 'global', 'nonlocal',
  'assert', 'del', 'async', 'await',
];

const YAML_WORDS = ['true', 'false', 'null', 'yes', 'no', 'on', 'off', '~/NULL'];

const HTTP_METHODS = 'GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT';

// 优先级即数组顺序：同位置命中时取靠前规则
function rulesFor(language: string): Rule[] | null {
  const lang = language.trim().toLowerCase();
  const stringRule: Rule = { re: /("(?:[^"\\]|\\.)*"?|'(?:[^'\\]|\\.)*'?)/g, type: 'string' };
  const urlRule: Rule = { re: /(https?:\/\/[^\s'"<>]+)/g, type: 'url' };
  const numberRule: Rule = { re: /\b\d[\d._]*\b/g, type: 'number' };

  if (['bash', 'sh', 'shell', 'zsh', 'console'].includes(lang)) {
    return [
      { re: /#.*/g, type: 'comment' },
      stringRule,
      urlRule,
      { re: /(\$\{[^}]*\}|\$\w+|\$[@#?*!$])/g, type: 'meta' },
      numberRule,
      { re: /(?:^|\s)(-{1,2}[\w][\w-]*)/g, type: 'meta' },
      { re: new RegExp(`\\b(?:${BASH_KEYWORDS.join('|')})\\b`, 'g'), type: 'keyword' },
    ];
  }
  if (['python', 'py', 'python3'].includes(lang)) {
    return [
      { re: /#.*/g, type: 'comment' },
      stringRule,
      urlRule,
      { re: /@[\w.]+/g, type: 'meta' },
      numberRule,
      { re: new RegExp(`\\b(?:${PY_KEYWORDS.join('|')})\\b`, 'g'), type: 'keyword' },
    ];
  }
  if (['yaml', 'yml'].includes(lang)) {
    return [
      { re: /#.*/g, type: 'comment' },
      stringRule,
      urlRule,
      { re: /^(\s*)([-\w.]+)(?=\s*:)/g, type: 'meta' },
      numberRule,
      { re: new RegExp(`\\b(?:${YAML_WORDS.join('|')})\\b`, 'g'), type: 'keyword' },
    ];
  }
  if (['http', 'https', 'rest'].includes(lang)) {
    return [
      stringRule,
      urlRule,
      { re: new RegExp(`^(${HTTP_METHODS})(?=\\s)`, 'g'), type: 'keyword' },
      { re: /^(HTTP\/[\d.]+)/g, type: 'keyword' },
      { re: /^([\w-]+)(?=:)/g, type: 'meta' },
      numberRule,
    ];
  }
  return null;
}

// 单行 token 化：各规则独立全局扫描，按命中位置合并（位置相同取高优先级）
export function tokenizeCodeLine(line: string, language: string): CodeToken[] {
  const rules = rulesFor(language);
  if (!rules || !line) return [{ text: line, type: 'plain' }];

  const hits: { start: number; end: number; type: CodeTokenType }[] = [];
  for (const rule of rules) {
    rule.re.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = rule.re.exec(line))) {
      if (!match[0]) break;
      const start = match.index + (match[0].length - match[0].trimStart().length);
      const text = match[0].trim();
      if (!text) continue;
      hits.push({ start, end: start + text.length, type: rule.type });
      if (rule.re.lastIndex === match.index) rule.re.lastIndex++;
    }
  }
  hits.sort((a, b) => a.start - b.start || a.end - b.end);

  const tokens: CodeToken[] = [];
  let cursor = 0;
  for (const hit of hits) {
    if (hit.start < cursor) continue; // 与已选 token 重叠，丢弃
    if (hit.start > cursor) tokens.push({ text: line.slice(cursor, hit.start), type: 'plain' });
    tokens.push({ text: line.slice(hit.start, hit.end), type: hit.type });
    cursor = hit.end;
  }
  if (cursor < line.length) tokens.push({ text: line.slice(cursor), type: 'plain' });
  return tokens;
}
