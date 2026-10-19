import { getText } from '../i18n';
import type { PayloadItem, TutorialContent } from '../types';
import { label } from './payloadDetailText';
import { tokenizeCodeLine } from '../utils/syntax-highlight';
import type { ReactNode } from 'react';

interface TutorialPanelProps {
  payload: PayloadItem;
  tutorial: TutorialContent;
  language: 'zh' | 'en';
}

interface ProseBlock { kind: 'prose'; text: string }
interface CodeBlock { kind: 'code'; text: string }
type TextBlock = ProseBlock | CodeBlock;

// 教程段文本可携带缩进防护代码（连续 4 空格及以上缩进行）；HTML 默认折叠空白会毁掉代码结构，
// 这里拆成 prose/code 两类块分别渲染，代码块复用全局 .code-block 样式。
const splitProseCode = (raw: string): TextBlock[] => {
  const lines = String(raw ?? '').replace(/\r\n?/g, '\n').split('\n');
  const blocks: TextBlock[] = [];
  let prose: string[] = [];
  let code: string[] = [];
  const flushProse = () => {
    if (prose.length) { blocks.push({ kind: 'prose', text: prose.join(' ').replace(/\s{2,}/g, ' ').trim() }); prose = []; }
  };
  const flushCode = () => {
    if (code.length) {
      // 剥离块内最小公共缩进（tab 计 4 空格），代码顶格展示
      const width = (l: string) => { const m = l.match(/^[ \t]*/)?.[0] ?? ''; return m.replace(/\t/g, '    ').length; };
      const min = Math.min(...code.map(width));
      blocks.push({
        kind: 'code',
        text: code.map(l => l.replace(/^[ \t]*/, '').padStart(Math.max(0, width(l) - min))).join('\n').replace(/[ \t]+$/gm, ''),
      });
      code = [];
    }
  };
  for (const line of lines) {
    if (/^ {4,}|^\t/.test(line)) { flushProse(); code.push(line); }
    else if (/^\s*$/.test(line)) { if (code.length) code.push(''); else prose.push(''); }
    else { flushCode(); prose.push(line); }
  }
  flushProse();
  flushCode();
  return blocks.filter(b => b.text.length > 0);
};

// ---- B-8：防护建议混排代码按语言拆分（渲染层切分，不动库数据） ----

// 语言注释标记行：`// PHP`、`// Java JDBC`、`# Python`、`-- SQL` 等（独占一行）
const LANG_MARK_RE = /^\s*(?:\/\/|#|--|;)\s*([A-Za-z][A-Za-z+#.0-9]*(?:\s+[A-Za-z+#.0-9]+)?)\s*$/;

const LANG_ALIAS: Record<string, string> = {
  php: 'php', java: 'java', python: 'python', py: 'python', sql: 'sql', mysql: 'sql',
  bash: 'bash', sh: 'bash', shell: 'bash', zsh: 'bash',
  javascript: 'javascript', js: 'javascript', typescript: 'typescript', ts: 'typescript',
  ruby: 'ruby', go: 'go', golang: 'go', c: 'c', cpp: 'cpp', 'c++': 'cpp',
  csharp: 'csharp', 'c#': 'csharp', yaml: 'yaml', yml: 'yaml', html: 'html', css: 'css', json: 'json',
};

interface LangCodeBlock { kind: 'lang-code'; language: string; tag: string; text: string }
type RenderBlock = ProseBlock | LangCodeBlock;

// 中文叙述行判定：CJK 占比高、非注释语法、无代码标点——移出为正文段落（如"修复后重放验证：…"）
const isChineseProse = (line: string) => {
  const trimmed = line.trim();
  if (!trimmed || /^(\/\/|#|--|;)/.test(trimmed)) return false;
  const cjk = (trimmed.match(/[\u4e00-\u9fff]/g) || []).length;
  if (!cjk) return false;
  const body = trimmed.replace(/\s/g, '');
  return cjk / body.length >= 0.3 && !/[{}<>$`=[\]()]|=>/.test(trimmed);
};

const splitCodeSegments = (code: string): RenderBlock[] => {
  const blocks: RenderBlock[] = [];
  let proseBuf: string[] = [];
  let current: LangCodeBlock | null = null;
  const flushProse = () => {
    const text = proseBuf.join(' ').replace(/\s{2,}/g, ' ').trim();
    if (text) blocks.push({ kind: 'prose', text });
    proseBuf = [];
  };
  const flushCode = () => {
    if (current && current.text.trim()) blocks.push(current);
    current = null;
  };
  for (const line of code.split('\n')) {
    const mark = line.match(LANG_MARK_RE);
    const rawKey = mark ? mark[1].trim().toLowerCase() : '';
    // 复合标记（如 "Java JDBC"）整词未命中时按首词回落
    const alias = rawKey ? (LANG_ALIAS[rawKey] ?? LANG_ALIAS[rawKey.split(/\s+/)[0]]) : undefined;
    if (mark && alias) {
      flushProse();
      flushCode();
      current = { kind: 'lang-code', language: alias, tag: mark[1].trim(), text: '' };
      continue;
    }
    if (isChineseProse(line)) { flushCode(); proseBuf.push(line.trim()); continue; }
    if (!current) current = { kind: 'lang-code', language: '', tag: '', text: '' };
    current.text += (current.text ? '\n' : '') + line;
  }
  flushProse();
  flushCode();
  return blocks;
};

// 高亮渲染：plain 输出纯文本，其余按 tok-* 类着色（与 EXP 详情利用代码同一 tokenizer）
const renderCodeContent = (text: string, language: string): ReactNode => (
  text.split('\n').map((line, lineIndex) => (
    <span key={lineIndex}>
      {lineIndex > 0 ? '\n' : null}
      {tokenizeCodeLine(line, language).map((token, tokenIndex) => (
        token.type === 'plain' ? token.text : <span key={tokenIndex} className={`tok-${token.type}`}>{token.text}</span>
      ))}
    </span>
  ))
);

const renderSegment = (block: RenderBlock, index: number): ReactNode => {
  if (block.kind === 'prose') return <p key={index}>{block.text}</p>;
  // 无语言标记的代码块保持原形态（pre.code-block），不引入空标签头
  if (!block.tag) return <pre key={index} className="code-block tutorial-code">{block.text}</pre>;
  return (
    <div key={index} className="tutorial-code-block">
      <div className="tutorial-code-head">
        <span className="tutorial-code-lang">{block.tag}</span>
      </div>
      <pre className="code-block tutorial-code"><code>{renderCodeContent(block.text, block.language)}</code></pre>
    </div>
  );
};

export const ProseWithCode = ({ text }: { text: string }) => {
  const blocks = splitProseCode(text);
  if (!blocks.length) return null;
  return (
    <>
      {blocks.map((block, index) => block.kind === 'code'
        ? splitCodeSegments(block.text).map(renderSegment)
        : <p key={index}>{block.text}</p>)}
    </>
  );
};

function TutorialPanel({ payload, tutorial, language }: TutorialPanelProps) {
  return (
    <div className="tutorial-section" role="tabpanel">
      <div className="tutorial-card">
        <h3>{label('overview', language)}</h3>
        <ProseWithCode text={getText(tutorial.overview, language)} />
      </div>
      <div className="tutorial-card">
        <h3>{label('vulnerability', language)}</h3>
        <ProseWithCode text={getText(tutorial.vulnerability, language)} />
      </div>
      <div className="tutorial-card">
        <h3>{label('exploitation', language)}</h3>
        <ProseWithCode text={getText(tutorial.exploitation, language)} />
      </div>
      <div className="tutorial-card">
        <h3>{label('mitigation', language)}</h3>
        <ProseWithCode text={getText(tutorial.mitigation, language)} />
      </div>
      <div className="analysis-card">
        <h3>{label('notesTitle', language)}</h3>
        <ProseWithCode text={payload.analysis ? getText(payload.analysis, language) : ''} />
        {!payload.analysis ? <p>{label('noNotes', language)}</p> : null}
      </div>
      {payload.opsecTips?.length ? (
        <div className="analysis-card warning">
          <h3>{label('opsec', language)}</h3>
          <ul>
            {payload.opsecTips.map((tip, index) => <li key={index}>{getText(tip, language)}</li>)}
          </ul>
        </div>
      ) : null}
      {payload.references?.length ? (
        <div className="analysis-card">
          <h3>{label('refs', language)}</h3>
          <ul className="references-list">
            {payload.references.map((ref, index) => (
              <li key={index}><a href={ref} target="_blank" rel="noopener noreferrer">{ref}</a></li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

export default TutorialPanel;
