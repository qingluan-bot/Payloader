// 数织（Nonogram）求解卡（杂项取证域，B3-4）：纯输入工具，粘贴行/列约束即解。
// 输入格式两段式（--- 分隔行约束/列约束），求解引擎在 utils/ctf/nonogram（线求解器迭代收敛，
// 40×40 上限 / 单线 20 万组合跳过 / 200 轮护栏）。输出：字符画（# 填 . 空 ? 未定）、0/1 位流、
// RGBA 栅格直通 decodeQrCodes 的二维码自动识别（数织→二维码是 misc 高频题型链）。
// 复用 ctf-forensics.css 的 ff-* token，不新增样式。
import { useState } from 'react';
import { notifications } from '@mantine/notifications';
import { FlagAutoText } from '../codec/FlagAutoText';
import {
  solveNonogram,
  nonogramGridToAscii,
  nonogramToBitString,
  nonogramToRgba,
} from '../../utils/ctf/nonogram';
import type { NonogramResult } from '../../utils/ctf/nonogram';
import { decodeQrCodes } from '../../utils/ctf/qrDecode';
import { copyToClipboard } from '../../utils/clipboard';
import type { Language } from '../../i18n';

// 示例取 5×5 菱形（tests/nonogram.test.mjs 教材样例，全解唯一）。
const SAMPLE = ['1', '3', '5', '3', '1', '---', '1', '3', '5', '3', '1'].join('\n');

interface NonogramCardProps {
  language: Language;
}

interface SolveOutcome {
  result: NonogramResult;
  ascii: string;
  qrHits: Array<{ source: string; text: string }>;
}

function NonogramCard({ language }: NonogramCardProps) {
  const zh = language === 'zh';
  const [input, setInput] = useState('');
  const [outcome, setOutcome] = useState<SolveOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = () => {
    setError(null);
    try {
      const result = solveNonogram(input);
      let qrHits: SolveOutcome['qrHits'] = [];
      if (result.solved) {
        // 数织→二维码链：全解栅格转 RGBA 直喂 decodeQrCodes（宽=列数，高=行数）。
        const rgba = nonogramToRgba(result);
        qrHits = decodeQrCodes(rgba, result.cols, result.rows)
          .map(hit => ({ source: zh ? '数织栅格二维码' : 'Grid QR', text: hit.text }))
          .filter(hit => hit.text.length > 0);
      }
      setOutcome({ result, ascii: nonogramGridToAscii(result.grid), qrHits });
    } catch (caught) {
      setOutcome(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const copyText = (text: string) => {
    void copyToClipboard(text).then(ok => {
      if (!ok) notifications.show({ message: zh ? '复制失败，请手动选择文本。' : 'Copy failed.', color: 'red' });
      else notifications.show({ message: zh ? '已复制。' : 'Copied.', color: 'teal', autoClose: 1600 });
    });
  };

  return (
    <section id="ff-card-nonogram" className="ff-card" aria-label={zh ? '数织求解器' : 'Nonogram solver'}>
      <div className="ff-card-head">
        <strong>{zh ? '数织求解器' : 'Nonogram solver'}</strong>
        <span className="ff-badge">{zh ? '线求解器 · 40×40 上限' : 'Line solver · 40×40 limit'}</span>
      </div>
      <p className="ff-note">
        {zh
          ? '粘贴两段式约束（上行约束每行一条、下列约束每列一条，--- 分隔；逗号分隔块长，0 表示空线）。全解输出 #/. 字符画；多解保留 ?（部分解不猜测）。解满后自动尝试栅格二维码识别。'
          : 'Paste row clues then column clues separated by a --- line (comma-separated block lengths, 0 = empty line). Solved grids render as #/. art; ambiguous cells stay ?. Fully solved grids are auto-scanned for QR codes.'}
      </p>
      <textarea
        className="ff-input"
        rows={8}
        spellCheck={false}
        value={input}
        onChange={event => setInput(event.target.value)}
        placeholder={SAMPLE}
        aria-label={zh ? '数织约束输入' : 'Nonogram clues'}
      />
      <div className="ff-row">
        <button type="button" className="ff-button ff-button-primary" onClick={run}>
          {zh ? '求解' : 'Solve'}
        </button>
        <button type="button" className="ff-button" onClick={() => { setInput(SAMPLE); setOutcome(null); setError(null); }}>
          {zh ? '填入示例' : 'Load sample'}
        </button>
        <button type="button" className="ff-button" onClick={() => { setInput(''); setOutcome(null); setError(null); }}>
          {zh ? '清空' : 'Clear'}
        </button>
      </div>
      {error && <p className="ff-note">{error}</p>}
      {outcome && (
        <>
          <div className="ff-tool">
            <span className="ff-label">
              {zh
                ? `结果（${outcome.result.rows}×${outcome.result.cols} · ${outcome.result.solved ? '全解' : '部分解，? 为未定'}${outcome.result.skippedLines > 0 ? ` · ${outcome.result.skippedLines} 条线组合数超限跳过` : ''}）`
                : `Result (${outcome.result.rows}×${outcome.result.cols} · ${outcome.result.solved ? 'solved' : 'partial, ? = undetermined'}${outcome.result.skippedLines > 0 ? ` · ${outcome.result.skippedLines} lines skipped (combo cap)` : ''})`}
            </span>
            <code className="ff-code"><FlagAutoText text={outcome.ascii} /></code>
            <div className="ff-row">
              <button type="button" className="ff-button" onClick={() => copyText(outcome.ascii)}>{zh ? '复制字符画' : 'Copy art'}</button>
              <button type="button" className="ff-button" onClick={() => copyText(nonogramToBitString(outcome.result))}>{zh ? '复制 0/1 位流' : 'Copy bit string'}</button>
            </div>
          </div>
          {outcome.qrHits.length > 0 && (
            <div className="ff-tool">
              <span className="ff-label">{zh ? '二维码命中（栅格 → RGBA → 解码）' : 'QR hits (grid → RGBA → decode)'}</span>
              {outcome.qrHits.map((hit, index) => (
                <div key={`qr-${index}`} className="ff-row">
                  <span className="ff-badge ff-badge-ok">{hit.source}</span>
                  <code className="ff-code" style={{ flex: 1 }}><FlagAutoText text={hit.text} /></code>
                  <button type="button" className="ff-button" onClick={() => { void copyToClipboard(hit.text); }}>
                    {zh ? '复制' : 'Copy'}
                  </button>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </section>
  );
}

export default NonogramCard;
