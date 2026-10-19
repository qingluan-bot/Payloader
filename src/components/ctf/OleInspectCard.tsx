import { useMemo, useState } from 'react';
import { parseOle } from '../../utils/ctf/oleExtract';
import { downloadBytes } from './ffDownload';

// OLE/CFB 复合文档只读提取卡（文件取证域）：目录红黑树列出 storage/stream 结构，
// 流字节一键导出（≤32MB），加密迹象提示。只读解析、绝不执行宏。
// 规范口径：[MS-CFB]；流字节与 Python olefile 权威读数逐位对拍（见 tests/ole-extract.test.mjs）。
interface OleInspectCardProps {
  fileName: string;
  bytes: Uint8Array;
  language: 'zh' | 'en';
}

function OleInspectCard({ fileName, bytes, language }: OleInspectCardProps) {
  const zh = language === 'zh';
  const [selected, setSelected] = useState<string | null>(null);
  const result = useMemo(() => parseOle(bytes), [bytes]);
  const selectedBytes = useMemo(
    () => (selected ? result.streams.find(s => s.path === selected)?.bytes ?? null : null),
    [result, selected],
  );

  if (!result.ok) {
    return (
      <section id="ff-card-ole" className="ff-card" aria-label={zh ? 'OLE/CFB 提取' : 'OLE/CFB extraction'}>
        <div className="ff-card-head"><strong>{zh ? 'OLE/CFB 复合文档' : 'OLE/CFB compound document'}</strong></div>
        <p className="ff-note" style={{ color: 'var(--sev-critical)' }} role="alert">{result.failure}</p>
      </section>
    );
  }

  return (
    <section id="ff-card-ole" className="ff-card" aria-label={zh ? 'OLE/CFB 提取' : 'OLE/CFB extraction'}>
      <div className="ff-card-head">
        <strong>{zh ? 'OLE/CFB 复合文档' : 'OLE/CFB compound document'}</strong>
        <span className="ff-badge">CFB v{result.version}</span>
        <span className="ff-badge">{zh ? `扇区 ${result.sectorSize}B` : `${result.sectorSize}B sectors`}</span>
        <span className="ff-badge ff-mono" title={fileName}>{fileName}</span>
      </div>
      {result.encryptedHints.length > 0 && (
        <div className="ff-tool">
          {result.encryptedHints.map((hint, index) => (
            <p key={index} className="ff-note" style={{ color: 'var(--sev-critical)' }}>{zh ? '加密迹象：' : 'Encryption hint: '}{hint}</p>
          ))}
          <p className="ff-note">{zh ? '流内容可能是密文，提取仅供离线分析；本工具只读，绝不执行宏。' : 'Stream content may be ciphertext; extraction is for offline analysis only. This tool is read-only and never executes macros.'}</p>
        </div>
      )}
      <div className="ff-tool">
        <span className="ff-label">{zh ? `结构树（${result.entries.length} 个条目，红黑树遍历）` : `Structure tree (${result.entries.length} entries, red-black tree walk)`}</span>
        <div className="ff-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
          {result.entries.map(entry => (
            <div key={entry.path} className="ff-row">
              <span className="ff-mono" style={{ paddingLeft: Math.min(4, entry.path.split('/').length - 1) * 16 }}>
                {entry.type === 'storage' ? '📁' : entry.type === 'root' ? '🏛' : '📄'} {entry.name}
              </span>
              <span className="ff-badge">{entry.type}</span>
              {entry.type === 'stream' && <span className="ff-badge">{entry.size}B</span>}
              {entry.clsidHex && <span className="ff-badge" title={entry.clsidHex}>CLSID</span>}
            </div>
          ))}
        </div>
      </div>
      <div className="ff-tool">
        <span className="ff-label">{zh ? '导出流' : 'Export stream'}</span>
        <div className="ff-row">
          <select
            className="ff-select"
            value={selected ?? ''}
            aria-label={zh ? '选择要导出的流' : 'Select stream to export'}
            onChange={event => setSelected(event.target.value || null)}
          >
            <option value="">{zh ? '（选择流）' : '(select a stream)'}</option>
            {result.entries.filter(e => e.type === 'stream').map(e => (
              <option key={e.path} value={e.path}>{e.path}（{e.size}B）</option>
            ))}
          </select>
          {selectedBytes && selected && (
            <button
              type="button"
              className="ff-button ff-button-primary"
              onClick={() => downloadBytes(selectedBytes, selected.split('/').pop() ?? 'stream.bin')}
            >
              {zh ? `下载 ${selectedBytes.length}B` : `Download ${selectedBytes.length}B`}
            </button>
          )}
        </div>
        {selected && !selectedBytes && (
          <p className="ff-note">{zh ? '该流超过导出上限或为空。' : 'This stream exceeds the export limit or is empty.'}</p>
        )}
        {selectedBytes && selectedBytes.length > 0 && (
          <code className="ff-code">
            {Array.from(selectedBytes.subarray(0, 256)).map(value => value.toString(16).padStart(2, '0')).join(' ')}
            {selectedBytes.length > 256 ? ' …' : ''}
          </code>
        )}
      </div>
      {result.notes.map((note, index) => <p key={index} className="ff-note">{note}</p>)}
      {zh ? '只读解析：不执行宏、不上传、不修改文件。' : 'Read-only: never executes macros, uploads, or modifies the file.'}
    </section>
  );
}

export default OleInspectCard;
