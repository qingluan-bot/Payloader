import { useState } from 'react';
import type { HttpBodyDecodeResult, HttpTransaction } from '../../../utils/ctf/pcap/analyze';
import { formatBytes } from '../../../utils/ctf/pcap/format';
import { copyToClipboard } from '../../../utils/clipboard';
import { downloadBytes } from '../../../utils/download';
import { Icon } from '../../Icon';
import '../../../styles/http-objects.css';

const BODY_PREVIEW_CHARS = 4096;
const MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024;

interface HttpObjectsProps {
  transactions: HttpTransaction[];
  httpTotal: number;
  // 批次二补强（Lane K）：body 多层解压产物（gzip/deflate/base64/内嵌 HTTP），按事务序号归属。
  decoded?: HttpBodyDecodeResult[];
  language: 'zh' | 'en';
}

// HTTP 对象视图（批次 L）：请求-响应事务列表，展开看参数、头与响应体；flag 命中显式徽标。
// 批次二增补：压缩 body 的逐层解压链（每层类型与字节数）与最终产物预览/导出。
function HttpObjects({ transactions, httpTotal, decoded, language }: HttpObjectsProps) {
  const [expanded, setExpanded] = useState<number | null>(transactions.length ? 0 : null);
  const zh = language === 'zh';

  if (transactions.length === 0) {
    return (
      <p className="pw-note">
        {zh ? '未识别出 HTTP 报文。流量里的 HTTP 明文会在这里按请求-响应配对列出。' : 'No HTTP messages identified. Plaintext HTTP traffic would be listed here as request-response pairs.'}
      </p>
    );
  }

  return (
    <div className="pw-http">
      <p className="pw-note">
        {zh ? `共 ${httpTotal} 条 HTTP 报文，配对成 ${transactions.length} 个事务。` : `${httpTotal} HTTP messages paired into ${transactions.length} transactions.`}
      </p>
      <div className="pw-http-list">
        {transactions.map((transaction, index) => {
          const isOpen = expanded === index;
          const hasFlag = (transaction.request?.hasFlag ?? false) || (transaction.response?.hasFlag ?? false);
          return (
            <div key={index} className={`pw-http-item${hasFlag ? ' pw-http-item-flag' : ''}`}>
              <button type="button" className="pw-http-head" onClick={() => setExpanded(isOpen ? null : index)} aria-expanded={isOpen}>
                <span className="pw-mono">#{index + 1}</span>
                <span className="pw-http-line pw-http-req">{transaction.request?.startLine ?? (zh ? '（无请求）' : '(no request)')}</span>
                <span className="pw-http-line pw-http-res">{transaction.response?.startLine ?? (zh ? '（无响应）' : '(no response)')}</span>
                {hasFlag && <span className="pw-badge pw-badge-flag"><Icon name="flag" size={12} /> flag</span>}
                <span className="pw-http-arrow" aria-hidden="true"><Icon name={isOpen ? 'chevron-down' : 'chevron-right'} size={14} /></span>
              </button>
              {isOpen && (
                <div className="pw-http-body">
                  {transaction.request && (
                    <div className="pw-http-section">
                      <strong>{zh ? '请求参数' : 'Request parameters'}</strong>
                      {transaction.request.query.length > 0 ? (
                        <table className="pw-kv">
                          <tbody>
                            {transaction.request.query.map(([key, value], paramIndex) => (
                              <tr key={`${key}-${paramIndex}`}>
                                <td className="pw-mono">{key}</td>
                                <td className="pw-mono">{value}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      ) : (
                        <span className="pw-note">{zh ? 'URL 无查询参数。' : 'No query parameters.'}</span>
                      )}
                      <div className="pw-row">
                        <button type="button" className="pw-button" onClick={() => { void copyToClipboard(transaction.request!.bodyText); }}>
                          {zh ? '复制请求体' : 'Copy request body'}
                        </button>
                        <span className="pw-note">{zh ? `请求体 ${formatBytes(transaction.request.bodyBytes.length)}` : `Body ${formatBytes(transaction.request.bodyBytes.length)}`}</span>
                        {transaction.request.hasFlag && <span className="pw-badge pw-badge-flag"><Icon name="flag" size={12} /> {zh ? '请求中发现 flag' : 'flag in request'}</span>}
                      </div>
                      {transaction.request.bodyText && (
                        <pre className="pw-code">{transaction.request.bodyText.slice(0, BODY_PREVIEW_CHARS)}</pre>
                      )}
                    </div>
                  )}
                  {transaction.response && (
                    <div className="pw-http-section">
                      <strong>{zh ? '响应内容' : 'Response content'}</strong>
                      <div className="pw-row">
                        <span className="pw-note">{zh ? `响应体 ${formatBytes(transaction.response.bodyBytes.length)}` : `Body ${formatBytes(transaction.response.bodyBytes.length)}`}</span>
                        {transaction.response.bodyTruncated && <span className="pw-badge pw-badge-warn">{zh ? '体过大，仅预览' : 'large body, preview only'}</span>}
                        {transaction.response.hasFlag && <span className="pw-badge pw-badge-flag"><Icon name="flag" size={12} /> {zh ? '响应中发现 flag' : 'flag in response'}</span>}
                      </div>
                      <pre className="pw-code">{transaction.response.bodyText.slice(0, BODY_PREVIEW_CHARS) || (zh ? '（空响应体）' : '(empty body)')}</pre>
                      <div className="pw-row">
                        <button type="button" className="pw-button" onClick={() => { void copyToClipboard(transaction.response!.bodyText); }}>
                          {zh ? '复制响应体' : 'Copy response body'}
                        </button>
                        {transaction.response.bodyBytes.length > 0 && transaction.response.bodyBytes.length <= MAX_DOWNLOAD_BYTES && (
                          <button
                            type="button"
                            className="pw-button"
                            onClick={() => downloadBytes(transaction.response!.bodyBytes, `response-${index + 1}.bin`)}
                          >
                            {zh ? '下载响应体' : 'Download response body'}
                          </button>
                        )}
                      </div>
                    </div>
                  )}
                  {/* 批次二补强（Lane K）：压缩 body 的逐层解压链 + 最终产物预览/导出。 */}
                  {(decoded ?? []).filter(item => item.transactionIndex === index).map(item => (
                    <div key={`decoded-${index}-${item.direction}`} className="pw-http-section">
                      <strong>{zh ? '解压产物' : 'Decoded body'}</strong>
                      <div className="pw-row">
                        <span className="pw-mono">{item.startLine}</span>
                        <span className="pw-note">{item.direction === 'req' ? (zh ? '请求' : 'request') : (zh ? '响应' : 'response')}</span>
                        {item.contentEncoding && <span className="pw-badge">Content-Encoding: {item.contentEncoding}</span>}
                      </div>
                      <div className="pw-row">
                        {Array.from(item.layers, (layer, layerIndex) => (
                          <span key={`decoded-layer-${index}-${item.direction}-${layerIndex}`} className="pw-badge" title={layer.preview}>
                            {layer.kind} · {formatBytes(layer.byteLength)}
                          </span>
                        ))}
                      </div>
                      {item.error && (
                        <p className="pw-warn"><Icon name="alert-triangle" size={14} /> {item.error}</p>
                      )}
                      {item.finalText && (
                        <pre className="pw-code">{item.finalText.slice(0, BODY_PREVIEW_CHARS)}</pre>
                      )}
                      {item.finalBytes && item.finalBytes.length > 0 && item.finalBytes.length <= MAX_DOWNLOAD_BYTES && (
                        <button
                          type="button"
                          className="pw-button"
                          onClick={() => downloadBytes(item.finalBytes!, `decoded-${index + 1}-${item.direction}.bin`)}
                        >
                          {zh ? '下载解压产物' : 'Download decoded body'}
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default HttpObjects;
