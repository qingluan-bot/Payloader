import { useState } from 'react';
import type { FtpSession, FtpTransfer, FtpTransferStatus } from '../../../utils/ctf/pcap/analyze';
import { formatBytes } from '../../../utils/ctf/pcap/format';
import { downloadBytes } from '../../../utils/download';
import { Icon } from '../../Icon';

interface FtpCardProps {
  sessions: FtpSession[];
  language: 'zh' | 'en';
}

const STATUS_LABELS: Record<FtpTransferStatus, { zh: string; en: string }> = {
  ok: { zh: '已导出', en: 'extracted' },
  'no-announcement': { zh: '无端点公告', en: 'no endpoint announcement' },
  'stream-missing': { zh: '无数据流', en: 'no data stream' },
  'stream-consumed': { zh: '数据流已占用', en: 'data stream already used' },
  'empty-data': { zh: '空数据', en: 'empty data' },
};

const COMMAND_TEXT_LIMIT = 4096;
const SHA_PREVIEW_CHARS = 16;

const statusBadge = (status: FtpTransferStatus, language: 'zh' | 'en') => {
  const labels = STATUS_LABELS[status];
  const text = language === 'zh' ? labels.zh : labels.en;
  if (status === 'ok') return <span className="pw-badge">{text}</span>;
  return <span className="pw-badge pw-badge-warn">{text}</span>;
};

const transferLine = (transfer: FtpTransfer, language: 'zh' | 'en'): string => {
  const zh = language === 'zh';
  const direction = transfer.direction === 'server-to-client'
    ? (zh ? '服务器 → 客户端' : 'server → client')
    : (zh ? '客户端 → 服务器' : 'client → server');
  const mode = transfer.mode === 'passive' ? (zh ? '被动' : 'passive') : (zh ? '主动' : 'active');
  return `${transfer.command} ${transfer.filename ?? '-'} · ${mode} · ${direction}`;
};

// FTP 会话卡（批次二 Lane K）：控制流凭据/命令行 + 数据流文件导出（SHA-256 与大小），
// 配对冲突与 FTPS 限制如实声明。引擎纯函数，本卡只渲染；换文件由父层 key remount。
function FtpCard({ sessions, language }: FtpCardProps) {
  const zh = language === 'zh';
  const [expanded, setExpanded] = useState<number | null>(0);

  return (
    <section className="pw-card" aria-label={zh ? 'FTP 会话' : 'FTP sessions'}>
      <div className="pw-card-head">
        <strong>{zh ? `FTP 会话（${sessions.length}）` : `FTP sessions (${sessions.length})`}</strong>
        <span className="pw-note">{zh ? 'RFC 959 控制/数据流配对，RETR/STOR 按方向导出文件' : 'RFC 959 control/data pairing; RETR/STOR exported by direction'}</span>
      </div>
      {sessions.map((session, sessionIndex) => {
        const isOpen = expanded === sessionIndex;
        return (
          <div key={`ftp-session-${session.streamId}`} className="pw-tool">
            <button
              type="button"
              className="pw-http-head"
              aria-expanded={isOpen}
              onClick={() => setExpanded(isOpen ? null : sessionIndex)}
            >
              <span className="pw-mono">#{sessionIndex + 1}</span>
              <span className="pw-http-line">{session.client} ⇄ {session.server}</span>
              {session.username && <span className="pw-badge">USER {session.username}</span>}
              {session.password && <span className="pw-badge" title={`PASS ${session.password}`}>PASS •••</span>}
              {session.loggedIn === true && <span className="pw-badge">{zh ? '已登录' : 'logged in'}</span>}
              {session.loggedIn === false && <span className="pw-badge pw-badge-warn">{zh ? '登录失败' : 'login failed'}</span>}
              {session.ftps && <span className="pw-badge pw-badge-warn">FTPS</span>}
              <span className="pw-http-arrow" aria-hidden="true"><Icon name={isOpen ? 'chevron-down' : 'chevron-right'} size={14} /></span>
            </button>
            {isOpen && (
              <div className="pw-http-body">
                {session.notes.map((note, noteIndex) => (
                  <p key={`ftp-note-${session.streamId}-${noteIndex}`} className="pw-warn">
                    <Icon name="alert-triangle" size={14} /> {note}
                  </p>
                ))}
                {session.unmatched.map((entry, entryIndex) => (
                  <p key={`ftp-unmatched-${session.streamId}-${entryIndex}`} className="pw-warn">
                    <Icon name="alert-triangle" size={14} /> {entry}
                  </p>
                ))}
                {session.transfers.length > 0 ? (
                  session.transfers.map((transfer, transferIndex) => (
                    <div key={`ftp-transfer-${session.streamId}-${transferIndex}`} className="pw-http-section">
                      <div className="pw-row">
                        <span className="pw-mono">{transferLine(transfer, language)}</span>
                        {statusBadge(transfer.status, language)}
                        {transfer.dataStreamId !== null && (
                          <span className="pw-note">{zh ? `数据流 #${transfer.dataStreamId}` : `stream #${transfer.dataStreamId}`}</span>
                        )}
                      </div>
                      {transfer.status === 'ok' && (
                        <div className="pw-row">
                          <span className="pw-note">{zh ? `${formatBytes(transfer.size)} · SHA-256 ${transfer.sha256.slice(0, SHA_PREVIEW_CHARS)}…` : `${formatBytes(transfer.size)} · SHA-256 ${transfer.sha256.slice(0, SHA_PREVIEW_CHARS)}…`}</span>
                          {transfer.bytes && (
                            <button
                              type="button"
                              className="pw-button"
                              onClick={() => downloadBytes(transfer.bytes!, transfer.filename ?? `ftp-transfer-${transferIndex + 1}.bin`)}
                            >
                              {zh ? '导出文件' : 'Export file'}
                            </button>
                          )}
                        </div>
                      )}
                      {transfer.note && <span className="pw-note">{transfer.note}</span>}
                    </div>
                  ))
                ) : (
                  <p className="pw-note">{zh ? '未发现 RETR/STOR/LIST/NLST 传输命令。' : 'No RETR/STOR/LIST/NLST transfer commands.'}</p>
                )}
                {session.commands.length > 0 && (
                  <details className="pw-http-section">
                    <summary className="pw-note">{zh ? `控制流命令行（${session.commands.length} 条）` : `Control lines (${session.commands.length})`}</summary>
                    <pre className="pw-code">
                      {Array.from(session.commands, command =>
                        command.fromClient
                          ? `> ${command.command}${command.argument ? ` ${command.argument}` : ''}`
                          : `< ${command.replyCode}${command.argument ? ` ${command.argument}` : ''}`)
                        .slice(0, COMMAND_TEXT_LIMIT / 40)
                        .join('\n')}
                    </pre>
                  </details>
                )}
              </div>
            )}
          </div>
        );
      })}
    </section>
  );
}

export default FtpCard;
