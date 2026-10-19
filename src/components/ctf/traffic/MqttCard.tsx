import { useState } from 'react';
import type { MqttSession } from '../../../utils/ctf/pcap/analyze';
import { formatBytes } from '../../../utils/ctf/pcap/format';
import { downloadBytes } from '../../../utils/download';
import { Icon } from '../../Icon';

interface MqttCardProps {
  sessions: MqttSession[];
  language: 'zh' | 'en';
}

const PAYLOAD_PREVIEW_CHARS = 256;

const payloadPreview = (payload: Uint8Array): string => {
  const text = new TextDecoder('utf-8', { fatal: false }).decode(payload.subarray(0, PAYLOAD_PREVIEW_CHARS));
  let out = '';
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    const printable = code === 9 || code === 10 || code === 13 || code >= 32;
    out += printable ? ch : '·';
  }
  return out;
};

// MQTT 会话卡（批次二 Lane K）：主题表（topic × 消息数 + 载荷魔数 + flag）+ 报文级明细与载荷导出。
// 引擎纯函数，本卡只渲染；换文件由父层 key remount。
function MqttCard({ sessions, language }: MqttCardProps) {
  const zh = language === 'zh';
  const [expanded, setExpanded] = useState<number | null>(0);

  return (
    <section className="pw-card" aria-label={zh ? 'MQTT 会话' : 'MQTT sessions'}>
      <div className="pw-card-head">
        <strong>{zh ? `MQTT 会话（${sessions.length}）` : `MQTT sessions (${sessions.length})`}</strong>
        <span className="pw-note">{zh ? 'MQTT 3.1.1/5.0 剩余长度变长编码逐包解析，主题表按 topic 聚合' : 'MQTT 3.1.1/5.0 packet parsing with remaining-length varint; topics aggregated'}</span>
      </div>
      {sessions.map((session, sessionIndex) => {
        const isOpen = expanded === sessionIndex;
        return (
          <div key={`mqtt-session-${session.streamId}`} className="pw-tool">
            <button
              type="button"
              className="pw-http-head"
              aria-expanded={isOpen}
              onClick={() => setExpanded(isOpen ? null : sessionIndex)}
            >
              <span className="pw-mono">#{sessionIndex + 1}</span>
              <span className="pw-http-line">{session.client} ⇄ {session.server}</span>
              {session.clientId && <span className="pw-badge" title={session.clientId}>clientId: {session.clientId}</span>}
              {session.protocolName && <span className="pw-badge">{session.protocolName} L{session.protocolLevel ?? '?'}</span>}
              <span className="pw-note">{zh ? `${session.packets.length} 报文 · ${session.topics.length} 主题` : `${session.packets.length} packets · ${session.topics.length} topics`}</span>
              <span className="pw-http-arrow" aria-hidden="true"><Icon name={isOpen ? 'chevron-down' : 'chevron-right'} size={14} /></span>
            </button>
            {isOpen && (
              <div className="pw-http-body">
                {session.notes.map((note, noteIndex) => (
                  <p key={`mqtt-note-${session.streamId}-${noteIndex}`} className="pw-warn">
                    <Icon name="alert-triangle" size={14} /> {note}
                  </p>
                ))}
                {session.topics.length > 0 && (
                  <div className="pw-http-section">
                    <strong>{zh ? '主题表' : 'Topic table'}</strong>
                    <table className="pw-kv">
                      <thead>
                        <tr>
                          <th>{zh ? '主题' : 'Topic'}</th>
                          <th>{zh ? '消息数' : 'Count'}</th>
                          <th>{zh ? '载荷字节' : 'Payload'}</th>
                          <th>{zh ? 'QoS' : 'QoS'}</th>
                          <th>{zh ? '类型' : 'Type'}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {session.topics.map(row => (
                          <tr key={`mqtt-topic-${session.streamId}-${row.topic}`}>
                            <td className="pw-mono">
                              {row.topic}
                              {row.hasFlag && <span className="pw-badge pw-badge-flag"><Icon name="flag" size={12} /> flag</span>}
                            </td>
                            <td className="pw-mono">{row.count}</td>
                            <td className="pw-mono">{formatBytes(row.totalPayloadBytes)}</td>
                            <td className="pw-mono">{row.qosLevels.join('/')}</td>
                            <td className="pw-mono">{row.magic ?? (zh ? '文本/未知' : 'text/unknown')}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <details className="pw-http-section">
                  <summary className="pw-note">{zh ? `报文明细（${session.packets.length} 条）` : `Packets (${session.packets.length})`}</summary>
                  {session.packets.map((packet, packetIndex) => (
                    <div key={`mqtt-packet-${session.streamId}-${packetIndex}`} className="pw-http-section">
                      <div className="pw-row">
                        <span className="pw-mono">
                          {packet.direction === 'c2s' ? '→' : '←'} {packet.typeName}
                          {packet.typeName === 'PUBLISH' && ` · ${packet.topic ?? '-'}`}
                          {packet.qos > 0 && ` · QoS${packet.qos}`}
                          {packet.packetId !== null && ` · id=${packet.packetId}`}
                          {packet.retain && ' · retain'}
                          {packet.dup && ' · dup'}
                          {packet.topicFilters.length > 0 && ` · ${packet.topicFilters.join(', ')}`}
                          {` · #${packet.packetIndex}`}
                        </span>
                        {packet.hasFlag && <span className="pw-badge pw-badge-flag"><Icon name="flag" size={12} /> flag</span>}
                      </div>
                      {packet.payload && packet.payload.length > 0 && (
                        <div className="pw-row">
                          <code className="pw-code">{payloadPreview(packet.payload)}{packet.payloadTruncated || packet.payload.length > PAYLOAD_PREVIEW_CHARS ? '…' : ''}</code>
                          <button
                            type="button"
                            className="pw-button"
                            onClick={() => downloadBytes(packet.payload!, `mqtt-${packet.typeName.toLowerCase()}-${packetIndex + 1}.bin`)}
                          >
                            {zh ? '导出载荷' : 'Export payload'}
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                </details>
              </div>
            )}
          </div>
        );
      })}
    </section>
  );
}

export default MqttCard;
