import { memo, useMemo } from 'react';
import type { CaptureAnalysis, DnsExchange, TcpStream } from '../../../utils/ctf/pcap/analyze';
import { parseTlsHandshakes, type TlsHandshake } from '../../../utils/ctf/pcap/protocols';
import '../../../styles/packet-table.css';

interface DnsTlsCardProps {
  analysis: CaptureAnalysis;
  streams: TcpStream[];
  language: 'zh' | 'en';
}

interface TlsRow {
  key: string;
  streamId: number;
  endpoints: string;
  direction: string;
  handshake: TlsHandshake;
}

// RCODE 展示文案：解析器给的是标准文本（protocols.ts DNS_RCODE_TEXT），这里补中文说明。
const RCODE_HINT: Record<string, { zh: string; en: string }> = {
  NOERROR: { zh: '无错误', en: 'no error' },
  FORMERR: { zh: '格式错误', en: 'format error' },
  SERVFAIL: { zh: '服务器失败', en: 'server failure' },
  NXDOMAIN: { zh: '域名不存在', en: 'name does not exist' },
  NOTIMP: { zh: '未实现', en: 'not implemented' },
  REFUSED: { zh: '拒绝', en: 'refused' },
};

const toHexPreview = (bytes: Uint8Array, visibleBytes = 16): string => {
  if (!bytes.length) return '-';
  const head = Array.from(bytes.subarray(0, visibleBytes), byte => byte.toString(16).padStart(2, '0')).join('');
  return bytes.length > visibleBytes ? `${head}…（共 ${bytes.length}B）` : head;
};

// DNS 问答表 + TLS 握手卡（批次二 Lane J）：透出 analyze.dnsExchanges（UDP/TCP 53 双通道）
// 与流重组后 parseTlsHandshakes 提取的 ClientHello/ServerHello（SNI、random、session_id）。
// 纯展示组件：全部数据由 props 派生（useMemo），无本地 effect。
function DnsTlsCard({ analysis, streams, language }: DnsTlsCardProps) {
  const zh = language === 'zh';

  // TLS 行派生：对每条流两个方向做廉价预筛（record 类型 20-23 + 版本 0x03 0x00-0x04），
  // 疑似 TLS 才深度解析，避免对全部流做整缓冲扫描。
  const tlsRows = useMemo<TlsRow[]>(() => {
    const rows: TlsRow[] = [];
    for (const stream of streams) {
      const directions: Array<[string, Uint8Array]> = [
        [`${stream.endpointA} → ${stream.endpointB}`, stream.bufferAtoB],
        [`${stream.endpointB} → ${stream.endpointA}`, stream.bufferBtoA],
      ];
      for (const [direction, buffer] of directions) {
        if (buffer.length < 6 || buffer[0] < 20 || buffer[0] > 23 || buffer[1] !== 0x03 || buffer[2] > 0x04) continue;
        parseTlsHandshakes(buffer).forEach((handshake, index) => {
          rows.push({ key: `tls-${stream.id}-${direction}-${index}`, streamId: stream.id, endpoints: `${stream.endpointA} ↔ ${stream.endpointB}`, direction, handshake });
        });
      }
    }
    return rows;
  }, [streams]);

  // 问答表平铺行：一条报文先列 Question 行再列各记录行。
  const dnsRows = useMemo(() => {
    const rows: Array<{
      key: string;
      exchangeIndex: number;
      transport: DnsExchange['transport'];
      isResponse: boolean;
      id: number;
      rcodeText: string;
      name: string;
      typeText: string;
      value: string;
      ttl: string;
      hasFlag: boolean;
      parseError: string | null;
    }> = [];
    analysis.dnsExchanges.forEach((exchange, exchangeIndex) => {
      for (const question of exchange.questions) {
        rows.push({
          key: `dns-${exchangeIndex}-q-${rows.length}`,
          exchangeIndex,
          transport: exchange.transport,
          isResponse: exchange.isResponse,
          id: exchange.id,
          rcodeText: '',
          name: question.name,
          typeText: question.typeText,
          value: '-',
          ttl: '',
          hasFlag: false,
          parseError: null,
        });
      }
      for (const record of exchange.records) {
        rows.push({
          key: `dns-${exchangeIndex}-r-${rows.length}`,
          exchangeIndex,
          transport: exchange.transport,
          isResponse: exchange.isResponse,
          id: exchange.id,
          rcodeText: record.type === 16 ? exchange.rcodeText : '',
          name: record.name,
          typeText: record.typeText,
          value: record.value,
          ttl: String(record.ttl),
          hasFlag: exchange.hasFlag && record.type === 16,
          parseError: null,
        });
      }
      if (exchange.questions.length === 0 && exchange.records.length === 0) {
        rows.push({
          key: `dns-${exchangeIndex}-empty`,
          exchangeIndex,
          transport: exchange.transport,
          isResponse: exchange.isResponse,
          id: exchange.id,
          rcodeText: exchange.rcodeText,
          name: '-',
          typeText: '-',
          value: '-',
          ttl: '',
          hasFlag: false,
          parseError: exchange.parseError,
        });
      }
    });
    return rows;
  }, [analysis.dnsExchanges]);

  const errorExchanges = useMemo(
    () => analysis.dnsExchanges.filter(exchange => exchange.parseError !== null),
    [analysis.dnsExchanges],
  );

  return (
    <section className="pw-card" aria-label={zh ? 'DNS 与 TLS' : 'DNS and TLS'}>
      <div className="pw-card-head">
        <strong>{zh ? 'DNS 问答表' : 'DNS query table'}</strong>
        <span className="pw-note">{zh ? `共 ${analysis.dnsTotal} 条报文` : `${analysis.dnsTotal} messages`}</span>
      </div>
      {analysis.dnsTotal === 0 ? (
        <p className="pw-note">{zh ? '未发现 DNS 报文（UDP 53 / TCP 53 双通道均无）。' : 'No DNS messages found (both UDP 53 and TCP 53).'}</p>
      ) : (
        <div className="pw-table-scroll">
          <table className="pw-table">
            <thead>
              <tr>
                <th>#</th>
                <th>{zh ? '传输' : 'Trans'}</th>
                <th>{zh ? '方向' : 'Dir'}</th>
                <th>{zh ? '事务 ID' : 'TxID'}</th>
                <th>{zh ? '域名' : 'Name'}</th>
                <th>{zh ? '类型' : 'Type'}</th>
                <th>{zh ? '值' : 'Value'}</th>
                <th>{zh ? 'TTL' : 'TTL'}</th>
              </tr>
            </thead>
            <tbody>
              {dnsRows.map(row => (
                <tr key={row.key}>
                  <td className="pw-mono">{row.exchangeIndex + 1}</td>
                  <td className="pw-mono">{row.transport}</td>
                  <td>{row.isResponse ? (zh ? `响应${row.rcodeText ? `（${RCODE_HINT[row.rcodeText]?.[language] ?? row.rcodeText}）` : ''}` : `resp${row.rcodeText ? ` (${row.rcodeText})` : ''}`) : zh ? '查询' : 'query'}</td>
                  <td className="pw-mono">{row.id.toString(16).padStart(4, '0')}</td>
                  <td className="pw-mono">{row.name || '-'}</td>
                  <td>{row.typeText}</td>
                  <td className="pw-info">
                    {row.hasFlag && <span className="pw-badge pw-badge-flag" title={zh ? 'TXT 含 flag' : 'flag in TXT'}>flag</span>}{' '}
                    {row.value}
                  </td>
                  <td className="pw-mono">{row.ttl}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {errorExchanges.length > 0 && (
        <p className="pw-warn">
          {zh
            ? `${errorExchanges.length} 条报文存在结构异常（名字指针非法或 RR 越界），已尽量保留可解部分。`
            : `${errorExchanges.length} message(s) had malformed structures (bad name pointers or out-of-range RRs); parsed fields are kept where possible.`}
        </p>
      )}

      <div className="pw-card-head">
        <strong>{zh ? 'TLS 握手（ClientHello / ServerHello）' : 'TLS handshakes (ClientHello / ServerHello)'}</strong>
        <span className="pw-note">{zh ? `共 ${tlsRows.length} 条` : `${tlsRows.length} total`}</span>
      </div>
      {tlsRows.length === 0 ? (
        <p className="pw-note">{zh ? '未发现 TLS 握手（TCP 流重组后按 record 解析）。' : 'No TLS handshakes found (parsed from reassembled TCP streams).'}</p>
      ) : (
        <div className="pw-table-scroll">
          <table className="pw-table">
            <thead>
              <tr>
                <th>{zh ? '流' : 'Stream'}</th>
                <th>{zh ? '消息' : 'Message'}</th>
                <th>{zh ? '版本' : 'Version'}</th>
                <th>SNI</th>
                <th>random (32B)</th>
                <th>session_id</th>
              </tr>
            </thead>
            <tbody>
              {tlsRows.map(row => (
                <tr key={row.key}>
                  <td className="pw-mono">{row.endpoints}</td>
                  <td>{row.handshake.kind === 'client' ? (zh ? 'ClientHello' : 'ClientHello') : 'ServerHello'}</td>
                  <td className="pw-mono">{row.handshake.handshakeVersion}</td>
                  <td className="pw-info">
                    {row.handshake.sni
                      ? <span className="pw-badge">{row.handshake.sni}</span>
                      : <span className="pw-note">-</span>}
                  </td>
                  <td className="pw-mono" title={toHexPreview(row.handshake.random, 64)}>{toHexPreview(row.handshake.random)}</td>
                  <td className="pw-mono" title={toHexPreview(row.handshake.sessionId, 64)}>{toHexPreview(row.handshake.sessionId)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="pw-note">
        {zh
          ? 'SNI 揭示客户端访问的域名（即使后续流量加密）；random/session_id 为 TLS 密钥匹配（keylog）预留字段。'
          : 'SNI reveals the hostname a client contacted even when the rest is encrypted; random/session_id are kept for TLS key matching (keylog).'}
      </p>
    </section>
  );
}

export default memo(DnsTlsCard);
