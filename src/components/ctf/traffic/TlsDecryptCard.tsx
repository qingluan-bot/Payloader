import { useMemo, useState } from 'react';
import { FlagAutoText } from '../../codec/FlagAutoText';
import { decryptTls12Stream } from '../../../utils/ctf/tlsDecrypt';
import type { TcpStream } from '../../../utils/ctf/pcap/analyze';

// TLS 1.2 已知密钥解密卡（流量域）：粘贴 NSS keylog（CLIENT_RANDOM 行），选一条 TCP 双向流，
// 引擎按 RFC 5246 做记录层校验 / 握手随机数提取 / PRF 密钥展开 / AES-GCM 认证解密。
// 本卡只渲染；引擎纯函数，换抓包由父层 key remount。
interface TlsDecryptCardProps {
  streams: TcpStream[];
  language: 'zh' | 'en';
}

function TlsDecryptCard({ streams, language }: TlsDecryptCardProps) {
  const zh = language === 'zh';
  const [keylog, setKeylog] = useState('');
  const [streamId, setStreamId] = useState(streams[0]?.id ?? 0);
  const [result, setResult] = useState<ReturnType<typeof decryptTls12Stream> | null>(null);
  const [error, setError] = useState<string | null>(null);
  // 完整明文预览按记录展开的展开态（大结果默认折叠）
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const stream = useMemo(() => streams.find(s => s.id === streamId) ?? null, [streams, streamId]);

  const run = () => {
    setError(null);
    setResult(null);
    if (!stream) return;
    if (!keylog.trim()) {
      setError(zh ? '请先粘贴 NSS keylog 内容（CLIENT_RANDOM 行）。' : 'Paste an NSS keylog (CLIENT_RANDOM lines) first.');
      return;
    }
    try {
      setResult(decryptTls12Stream(stream.bufferAtoB, stream.bufferBtoA, keylog));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const statusBadge = (status: string) => {
    if (status === 'decrypted') return <span className="pw-badge">{zh ? '已解密' : 'decrypted'}</span>;
    if (status === 'auth-failed') return <span className="pw-badge pw-badge-warn">{zh ? '认证失败' : 'auth failed'}</span>;
    return null;
  };

  return (
    <section className="pw-card" aria-label={zh ? 'TLS 1.2 已知密钥解密' : 'TLS 1.2 known-key decryption'}>
      <div className="pw-card-head">
        <strong>{zh ? 'TLS 1.2 已知密钥解密（AES-GCM）' : 'TLS 1.2 known-key decryption (AES-GCM)'}</strong>
        <span className="pw-badge">{zh ? 'RFC 5246 口径' : 'RFC 5246'}</span>
      </div>
      <p className="pw-note">
        {zh
          ? '粘贴 NSS keylog（格式：CLIENT_RANDOM <64位hex> <96位hex>），选择一条 TCP 双向流。TLS 1.3 / CBC / ChaCha20 / SHA-384 套件会显式拒绝；解不开的记录如实登记，不伪造明文。'
          : 'Paste an NSS keylog (format: CLIENT_RANDOM <64 hex> <96 hex>) and pick a TCP stream. TLS 1.3 / CBC / ChaCha20 / SHA-384 suites are explicitly rejected; records that fail to decrypt are logged honestly.'}
      </p>
      <div className="pw-tool">
        <span className="pw-label">{zh ? 'NSS keylog（ssl.log）' : 'NSS keylog (ssl.log)'}</span>
        <textarea
          className="ff-textarea"
          rows={3}
          value={keylog}
          onChange={event => setKeylog(event.target.value)}
          placeholder="CLIENT_RANDOM 0123…cdef 0123…89ab"
          aria-label={zh ? 'NSS keylog 内容' : 'NSS keylog content'}
        />
      </div>
      <div className="pw-row">
        <span className="pw-label">{zh ? 'TCP 流' : 'TCP stream'}</span>
        <select
          className="ff-select"
          value={streamId}
          aria-label={zh ? '选择 TCP 流' : 'Select TCP stream'}
          onChange={event => { setStreamId(Number(event.target.value)); setResult(null); }}
        >
          {streams.map(s => (
            <option key={s.id} value={s.id}>
              #{s.id} {s.endpointA} ↔ {s.endpointB}（{s.byteCount}B）
            </option>
          ))}
        </select>
        <button type="button" className="pw-button pw-button-primary" onClick={run} disabled={!stream}>
          {zh ? '解密' : 'Decrypt'}
        </button>
      </div>
      {error && <p className="pw-warn">{error}</p>}
      {result && (
        <>
          <div className="pw-row">
            {result.ok
              ? <span className="pw-badge">{zh ? `解密成功 ${result.decryptedCount} 条记录` : `${result.decryptedCount} records decrypted`}</span>
              : <span className="pw-badge pw-badge-warn">{zh ? '未能解密' : 'no records decrypted'}</span>}
            <span className="pw-badge">{result.cipherSuite ?? (zh ? '套件未知' : 'unknown suite')}</span>
            <span className="pw-badge">
              {result.keylogMatched
                ? (zh ? 'keylog 已命中' : 'keylog matched')
                : (zh ? 'keylog 未命中' : 'keylog unmatched')}
            </span>
          </div>
          <div className="pw-tool">
            <span className="pw-label">{zh ? '密钥材料（key block 切片）' : 'Key material (key block slices)'}</span>
            {result.keys ? (
              <code className="pw-code">
                {`client_write_key=${result.keys.clientWriteKey}\nserver_write_key=${result.keys.serverWriteKey}\nclient_write_iv=${result.keys.clientWriteIv}\nserver_write_iv=${result.keys.serverWriteIv}`}
              </code>
            ) : (
              <p className="pw-note">{zh ? '（未派生）' : '(not derived)'}</p>
            )}
          </div>
          {result.failures.map((failure, index) => (
            <p key={index} className="pw-warn">{failure}</p>
          ))}
          {result.notes.map((note, index) => (
            <p key={index} className="pw-note">{note}</p>
          ))}
          <div className="pw-tool">
            <span className="pw-label">{zh ? `记录明细（${result.records.length} 条）` : `Records (${result.records.length})`}</span>
            <div className="pw-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
              {result.records.map(rec => {
                const key = `${rec.direction}-${rec.index}`;
                const open = expanded[key] ?? false;
                return (
                  <div key={key} className="pw-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
                    <div className="pw-row">
                      <span className="pw-mono">{rec.direction === 'c2s' ? 'C→S' : 'S→C'} #{rec.index}</span>
                      <span className="pw-mono">{rec.typeName}</span>
                      <span className="pw-mono">{rec.length}B</span>
                      {statusBadge(rec.status)}
                      {rec.preview && (
                        <button type="button" className="pw-button" onClick={() => setExpanded(prev => ({ ...prev, [key]: !open }))}>
                          {open ? (zh ? '收起' : 'Collapse') : (zh ? '展开明文' : 'Show plaintext')}
                        </button>
                      )}
                    </div>
                    {rec.note && <span className="pw-note">{rec.note}</span>}
                    {rec.preview && open && (
                      <code className="pw-code"><FlagAutoText text={rec.preview} /></code>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </>
      )}
    </section>
  );
}

export default TlsDecryptCard;
