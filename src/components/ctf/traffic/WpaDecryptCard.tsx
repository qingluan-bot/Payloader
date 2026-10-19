import { useMemo, useState } from 'react';
import { FlagAutoText } from '../../codec/FlagAutoText';
import { downloadBytes } from '../ffDownload';
import { analyzeWpaCapture, decryptWpaCapture } from '../../../utils/ctf/wpaDecrypt';
import type { ParsedCapture } from '../../../utils/ctf/pcap/parser';

// WiFi 解密卡（流量域，linkType 105/127）：WPA2 四次握手 + CCMP 解密入口。
// 结构预扫描（SSID 候选/握手齐全性/密码套件）在 useMemo 完成；口令派生与逐帧解密在
// 点击"解密"时执行。解密产物 Ethernet pcap 可下载或直接交回工作区重走完整分析链。
// 本卡由父层按文件 key remount，无跨文件残留；所有 setState 都在事件回调里（无 effect）。
interface WpaDecryptCardProps {
  capture: ParsedCapture;
  language: 'zh' | 'en';
  // 解密产物交回工作区直接重新加载（走 TrafficWorkspace.loadFile 的完整分析链）。
  onPcapReady: (bytes: Uint8Array, name: string) => void;
}

const PAYLOAD_PREVIEW_CHARS = 2048;
const MAX_FRAME_ROWS = 50;

const latin1 = (bytes: Uint8Array): string => {
  let out = '';
  for (let index = 0; index < bytes.length; index += 1) out += String.fromCharCode(bytes[index]);
  return out;
};

function WpaDecryptCard({ capture, language, onPcapReady }: WpaDecryptCardProps) {
  const zh = language === 'zh';
  // 结构预扫描：失败（非 802.11/TKIP/WPA3/无握手）直接展示原因，不给解密入口。
  const scan = useMemo(() => {
    try {
      return { ok: true as const, analysis: analyzeWpaCapture(capture) };
    } catch (error) {
      return { ok: false as const, error: error instanceof Error ? error.message : String(error) };
    }
  }, [capture]);

  const [passphrase, setPassphrase] = useState('');
  const [ssid, setSsid] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ReturnType<typeof decryptWpaCapture> | null>(null);

  if (!scan.ok) {
    return (
      <section className="pw-card" aria-label={zh ? 'WiFi 解密' : 'WiFi decryption'}>
        <div className="pw-card-head">
          <strong>{zh ? 'WiFi 解密（WPA2-PSK + CCMP）' : 'WiFi decryption (WPA2-PSK + CCMP)'}</strong>
        </div>
        <p className="pw-warn">{scan.error}</p>
      </section>
    );
  }

  const analysis = scan.analysis;
  const ssidPlaceholder = analysis.ssidCandidates[0] ?? (zh ? '无线网络名（SSID）' : 'network name (SSID)');

  const runDecrypt = () => {
    setBusy(true);
    setError(null);
    try {
      const output = decryptWpaCapture(capture, {
        passphrase,
        ssid: ssid || (analysis.ssidCandidates[0] ?? ''),
      });
      setResult(output);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
      setResult(null);
    } finally {
      setBusy(false);
    }
  };

  const canDecrypt = analysis.hasHandshake && analysis.protectedDataFrames > 0 && !analysis.rejection && passphrase.length > 0;

  return (
    <section className="pw-card" aria-label={zh ? 'WiFi 解密' : 'WiFi decryption'}>
      <div className="pw-card-head">
        <strong>{zh ? 'WiFi 解密（WPA2-PSK + CCMP）' : 'WiFi decryption (WPA2-PSK + CCMP)'}</strong>
        {analysis.hasHandshake && analysis.keyDescriptorVersion !== null && (
          <span className="pw-badge">
            {zh ? `EAPOL ×${analysis.eapolCount}（描述符 v${analysis.keyDescriptorVersion}）` : `EAPOL ×${analysis.eapolCount} (descriptor v${analysis.keyDescriptorVersion})`}
          </span>
        )}
        {analysis.protectedDataFrames > 0 && (
          <span className="pw-badge">{zh ? `受保护数据帧 ×${analysis.protectedDataFrames}` : `${analysis.protectedDataFrames} protected frames`}</span>
        )}
      </div>

      {analysis.rejection !== null ? (
        <p className="pw-warn">{analysis.rejection}</p>
      ) : (
        <>
          <div className="pw-row">
            <input
              style={{ width: 220 }}
              type="password"
              placeholder={zh ? 'WPA 口令（passphrase）' : 'WPA passphrase'}
              aria-label={zh ? 'WPA 口令' : 'WPA passphrase'}
              value={passphrase}
              onChange={event => setPassphrase(event.target.value)}
            />
            <input
              style={{ width: 180 }}
              type="text"
              placeholder={ssidPlaceholder}
              aria-label={zh ? 'SSID' : 'SSID'}
              value={ssid}
              onChange={event => setSsid(event.target.value)}
            />
            <button type="button" className="pw-button pw-button-primary" disabled={!canDecrypt || busy} onClick={runDecrypt}>
              {busy ? (zh ? '解密中…' : 'Decrypting…') : zh ? '解密' : 'Decrypt'}
            </button>
          </div>
          {analysis.ssidCandidates.length > 0 && (
            <p className="pw-note">
              {zh
                ? `抓包内 Beacon 探测到的 SSID 候选：${analysis.ssidCandidates.join('、')}（PBKDF2 需要网络名与口令）`
                : `SSIDs seen in beacons: ${analysis.ssidCandidates.join(', ')} (PBKDF2 needs the network name)`}
            </p>
          )}
          {!analysis.hasHandshake && (
            <p className="pw-note">{zh ? '未发现完整四次握手（需要 M1/M3 的 ANonce 与 M2/M4 的 SNonce）。' : 'No complete 4-way handshake found (need ANonce + SNonce).'}</p>
          )}
        </>
      )}

      {error !== null && <p className="pw-warn">{error}</p>}

      {result && result.authFailure && (
        <p className="pw-warn">
          {zh
            ? '口令或 SSID 不匹配：全部 MIC 校验失败（确定性拒绝，未做解密）。请核对网络名大小写与口令。'
            : 'Wrong passphrase or SSID: every MIC check failed (deterministic reject; no decryption attempted).'}
        </p>
      )}

      {result && !result.authFailure && (
        <>
          <div className="pw-row">
            <span className="pw-badge pw-badge-flag">
              {zh
                ? `MIC 校验通过（${result.micCheckedCount} 条 EAPOL-Key）`
                : `MIC verified (${result.micCheckedCount} EAPOL-Key frames)`}
            </span>
            <span className="pw-badge">{zh ? `解密 ${result.decrypted.length} 帧` : `${result.decrypted.length} frames decrypted`}</span>
            {result.rejected.length > 0 && <span className="pw-badge">{zh ? `拒绝 ${result.rejected.length} 帧` : `${result.rejected.length} rejected`}</span>}
            {result.fcsTrimmed > 0 && <span className="pw-badge">{zh ? `${result.fcsTrimmed} 帧按 FCS 裁尾` : `${result.fcsTrimmed} FCS-trimmed`}</span>}
          </div>
          <div className="pw-row">
            <button
              type="button"
              className="pw-button"
              onClick={() => downloadBytes(result.ethernetPcap, 'wpa-decrypted.pcap', 'application/octet-stream')}
            >
              {zh ? '下载解密 pcap（Ethernet）' : 'Download decrypted pcap (Ethernet)'}
            </button>
            <button
              type="button"
              className="pw-button pw-button-primary"
              onClick={() => onPcapReady(result.ethernetPcap, 'wpa-decrypted.pcap')}
            >
              {zh ? '在流量域重新加载解密结果' : 'Reload decrypted capture here'}
            </button>
          </div>
          {result.decrypted.slice(0, MAX_FRAME_ROWS).map(frame => {
            const preview = latin1(frame.payload).slice(0, PAYLOAD_PREVIEW_CHARS);
            return (
              <div key={`wpa-dec-${frame.frameIndex}`} className="pw-tool">
                <span className="pw-label">
                  {`#${frame.frameIndex} ${frame.src} → ${frame.dst} · ether 0x${frame.ethertype.toString(16).padStart(4, '0')} · PN ${frame.pnText} · ${frame.payload.length}B`}
                </span>
                <code className="pw-code"><FlagAutoText text={preview} /></code>
              </div>
            );
          })}
          {result.rejected.slice(0, MAX_FRAME_ROWS).map(frame => (
            <p key={`wpa-rej-${frame.frameIndex}`} className="pw-note">{`#${frame.frameIndex} ${frame.reason}`}</p>
          ))}
        </>
      )}
    </section>
  );
}

export default WpaDecryptCard;
