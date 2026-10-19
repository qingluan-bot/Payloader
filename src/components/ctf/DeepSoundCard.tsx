import { useState } from 'react';
import { notifications } from '@mantine/notifications';
import { FlagAutoText } from '../codec/FlagAutoText';
import { extractDeepSound } from '../../utils/ctf/deepSound';
import { copyToClipboard } from '../../utils/clipboard';
import { downloadBytes } from './ffDownload';

// DeepSound 音频隐写提取卡（音频域）：RIFF 载体扫描 DSCF/DSC2 头 → 低位提取 → DSSF 记录链
// → 可选 AES-256-ECB 解密（DSC2 密钥=SHA-256(UTF-16LE 口令)、DSCF=ASCII 口令补零 32B）。
// 引擎纯函数，本卡只渲染；格式口径经官方 DeepSound 2.0/2.3 工具产物实测锚定。
interface DeepSoundCardProps {
  fileName: string;
  bytes: Uint8Array;
  language: 'zh' | 'en';
}

function DeepSoundCard({ fileName, bytes, language }: DeepSoundCardProps) {
  const zh = language === 'zh';
  const [password, setPassword] = useState('');
  const [result, setResult] = useState<ReturnType<typeof extractDeepSound> | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = (pw?: string) => {
    setError(null);
    try {
      setResult(extractDeepSound(bytes, pw ? { password: pw } : undefined));
    } catch (e) {
      setResult(null);
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const copyText = (text: string) => {
    void copyToClipboard(text).then(ok => {
      if (!ok) notifications.show({ message: zh ? '复制失败，请手动选择文本。' : 'Copy failed.', color: 'red' });
      else notifications.show({ message: zh ? '已复制。' : 'Copied.', color: 'teal', autoClose: 1600 });
    });
  };

  const baseName = fileName.replace(/\.[^.]+$/, '');

  return (
    <section id="ff-card-deepsound" className="ff-card" aria-label={zh ? 'DeepSound 提取' : 'DeepSound extraction'}>
      <div className="ff-card-head">
        <strong>{zh ? 'DeepSound 提取（DSCF/DSC2）' : 'DeepSound extraction (DSCF/DSC2)'}</strong>
        {result?.marker && <span className="ff-badge">{result.marker}</span>}
        {result?.mode && <span className="ff-badge">{zh ? `mode ${result.mode}` : `mode ${result.mode}`}</span>}
        {result?.encrypted && <span className="ff-badge ff-badge-warn">AES-256</span>}
      </div>
      <div className="ff-row">
        <input
          className="ff-input"
          type="text"
          value={password}
          onChange={event => setPassword(event.target.value)}
          placeholder={zh ? '口令（加密载体必填，无密码留空）' : 'password (required for encrypted carriers)'}
          aria-label={zh ? 'DeepSound 口令' : 'DeepSound password'}
        />
        <button type="button" className="ff-button ff-button-primary" onClick={() => run(password || undefined)}>
          {zh ? '扫描提取' : 'Scan & extract'}
        </button>
      </div>
      {error && <p className="ff-note" style={{ color: 'var(--sev-critical)' }}>{error}</p>}
      {result && (
        <>
          {result.notes.map((note, index) => <p key={index} className="ff-note">{note}</p>)}
          {result.passwordDigest && (
            <p className="ff-note">
              {zh ? '口令摘要（20B）：' : 'Password digest (20B): '}
              <code className="ff-mono">{result.passwordDigest}</code>
            </p>
          )}
          {result.failure && <p className="ff-note" style={{ color: 'var(--sev-critical)' }} role="alert">{result.failure}</p>}
          {result.files.length > 0 && (
            <div className="ff-tool">
              <span className="ff-label">{zh ? `解出 ${result.files.length} 个隐藏文件` : `${result.files.length} hidden file(s) extracted`}</span>
              {result.files.map((file, index) => (
                <div key={`${file.fileName}:${index}`} className="ff-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
                  <div className="ff-row">
                    <span className="ff-name">{file.fileName}</span>
                    <span className="ff-badge">{file.size}B</span>
                    <button type="button" className="ff-button" onClick={() => downloadBytes(file.bytes, file.fileName)}>
                      {zh ? '下载' : 'Download'}
                    </button>
                    <button
                      type="button"
                      className="ff-button"
                      onClick={() => {
                        const text = new TextDecoder('latin1').decode(file.bytes);
                        if (/^[\x20-\x7e\r\n\t]*$/.test(text)) copyText(text);
                        else notifications.show({ message: zh ? '内容非纯文本，请下载查看。' : 'Binary content; download to inspect.', color: 'yellow' });
                      }}
                    >
                      {zh ? '复制文本' : 'Copy text'}
                    </button>
                  </div>
                  <code className="ff-code"><FlagAutoText text={new TextDecoder('latin1').decode(file.bytes.subarray(0, 512))} /></code>
                </div>
              ))}
              <div className="ff-row">
                <button
                  type="button"
                  className="ff-button"
                  onClick={() => downloadBytes(result.files[0].bytes, `${baseName}-deepsound-${result.files[0].fileName}`)}
                >
                  {zh ? '下载首个文件' : 'Download first file'}
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </section>
  );
}

export default DeepSoundCard;
