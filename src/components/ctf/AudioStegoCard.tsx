import { useEffect, useMemo, useRef, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { FlagAutoText } from '../codec/FlagAutoText';
import { bytesToPreviewText } from '../../utils/ctf/imagePlanes';
import {
  channelDiffWav,
  computeSpectrogram,
  deltaWav,
  extractThresholdBitstream,
  extractWavLsb,
  invertWav,
  morseDecodeAudio,
  dtmfDecode,
  parseWav,
  reverseWav,
} from '../../utils/ctf/audioStego';
import { copyToClipboard } from '../../utils/clipboard';
import { downloadBytes } from './ffDownload';

// 音频隐写卡：WAV 直接进纯函数引擎；mp3/flac/ogg 用浏览器 decodeAudioData 解成 PCM 采样后走同一套
// 引擎（LSB 仅对 WAV 有意义——有损压缩重建的采样不保留原始低位，UI 上对非 WAV 隐藏 LSB 区）。
interface AudioStegoCardProps {
  file: File;
  language: 'zh' | 'en';
}

interface DecodedAudio {
  samples: Float64Array;
  sampleRate: number;
  channels: number;
  isWav: boolean;
  bitsPerSample: number | null;
  frames: number;
}

const LSB_PREVIEW_CHARS = 2048;
// 倒放产物预览的变速档位（audio.playbackRate 直设，不重采样）。
const PLAYBACK_RATES = [0.5, 0.75, 1, 1.25, 1.5];
// 阈值位流预览的游程段数上限（超出部分只计入统计，不刷屏）。
const RUNS_PREVIEW_COUNT = 32;

// 频谱热力色（黑→深蓝→橙→白 的简易插值，亮=能量高）：v∈[0,1]。
const heatColor = (value: number): [number, number, number] => {
  const v = Math.min(1, Math.max(0, value));
  const r = Math.round(255 * Math.min(1, Math.max(0, 2.2 * v - 0.5)));
  const g = Math.round(255 * Math.min(1, Math.max(0, 1.9 * v - 0.75)));
  const b = Math.round(255 * Math.min(1, Math.max(0, v < 0.35 ? 1.15 * v + 0.25 : 1.65 - 3.6 * v)));
  return [r, g, b];
};

function AudioStegoCard({ file, language }: AudioStegoCardProps) {
  const zh = language === 'zh';
  const [decoded, setDecoded] = useState<DecodedAudio | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const [dtmf, setDtmf] = useState<string | null>(null);
  const [morse, setMorse] = useState<{ text: string; timeline: string } | null>(null);
  const [morseLower, setMorseLower] = useState(false);
  const [lsbChannel, setLsbChannel] = useState(0);
  const [lsbBit, setLsbBit] = useState(0);
  const [lsbText, setLsbText] = useState<string | null>(null);
  // 倒放：原始文件字节留引用供 reverseWav 整体解析（本卡按文件 key remount，无跨文件残留）。
  const bytesRef = useRef<Uint8Array | null>(null);
  const [reversed, setReversed] = useState<{ url: string; bytes: Uint8Array } | null>(null);
  const [reversedError, setReversedError] = useState<string | null>(null);
  // PCM 波形变换（声道差/一阶差分/波形反相）：产物 WAV + 说明；阈值位流：字节流 + 游程统计。
  const [pcmTransform, setPcmTransform] = useState<{ url: string; bytes: Uint8Array; note: string; suffix: string } | null>(null);
  const [bitstream, setBitstream] = useState<{ bytes: Uint8Array; note: string; runsText: string } | null>(null);
  const [transformError, setTransformError] = useState<string | null>(null);
  const [thresholdValue, setThresholdValue] = useState(0);
  const [thresholdWindow, setThresholdWindow] = useState(1);
  // blob 音频被页面 CSP（media-src 缺 blob:）或环境拦截时 audio 触发 error：给持久红字兜底而非静默控件
  const [reversedLoadError, setReversedLoadError] = useState(false);
  const [playbackRate, setPlaybackRate] = useState(1);
  const reverseAudioRef = useRef<HTMLAudioElement | null>(null);
  const spectroRef = useRef<HTMLCanvasElement | null>(null);

  // 解码是异步副作用：本卡由父层按文件 key remount，state 无跨文件残留。
  useEffect(() => {
    let cancelled = false;
    const decode = async () => {
      try {
        const bytes = new Uint8Array(await file.arrayBuffer());
        bytesRef.current = bytes;
        try {
          const wav = parseWav(bytes);
          if (!cancelled) setDecoded({
            samples: wav.samples, sampleRate: wav.info.sampleRate, channels: wav.info.channels,
            isWav: true, bitsPerSample: wav.info.bitsPerSample, frames: wav.info.frames,
          });
          return;
        } catch {
          // 非 PCM WAV：交给浏览器解码（mp3/flac/ogg 等压缩格式）
        }
        const AudioCtx = window.AudioContext ?? (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
        const ctx = new AudioCtx();
        try {
          const buffer = await ctx.decodeAudioData(await file.arrayBuffer());
          const channels = buffer.numberOfChannels;
          const frames = buffer.length;
          const samples = new Float64Array(frames * channels);
          for (let channel = 0; channel < channels; channel += 1) {
            const data = buffer.getChannelData(channel);
            for (let frame = 0; frame < frames; frame += 1) samples[frame * channels + channel] = data[frame];
          }
          if (!cancelled) setDecoded({ samples, sampleRate: buffer.sampleRate, channels, isWav: false, bitsPerSample: null, frames });
        } finally {
          void ctx.close();
        }
      } catch {
        if (!cancelled) setFailed(zh ? '无法解码该音频（浏览器不支持的格式）。' : 'The browser could not decode this audio format.');
      }
    };
    void decode();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [file]);

  // 第一通道（分析口径与引擎一致：DTMF/摩尔斯/频谱均单声道足够）。
  const mono = useMemo(() => {
    if (!decoded) return null;
    if (decoded.channels === 1) return decoded.samples;
    const out = new Float64Array(decoded.frames);
    for (let frame = 0; frame < decoded.frames; frame += 1) out[frame] = decoded.samples[frame * decoded.channels];
    return out;
  }, [decoded]);

  // 频谱图：引擎算矩阵，这里只做像素映射（y 轴翻转：低频在下）。
  const spectrogram = useMemo(() => (mono && decoded ? computeSpectrogram(mono, decoded.sampleRate) : null), [mono, decoded]);

  useEffect(() => {
    const canvas = spectroRef.current;
    if (!canvas || !spectrogram) return;
    const { matrix, bins, frames } = spectrogram;
    canvas.width = Math.max(1, frames);
    canvas.height = Math.max(1, bins);
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const image = ctx.createImageData(canvas.width, canvas.height);
    for (let frame = 0; frame < frames; frame += 1) {
      for (let bin = 0; bin < bins; bin += 1) {
        const [r, g, b] = heatColor(matrix[frame * bins + bin]);
        const offset = ((bins - 1 - bin) * frames + frame) * 4;
        image.data[offset] = r;
        image.data[offset + 1] = g;
        image.data[offset + 2] = b;
        image.data[offset + 3] = 255;
      }
    }
    ctx.putImageData(image, 0, 0);
  }, [spectrogram]);

  const runLsb = () => {
    if (!decoded || !decoded.isWav) return;
    const bytes = extractWavLsb({ info: { sampleRate: decoded.sampleRate, channels: decoded.channels, bitsPerSample: decoded.bitsPerSample ?? 16, dataBytes: 0, frames: decoded.frames, formatTag: 1 }, samples: decoded.samples }, { channel: lsbChannel, bit: lsbBit });
    setLsbText(bytesToPreviewText(bytes, LSB_PREVIEW_CHARS));
  };

  const copyText = (text: string) => {
    void copyToClipboard(text).then(ok => {
      if (!ok) notifications.show({ message: zh ? '复制失败，请手动选择文本。' : 'Copy failed; select the text manually.', color: 'red' });
      else notifications.show({ message: zh ? '已复制。' : 'Copied.', color: 'teal', autoClose: 1600 });
    });
  };

  const baseName = file.name.replace(/\.[^.]+$/, '');
  // DTMF 未检出占位文案（按钮 onClick 与复制按钮门控共用同一常量，避免两处字符串漂移）
  const dtmfEmptyText = zh ? '（未检出 DTMF 按键）' : '(no DTMF digits detected)';

  // 倒放对整份文件字节跑引擎（解析→帧反转→重编码）；失败信息来自引擎的中文错误直接展示。
  const runReverse = () => {
    const fileBytes = bytesRef.current;
    if (!fileBytes) return;
    try {
      const out = reverseWav(fileBytes);
      const url = URL.createObjectURL(new Blob([out.slice()], { type: 'audio/wav' }));
      if (reversed) URL.revokeObjectURL(reversed.url);
      setReversed({ url, bytes: out });
      setReversedError(null);
      setReversedLoadError(false);
    } catch (error) {
      setReversedError(error instanceof Error ? error.message : String(error));
    }
  };

  // 变速只改 audio.playbackRate（不重采样）；audio 元素重建后借 onLoadedMetadata 回填当前档位。
  const changePlaybackRate = (rate: number) => {
    setPlaybackRate(rate);
    if (reverseAudioRef.current) reverseAudioRef.current.playbackRate = rate;
  };

  // PCM 波形变换三档：整份文件字节跑引擎，产物 WAV 可试听/下载；失败展示引擎中文错误。
  const runPcmTransform = (kind: 'chdiff' | 'delta' | 'invert') => {
    const fileBytes = bytesRef.current;
    if (!fileBytes) return;
    try {
      let wav: Uint8Array;
      let note: string;
      if (kind === 'chdiff') {
        const result = channelDiffWav(fileBytes);
        wav = result.wav;
        note = zh
          ? `声道差（L−R）→ 32bit 单声道；${result.clamped} 个样本饱和钳位`
          : `Channel diff (L−R) → 32-bit mono; ${result.clamped} samples clamped`;
      } else if (kind === 'delta') {
        wav = deltaWav(fileBytes);
        note = zh ? '一阶差分（逐通道 wrap，d[0]=x[0]）' : 'First-order delta (per-channel wrap, d[0]=x[0])';
      } else {
        wav = invertWav(fileBytes);
        note = zh ? '波形反相（wrap −x）' : 'Waveform inverted (wrap −x)';
      }
      const url = URL.createObjectURL(new Blob([wav.slice()], { type: 'audio/wav' }));
      if (pcmTransform) URL.revokeObjectURL(pcmTransform.url);
      setPcmTransform({ url, bytes: wav, note, suffix: kind });
      setTransformError(null);
    } catch (error) {
      setTransformError(error instanceof Error ? error.message : String(error));
    }
  };

  // 阈值位流：按当前阈值/窗宽对解码样本执行，展示 LSB-first 字节预览与游程统计。
  const runThreshold = () => {
    if (!decoded) return;
    try {
      const result = extractThresholdBitstream(
        {
          info: {
            sampleRate: decoded.sampleRate, channels: decoded.channels, bitsPerSample: decoded.bitsPerSample ?? 16,
            dataBytes: 0, frames: decoded.frames, formatTag: 1,
          },
          samples: decoded.samples,
        },
        { threshold: thresholdValue, window: Math.max(1, Math.floor(thresholdWindow)) },
      );
      const runsShown = result.runs.slice(0, RUNS_PREVIEW_COUNT);
      const runsText = [
        runsShown.map(run => `${run.value}×${run.length}`).join(', '),
        result.runs.length > RUNS_PREVIEW_COUNT ? '…' : '',
      ].filter(Boolean).join('');
      const note = zh
        ? `${result.totalBits} 位（窗口 ${Math.max(1, Math.floor(thresholdWindow))}），1 共 ${result.ones} 个${result.droppedTailSamples > 0 ? `；尾样本丢弃 ${result.droppedTailSamples}` : ''}`
        : `${result.totalBits} bits (window ${Math.max(1, Math.floor(thresholdWindow))}), ${result.ones} ones${result.droppedTailSamples > 0 ? `; ${result.droppedTailSamples} tail samples dropped` : ''}`;
      setBitstream({ bytes: result.bytes, note, runsText });
      setTransformError(null);
    } catch (error) {
      setTransformError(error instanceof Error ? error.message : String(error));
    }
  };

  if (failed) {
    return (
      <section id="ff-card-audio" className="ff-card" aria-label={zh ? '音频隐写分析' : 'Audio steganography'}>
        <div className="ff-card-head"><strong>{zh ? '音频隐写分析' : 'Audio steganography'}</strong></div>
        <p className="ff-note">{failed}</p>
      </section>
    );
  }

  return (
    <section id="ff-card-audio" className="ff-card" aria-label={zh ? '音频隐写分析' : 'Audio steganography'}>
      <div className="ff-card-head">
        <strong>{zh ? '音频隐写分析' : 'Audio steganography'}</strong>
        {decoded && (
          <span className="ff-badge">
            {decoded.sampleRate} Hz · {decoded.channels}ch · {(decoded.frames / decoded.sampleRate).toFixed(1)}s{decoded.isWav && decoded.bitsPerSample ? ` · ${decoded.bitsPerSample}bit` : ''}
          </span>
        )}
      </div>
      {!decoded && <p className="ff-note">{zh ? '正在解码音频…' : 'Decoding audio…'}</p>}
      {decoded && mono && (
        <>
          <div className="ff-tool">
            <span className="ff-label">{zh ? '频谱图（隐藏文字/摩尔斯/SSTV 常藏在频谱里；y 轴低频在下，亮色 = 能量高）' : 'Spectrogram (hidden text/Morse/SSTV often live here; low freq at bottom, bright = energy)'}</span>
            {spectrogram && (
              <canvas ref={spectroRef} className="ff-spectrogram" aria-label={zh ? '频谱图' : 'Spectrogram'} />
            )}
          </div>
          <div className="ff-tool">
            <span className="ff-label">{zh ? '信号解码（DTMF 电话拨号音 / 摩尔斯电码）' : 'Signal decoding (DTMF tones / Morse code)'}</span>
            <div className="ff-row">
              <button type="button" className="ff-button" onClick={() => setDtmf(dtmfDecode(mono, decoded.sampleRate) || dtmfEmptyText)}>
                {zh ? 'DTMF 解码' : 'Decode DTMF'}
              </button>
              <button type="button" className="ff-button" onClick={() => setMorse(morseDecodeAudio(mono, decoded.sampleRate))}>
                {zh ? '摩尔斯解码' : 'Decode Morse'}
              </button>
            </div>
            {dtmf !== null && (
              <>
                <code className="ff-code"><FlagAutoText text={dtmf} /></code>
                {/* F-15：解码结果一键复制（复用卡内 copyText + toast 反馈）；未检出占位不给复制按钮 */}
                {dtmf !== dtmfEmptyText && (
                  <div className="ff-row">
                    <button type="button" className="ff-button" onClick={() => copyText(dtmf)}>{zh ? '复制结果' : 'Copy result'}</button>
                  </div>
                )}
              </>
            )}
            {morse && (
              <>
                <code className="ff-code">
                  {`${zh ? '文本' : 'Text'}: ${morseLower ? morse.text.toLowerCase() : (morse.text || (zh ? '（空）' : '(empty)'))}\n${zh ? '原始点划' : 'Raw timeline'}: ${morse.timeline}`}
                </code>
                {morse.text && (
                  <div className="ff-row">
                    <button type="button" className="ff-button" onClick={() => copyText(morseLower ? morse.text.toLowerCase() : morse.text)}>
                      {zh ? '复制文本' : 'Copy text'}
                    </button>
                  </div>
                )}
              </>
            )}
            {morse && morse.text && (
              <div className="ff-row">
                {/* 摩尔斯本身无大小写语义，引擎输出统一大写；对拍大小写敏感的 flag 时切小写（UI 审计 B4） */}
                <label className="ff-label" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  <input type="checkbox" checked={morseLower} onChange={event => setMorseLower(event.target.checked)} />
                  {zh ? '小写输出（对拍大小写敏感的 flag）' : 'lowercase output (case-sensitive flag compare)'}
                </label>
              </div>
            )}
          </div>
          {decoded.isWav && (
            <div className="ff-tool">
              <span className="ff-label">{zh ? 'WAV LSB 提取（帧序、高位在前组字节）' : 'WAV LSB extraction (frame order, MSB first)'}</span>
              <div className="ff-row">
                <select className="ff-select" value={lsbChannel} aria-label={zh ? '提取通道' : 'Channel'} onChange={event => setLsbChannel(Number(event.target.value))}>
                  {Array.from({ length: decoded.channels }, (_, index) => index).map(channel => (
                    <option key={channel} value={channel}>{zh ? `通道 ${channel}` : `Channel ${channel}`}</option>
                  ))}
                </select>
                <select className="ff-select" value={lsbBit} aria-label={zh ? '提取位' : 'Bit'} onChange={event => setLsbBit(Number(event.target.value))}>
                  {(decoded.bitsPerSample && decoded.bitsPerSample >= 16 ? [0, 1, 2, 3, 4, 5, 6, 7] : [0, 1, 2, 3]).map(bit => <option key={bit} value={bit}>bit {bit}</option>)}
                </select>
                <button type="button" className="ff-button ff-button-primary" onClick={runLsb}>{zh ? '提取' : 'Extract'}</button>
              </div>
              {lsbText !== null && (
                <>
                  <code className="ff-code"><FlagAutoText text={lsbText} /></code>
                  <div className="ff-row">
                    <button type="button" className="ff-button" onClick={() => copyText(lsbText)}>{zh ? '复制文本' : 'Copy text'}</button>
                  </div>
                </>
              )}
            </div>
          )}
          {decoded.isWav && (
            <div className="ff-tool">
              <span className="ff-label">{zh ? 'PCM 波形变换（声道差抬升立体声平衡差 / 差分放大突变 / 反相消背景）' : 'PCM transforms (channel diff, delta, invert)'}</span>
              <div className="ff-row">
                <button type="button" className="ff-button" onClick={() => runPcmTransform('chdiff')}>{zh ? '声道差' : 'Channel diff'}</button>
                <button type="button" className="ff-button" onClick={() => runPcmTransform('delta')}>{zh ? '一阶差分' : 'Delta'}</button>
                <button type="button" className="ff-button" onClick={() => runPcmTransform('invert')}>{zh ? '波形反相' : 'Invert'}</button>
              </div>
              <div className="ff-row">
                <label className="ff-label">
                  {zh ? '阈值' : 'Threshold'}
                  <input
                    className="ff-input"
                    style={{ width: 84 }}
                    type="number"
                    value={thresholdValue}
                    aria-label={zh ? '阈值位流阈值' : 'Bitstream threshold'}
                    onChange={event => setThresholdValue(Number(event.target.value))}
                  />
                </label>
                <label className="ff-label">
                  {zh ? '窗宽' : 'Window'}
                  <input
                    className="ff-input"
                    style={{ width: 64 }}
                    type="number"
                    min={1}
                    value={thresholdWindow}
                    aria-label={zh ? '阈值位流窗宽' : 'Bitstream window'}
                    onChange={event => setThresholdWindow(Number(event.target.value))}
                  />
                </label>
                <button type="button" className="ff-button" onClick={runThreshold}>{zh ? '阈值位流' : 'Threshold bitstream'}</button>
              </div>
              {pcmTransform && (
                <>
                  <code className="ff-code">{pcmTransform.note}</code>
                  <div className="ff-row">
                    <button
                      type="button"
                      className="ff-button"
                      onClick={() => downloadBytes(pcmTransform.bytes, `${baseName}-${pcmTransform.suffix}.wav`, 'audio/wav')}
                    >
                      {zh ? '下载产物 WAV' : 'Download WAV'}
                    </button>
                  </div>
                  <audio
                    controls
                    src={pcmTransform.url}
                    style={{ width: '100%' }}
                    onError={() => setTransformError(zh ? '变换产物 WAV 加载失败' : 'Transformed WAV failed to load')}
                  />
                </>
              )}
              {bitstream && (
                <>
                  <code className="ff-code">{`${bitstream.note}\n${zh ? '游程' : 'Runs'}: ${bitstream.runsText}`}</code>
                  <code className="ff-code"><FlagAutoText text={bytesToPreviewText(bitstream.bytes, LSB_PREVIEW_CHARS)} /></code>
                  <div className="ff-row">
                    <button type="button" className="ff-button" onClick={() => downloadBytes(bitstream.bytes, `${baseName}-threshold.bin`, 'application/octet-stream')}>
                      {zh ? '下载位流' : 'Download bitstream'}
                    </button>
                    <button type="button" className="ff-button" onClick={() => copyText(bytesToPreviewText(bitstream.bytes, LSB_PREVIEW_CHARS))}>
                      {zh ? '复制文本' : 'Copy text'}
                    </button>
                  </div>
                </>
              )}
              {transformError !== null && <p className="ff-note">{transformError}</p>}
            </div>
          )}
          {decoded.isWav && (
            <div className="ff-tool">
              <span className="ff-label">{zh ? '音频倒放（时间维反转；倒放语音/摩尔斯是常见藏匿手法，可变速试听）' : 'Audio reversal (time-reversed; reversed speech/Morse is a common hideout, try variable speed)'}</span>
              <div className="ff-row">
                <button type="button" className="ff-button ff-button-primary" onClick={runReverse}>{zh ? '生成倒放' : 'Reverse audio'}</button>
                {reversed && (
                  <>
                    <select
                      className="ff-select"
                      value={playbackRate}
                      aria-label={zh ? '变速播放' : 'Playback speed'}
                      onChange={event => changePlaybackRate(Number(event.target.value))}
                    >
                      {PLAYBACK_RATES.map(rate => <option key={rate} value={rate}>{rate}x</option>)}
                    </select>
                    <button type="button" className="ff-button" onClick={() => downloadBytes(reversed.bytes, `${baseName}-reversed.wav`, 'audio/wav')}>
                      {zh ? '下载倒放' : 'Download reversed'}
                    </button>
                  </>
                )}
              </div>
              {reversedError !== null && <p className="ff-note">{reversedError}</p>}
              {reversed && reversedLoadError && (
                <p className="ff-note" style={{ color: 'var(--sev-critical)' }} role="alert">
                  {zh
                    ? '倒放音频加载失败：浏览器安全策略拦截了本地音频（media-src 未放行 blob:）。请升级服务端后刷新重试，或改用「下载倒放」在本地播放器中收听。'
                    : 'Reversed audio failed to load: the browser security policy blocked local audio (media-src does not allow blob:). Update the server and retry, or use "Download reversed" to listen in a local player.'}
                </p>
              )}
              {reversed && (
                <audio
                  ref={reverseAudioRef}
                  controls
                  src={reversed.url}
                  onError={() => setReversedLoadError(true)}
                  onLoadedMetadata={() => { setReversedLoadError(false); if (reverseAudioRef.current) reverseAudioRef.current.playbackRate = playbackRate; }}
                  style={{ width: '100%' }}
                />
              )}
            </div>
          )}
        </>
      )}
    </section>
  );
}

export default AudioStegoCard;
