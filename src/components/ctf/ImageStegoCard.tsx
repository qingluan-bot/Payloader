import { useCallback, useRef, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { FlagAutoText } from '../codec/FlagAutoText';
import type { PlaneImage } from './ImagePlanesCard';
import { arnoldInverse, arnoldPeriod, arnoldTransform } from '../../utils/ctf/arnold';
import { rasterCompact, rasterPhasePlan, stereogramDiff, stereogramEstimateOffset } from '../../utils/ctf/rasterStego';
import { blindWatermarkDecode } from '../../utils/ctf/blindWatermark';
import {
  dwtSvdEmbedText,
  dwtSvdExtractImage,
  dwtSvdExtractText,
  dwtSvdExtractTextAuto,
} from '../../utils/ctf/blindWatermarkDwtSvd';
import { watermarkhExtract } from '../../utils/ctf/watermarkhFft';
import { pixelJihadDecode } from '../../utils/ctf/pixelJihad';
import { runImageProgram } from '../../utils/ctf/esolangs';
import { runPiet } from '../../utils/ctf/pietInterp';
import { stegpyDecodeFromPixels } from '../../utils/ctf/stegpy';
import { openstegoDecodeFromPixels } from '../../utils/ctf/openstego';
import { decodeQrCodes } from '../../utils/ctf/qrDecode';
import { scaleNearest } from '../../utils/ctf/imageOps';
import { downloadBlob } from '../../utils/download';

// 置乱与频域隐写卡（批次 SI·C/B 线）：Arnold 猫脸/光栅相位/Stereogram 偏移差分/盲水印双图提取/
// PixelJihad/Brainloller+Braincopter。全部纯本地运算。
interface ImageStegoCardProps {
  image: PlaneImage;
  language: 'zh' | 'en';
}

type AnyImage = { data: Uint8ClampedArray | ArrayLike<number>; width: number; height: number };

const RASTER_THUMB = 110;

function StegoCanvas({ image, scaleTo, language }: { image: AnyImage; scaleTo: number; language: 'zh' | 'en' }) {
  const ref = useRef<HTMLCanvasElement | null>(null);
  const attach = useCallback(
    (node: HTMLCanvasElement | null) => {
      ref.current = node;
      if (node === null) return;
      const source = document.createElement('canvas');
      source.width = image.width;
      source.height = image.height;
      const sourceCtx = source.getContext('2d');
      if (sourceCtx === null) return;
      const clamped = image.data instanceof Uint8ClampedArray ? image.data : new Uint8ClampedArray(image.data);
      sourceCtx.putImageData(new ImageData(clamped as Uint8ClampedArray<ArrayBuffer>, image.width, image.height), 0, 0);
      const scale = Math.min(1, scaleTo / Math.max(image.width, image.height));
      node.width = Math.max(1, Math.round(image.width * scale));
      node.height = Math.max(1, Math.round(image.height * scale));
      const ctx = node.getContext('2d');
      if (ctx === null) return;
      ctx.imageSmoothingEnabled = false;
      ctx.drawImage(source, 0, 0, node.width, node.height);
    },
    [image, scaleTo],
  );
  const download = useCallback(() => {
    const canvas = document.createElement('canvas');
    canvas.width = image.width;
    canvas.height = image.height;
    const ctx = canvas.getContext('2d');
    if (ctx === null) return;
    const clamped = image.data instanceof Uint8ClampedArray ? image.data : new Uint8ClampedArray(image.data);
    ctx.putImageData(new ImageData(clamped as Uint8ClampedArray<ArrayBuffer>, image.width, image.height), 0, 0);
    void canvas.toBlob(blob => {
      if (blob !== null) void downloadBlob(blob, 'stego-result.png');
    });
  }, [image]);
  void language;
  return (
    <div className="ff-row">
      <canvas ref={attach} className="ff-canvas" aria-label="result" />
      <button type="button" className="ff-button" onClick={download}>PNG</button>
    </div>
  );
}

const readSecondImage = async (file: File): Promise<AnyImage> => {
  const bitmap = await createImageBitmap(file);
  const width = bitmap.width;
  const height = bitmap.height;
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  if (ctx === null) throw new Error('canvas 2d 上下文不可用');
  ctx.drawImage(bitmap, 0, 0);
  bitmap.close();
  if (width * height > 4_000_000) throw new Error(`第二张图 ${width}×${height} 超过 400 万像素上限，请先缩小`);
  return { data: ctx.getImageData(0, 0, width, height).data, width, height };
};

function ImageStegoCard({ image, language }: ImageStegoCardProps) {
  const zh = language === 'zh';
  const source: AnyImage = { data: image.rgba, width: image.width, height: image.height };
  const square = image.width === image.height;
  const [result, setResult] = useState<AnyImage | null>(null);
  const [textOut, setTextOut] = useState<string | null>(null);
  const [arnoldIterations, setArnoldIterations] = useState('1');
  const [arnoldA, setArnoldA] = useState('1');
  const [arnoldB, setArnoldB] = useState('1');
  const [rasterCandidates, setRasterCandidates] = useState<Array<{ axis: string; period: number; phase: number; image: AnyImage }> | null>(null);
  const [stereoOffset, setStereoOffset] = useState('100');
  const [bwSecond, setBwSecond] = useState<AnyImage | null>(null);
  const [bwSeed, setBwSeed] = useState('20160930');
  const [bwAlpha, setBwAlpha] = useState('3');
  const [pjPassword, setPjPassword] = useState('');
  const [dwtSvdMessage, setDwtSvdMessage] = useState('flag{watermark}');
  const [dwtSvdPasswordImg, setDwtSvdPasswordImg] = useState('1');
  const [dwtSvdPasswordWm, setDwtSvdPasswordWm] = useState('1');
  const [dwtSvdMode, setDwtSvdMode] = useState<'text' | 'image'>('text');
  const [dwtSvdBitCount, setDwtSvdBitCount] = useState('');
  const [dwtSvdWmWidth, setDwtSvdWmWidth] = useState('32');
  const [dwtSvdWmHeight, setDwtSvdWmHeight] = useState('32');
  const [wmhAuto, setWmhAuto] = useState(true);
  const [wmhSuppress, setWmhSuppress] = useState(false);
  const [wmhNormalize, setWmhNormalize] = useState(true);
  const [wmhGain, setWmhGain] = useState('10');

  const arnoldOptions = () => {
    const iterations = Math.max(1, Number(arnoldIterations) || 1);
    const a = Number(arnoldA) || 1;
    const b = Number(arnoldB) || 1;
    return { iterations, a, b };
  };

  return (
    <section id="ff-card-imagestego" className="ff-card" aria-label={zh ? '置乱与频域隐写' : 'Scramble & frequency stego'}>
      <div className="ff-card-head">
        <strong>{zh ? '置乱与频域隐写' : 'Scramble & frequency stego'}</strong>
        <span className="ff-badge">{image.width}×{image.height}</span>
      </div>

      <div className="ff-tool">
        <span className="ff-label">{zh ? 'Arnold 猫脸变换（矩阵 [[1,a],[b,ab+1]]，a=b=1 标准）' : 'Arnold cat map'}</span>
        {!square && <p className="ff-note">{zh ? '非方阵图像需先裁成正方形（Arnold 要求 N×N）。' : 'Arnold requires a square image.'}</p>}
        {square && (
          <>
            <div className="ff-row">
              <input className="ff-input" style={{ width: 80 }} value={arnoldIterations} aria-label={zh ? '迭代次数' : 'Iterations'} onChange={event => setArnoldIterations(event.target.value)} />
              <input className="ff-input" style={{ width: 50 }} value={arnoldA} aria-label="a" onChange={event => setArnoldA(event.target.value)} />
              <input className="ff-input" style={{ width: 50 }} value={arnoldB} aria-label="b" onChange={event => setArnoldB(event.target.value)} />
              <button type="button" className="ff-button ff-button-primary" onClick={() => { setResult(arnoldTransform(source, arnoldOptions())); setTextOut(null); }}>{zh ? '置乱' : 'Scramble'}</button>
              <button type="button" className="ff-button" onClick={() => { setResult(arnoldInverse(source, arnoldOptions())); setTextOut(null); }}>{zh ? '还原' : 'Restore'}</button>
              <span className="ff-badge">
                {zh ? `周期 ${arnoldPeriod(image.width, Number(arnoldA) || 1, Number(arnoldB) || 1)}` : `Period ${arnoldPeriod(image.width, Number(arnoldA) || 1, Number(arnoldB) || 1)}`}
              </span>
            </div>
            <p className="ff-note">{zh ? '无迭代次数时按周期穷举：依次试「还原 1..周期-1 次」目检。' : 'Brute-force tip: restore 1..period-1 times and eyeball.'}</p>
          </>
        )}
      </div>

      <div className="ff-tool">
        <span className="ff-label">{zh ? '光栅栅栏图（周期 2-10 相位抽取）' : 'Raster interleaving (period 2-10)'}</span>
        <div className="ff-row">
          <button type="button" className="ff-button" onClick={() => {
            // 元数据先行 + 懒算（reviewer P1：逐候选物化整图在 4M 像素图上瞬时分配 >1GB）
            const plan = rasterPhasePlan(image.width, image.height, 10).slice(0, 60);
            setRasterCandidates(plan.map(item => ({ axis: item.axis, period: item.period, phase: item.phase, image: rasterCompact(source, item.axis, item.period, item.phase) })));
          }}>{zh ? '全相位扫描' : 'Scan all phases'}</button>
          {rasterCandidates !== null && <span className="ff-badge">{rasterCandidates.length} {zh ? '候选' : 'candidates'}</span>}
        </div>
        {rasterCandidates !== null && (
          <div className="ff-row" style={{ flexWrap: 'wrap' }}>
            {rasterCandidates.map(item => (
              <div key={`${item.axis}-${item.period}-${item.phase}`} style={{ textAlign: 'center' }}>
                <StegoCanvas image={item.image} scaleTo={RASTER_THUMB} language={language} />
                <span className="ff-badge">{item.axis === 'x' ? '列' : '行'}p{item.period}·φ{item.phase}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="ff-tool">
        <span className="ff-label">{zh ? 'Stereogram 立体图求解（偏移差分显深度）' : 'Stereogram solver'}</span>
        <div className="ff-row">
          <input className="ff-input" style={{ width: 80 }} value={stereoOffset} aria-label="offset" onChange={event => setStereoOffset(event.target.value)} />
          <button type="button" className="ff-button" onClick={() => { setResult(stereogramDiff(source, Math.max(1, Number(stereoOffset) || 1))); setTextOut(null); }}>{zh ? '差分' : 'Diff'}</button>
          <button type="button" className="ff-button" onClick={() => {
            const estimate = stereogramEstimateOffset(source, 32, 256);
            setStereoOffset(String(estimate.bestOffset));
            setResult(stereogramDiff(source, estimate.bestOffset));
            setTextOut(null);
          }}>{zh ? '自动估周期' : 'Auto offset'}</button>
        </div>
      </div>

      <div className="ff-tool">
        <span className="ff-label">{zh ? '盲水印双图提取（chishaxie FFT 版，需原图+水印图）' : 'Blind watermark (FFT)'}</span>
        <div className="ff-row">
          <input
            type="file"
            accept="image/*"
            aria-label={zh ? '水印图（第二张）' : 'Watermarked image'}
            onChange={event => {
              const file = event.target.files?.[0];
              if (file === undefined) return;
              void readSecondImage(file).then(
                loaded => setBwSecond(loaded),
                error => notifications.show({ message: (error as Error).message, color: 'red' }),
              );
            }}
          />
          {bwSecond !== null && <span className="ff-badge">{bwSecond.width}×{bwSecond.height}</span>}
        </div>
        <div className="ff-row">
          <input className="ff-input" style={{ width: 110 }} value={bwSeed} aria-label="seed" onChange={event => setBwSeed(event.target.value)} />
          <input className="ff-input" style={{ width: 60 }} value={bwAlpha} aria-label="alpha" onChange={event => setBwAlpha(event.target.value)} />
          <button type="button" className="ff-button ff-button-primary" disabled={bwSecond === null} onClick={() => {
            try {
              setResult(blindWatermarkDecode(source, bwSecond!, { seed: Number(bwSeed), alpha: Number(bwAlpha) }));
              setTextOut(null);
            } catch (error) { notifications.show({ message: (error as Error).message, color: 'red' }); }
          }}>{zh ? '提取水印' : 'Extract'}</button>
        </div>
      </div>

      <div className="ff-tool">
        <span className="ff-label">{zh ? '盲水印 DWT-DCT-SVD（guofei9987 版，单图真盲：提取不需要原图）' : 'Blind watermark DWT-DCT-SVD (single image)'}</span>
        <div className="ff-row">
          <input className="ff-input" style={{ width: 200 }} value={dwtSvdMessage} aria-label={zh ? '水印文本（嵌入用）' : 'Watermark text'} placeholder="flag{...}" onChange={event => setDwtSvdMessage(event.target.value)} />
          <input className="ff-input" style={{ width: 60 }} value={dwtSvdPasswordImg} aria-label={zh ? 'password_img（图种子）' : 'password_img'} title={zh ? '频域分块置乱种子，默认 1' : 'Block shuffle seed, default 1'} onChange={event => setDwtSvdPasswordImg(event.target.value)} />
          <input className="ff-input" style={{ width: 60 }} value={dwtSvdPasswordWm} aria-label={zh ? 'password_wm（文种子）' : 'password_wm'} title={zh ? '水印位流置乱种子，默认 1' : 'Bit shuffle seed, default 1'} onChange={event => setDwtSvdPasswordWm(event.target.value)} />
          <button type="button" className="ff-button ff-button-primary" onClick={() => {
            try {
              const outcome = dwtSvdEmbedText(source, dwtSvdMessage, { passwordImg: Number(dwtSvdPasswordImg) || 1, passwordWm: Number(dwtSvdPasswordWm) || 1 });
              setResult(outcome.image);
              setTextOut(`${zh ? '已嵌入' : 'Embedded'} ${outcome.wmBitCount} bit / ${outcome.blockNum} ${zh ? '块' : 'blocks'}——下载 PNG 后可用本工具或 blind_watermark 库提取`);
            } catch (error) { notifications.show({ message: (error as Error).message, color: 'red' }); }
          }}>{zh ? '嵌入文本水印' : 'Embed text'}</button>
        </div>
        <div className="ff-row">
          <select className="ff-input" style={{ width: 90 }} value={dwtSvdMode} aria-label={zh ? '水印类型' : 'Watermark kind'} onChange={event => setDwtSvdMode(event.target.value === 'image' ? 'image' : 'text')}>
            <option value="text">{zh ? '文本水印' : 'Text'}</option>
            <option value="image">{zh ? '图片水印' : 'Image'}</option>
          </select>
          {dwtSvdMode === 'text' ? (
            <input className="ff-input" style={{ width: 130 }} value={dwtSvdBitCount} aria-label={zh ? '水印位长（留空自动扫）' : 'Bit count'} placeholder={zh ? '位长(空=自动)' : 'bits (auto)'} title={zh ? '嵌入时输出的 bit 数；不知道就留空自动扫描' : 'Bit count printed on embed; leave empty to auto-scan'} onChange={event => setDwtSvdBitCount(event.target.value)} />
          ) : (
            <>
              <input className="ff-input" style={{ width: 60 }} value={dwtSvdWmWidth} aria-label="wm width" onChange={event => setDwtSvdWmWidth(event.target.value)} />
              <input className="ff-input" style={{ width: 60 }} value={dwtSvdWmHeight} aria-label="wm height" onChange={event => setDwtSvdWmHeight(event.target.value)} />
            </>
          )}
          <button type="button" className="ff-button ff-button-primary" onClick={() => {
            const options = { passwordImg: Number(dwtSvdPasswordImg) || 1, passwordWm: Number(dwtSvdPasswordWm) || 1 };
            try {
              if (dwtSvdMode === 'text') {
                const bitCount = Number(dwtSvdBitCount);
                const text = Number.isFinite(bitCount) && dwtSvdBitCount.trim() !== ''
                  ? dwtSvdExtractText(source, bitCount, options)
                  : dwtSvdExtractTextAuto(source, options).text;
                setTextOut(`${zh ? '提取文本' : 'Text'}: ${text}`);
                setResult(null);
              } else {
                setResult(dwtSvdExtractImage(source, { width: Math.max(1, Number(dwtSvdWmWidth) || 1), height: Math.max(1, Number(dwtSvdWmHeight) || 1) }, options));
                setTextOut(null);
              }
            } catch (error) { notifications.show({ message: (error as Error).message, color: 'red' }); }
          }}>{zh ? '提取水印' : 'Extract'}</button>
          <span className="ff-badge">{zh ? '密码' : 'keys'} img/wm = {dwtSvdPasswordImg || 1}/{dwtSvdPasswordWm || 1}</span>
        </div>
        <p className="ff-note">{zh ? '与 Python 库 blind_watermark（guofei9987）互通：默认参数 d1=36/d2=20、块 4×4、密码 1/1。图片水印提取需知道水印图宽高（wmShape）。' : 'Interop with the blind_watermark Python library: d1=36/d2=20, 4×4 blocks, keys 1/1. Image-watermark extraction needs wmShape.'}</p>
      </div>

      <div className="ff-tool">
        <span className="ff-label">{zh ? 'WaterMarkH 频域水印提取（幅度谱出图，文字人眼判读）' : 'WaterMarkH spectrum extraction'}</span>
        <div className="ff-row">
          <label className="ff-label" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <input type="checkbox" checked={wmhAuto} aria-label={zh ? '自动增益' : 'Auto gain'} onChange={event => setWmhAuto(event.target.checked)} />
            {zh ? '自动增益' : 'Auto gain'}
          </label>
          <label className="ff-label" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }} title={zh ? 'max(0, v−旋转180°副本)：削掉中心对称图案的重叠部分' : 'max(0, v − 180°-rotated copy)'}>
            <input type="checkbox" checked={wmhSuppress} aria-label={zh ? '压制镜像副本' : 'Suppress mirror'} onChange={event => setWmhSuppress(event.target.checked)} />
            {zh ? '压制镜像副本' : 'Suppress mirror'}
          </label>
          <label className="ff-label" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }} title={zh ? '按分位数把背景拉黑、文字提亮' : 'Percentile stretch'}>
            <input type="checkbox" checked={wmhNormalize} aria-label={zh ? '去背景归一化' : 'Normalize'} onChange={event => setWmhNormalize(event.target.checked)} />
            {zh ? '去背景归一化' : 'Normalize'}
          </label>
          {!wmhAuto && (
            <input className="ff-input" style={{ width: 70 }} value={wmhGain} aria-label="gain" title={zh ? '亮度系数，原软件默认 10' : 'Brightness, default 10'} onChange={event => setWmhGain(event.target.value)} />
          )}
          <button type="button" className="ff-button ff-button-primary" onClick={() => {
            try {
              const outcome = watermarkhExtract(source, {
                autoGain: wmhAuto,
                suppressMirror: wmhSuppress,
                normalize: wmhNormalize,
                gain: Number(wmhGain) || 10,
              });
              setResult(outcome.image);
              setTextOut(outcome.notes.join('\n') || null);
              if (wmhAuto) notifications.show({ message: `${zh ? '自动增益' : 'Auto gain'} ${outcome.gain.toFixed(1)}`, color: 'teal', autoClose: 3000 });
            } catch (error) { notifications.show({ message: (error as Error).message, color: 'red' }); }
          }}>{zh ? '提取幅度谱' : 'Extract spectrum'}</button>
        </div>
        <p className="ff-note">{zh ? '宽高需为 2 的幂（否则自动最近邻缩放并提示）。输出为幅度谱图：频谱上出现可读文字即命中 WaterMarkH（吾爱版）类隐藏水印。' : 'Width/height must be powers of two (auto nearest-neighbor scaled with a note otherwise). Readable text in the spectrum means a WaterMarkH-style watermark.'}</p>
      </div>

      <div className="ff-tool">
        <span className="ff-label">{zh ? 'PixelJihad 提取 / Brainloller·Braincopter 执行' : 'PixelJihad / brainloller·braincopter'}</span>
        <div className="ff-row">
          <input className="ff-input" style={{ width: 130 }} value={pjPassword} aria-label={zh ? '口令（可空）' : 'Password'} placeholder={zh ? '口令(可空)' : 'password'} onChange={event => setPjPassword(event.target.value)} />
          <button type="button" className="ff-button" onClick={() => {
            try {
              setTextOut(`${zh ? 'PixelJihad' : 'PixelJihad'}: ${pixelJihadDecode(source, pjPassword)}`);
              setResult(null);
            } catch (error) { notifications.show({ message: (error as Error).message, color: 'red' }); }
          }}>PixelJihad</button>
          <button type="button" className="ff-button" onClick={() => {
            // stegpy：像素字节流上的顺序 LSB（位深标记在第 0 字节），口令可选（Fernet）
            void stegpyDecodeFromPixels(source.data as unknown as Uint8Array, pjPassword).then(
              outcome => {
                const decodedText = new TextDecoder().decode(outcome.data);
                setTextOut(`stegpy${outcome.fileName !== '' ? ` (${outcome.fileName})` : ''}: ${decodedText.slice(0, 400)}`);
                setResult(null);
              },
              error => notifications.show({ message: (error as Error).message, color: 'red' }),
            );
          }}>stegpy</button>
          <button type="button" className="ff-button" onClick={() => {
            // openstego：lsb/randlsb 双试，口令参与 randlsb 位置与 PBE 解密
            void openstegoDecodeFromPixels({ data: source.data, width: source.width, height: source.height }, pjPassword).then(
              outcome => {
                const decodedText = new TextDecoder().decode(outcome.data.subarray(0, 400));
                setTextOut(`openstego${outcome.fileName !== '' ? ` (${outcome.fileName})` : ''}: ${decodedText}`);
                setResult(null);
                outcome.notes.forEach(note => notifications.show({ message: note, color: 'yellow', autoClose: 3000 }));
              },
              error => notifications.show({ message: (error as Error).message, color: 'red' }),
            );
          }}>OpenStego</button>
          <button type="button" className="ff-button" onClick={() => {
            // Piet：直接在像素上执行程序（先按最小边缩到单像素 codel？由调用方控制——这里原样执行）
            const outcome = runPiet(source.data, source.width, source.height);
            setTextOut(`Piet: ${outcome.output !== '' ? outcome.output.slice(0, 400) : (outcome.error ?? (zh ? '（无输出）' : '(no output)'))}`);
            setResult(null);
          }}>Piet</button>
          {(['brainloller', 'braincopter'] as const).map(flavor => (
            <button key={flavor} type="button" className="ff-button" onClick={() => {
              const outcome = runImageProgram(source, flavor);
              setTextOut(`${flavor}: ${outcome.run.output !== '' ? outcome.run.output.slice(0, 400) : (outcome.run.error ?? (zh ? '（无输出）' : '(no output)'))}`);
              setResult(null);
            }}>{flavor === 'brainloller' ? 'Brainloller' : 'Braincopter'}</button>
          ))}
        </div>
      </div>

      {result !== null && (
        <div className="ff-tool">
          <StegoCanvas image={result} scaleTo={360} language={language} />
          <button type="button" className="ff-button" onClick={() => {
            const scaled = result.width * result.height <= 128 * 128 ? scaleNearest(result, 4) : result;
            const hits = decodeQrCodes(scaled.data as ArrayLike<number>, scaled.width, scaled.height);
            setTextOut(hits.length > 0 ? `${zh ? '二维码命中' : 'QR hit'}: ${hits.map(hit => hit.text).join(' | ')}` : (zh ? '结果图中未识别出二维码' : 'No QR in result'));
          }}>{zh ? '识别结果图二维码' : 'Detect QR in result'}</button>
        </div>
      )}
      {textOut !== null && <code className="ff-code"><FlagAutoText text={textOut.slice(0, 4000)} /></code>}
    </section>
  );
}

export default ImageStegoCard;
