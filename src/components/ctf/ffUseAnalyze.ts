// ffUseAnalyze：杂项取证域的分析管线 hook（批次 P2-5 拆分自 FileForensicsWorkspace）。
// 承接原工作区的分析编排：文件载入/探测报告（loadFile）、图片预览 data URL、
// 位平面异步解码、五类修复（PNG/ZIP/BMP/GIF/JPG）状态机。纯状态与副作用容器，无 JSX；
// 视图消费方为 FileForensicsShell（面板渲染）与 OverviewCard（概览渲染）。
import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import { notifications } from '@mantine/notifications';
import {
  MAX_FILE_BYTES,
  detectFileTypes,
  detectZipEncryption,
  entropyLevel,
  extractStrings,
  extractZeroWidthFromText,
  fixPngDimensions,
  fixZipPseudoEncryption,
  hexdumpPreview,
  parsePngIhdr,
  scanSuspiciousContent,
  shannonEntropy,
} from '../../utils/ctf/fileDetect';
import {
  enumeratePngChunks,
  findGifTrailer,
  findJpegTrailer,
  findPngTrailer,
  scanEmbeddedSignatures,
} from '../../utils/ctf/embedScan';
import type { PngChunkList } from "../../utils/ctf/embedScan";
import {
  guessGifSize,
  repairBmp,
  repairGif,
  repairGifWithSize,
  repairJpg,
} from '../../utils/ctf/fileRepair';
import type { FileRepairResult, GifSizeGuess, JpgRepairResult } from '../../utils/ctf/fileRepair';
import { extractNtfsAds } from '../../utils/ctf/ntfsAds';
import type { NtfsAdsReport } from '../../utils/ctf/ntfsAds';
import { MAX_ANALYSIS_PIXELS } from '../../utils/ctf/imagePlanes';
import type { Language } from '../../i18n';
import type { EmbeddedReport } from './EmbeddedCard';
import type { PlaneImage } from './ImagePlanesCard';

export interface FileAnalysis {
  name: string;
  size: number;
  bytes: Uint8Array;
  // 保留原始 File 句柄：推荐工具条跨域移交（PCAP → 流量分析域）时交回框架重走魔数路由。
  file: File;
}

export interface FileReport {
  types: ReturnType<typeof detectFileTypes>;
  entropy: number;
  level: ReturnType<typeof entropyLevel>;
  strings: ReturnType<typeof extractStrings>;
  suspicious: ReturnType<typeof scanSuspiciousContent>;
  hexdump: string;
  png: ReturnType<typeof parsePngIhdr>;
  zip: ReturnType<typeof detectZipEncryption> | null;
  zeroWidth: ReturnType<typeof extractZeroWidthFromText>;
  embedded: EmbeddedReport;
  chunks: PngChunkList | null;
  // ZIP 载体的 NTFS ADS 数据流报告（非 ZIP 为 null）。
  ntfs: NtfsAdsReport | null;
}

export interface PngFixState {
  status: 'idle' | 'running' | 'done' | 'failed';
  width?: number;
  height?: number;
  bytes?: Uint8Array;
}

export interface ZipFixState {
  cleared: number;
  bytes: Uint8Array;
}

// BMP/GIF/JPG 修复结果（对齐 PngFixState 的状态机；JPG 额外携带段结构）。
export interface ImageFixState {
  status: 'idle' | 'running' | 'done' | 'failed';
  result?: FileRepairResult;
  jpg?: JpgRepairResult;
}

// 修复目标判定结果（魔数命中或扩展名匹配，魔数被改坏的题靠扩展名兜底进修复区）。
export interface FFRepairTarget {
  bmp: boolean;
  gif: boolean;
  jpg: boolean;
  // pyc 魔数随版本漂移无法魔数探测，靠扩展名路由（.pyc/.pyo）。
  pyc: boolean;
}

// 位平面/色道卡的解码状态机。
export type PlaneStatus = 'idle' | 'loading' | 'ready' | 'failed';

export const formatBytes = (value: number): string => {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MB`;
};

// 浏览器可原生解码的图片类型：位平面/色道卡只对这些文件渲染。
const IMAGE_MIME_MAP: Record<string, string> = { png: 'image/png', jpg: 'image/jpeg', gif: 'image/gif', bmp: 'image/bmp', webp: 'image/webp', ico: 'image/x-icon' };

// strings 提取上限（与 StringsCard 内常量同值）；hexdump 每页 512B（与 HexdumpCard 同值）。
const STRINGS_EXTRACT_LIMIT = 20000;
const HEX_PAGE_BYTES = 512;

const toBinaryString = (bytes: Uint8Array): string => {
  let binary = '';
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return binary;
};

export interface FFAnalyzeState {
  analysis: FileAnalysis | null;
  report: FileReport | null;
  analyzing: boolean;
  busy: boolean;
  // ≤5MB 且浏览器可解码图片的 data URL（preview 面板）；其余文件为 null。
  imagePreviewUrl: string | null;
  planeImage: PlaneImage | null;
  planeStatus: PlaneStatus;
  pngFix: PngFixState;
  zipFix: ZipFixState | null;
  bmpFix: ImageFixState;
  gifFix: ImageFixState;
  jpgFix: ImageFixState;
  gifGuess: GifSizeGuess | null;
  // GIF 手工宽高（空串表示未填；修复题画布推断歧义时人工指定）。
  gifManualW: string;
  gifManualH: string;
  setGifManualW: Dispatch<SetStateAction<string>>;
  setGifManualH: Dispatch<SetStateAction<string>>;
  repairTarget: FFRepairTarget | null;
  loadFile: (file: File) => Promise<void>;
  runPngFix: () => Promise<void>;
  runZipFix: () => void;
  runBmpFix: () => Promise<void>;
  runGifFix: () => Promise<void>;
  runGifManualFix: () => Promise<void>;
  runJpgFix: () => Promise<void>;
}

// 杂项取证域分析管线：文件载入 → 本地探测 → 报告落态；修复与位平面解码同属分析状态机。
export function useFFAnalyze({ language }: { language: Language }): FFAnalyzeState {
  const [analysis, setAnalysis] = useState<FileAnalysis | null>(null);
  const [report, setReport] = useState<FileReport | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [pngFix, setPngFix] = useState<PngFixState>({ status: 'idle' });
  const [zipFix, setZipFix] = useState<ZipFixState | null>(null);
  const [bmpFix, setBmpFix] = useState<ImageFixState>({ status: 'idle' });
  const [gifFix, setGifFix] = useState<ImageFixState>({ status: 'idle' });
  const [jpgFix, setJpgFix] = useState<ImageFixState>({ status: 'idle' });
  const [gifGuess, setGifGuess] = useState<GifSizeGuess | null>(null);
  const [gifManualW, setGifManualW] = useState('');
  const [gifManualH, setGifManualH] = useState('');
  const [busy, setBusy] = useState(false);
  // 位平面卡：浏览器异步解码出的 RGBA 像素（>4MP 自动降采样）。
  const [planeImage, setPlaneImage] = useState<PlaneImage | null>(null);
  const [planeStatus, setPlaneStatus] = useState<PlaneStatus>('idle');

  const loadFile = useCallback(async (file: File) => {
    if (file.size > MAX_FILE_BYTES) {
      notifications.show({
        title: language === 'zh' ? '文件过大' : 'File too large',
        message: language === 'zh'
          ? `「${file.name}」有 ${formatBytes(file.size)}，超过 20MB 上限。请先在本地裁剪或压缩后再试。`
          : `"${file.name}" is ${formatBytes(file.size)}, over the 20MB limit. Trim or compress it locally first.`,
        color: 'red',
      });
      return;
    }
    setBusy(true);
    setAnalyzing(false);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      setAnalysis({ name: file.name, size: file.size, bytes, file });
      setPngFix({ status: 'idle' });
      setZipFix(null);
      setBmpFix({ status: 'idle' });
      setGifFix({ status: 'idle' });
      setJpgFix({ status: 'idle' });
      setGifGuess(null);
      setGifManualW('');
      setGifManualH('');
      // 重置位平面卡状态：其余卡片的过滤/翻页/搜索状态随 key remount 自行重置。
      setPlaneImage(null);
      setPlaneStatus('idle');
      setBusy(false);
      // 让文件概要先渲染一帧，再做同步分析（接近 20MB 的文件约 0.5-2s）；
      // 判读文案等语言相关内容在渲染层现算，切换语言不会触发重分析。
      setAnalyzing(true);
      await new Promise(resolve => setTimeout(resolve, 0));
      const types = detectFileTypes(bytes);
      const entropy = shannonEntropy(bytes);
      const latin1 = new TextDecoder('latin1').decode(bytes);
      const utf8Text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, 512 * 1024));
      // 嵌入扫描：首字节跳转式滑窗（前 8MB），尾附检测与 chunk 枚举是 O(n) 单遍。
      const pngTrailer = findPngTrailer(bytes);
      const jpgTrailer = pngTrailer ? null : findJpegTrailer(bytes);
      const gifTrailer = pngTrailer || jpgTrailer ? null : findGifTrailer(bytes);
      const isZip = types.some(type => type.ext === 'zip' || type.ext === 'jar' || type.ext === 'apk') || (bytes.length > 4 && bytes[0] === 0x50 && bytes[1] === 0x4b);
      setReport({
        types,
        entropy,
        level: entropyLevel(entropy, bytes.length),
        strings: extractStrings(bytes, { limit: STRINGS_EXTRACT_LIMIT }),
        suspicious: scanSuspiciousContent(latin1),
        hexdump: hexdumpPreview(bytes, { length: HEX_PAGE_BYTES }),
        png: parsePngIhdr(bytes),
        zip: isZip ? detectZipEncryption(bytes) : null,
        zeroWidth: extractZeroWidthFromText(utf8Text),
        embedded: {
          hits: scanEmbeddedSignatures(bytes),
          pngTrailer: pngTrailer ? { offset: pngTrailer.offset, size: pngTrailer.trailing.length } : null,
          jpgTrailer: jpgTrailer ? { offset: jpgTrailer.offset, size: jpgTrailer.trailing.length } : null,
          gifTrailer: gifTrailer ? { offset: gifTrailer.offset, size: gifTrailer.trailing.length } : null,
        },
        chunks: types.some(type => type.ext === 'png') ? enumeratePngChunks(bytes) : null,
        ntfs: isZip ? extractNtfsAds(bytes) : null,
      });
      setAnalyzing(false);
    } catch {
      notifications.show({
        title: language === 'zh' ? '读取失败' : 'Read failed',
        message: language === 'zh' ? '无法读取该文件的内容，请确认文件仍存在且可访问。' : 'The file could not be read; make sure it still exists and is accessible.',
        color: 'red',
      });
    } finally {
      setBusy(false);
      setAnalyzing(false);
    }
  }, [language]);

  // strings 提取在 StringsCard 内完成；hexdump 渲染在 HexdumpCard 内完成。

  const imagePreviewUrl = useMemo(() => {
    if (!analysis || !report || report.types.length === 0) return null;
    const mime = IMAGE_MIME_MAP[report.types[0].ext];
    if (!mime || analysis.size > 5 * 1024 * 1024) return null;
    return `data:${mime};base64,${btoa(toBinaryString(analysis.bytes))}`;
  }, [analysis, report]);

  // 位平面/色道卡的图片解码：createImageBitmap 统一解成 RGBA（>4MP 降采样，内存红线 16MB）。
  // 状态重置在 loadFile 换文件时完成；这里非图片文件直接不启动解码。
  // 失败（浏览器不支持该格式）时卡片给出说明，不阻塞其它卡。
  useEffect(() => {
    if (!analysis || !report || report.types.length === 0) return;
    const mime = IMAGE_MIME_MAP[report.types[0].ext];
    if (!mime) return;
    let cancelled = false;
    const decode = async () => {
      try {
        setPlaneStatus('loading');
        const blob = new Blob([analysis.bytes.slice()], { type: mime });
        let bitmap = await createImageBitmap(blob);
        const originalWidth = bitmap.width;
        const originalHeight = bitmap.height;
        let width = originalWidth;
        let height = originalHeight;
        let downsampled = false;
        if (originalWidth * originalHeight > MAX_ANALYSIS_PIXELS) {
          const scale = Math.sqrt(MAX_ANALYSIS_PIXELS / (originalWidth * originalHeight));
          width = Math.max(1, Math.floor(originalWidth * scale));
          height = Math.max(1, Math.floor(originalHeight * scale));
          bitmap.close();
          bitmap = await createImageBitmap(blob, { resizeWidth: width, resizeHeight: height, resizeQuality: 'medium' });
          downsampled = true;
        }
        const canvas = document.createElement('canvas');
        canvas.width = bitmap.width;
        canvas.height = bitmap.height;
        const ctx = canvas.getContext('2d');
        if (!ctx) throw new Error('no 2d context');
        ctx.drawImage(bitmap, 0, 0);
        // ImageBitmap.close() 后宽高按规范归零，必须先取出再关。
        const decodedWidth = bitmap.width;
        const decodedHeight = bitmap.height;
        const imageData = ctx.getImageData(0, 0, decodedWidth, decodedHeight);
        bitmap.close();
        if (cancelled) return;
        setPlaneImage({ rgba: imageData.data, width: decodedWidth, height: decodedHeight, downsampled, originalWidth, originalHeight });
        setPlaneStatus('ready');
      } catch {
        if (!cancelled) {
          setPlaneImage(null);
          setPlaneStatus('failed');
        }
      }
    };
    void decode();
    return () => {
      cancelled = true;
    };
  }, [analysis, report]);

  const runPngFix = async () => {
    if (!analysis) return;
    setPngFix({ status: 'running' });
    const result = await fixPngDimensions(analysis.bytes);
    if (result) setPngFix({ status: 'done', width: result.width, height: result.height, bytes: result.bytes });
    else setPngFix({ status: 'failed' });
  };

  const runZipFix = () => {
    if (!analysis) return;
    const result = fixZipPseudoEncryption(analysis.bytes);
    if (result) setZipFix({ cleared: result.cleared, bytes: result.bytes });
  };

  // 修复目标判定：魔数命中或扩展名匹配（魔数被改坏的题靠扩展名兜底进修复区）。
  const repairTarget = useMemo(() => {
    if (!analysis || !report) return null;
    const ext = analysis.name.includes('.') ? analysis.name.split('.').pop()!.toLowerCase() : '';
    const detected = new Set(report.types.map(type => type.ext));
    return {
      bmp: detected.has('bmp') || ext === 'bmp',
      gif: detected.has('gif') || ext === 'gif',
      jpg: detected.has('jpg') || ext === 'jpg' || ext === 'jpeg' || ext === 'jfif',
      // pyc 魔数随版本漂移无法魔数探测，靠扩展名路由（.pyc/.pyo）。
      pyc: ext === 'pyc' || ext === 'pyo',
    };
  }, [analysis, report]);

  const runBmpFix = async () => {
    if (!analysis) return;
    setBmpFix({ status: 'running' });
    const result = await repairBmp(analysis.bytes);
    setBmpFix(result.bytes ? { status: 'done', result } : { status: 'failed', result });
  };

  const runGifFix = async () => {
    if (!analysis) return;
    setGifFix({ status: 'running' });
    setGifGuess(guessGifSize(analysis.bytes));
    const result = await repairGif(analysis.bytes);
    setGifFix(result.bytes ? { status: 'done', result } : { status: 'failed', result });
  };

  const runGifManualFix = async () => {
    if (!analysis) return;
    const w = Number.parseInt(gifManualW, 10);
    const h = Number.parseInt(gifManualH, 10);
    if (!Number.isFinite(w) || !Number.isFinite(h) || w < 1 || h < 1) {
      notifications.show({ message: language === 'zh' ? '请先填写 1-65535 范围内的宽和高。' : 'Enter width and height in 1-65535 first.', color: 'red' });
      return;
    }
    setGifFix({ status: 'running' });
    const result = await repairGifWithSize(analysis.bytes, w, h);
    setGifFix(result.bytes ? { status: 'done', result } : { status: 'failed', result });
  };

  const runJpgFix = async () => {
    if (!analysis) return;
    setJpgFix({ status: 'running' });
    const result = await repairJpg(analysis.bytes);
    setJpgFix({ status: 'done', jpg: result });
  };

  return {
    analysis,
    report,
    analyzing,
    busy,
    imagePreviewUrl,
    planeImage,
    planeStatus,
    pngFix,
    zipFix,
    bmpFix,
    gifFix,
    jpgFix,
    gifGuess,
    gifManualW,
    gifManualH,
    setGifManualW,
    setGifManualH,
    repairTarget,
    loadFile,
    runPngFix,
    runZipFix,
    runBmpFix,
    runGifFix,
    runGifManualFix,
    runJpgFix,
  };
}
