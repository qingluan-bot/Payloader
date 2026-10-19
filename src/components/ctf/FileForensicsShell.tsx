// FileForensicsShell：杂项取证域二级菜单壳（批次 P2-5 拆分自 FileForensicsWorkspace）。
// 承接 ctf-toolnav 布局：左列分组选工具、右侧单工具视图（hidden 保挂载切换不丢状态，
// 模式同 ReverseWorkspace/WebWorkspace）；概览面板内容在 OverviewCard，
// 分析状态束来自 useFFAnalyze（由编排层 FileForensicsWorkspace 透传）。
import { useState } from 'react';
import { Icon } from '../Icon';
import { copyToClipboard } from '../../utils/clipboard';
import EmbeddedCard from './EmbeddedCard';
import ImagePlanesCard from './ImagePlanesCard';
import ImageOpsCard from './ImageOpsCard';
import ImageStegoCard from './ImageStegoCard';
import JpegStegoCard from './JpegStegoCard';
import SteghideCard from './SteghideCard';
import AudioStegoCard from './AudioStegoCard';
import DeepSoundCard from './DeepSoundCard';
import OleInspectCard from './OleInspectCard';
import GifInspectCard from './GifInspectCard';
import ZipBruteCard from './ZipBruteCard';
import PdfInspectCard from './PdfInspectCard';
import RarInspectCard from './RarInspectCard';
import PycInspectCard from './PycInspectCard';
import ApkInspectCard from './ApkInspectCard';
import NbtInspectCard from './NbtInspectCard';
import NonogramCard from './NonogramCard';
import RouterConfigCard from './RouterConfigCard';
import StringsCard from './StringsCard';
import HexdumpCard from './HexdumpCard';
import { downloadBytes } from './ffDownload';
import OverviewCard from './OverviewCard';
import { formatBytes } from './ffUseAnalyze';
import type { FFAnalyzeState } from './ffUseAnalyze';
import type { Language } from '../../i18n';

interface FileForensicsShellProps {
  language: Language;
  // 分析管线状态束（useFFAnalyze 返回值）：载入/报告/位平面/修复全部面板所需状态与动作。
  ff: FFAnalyzeState;
  // 二级菜单当前视图 id。
  activeTool: string;
  // 切视图（编排层同时反向同步题型选择卡分类）。
  onSwitchTool: (toolId: string) => void;
  // 打开文件选择器（菜单栏「选择文件」与未加载空态按钮）。
  onOpenPicker: () => void;
  // 概览推荐工具条域内锚点定位（openCard 驻留编排层）。
  onOpenCard: (cardId: string, missingMessage: { zh: string; en: string }) => void;
  // 概览推荐工具条跨域移交 / 纯导航切域。
  onHandOffFile?: (file: File) => void;
  onSwitchModule?: (moduleId: string) => void;
}

// 二级菜单分组（批次 FF-NAV，仿 WebWorkspace WEB_TOOL_GROUPS）：左侧分组选工具、右侧单工具视图。
// 每个视图 id 对应下方一个 ctf-toolpanel；卡片归属按语义分组（概览=报告头，其余按载体类型）。
const FF_TOOL_GROUPS: ReadonlyArray<{
  id: string;
  zh: string;
  en: string;
  tools: ReadonlyArray<{ id: string; zh: string; en: string }>;
}> = [
  {
    id: 'overview',
    zh: '概览',
    en: 'Overview',
    tools: [
      { id: 'summary', zh: '概要与报告', en: 'Summary & report' },
    ],
  },
  {
    id: 'image',
    zh: '图片',
    en: 'Images',
    tools: [
      { id: 'preview', zh: '图片预览', en: 'Preview' },
      { id: 'planes', zh: '位平面与色道', en: 'Bit planes & channels' },
      { id: 'imageops', zh: '图像运算与转换', en: 'Image operations' },
      { id: 'imagestego', zh: '置乱与频域隐写', en: 'Scramble & frequency' },
      { id: 'jpegstego', zh: 'JPEG DCT 隐写', en: 'JPEG DCT stego' },
      { id: 'steghide-bmp', zh: 'steghide（BMP）', en: 'steghide (BMP)' },
    ],
  },
  {
    id: 'media',
    zh: '媒体',
    en: 'Media',
    tools: [
      { id: 'audio', zh: '音频隐写', en: 'Audio stego' },
      { id: 'deepsound', zh: 'DeepSound 提取', en: 'DeepSound' },
      { id: 'steghide-wav', zh: 'steghide（WAV）', en: 'steghide (WAV)' },
      { id: 'gif', zh: 'GIF 解析', en: 'GIF inspect' },
    ],
  },
  {
    id: 'docs',
    zh: '文档与压缩',
    en: 'Docs & Archives',
    tools: [
      { id: 'pdf', zh: 'PDF 取证', en: 'PDF forensics' },
      { id: 'ole', zh: 'OLE/CFB 提取', en: 'OLE/CFB' },
      { id: 'rar', zh: 'RAR 解析', en: 'RAR inspect' },
      { id: 'apk', zh: 'APK 逆向', en: 'APK analysis' },
      { id: 'router', zh: '路由器备份', en: 'Router backup' },
      { id: 'zipbrute', zh: 'ZIP 密码爆破', en: 'ZIP brute force' },
    ],
  },
  {
    id: 'structure',
    zh: '结构与取证',
    en: 'Structure',
    tools: [
      { id: 'repair', zh: '文件修复', en: 'Repair' },
      { id: 'ntfs', zh: 'NTFS 数据流', en: 'NTFS streams' },
      { id: 'embedded', zh: '嵌入数据与 chunk', en: 'Embedded & chunks' },
      { id: 'pyc', zh: 'pyc 字节码', en: 'pyc bytecode' },
      { id: 'nbt', zh: 'Minecraft NBT', en: 'Minecraft NBT' },
    ],
  },
  {
    id: 'puzzle',
    zh: '谜题求解',
    en: 'Puzzle',
    tools: [
      { id: 'nonogram', zh: '数织求解器', en: 'Nonogram solver' },
    ],
  },
  {
    id: 'general',
    zh: '通用分析',
    en: 'General',
    tools: [
      { id: 'strings', zh: '可读字符串', en: 'Strings' },
      { id: 'hexdump', zh: 'HEX 转储', en: 'Hexdump' },
    ],
  },
];

function FileForensicsShell({ language, ff, activeTool, onSwitchTool, onOpenPicker, onOpenCard, onHandOffFile, onSwitchModule }: FileForensicsShellProps) {
  const {
    analysis,
    report,
    planeImage,
    planeStatus,
    imagePreviewUrl,
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
  } = ff;

  // 图片真实渲染尺寸（UX 走查 P1：图片题第一眼要看尺寸，IHDR 伪造/高度截断题靠它识别）
  const [previewNaturalSize, setPreviewNaturalSize] = useState('…');

  // 未加载文件时任何二级视图的统一空态：提示选择文件并给出入口（拖拽仍由外层容器承接，原整页 dropzone 拆到各视图）。
  const pickFileNote = (
    <div className="ff-dropzone">
      <div className="ff-dropzone-icon" aria-hidden="true"><Icon name="file-text" size={30} /></div>
      <strong>{language === 'zh' ? '请先选择文件，再使用该工具' : 'Choose a file to use this tool'}</strong>
      <small>
        {language === 'zh'
          ? '把文件拖到这里，或点击下方按钮选择；自动识别文件类型并按需分析。文件仅在本浏览器内处理，不会上传，上限 20MB。'
          : 'Drop a file here, or click the button below; types are detected automatically. Files never leave your browser. 20MB limit.'}
      </small>
      <button type="button" className="ff-button ff-button-primary" onClick={onOpenPicker}>
        {language === 'zh' ? '选择文件' : 'Choose file'}
      </button>
    </div>
  );

  return (
    <div className="ctf-toolnav">
      <nav className="ctf-toolnav-menu" aria-label={language === 'zh' ? '杂项取证工具选择' : 'Forensics tools'}>
        <button type="button" className="ctf-toolnav-file-btn" onClick={onOpenPicker}>
          <Icon name="file-text" size={14} />
          {analysis
            ? (language === 'zh' ? ` 换文件（${analysis.name.slice(0, 18)}）` : ` Replace (${analysis.name.slice(0, 18)})`)
            : (language === 'zh' ? ' 选择文件' : ' Choose file')}
        </button>
        {FF_TOOL_GROUPS.map(group => (
          <div className="ctf-toolnav-group" key={group.id}>
            <div className="ctf-toolnav-group-title">{language === 'zh' ? group.zh : group.en}</div>
            {group.tools.map(tool => (
              <button
                key={tool.id}
                type="button"
                className={`ctf-toolnav-item ${activeTool === tool.id ? 'active' : ''}`}
                aria-current={activeTool === tool.id ? 'true' : undefined}
                onClick={() => onSwitchTool(tool.id)}
              >
                {language === 'zh' ? tool.zh : tool.en}
              </button>
            ))}
          </div>
        ))}
      </nav>
      <div className="ctf-toolnav-body">
        {/* 概览视图：推荐工具条 + 文件概要 + flag 命中 + 可疑内容（报告头内容集中在概览，渲染在 OverviewCard） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'summary'}>
          {!analysis ? pickFileNote : (
            <OverviewCard
              language={language}
              analysis={analysis}
              report={report}
              onOpenPicker={onOpenPicker}
              onOpenCard={onOpenCard}
              onHandOffFile={onHandOffFile}
              onSwitchModule={onSwitchModule}
            />
          )}
        </div>

        {/* 图片预览：仅浏览器可解码且 ≤5MB 的图片有 data URL */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'preview'}>
          {!analysis ? pickFileNote : imagePreviewUrl ? (
          <section id="ff-card-preview" className="ff-card" aria-label={language === 'zh' ? '图片预览' : 'Image preview'}>
            <div className="ff-card-head">
              <strong>{language === 'zh' ? '图片预览' : 'Image preview'}</strong>
              <button
                type="button"
                className="ff-button"
                onClick={() => { void copyToClipboard(imagePreviewUrl); }}
              >
                {language === 'zh' ? '复制 data URL' : 'Copy data URL'}
              </button>
            </div>
            <div className="ff-row">
              <span className="ff-name" title={analysis.name}>{analysis.name}</span>
              {report && report.types[0] && <span className="ff-badge">{report.types[0].name}</span>}
              <span className="ff-badge ff-badge-ok">{previewNaturalSize}</span>
              <span className="ff-badge">{formatBytes(analysis.size)}</span>
            </div>
            <img
              className="ff-preview"
              src={imagePreviewUrl}
              alt={analysis.name}
              onLoad={event => setPreviewNaturalSize(`${event.currentTarget.naturalWidth} × ${event.currentTarget.naturalHeight}`)}
            />
          </section>
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? '图片预览仅支持浏览器可直接解码的图片（png/jpg/gif/bmp/webp/ico），且不超过 5MB；当前文件不满足条件。'
                : 'Preview applies to browser-decodable images (png/jpg/gif/bmp/webp/ico) up to 5MB; this file does not qualify.'}
            </p>
          )}
        </div>

        {/* 位平面与色道（ImagePlanesCard 内含 ff-card-bitplanes / ff-card-channels 两张卡） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'planes'}>
          {!analysis ? pickFileNote : planeStatus !== 'idle' ? (
          <ImagePlanesCard
            key={`planes-${analysis.name}:${analysis.size}`}
            fileName={analysis.name}
            image={planeImage}
            status={planeStatus}
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? '位平面与色道分析仅支持浏览器可解码的图片文件；当前文件不是可解码的图片。'
                : 'Bit-plane and channel analysis applies to browser-decodable images; this file is not a decodable image.'}
            </p>
          )}
        </div>

        {/* 图像运算与转换 */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'imageops'}>
          {!analysis ? pickFileNote : planeStatus === 'ready' && planeImage !== null ? (
          <ImageOpsCard
            key={`ops-${analysis.name}:${analysis.size}`}
            image={planeImage}
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? '图像运算需要先成功解码一张图片：当前文件不是图片，或浏览器解码失败。'
                : 'Image operations need a successfully decoded image: this file is not an image, or decoding failed.'}
            </p>
          )}
        </div>

        {/* 置乱与频域隐写 */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'imagestego'}>
          {!analysis ? pickFileNote : planeStatus === 'ready' && planeImage !== null ? (
          <ImageStegoCard
            key={`stego-${analysis.name}:${analysis.size}`}
            image={planeImage}
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? '置乱/频域工具需要先成功解码一张图片：当前文件不是图片，或浏览器解码失败。'
                : 'Scramble and frequency tools need a decoded image: this file is not an image, or decoding failed.'}
            </p>
          )}
        </div>

        {/* JPEG DCT 隐写（魔数 FF D8 路由） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'jpegstego'}>
          {!analysis ? pickFileNote : analysis.bytes[0] === 0xff && analysis.bytes[1] === 0xd8 ? (
          <JpegStegoCard
            key={`jpegstego-${analysis.name}:${analysis.size}`}
            bytes={analysis.bytes}
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? 'JPEG DCT 隐写仅支持以 FF D8 魔数开头的 JPEG 文件。'
                : 'JPEG DCT stego applies to files starting with the FF D8 JPEG signature.'}
            </p>
          )}
        </div>

        {/* steghide（BMP 载体，魔数「BM」路由） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'steghide-bmp'}>
          {!analysis ? pickFileNote : analysis.bytes[0] === 0x42 && analysis.bytes[1] === 0x4d ? (
          <SteghideCard
            key={`steghide-bmp-${analysis.name}:${analysis.size}`}
            bytes={analysis.bytes}
            kind="bmp"
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? 'steghide（BMP）仅支持以「BM」开头的 BMP 载体文件。'
                : 'steghide (BMP) applies to BMP carriers starting with "BM".'}
            </p>
          )}
        </div>

        {/* 音频隐写（WAV/MP3/FLAC/OGG 类型路由；频谱图等由卡内 Web Audio 处理） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'audio'}>
          {!analysis ? pickFileNote : report && report.types.some(type => ['wav', 'mp3', 'flac', 'ogg'].includes(type.ext)) ? (
          <AudioStegoCard
            key={`audio-${analysis.name}:${analysis.size}`}
            file={analysis.file}
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? '音频隐写分析仅支持 WAV/MP3/FLAC/OGG 文件。'
                : 'Audio stego applies to WAV/MP3/FLAC/OGG files.'}
            </p>
          )}
        </div>

        {/* DeepSound 提取（RIFF 载体路由；引擎扫描 DSCF/DSC2 头，未命中时卡内明确说明） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'deepsound'}>
          {!analysis ? pickFileNote : analysis.bytes[0] === 0x52 && analysis.bytes[1] === 0x49 && analysis.bytes[2] === 0x46 && analysis.bytes[3] === 0x46 ? (
          <DeepSoundCard
            key={`deepsound-${analysis.name}:${analysis.size}`}
            fileName={analysis.name}
            bytes={analysis.bytes}
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? 'DeepSound 提取仅支持 RIFF/WAV 载体（官方 DeepSound 2.x 的输出格式）。'
                : 'DeepSound extraction applies to RIFF/WAV carriers (official DeepSound 2.x output format).'}
            </p>
          )}
        </div>

        {/* steghide（WAV 载体，魔数 RIFF 路由） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'steghide-wav'}>
          {!analysis ? pickFileNote : analysis.bytes[0] === 0x52 && analysis.bytes[1] === 0x49 && analysis.bytes[2] === 0x46 && analysis.bytes[3] === 0x46 ? (
          <SteghideCard
            key={`steghide-wav-${analysis.name}:${analysis.size}`}
            bytes={analysis.bytes}
            kind="wav"
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? 'steghide（WAV）仅支持以「RIFF」开头的 WAV 载体文件。'
                : 'steghide (WAV) applies to WAV carriers starting with "RIFF".'}
            </p>
          )}
        </div>

        {/* GIF 解析 */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'gif'}>
          {!analysis ? pickFileNote : report && report.types.some(type => type.ext === 'gif') ? (
          <GifInspectCard
            key={`gif-${analysis.name}:${analysis.size}`}
            fileName={analysis.name}
            bytes={analysis.bytes}
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? 'GIF 解析仅支持 GIF 文件。'
                : 'GIF inspection applies to GIF files.'}
            </p>
          )}
        </div>

        {/* PDF 取证（魔数 %PDF 路由） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'pdf'}>
          {!analysis ? pickFileNote : report && report.types.some(type => type.ext === 'pdf') ? (
          <PdfInspectCard
            key={`pdf-${analysis.name}:${analysis.size}`}
            fileName={analysis.name}
            bytes={analysis.bytes}
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? 'PDF 取证仅支持以「%PDF」开头的 PDF 文件。'
                : 'PDF forensics applies to files starting with the "%PDF" signature.'}
            </p>
          )}
        </div>

        {/* OLE/CFB 复合文档（魔数 D0 CF 11 E0 A1 B1 1A E1 路由；只读提取，绝不执行宏） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'ole'}>
          {!analysis ? pickFileNote : analysis.bytes[0] === 0xd0 && analysis.bytes[1] === 0xcf && analysis.bytes[2] === 0x11 && analysis.bytes[3] === 0xe0 && analysis.bytes[4] === 0xa1 && analysis.bytes[5] === 0xb1 && analysis.bytes[6] === 0x1a && analysis.bytes[7] === 0xe1 ? (
          <OleInspectCard
            key={`ole-${analysis.name}:${analysis.size}`}
            fileName={analysis.name}
            bytes={analysis.bytes}
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? 'OLE/CFB 提取仅支持以 D0 CF 11 E0 A1 B1 1A E1 魔数开头的复合文档（doc/xls/ppt/msg 等）。'
                : 'OLE/CFB extraction applies to compound documents starting with the D0 CF 11 E0 A1 B1 1A E1 signature (doc/xls/ppt/msg etc.).'}
            </p>
          )}
        </div>

        {/* RAR 解析（RAR4/RAR5 魔数路由） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'rar'}>
          {!analysis ? pickFileNote : report && report.types.some(type => type.ext === 'rar4' || type.ext === 'rar5') ? (
          <RarInspectCard
            key={`rar-${analysis.name}:${analysis.size}`}
            fileName={analysis.name}
            bytes={analysis.bytes}
            onContinueWithBytes={(repairedBytes, repairedName) => { void loadFile(new File([repairedBytes.slice()], repairedName)); }}
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? 'RAR 解析仅支持 RAR4/RAR5 文件。'
                : 'RAR inspection applies to RAR4/RAR5 archives.'}
            </p>
          )}
        </div>

        {/* APK 逆向（扩展名 .apk 路由） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'apk'}>
          {!analysis ? pickFileNote : report && analysis.name.toLowerCase().endsWith('.apk') ? (
          <ApkInspectCard
            key={`apk-${analysis.name}:${analysis.size}`}
            bytes={analysis.bytes}
            fileName={analysis.name}
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? 'APK 逆向按扩展名 .apk 路由；当前文件不是 .apk。'
                : 'APK analysis routes by the .apk extension; this file is not an .apk.'}
            </p>
          )}
        </div>

        {/* 路由器备份（扩展名 .cfg/.conf/.bin/rom-0 路由；.apk 优先归 APK 视图） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'router'}>
          {!analysis ? pickFileNote : report && /\.(cfg|conf|bin|rom-0|rom0)$/i.test(analysis.name) && !analysis.name.toLowerCase().endsWith('.apk') ? (
          <RouterConfigCard
            key={`router-${analysis.name}:${analysis.size}`}
            bytes={analysis.bytes}
            fileName={analysis.name}
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? '路由器备份分析按扩展名 .cfg/.conf/.bin/rom-0 路由；当前文件不匹配。'
                : 'Router backup analysis routes by .cfg/.conf/.bin/rom-0 extensions; no match.'}
            </p>
          )}
        </div>

        {/* ZIP 密码爆破（检测到加密/伪加密标志时可用） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'zipbrute'}>
          {!analysis ? pickFileNote : report && report.zip !== null && (report.zip.state === 'encrypted' || report.zip.state === 'pseudo') ? (
          <ZipBruteCard
            key={`zipbrute-${analysis.name}:${analysis.size}`}
            bytes={analysis.bytes}
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? 'ZIP 密码爆破在检测到加密/伪加密标志时可用；当前 ZIP 未加密，或不是 ZIP 文件。'
                : 'ZIP brute force applies when encryption or pseudo-encryption flags are detected; this ZIP is plain, or the file is not a ZIP.'}
            </p>
          )}
        </div>

        {/* 文件修复：PNG 宽高 / ZIP 伪加密 / BMP / GIF / JPG（魔数命中或扩展名兜底） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'repair'}>
          {!analysis ? pickFileNote : report && (report.png || report.zip || repairTarget?.bmp || repairTarget?.gif || repairTarget?.jpg) ? (
          <section id="ff-card-repair" className="ff-card" aria-label={language === 'zh' ? '文件修复工具' : 'Repair tools'}>
            <div className="ff-card-head">
              <strong>{language === 'zh' ? '修复工具' : 'Repair tools'}</strong>
            </div>
            {report.png && (
              <div className="ff-tool">
                <div className="ff-row">
                  <span className="ff-label">PNG IHDR</span>
                  <span className="ff-mono">
                    {report.png.width}×{report.png.height} · {language === 'zh' ? `色深 ${report.png.bitDepth}` : `depth ${report.png.bitDepth}`}
                  </span>
                  {report.png.crcOk
                    ? <span className="ff-badge ff-badge-ok">CRC {language === 'zh' ? '校验通过' : 'OK'}</span>
                    : <span className="ff-badge ff-badge-warn">CRC {language === 'zh' ? '校验失败——宽高可能被篡改' : 'mismatch — dimensions likely tampered'}</span>}
                </div>
                {!report.png.crcOk && (
                  <div className="ff-row">
                    {pngFix.status === 'idle' && <button type="button" className="ff-button ff-button-primary" onClick={() => { void runPngFix(); }}>{language === 'zh' ? '尝试修复宽高（CRC 爆破）' : 'Fix dimensions (CRC bruteforce)'}</button>}
                    {pngFix.status === 'running' && <span className="ff-note">{language === 'zh' ? '正在枚举宽高组合，稍候…' : 'Enumerating dimensions…'}</span>}
                    {pngFix.status === 'done' && pngFix.bytes && (
                      <>
                        <span className="ff-badge ff-badge-ok">{language === 'zh' ? `还原为 ${pngFix.width}×${pngFix.height}` : `Recovered ${pngFix.width}×${pngFix.height}`}</span>
                        <button type="button" className="ff-button" onClick={() => downloadBytes(pngFix.bytes!, `${analysis.name.replace(/\.png$/i, '')}-fixed.png`)}>
                          {language === 'zh' ? '下载修复后文件' : 'Download fixed file'}
                        </button>
                        {/* 修复文件重入分析链：宽高/CRC 已正常，位平面/图片预览直接可用（B1 闭环） */}
                        <button type="button" className="ff-button ff-button-primary" onClick={() => {
                          const fixedName = analysis.name.replace(/\.png$/i, '') + '-fixed.png';
                          const fixed = pngFix.bytes!.slice();
                          void loadFile(new File([fixed.buffer as ArrayBuffer], fixedName, { type: 'image/png' }));
                        }}>
                          {language === 'zh' ? '用修复文件继续分析' : 'Analyze fixed file'}
                        </button>
                      </>
                    )}
                    {pngFix.status === 'failed' && <span className="ff-note">{language === 'zh' ? '未能找到匹配的宽高组合：损坏可能不止宽高，或超出枚举范围。' : 'No matching dimensions found: damage may go beyond width/height or exceed the search range.'}</span>}
                  </div>
                )}
              </div>
            )}
            {report.zip && (
              <div className="ff-tool">
                <div className="ff-row">
                  <span className="ff-label">ZIP {language === 'zh' ? '加密标志' : 'encryption flags'}</span>
                  {report.zip.state === 'plain' && <span className="ff-badge ff-badge-ok">{language === 'zh' ? '未加密' : 'Not encrypted'}</span>}
                  {report.zip.state === 'pseudo' && <span className="ff-badge ff-badge-warn">{language === 'zh' ? '疑似伪加密（两处标志不一致）' : 'Pseudo-encrypted (flags disagree)'}</span>}
                  {report.zip.state === 'encrypted' && <span className="ff-badge ff-badge-warn">{language === 'zh' ? '标志位全 1：真加密或全量伪加密，需结合打开结果判断' : 'All flags set: real encryption or full pseudo-encryption'}</span>}
                  {report.zip.state === 'none' && <span className="ff-note">{language === 'zh' ? '未找到 ZIP 目录结构。' : 'No ZIP directory structure found.'}</span>}
                </div>
                {report.zip.state === 'pseudo' && !zipFix && (
                  <button type="button" className="ff-button ff-button-primary" onClick={runZipFix}>
                    {language === 'zh' ? '清除伪加密标志' : 'Clear pseudo-encryption flags'}
                  </button>
                )}
                {zipFix && (
                  <div className="ff-row">
                    <span className="ff-badge ff-badge-ok">{language === 'zh' ? `已清除 ${zipFix.cleared} 处标志位` : `Cleared ${zipFix.cleared} flag(s)`}</span>
                    <button type="button" className="ff-button" onClick={() => downloadBytes(zipFix.bytes, `${analysis.name.replace(/\.zip$/i, '')}-fixed.zip`)}>
                      {language === 'zh' ? '下载修复后文件' : 'Download fixed file'}
                    </button>
                  </div>
                )}
              </div>
            )}
            {repairTarget?.bmp && (
              <div className="ff-tool">
                <div className="ff-row">
                  <span className="ff-label">BMP</span>
                  {bmpFix.status === 'idle' && <button type="button" className="ff-button ff-button-primary" onClick={() => { void runBmpFix(); }}>{language === 'zh' ? '尝试修复（魔数重建 + 宽高反推）' : 'Repair (magic + dimensions)'}</button>}
                  {bmpFix.status === 'running' && <span className="ff-note">{language === 'zh' ? '正在按文件大小枚举合法宽高组合…' : 'Enumerating dimensions…'}</span>}
                  {bmpFix.status === 'done' && bmpFix.result?.bytes && (
                    <>
                      <span className="ff-badge ff-badge-ok">{language === 'zh' ? `还原为 ${bmpFix.result.width}×${bmpFix.result.height}` : `Recovered ${bmpFix.result.width}×${bmpFix.result.height}`}</span>
                      <button type="button" className="ff-button" onClick={() => downloadBytes(bmpFix.result!.bytes!, `${analysis.name.replace(/\.bmp$/i, '')}-fixed.bmp`)}>
                        {language === 'zh' ? '下载修复后文件' : 'Download fixed file'}
                      </button>
                    </>
                  )}
                  {bmpFix.status === 'failed' && <span className="ff-note">{language === 'zh' ? '未能修复：文件可能不是可识别的 BMP，或压缩 BI_RGB 之外的编码。' : 'Not repairable: unrecognized BMP or compressed encoding.'}</span>}
                </div>
                {bmpFix.result && bmpFix.result.diagnosis.length > 0 && (
                  <div className="ff-note">{bmpFix.result.diagnosis.map((line, index) => <div key={index}>{line}</div>)}</div>
                )}
              </div>
            )}
            {repairTarget?.gif && (
              <div className="ff-tool">
                <div className="ff-row">
                  <span className="ff-label">GIF</span>
                  {gifFix.status === 'idle' && <button type="button" className="ff-button ff-button-primary" onClick={() => { void runGifFix(); }}>{language === 'zh' ? '自动修复（头重建 + 画布推断）' : 'Auto repair (header + canvas)'}</button>}
                  {gifFix.status === 'running' && <span className="ff-note">{language === 'zh' ? '正在推断画布尺寸…' : 'Inferring canvas size…'}</span>}
                  {gifFix.status === 'done' && gifFix.result?.bytes && (
                    <>
                      <span className="ff-badge ff-badge-ok">{language === 'zh' ? `画布 ${gifFix.result.width}×${gifFix.result.height}` : `Canvas ${gifFix.result.width}×${gifFix.result.height}`}</span>
                      <button type="button" className="ff-button" onClick={() => downloadBytes(gifFix.result!.bytes!, `${analysis.name.replace(/\.gif$/i, '')}-fixed.gif`)}>
                        {language === 'zh' ? '下载修复后文件' : 'Download fixed file'}
                      </button>
                    </>
                  )}
                  {gifFix.status === 'failed' && <span className="ff-note">{language === 'zh' ? '未能修复：文件可能不是可识别的 GIF。' : 'Not repairable: unrecognized GIF.'}</span>}
                </div>
                <div className="ff-row">
                  <span className="ff-label">{language === 'zh' ? '手工宽高' : 'Manual size'}</span>
                  <input className="ff-input ff-input-narrow" inputMode="numeric" placeholder="W" value={gifManualW} onChange={event => setGifManualW(event.target.value)} aria-label={language === 'zh' ? '宽度' : 'width'} />
                  <span className="ff-mono">×</span>
                  <input className="ff-input ff-input-narrow" inputMode="numeric" placeholder="H" value={gifManualH} onChange={event => setGifManualH(event.target.value)} aria-label={language === 'zh' ? '高度' : 'height'} />
                  <button type="button" className="ff-button" onClick={() => { void runGifManualFix(); }}>{language === 'zh' ? '按指定宽高重写' : 'Rewrite size'}</button>
                  {gifGuess && <span className="ff-note">{language === 'zh' ? `帧覆盖推断 ${gifGuess.width}×${gifGuess.height}（${gifGuess.frameCount} 帧，${gifGuess.exact ? '精确' : '推断'}）` : `Frame-coverage ${gifGuess.width}×${gifGuess.height} (${gifGuess.frameCount} frames, ${gifGuess.exact ? 'exact' : 'inferred'})`}</span>}
                </div>
                {gifFix.result && gifFix.result.diagnosis.length > 0 && (
                  <div className="ff-note">{gifFix.result.diagnosis.map((line, index) => <div key={index}>{line}</div>)}</div>
                )}
              </div>
            )}
            {repairTarget?.jpg && (
              <div className="ff-tool">
                <div className="ff-row">
                  <span className="ff-label">JPG</span>
                  {jpgFix.status === 'idle' && <button type="button" className="ff-button ff-button-primary" onClick={() => { void runJpgFix(); }}>{language === 'zh' ? '诊断结构并修复（SOI/EOI）' : 'Diagnose & repair (SOI/EOI)'}</button>}
                  {jpgFix.status === 'running' && <span className="ff-note">{language === 'zh' ? '正在枚举段结构…' : 'Walking segments…'}</span>}
                  {jpgFix.status === 'done' && jpgFix.jpg && (
                    <>
                      {!jpgFix.jpg.bytes && <span className="ff-badge ff-badge-warn">{language === 'zh' ? '未能识别为 JPG（无有效段结构）' : 'Not recognized as JPG'}</span>}
                      {jpgFix.jpg.bytes && jpgFix.jpg.repairedSoi && <span className="ff-badge ff-badge-warn">{language === 'zh' ? 'SOI 已重写' : 'SOI rewritten'}</span>}
                      {jpgFix.jpg.bytes && jpgFix.jpg.repairedEoi && <span className="ff-badge ff-badge-warn">{language === 'zh' ? 'EOI 已补写' : 'EOI appended'}</span>}
                      {jpgFix.jpg.bytes && !jpgFix.jpg.repairedSoi && !jpgFix.jpg.repairedEoi && <span className="ff-badge ff-badge-ok">{language === 'zh' ? 'SOI/EOI 完好' : 'SOI/EOI intact'}</span>}
                      {jpgFix.jpg.sofFrames.length > 0 && <span className="ff-mono">{language === 'zh' ? 'SOF 尺寸' : 'SOF size'}: {jpgFix.jpg.sofFrames.map(frame => `${frame.width}×${frame.height}`).join(', ')}</span>}
                      {jpgFix.jpg.bytes && <button type="button" className="ff-button" onClick={() => downloadBytes(jpgFix.jpg!.bytes!, `${analysis.name.replace(/\.jpe?g$/i, '')}-fixed.jpg`)}>
                        {language === 'zh' ? '下载修复后文件' : 'Download fixed file'}
                      </button>}
                    </>
                  )}
                  {jpgFix.status === 'failed' && <span className="ff-note">{language === 'zh' ? '未能识别为 JPG。' : 'Not recognized as JPG.'}</span>}
                </div>
                {jpgFix.status === 'done' && jpgFix.jpg && (
                  <div className="ff-note">
                    <div>{language === 'zh'
                      ? `共 ${jpgFix.jpg.segments.length} 个段（熵编码数据 ${(jpgFix.jpg.segments.reduce((sum, seg) => sum + (seg.entropyBytes ?? 0), 0)).toLocaleString()} 字节）`
                      : `${jpgFix.jpg.segments.length} segments (${(jpgFix.jpg.segments.reduce((sum, seg) => sum + (seg.entropyBytes ?? 0), 0)).toLocaleString()} entropy bytes)`}</div>
                    {jpgFix.jpg.diagnosis.map((line, index) => <div key={index}>{line}</div>)}
                  </div>
                )}
              </div>
            )}
          </section>
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? '当前文件没有命中的修复工具（PNG 宽高 / ZIP 伪加密 / BMP / GIF / JPG）。'
                : 'No repair tool matches this file (PNG dimensions / ZIP pseudo-encryption / BMP / GIF / JPG).'}
            </p>
          )}
        </div>

        {/* NTFS 数据流（ZIP 载体专属） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'ntfs'}>
          {!analysis ? pickFileNote : report?.ntfs && report.ntfs.streams.length > 0 ? (
          <section id="ff-card-ntfs" className="ff-card" aria-label={language === 'zh' ? 'NTFS 数据流' : 'NTFS data streams'}>
            <div className="ff-card-head">
              <strong>{language === 'zh' ? `NTFS 数据流（${report.ntfs.streams.length}）` : `NTFS data streams (${report.ntfs.streams.length})`}</strong>
            </div>
            {report.ntfs.streams.map((stream, index) => (
              <div className="ff-tool" key={`${stream.entryName}:${stream.streamName}:${index}`}>
                <div className="ff-row">
                  <span className="ff-label ff-mono" title={`${stream.entryName}:${stream.streamName}`}>{stream.entryName}:{stream.streamName}</span>
                  <span className="ff-badge">{stream.source === 'entry-name' ? (language === 'zh' ? '冒号虚拟条目' : 'colon entry') : (language === 'zh' ? 'extra field 流' : 'extra-field stream')}</span>
                  {stream.bytes && (
                    <button
                      type="button"
                      className="ff-button"
                      onClick={() => downloadBytes(stream.bytes!, `${analysis.name}-${stream.streamName.replace(/[\\/:*?"<>|$]/g, '_')}`)}
                    >
                      {language === 'zh' ? '下载流内容' : 'Download stream'}
                    </button>
                  )}
                </div>
                {stream.preview && <code className="ff-code">{stream.preview}</code>}
                {stream.flags.map(flag => <span key={flag.prefix} className="ff-badge ff-badge-flag" title={flag.sample}>{flag.sample}</span>)}
                {stream.hint && <span className="ff-note">{stream.hint}</span>}
              </div>
            ))}
            {report.ntfs.diagnosis.length > 0 && (
              <div className="ff-note">{report.ntfs.diagnosis.map((line, index) => <div key={index}>{line}</div>)}</div>
            )}
          </section>
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? '未发现 NTFS 数据流，或当前文件不是 ZIP 载体。'
                : 'No NTFS data streams found, or the file is not a ZIP carrier.'}
            </p>
          )}
        </div>

        {/* 嵌入数据与 PNG chunk（EmbeddedCard 内含 ff-card-embedded / ff-card-chunks；无命中时返回 null，此时补空态说明） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'embedded'}>
          {!analysis ? pickFileNote : !report ? (
            <p className="ff-note">{language === 'zh' ? '正在分析文件，嵌入扫描稍后可用。' : 'Analyzing; the embedded scan will be available shortly.'}</p>
          ) : (
            <>
              <EmbeddedCard
                key={`embedded-${analysis.name}:${analysis.size}`}
                fileName={analysis.name}
                bytes={analysis.bytes}
                embedded={report.embedded}
                gifTrailer={report.embedded.gifTrailer}
                chunks={report.chunks}
                language={language}
              />
              {report.embedded.hits.length === 0 && !report.embedded.pngTrailer && !report.embedded.jpgTrailer && !report.embedded.gifTrailer && (report.chunks?.chunks.length ?? 0) === 0 && (
                <p className="ff-note">
                  {language === 'zh'
                    ? '当前文件没有检出嵌入文件、尾附数据或 PNG chunk。'
                    : 'No embedded files, trailing data, or PNG chunks were detected in this file.'}
                </p>
              )}
            </>
          )}
        </div>

        {/* pyc 字节码（扩展名 .pyc/.pyo 路由；pyc 魔数随版本漂移无法魔数探测） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'pyc'}>
          {!analysis ? pickFileNote : report && repairTarget?.pyc ? (
          <PycInspectCard
            key={`pyc-${analysis.name}:${analysis.size}`}
            bytes={analysis.bytes}
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? 'pyc 解析按扩展名 .pyc/.pyo 路由；当前文件不匹配。'
                : 'pyc inspection routes by the .pyc/.pyo extension; no match.'}
            </p>
          )}
        </div>

        {/* Minecraft NBT / level.dat（不限扩展名：引擎自动判 gzip/zlib/裸 NBT，非 NBT 卡内报错说明） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'nbt'}>
          {!analysis ? pickFileNote : (
          <NbtInspectCard
            key={`nbt-${analysis.name}:${analysis.size}`}
            fileName={analysis.name}
            bytes={analysis.bytes}
            language={language}
          />
          )}
        </div>

        {/* 数织求解器（纯输入工具，不依赖文件） */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'nonogram'}>
          <NonogramCard language={language} />
        </div>

        {/* 可读字符串 */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'strings'}>
          {!analysis ? pickFileNote : report && report.strings.total > 0 ? (
          <StringsCard
            key={`strings-${analysis.name}:${analysis.size}`}
            fileName={analysis.name}
            bytes={analysis.bytes}
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? '当前文件没有提取到可读字符串。'
                : 'No readable strings were extracted from this file.'}
            </p>
          )}
        </div>

        {/* HEX 转储 */}
        <div className="ctf-toolpanel" hidden={activeTool !== 'hexdump'}>
          {!analysis ? pickFileNote : report && report.hexdump ? (
          <HexdumpCard
            key={`hexdump-${analysis.name}:${analysis.size}`}
            bytes={analysis.bytes}
            size={analysis.size}
            language={language}
          />
          ) : (
            <p className="ff-note">
              {language === 'zh'
                ? '正在分析文件，hexdump 预览稍后可用。'
                : 'Analyzing; the hexdump preview will be available shortly.'}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

export default FileForensicsShell;
