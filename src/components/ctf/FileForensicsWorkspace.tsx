// 杂项取证域工作区（批次 K）：文件拖入/选择 → 本地探测 → 按需分析。
// 批次 FF-NAV 改造：卡片平铺改为二级菜单（ctf-toolnav，左列分组选工具、右侧单工具视图，
// hidden 保挂载切换不丢状态；模式同 ReverseWorkspace/WebWorkspace）。
// 批次 P2-5 拆分：分析管线在 ffUseAnalyze（hook）、二级菜单布局在 FileForensicsShell、
// 概览渲染在 OverviewCard；本文件保留框架接入与跨域编排（pendingFile 消费/移交/切域/题型定位）。
// 文件只读字节、不执行、不上传；超过 20MB 直接拒绝并说明原因。
import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { useLanguage } from '../../appContext';
import { challengeCatalog } from '../../utils/ctf/challengeCatalog';
import ChallengePickerCard from './ChallengePickerCard';
import FileForensicsShell from './FileForensicsShell';
import { useFFAnalyze } from './ffUseAnalyze';
import '../../styles/ctf-forensics.css';

// cardId → 二级视图 id：顶部菜单 / 推荐工具条 / 题型选择卡定位时先切视图再滚动。
// ff-card-steghide 由 BMP/WAV 两个载体视图共用同一卡 id（渲染条件互斥），按当前文件魔数动态路由，不进本表。
const CARD_VIEW_MAP: Record<string, string> = {
  'ff-card-summary': 'summary',
  'ff-card-flag': 'summary',
  'ff-card-suspicious': 'summary',
  'ff-card-preview': 'preview',
  'ff-card-bitplanes': 'planes',
  'ff-card-channels': 'planes',
  'ff-card-imageops': 'imageops',
  'ff-card-imagestego': 'imagestego',
  'ff-card-jpegstego': 'jpegstego',
  'ff-card-audio': 'audio',
  'ff-card-gif': 'gif',
  'ff-card-pdf': 'pdf',
  'ff-card-rar': 'rar',
  'ff-card-pyc': 'pyc',
  'ff-card-zipbrute': 'zipbrute',
  'ff-card-repair': 'repair',
  'ff-card-ntfs': 'ntfs',
  'ff-card-embedded': 'embedded',
  'ff-card-chunks': 'embedded',
  'ff-card-strings': 'strings',
  'ff-card-hexdump': 'hexdump',
};

export interface FileForensicsWorkspaceProps {
  // 框架层（CtfToolkit）传入的待分析文件；token 变化表示有新文件到达。
  pendingFile?: { file: File; token: number } | null;
  // 通知框架文件已被取走，框架清空 pendingFile 防止残留重放。
  onFileConsumed?: () => void;
  // 推荐工具条：把当前文件交回框架重走魔数路由（PCAP → 流量分析域，文件跟人走）。
  onHandOffFile?: (file: File) => void;
  // 推荐工具条：纯导航切域（ELF 常量扫描引导 → 逆向速查域）。
  onSwitchModule?: (moduleId: string) => void;
  // 题型选择卡：跳密码与编码域并定位到具体操作（CRC32 反推/零宽解码等纯输入工具）。
  onOpenCipherOperation?: (operationId: string) => void;
}

function FileForensicsWorkspace({ pendingFile, onFileConsumed, onHandOffFile, onSwitchModule, onOpenCipherOperation }: FileForensicsWorkspaceProps) {
  const { language } = useLanguage();
  const ff = useFFAnalyze({ language });
  // 编排层直接消费的四项：文件句柄（定位/移交）、载入动作、忙碌指示；其余状态束整体透传 Shell。
  const { analysis, loadFile, busy, analyzing } = ff;
  const inputRef = useRef<HTMLInputElement | null>(null);
  const lastTokenRef = useRef(0);
  // 二级菜单当前视图（批次 FF-NAV）：默认概览；载入新文件后由 loadAndShow 重置回概览。
  const [activeTool, setActiveTool] = useState('summary');
  // 题型选择卡受控分类（B3 单一状态源）：toolnav 切视图时反向同步 select。
  const [pickerCategoryId, setPickerCategoryId] = useState(challengeCatalog[0].id);

  const openPicker = () => inputRef.current?.click();

  // 载入完成后回到概览视图：在 loadFile 的 promise 回调里 setState，避开 set-state-in-effect 红线（同 ReverseWorkspace）。
  const loadAndShow = useCallback((file: File) => {
    void loadFile(file).then(() => setActiveTool('summary'));
  }, [loadFile]);

  // cardId → 二级视图：静态映射表 + steghide 双载体特判（BMP/WAV 渲染条件互斥，按当前文件魔数路由）。
  const resolveCardView = useCallback((cardId: string): string | null => {
    if (cardId === 'ff-card-steghide') {
      const bytes = analysis?.bytes;
      const isWav = !!bytes && bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46;
      return isWav ? 'steghide-wav' : 'steghide-bmp';
    }
    return CARD_VIEW_MAP[cardId] ?? null;
  }, [analysis]);

  // 视图 id → 题型目录分组 的静态反向映射（steghide 按 BMP 形态近似，WAV 形态由 resolveCardView 动态处理）。
  const viewToCategoryId = useMemo(() => {
    const map = new Map<string, string>();
    for (const cat of challengeCatalog) {
      for (const tool of cat.tools) {
        if (!tool.cardId) continue;
        const viewId = tool.cardId === 'ff-card-steghide' ? 'steghide-bmp' : CARD_VIEW_MAP[tool.cardId];
        if (viewId && !map.has(viewId)) map.set(viewId, cat.id);
      }
    }
    return map;
  }, []);
  const switchTool = (toolId: string) => {
    setActiveTool(toolId);
    const catId = viewToCategoryId.get(toolId);
    if (catId) setPickerCategoryId(catId);
  };
  // 顶部菜单栏（域联动）：文件与图片类菜单只在杂项取证域展示（工作区仅在本域挂载，天然满足）。
  // 未加载文件时一律先打开选择器；目标卡未渲染（该文件没有对应内容）时给出说明。
  // 批次 FF-NAV：定位语义升级为 openCard——先按 cardId 映射切二级视图（hidden 面板里 scrollIntoView
  // 不会滚动页面），等下一帧布局生效再滚动；无映射的 cardId 保持原滚动行为。
  const openCard = useCallback((cardId: string, missingMessage: { zh: string; en: string }) => {
    if (!analysis) {
      inputRef.current?.click();
      return;
    }
    const viewId = resolveCardView(cardId);
    if (viewId && viewId !== activeTool) setActiveTool(viewId);
    const node = document.getElementById(cardId);
    if (node) requestAnimationFrame(() => node.scrollIntoView({ behavior: 'smooth', block: 'start' }));
    else notifications.show({ message: missingMessage[language] });
  }, [analysis, activeTool, language, resolveCardView]);

  // 框架推送文件消费（token 去重）：取走即通知框架清空，随后载入并回到概览视图。
  useEffect(() => {
    if (!pendingFile || pendingFile.token === lastTokenRef.current) return;
    lastTokenRef.current = pendingFile.token;
    onFileConsumed?.();
    loadAndShow(pendingFile.file);
  }, [pendingFile, onFileConsumed, loadAndShow]);

  const onDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    // 阻止冒泡到 CtfToolkit 的页面级 drop，避免同一文件被两处重复读取。
    event.stopPropagation();
    const file = event.dataTransfer.files?.[0];
    if (file) loadAndShow(file);
  };

  return (
    <div className="file-forensics" onDragOver={event => event.preventDefault()} onDrop={onDrop}>
      <input
        ref={inputRef}
        type="file"
        aria-hidden="true"
        tabIndex={-1}
        style={{ display: 'none' }}
        onChange={event => {
          const file = event.target.files?.[0];
          if (file) loadAndShow(file);
          event.target.value = '';
        }}
      />

      <ChallengePickerCard
        language={language}
        hasFile={Boolean(analysis)}
        onPickFile={openPicker}
        categoryId={pickerCategoryId}
        onCategoryChange={setPickerCategoryId}
        onScrollToCard={(cardId) => {
          // 题型卡定位同样走"先切视图再滚动"：hidden 面板内的 scrollIntoView 不会滚动页面。
          const viewId = resolveCardView(cardId);
          if (viewId && viewId !== activeTool) setActiveTool(viewId);
          const node = document.getElementById(cardId);
          if (!node) return false;
          requestAnimationFrame(() => node.scrollIntoView({ behavior: 'smooth', block: 'start' }));
          return true;
        }}
        onOpenCipherOperation={operationId => { onOpenCipherOperation?.(operationId); }}
        onSwitchModule={moduleId => { onSwitchModule?.(moduleId); }}
        onHandOffCurrentFile={analysis && onHandOffFile ? () => { onHandOffFile(analysis.file); } : undefined}
      />

      {/* 二级菜单壳（批次 FF-NAV）：hidden 保挂载（同 ReverseWorkspace），切换视图不丢各卡的过滤/翻页/搜索状态。 */}
      <FileForensicsShell
        language={language}
        ff={ff}
        activeTool={activeTool}
        onSwitchTool={switchTool}
        onOpenPicker={openPicker}
        onOpenCard={openCard}
        onHandOffFile={onHandOffFile}
        onSwitchModule={onSwitchModule}
      />

      {(busy || analyzing) && <div className="ff-busy" role="status">{language === 'zh' ? (analyzing ? '正在分析文件…' : '正在读取文件…') : (analyzing ? 'Analyzing file…' : 'Reading file…')}</div>}

    </div>
  );
}

export default memo(FileForensicsWorkspace);
