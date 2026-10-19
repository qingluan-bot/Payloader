// OverviewCard：杂项取证域概览视图渲染卡（批次 P2-5 拆分自 FileForensicsWorkspace）。
// 承接概览面板四段：推荐工具条、文件概要（ff-card-summary）、flag 命中（ff-card-flag）、
// 可疑内容（ff-card-suspicious）。锚点定位/跨域移交回调由编排层注入，卡内仅做派生计算与渲染。
import { useMemo } from 'react';
import { notifications } from '@mantine/notifications';
import { Icon } from '../Icon';
import { FlagAutoText } from '../codec/FlagAutoText';
import { copyToClipboard } from '../../utils/clipboard';
import { entropyVerdictText } from '../../utils/ctf/fileDetect';
import { recommendTools } from '../../utils/ctf/recommendTools';
import type { ToolAnchor } from '../../utils/ctf/recommendTools';
import type { Language } from '../../i18n';
import { formatBytes } from './ffUseAnalyze';
import type { FileAnalysis, FileReport } from './ffUseAnalyze';

interface OverviewCardProps {
  language: Language;
  // 仅在已加载文件时挂载（未加载空态由外层 pickFileNote 处理），故为非空。
  analysis: FileAnalysis;
  report: FileReport | null;
  // 概要卡「换一个文件」按钮。
  onOpenPicker: () => void;
  // 推荐工具条域内锚点：先切二级视图再滚动（openCard 驻留编排层，含 steghide 双载体特判）。
  onOpenCard: (cardId: string, missingMessage: { zh: string; en: string }) => void;
  // 推荐工具条跨域移交（PCAP → 流量分析域，文件跟人走）。
  onHandOffFile?: (file: File) => void;
  // 推荐工具条纯导航切域（ELF 常量扫描引导 → 逆向速查域）。
  onSwitchModule?: (moduleId: string) => void;
}

function OverviewCard({ language, analysis, report, onOpenPicker, onOpenCard, onHandOffFile, onSwitchModule }: OverviewCardProps) {
  // 推荐工具条（文件探测驱动）：按探测类型映射适用操作，报告头部直达；纯映射在 recommendTools.ts。
  const recommendedTools = useMemo(
    () => (report ? recommendTools(report.types) : []),
    [report],
  );

  const extensionMatches = useMemo(() => {
    if (!analysis || !report) return null;
    const extension = analysis.name.includes('.') ? analysis.name.split('.').pop()!.toLowerCase() : '';
    if (!extension) return null;
    if (report.types.length === 0) return null;
    const detected = new Set(report.types.map(type => type.ext));
    if (detected.has(extension)) return true;
    if (detected.has('zip') && ['docx', 'xlsx', 'pptx', 'epub', 'apk', 'jar'].includes(extension)) return true;
    if (detected.has('jpg') && ['jpeg', 'jfif'].includes(extension)) return true;
    if (detected.has('exe') && ['dll', 'sys'].includes(extension)) return true;
    if (detected.has('pcapbe') && extension === 'pcap') return true;
    return false;
  }, [analysis, report]);

  const runToolAnchor = (tool: ToolAnchor) => {
    if (tool.handoffFile) {
      if (analysis) onHandOffFile?.(analysis.file);
      else notifications.show({ message: tool.missingMessage[language] });
      return;
    }
    if (tool.targetModuleId) {
      onSwitchModule?.(tool.targetModuleId);
      return;
    }
    // 域内锚点走 openCard：先切二级视图再滚动（handoffFile/targetModuleId 跨域分支不动）。
    if (tool.cardId) onOpenCard(tool.cardId, tool.missingMessage);
  };

  return (
    <>
          {recommendedTools.length > 0 && (
            <nav className="ff-recommend" aria-label={language === 'zh' ? '推荐工具' : 'Recommended tools'}>
              <span className="ff-recommend-label">{language === 'zh' ? '推荐工具' : 'Recommended'}</span>
              <div className="ff-recommend-tools">
                {recommendedTools.map(tool => (
                  /* B-10：规划中工具渲染为禁用态（title=规划中），去"可点但零反馈"的死按钮 */
                  tool.soon ? (
                    <button
                      key={tool.id}
                      type="button"
                      className="ff-button ff-recommend-soon"
                      disabled
                      title={language === 'zh' ? '规划中' : 'Planned'}
                    >
                      {tool.label[language]}
                      <span className="ff-recommend-soon-tag">{language === 'zh' ? '即将上线' : 'soon'}</span>
                    </button>
                  ) : (
                    <button
                      key={tool.id}
                      type="button"
                      className="ff-button ff-recommend-hit"
                      onClick={() => runToolAnchor(tool)}
                      title={tool.label[language]}
                    >
                      {tool.label[language]}
                    </button>
                  )
                ))}
              </div>
            </nav>
          )}

          <section id="ff-card-summary" className="ff-card" aria-label={language === 'zh' ? '文件概要' : 'File summary'}>
            <div className="ff-card-head">
              <strong>{language === 'zh' ? '文件概要' : 'Summary'}</strong>
              <button type="button" className="ff-button" onClick={onOpenPicker}>{language === 'zh' ? '换一个文件' : 'Replace'}</button>
            </div>
            <div className="ff-summary">
              <span className="ff-name" title={analysis.name}>{analysis.name}</span>
              <span className="ff-size">{formatBytes(analysis.size)}</span>
            </div>
            {report && (
              <>
                <div className="ff-row">
                  <span className="ff-label">{language === 'zh' ? '探测类型' : 'Detected type'}</span>
                  {report.types.length
                    ? report.types.map(type => (
                      <span key={type.ext} className="ff-badge" title={type.name}>{type.name}</span>
                    ))
                    : <span className="ff-badge ff-badge-warn">{language === 'zh' ? '未知类型（无已知魔数）' : 'Unknown (no magic match)'}</span>}
                </div>
                {extensionMatches !== null && (
                  <div className="ff-row">
                    <span className="ff-label">{language === 'zh' ? '扩展名比对' : 'Extension check'}</span>
                    {extensionMatches
                      ? <span className="ff-badge ff-badge-ok">{language === 'zh' ? '与扩展名一致' : 'Matches extension'}</span>
                      : <span className="ff-badge ff-badge-warn">{language === 'zh' ? '与扩展名不符——可能被改名，以探测结果为准' : 'Mismatches extension — likely renamed; trust the detected type'}</span>}
                  </div>
                )}
                <div className="ff-row">
                  <span className="ff-label">{language === 'zh' ? '信息熵' : 'Entropy'}</span>
                  <span className="ff-mono">{report.entropy.toFixed(3)} / 8</span>
                </div>
                <p className="ff-note">{entropyVerdictText(report.level, language, report.types)}</p>
              </>
            )}
          </section>

          {report && report.suspicious.flags.length > 0 && (
            <section id="ff-card-flag" className="ff-card ff-card-flag" aria-label={language === 'zh' ? 'flag 命中' : 'Flag hits'}>
              <div className="ff-card-head">
                <strong>
                  <Icon name="flag" size={14} />
                  {language === 'zh' ? ' 发现 flag' : ' Flag found'}
                </strong>
              </div>
              <div className="ff-row">
                {report.suspicious.flags.map(hit => (
                  <span key={hit.prefix} className="ff-badge ff-badge-flag" title={hit.sample}>{hit.sample}</span>
                ))}
              </div>
            </section>
          )}

          {report && (report.suspicious.flags.length > 0 || report.suspicious.base64Candidates.length > 0 || report.suspicious.keywordHits.length > 0 || report.zeroWidth.zeroWidthCount > 0) && (
            <section id="ff-card-suspicious" className="ff-card" aria-label={language === 'zh' ? '可疑内容' : 'Suspicious content'}>
              <div className="ff-card-head">
                <strong>{language === 'zh' ? '可疑内容' : 'Suspicious content'}</strong>
              </div>
              {report.suspicious.base64Candidates.length > 0 && (
                <div className="ff-tool">
                  <span className="ff-label">{language === 'zh' ? '疑似 Base64 片段（点击复制，可用「密码与编码」域解码）' : 'Base64-like fragments (click to copy; decode in Ciphers & Encoding)'}</span>
                  {report.suspicious.base64Candidates.map(candidate => (
                    <button
                      key={candidate}
                      type="button"
                      className="ff-code ff-code-click"
                      title={language === 'zh' ? '点击复制' : 'Click to copy'}
                      onClick={() => { void copyToClipboard(candidate); }}
                    >
                      {candidate.length > 96 ? `${candidate.slice(0, 96)}…` : candidate}
                    </button>
                  ))}
                </div>
              )}
              {report.suspicious.keywordHits.length > 0 && (
                <div className="ff-row">
                  <span className="ff-label">{language === 'zh' ? '关键词命中' : 'Keyword hits'}</span>
                  {report.suspicious.keywordHits.map(keyword => <span key={keyword} className="ff-badge">{keyword}</span>)}
                </div>
              )}
              {report.zeroWidth.zeroWidthCount > 0 && (
                <div className="ff-tool">
                  <span className="ff-label">{language === 'zh' ? `发现 ${report.zeroWidth.zeroWidthCount} 个零宽字符${report.zeroWidth.scheme ? `（${report.zeroWidth.scheme}）` : ''}` : `${report.zeroWidth.zeroWidthCount} zero-width characters${report.zeroWidth.scheme ? ` (${report.zeroWidth.scheme})` : ''}`}</span>
                  {report.zeroWidth.payload
                    ? <code className="ff-code"><FlagAutoText text={report.zeroWidth.payload} /></code>
                    : <span className="ff-note">{language === 'zh' ? '零宽字符未凑满完整字节序列，无法按零宽编码解码；可能只是不可见水印或分隔符。' : 'Zero-width characters do not form complete bytes; they may be watermarks or separators.'}</span>}
                </div>
              )}
            </section>
          )}
    </>
  );
}

export default OverviewCard;
