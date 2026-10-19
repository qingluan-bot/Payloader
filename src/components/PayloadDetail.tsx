import { useEffect, useMemo, useState } from 'react';
import type { JSX } from 'react';
import { useLanguage, useNav, useSession, useStaticData } from '../appContext';
import { getText } from '../i18n';
import type { AttackChainStep, I18nText, PayloadExecution, PayloadItem, SyntaxPart } from '../types';
import { cachedPayloadDetail, fetchPayloadDetail } from '../data/payloadDetailCache';
import { resolveVariableParts, resolveVariableText } from '../utils/variables';
import { sourceLabel } from '../utils/exploit-labels';
import { useCopyFeedback } from '../utils/clipboard';
import SyntaxModal from './SyntaxModal';
import { label, payloadIdAliases, tutorialIsSubstantive } from './payloadDetailText';
import type { DetailSection } from './payloadDetailText';
import PayloadDetailHeader from './PayloadDetailHeader';
import ExecutionListPanel from './ExecutionListPanel';
import AttackChainPanel from './AttackChainPanel';
import TutorialPanel from './TutorialPanel';
import { MOBILE_BREAKPOINT, useMediaQuery } from './useMediaQuery';
import '../styles/payload-detail.css';

interface PayloadDetailProps {
  payloadId: string;
}

function PayloadDetail({ payloadId }: PayloadDetailProps) {
  const { globalVariables } = useSession();
  const { bypassMode, setSelectedPayloadId } = useNav();
  const { language } = useLanguage();
  const { allPayloads } = useStaticData();
  const isMobile = useMediaQuery(MOBILE_BREAKPOINT);
  const { copiedKey: copiedIndex, copy } = useCopyFeedback();
  const [selectedSyntax, setSelectedSyntax] = useState<{ syntax: SyntaxPart[]; title: I18nText } | null>(null);
  const [sectionSelection, setSectionSelection] = useState<{ payloadId: string; section: DetailSection }>({
    payloadId,
    section: 'payloads',
  });
  const [payloadQueryState, setPayloadQueryState] = useState({ payloadId, value: '' });

  const resolvedPayloadId = payloadIdAliases[payloadId] || payloadId;
  // P1-2 首屏载荷瘦身：列表条目只含投影字段，详情级内容按需拉取。
  // 挂载初值取缓存命中；未命中时 effect 内异步拉取（key 由父组件绑定 payloadId，
  // 切换条目触发重挂，局部状态自然清零）。拉取失败回落列表态渲染（旧离线包 404 场景）。
  const [detail, setDetail] = useState<PayloadItem | null>(() => cachedPayloadDetail(resolvedPayloadId));
  const [detailMissing, setDetailMissing] = useState(false);
  const listItem = allPayloads.find(item => item.id === payloadId) || allPayloads.find(item => item.id === resolvedPayloadId);

  useEffect(() => {
    if (cachedPayloadDetail(resolvedPayloadId)) return;
    let isCurrent = true;
    fetchPayloadDetail(resolvedPayloadId).then(item => {
      if (!isCurrent) return;
      if (item) setDetail(item);
      else setDetailMissing(true);
    });
    return () => {
      isCurrent = false;
    };
  }, [resolvedPayloadId]);

  const payload = detail ?? listItem;
  const detailPending = !detail && !detailMissing && Boolean(listItem);
  const hasSubstantiveTutorial = tutorialIsSubstantive(payload?.tutorial);
  const hasWafContent = Boolean(payload?.wafBypass?.length);
  const requestedSection = sectionSelection.payloadId === payloadId ? sectionSelection.section : 'payloads';
  const activeSection = requestedSection === 'tutorial' && !hasSubstantiveTutorial ? 'payloads' : requestedSection;
  const setActiveSection = (section: DetailSection) => setSectionSelection({ payloadId, section });

  const payloadQuery = payloadQueryState.payloadId === payloadId ? payloadQueryState.value : '';

  const executionItems = useMemo<PayloadExecution[]>(() => {
    if (!payload) return [];
    if (bypassMode === 'waf') return payload.wafBypass || [];
    // 列表投影态（详情未到达）execution 为 undefined：链式 fallback 的 useMemo 无条件
    // 求值，必须兜底空数组，否则 executionItems[0] 渲染期崩树
    return payload.execution || [];
  }, [bypassMode, payload]);

  const attackChainItems = useMemo<AttackChainStep[]>(() => {
    if (!payload) return [];
    if (payload.attackChain?.length) return payload.attackChain;
    return [
      {
        title: { zh: '确认适用场景', en: 'Confirm the scenario' },
        description: payload.description,
      },
      {
        title: label('chainFallbackTitle', language),
        description: label('chainFallbackDesc', language),
        payload: executionItems[0]?.command,
      },
      {
        title: { zh: '记录结果', en: 'Record results' },
        description: payload.analysis || { zh: '记录上传响应、保存文件名、访问路径、服务端是否解析以及防护设备命中情况。', en: 'Record the upload response, saved filename, access path, server-side parsing behavior, and defensive detections.' },
      },
      {
        title: { zh: '加固复盘', en: 'Review mitigation' },
        description: payload.tutorial?.mitigation || { zh: '根据验证结果收敛上传类型、存储目录、脚本执行权限、鉴权、审计和告警策略。', en: 'Use the validation result to tighten type checks, storage paths, script execution permissions, authorization, auditing, and alerting.' },
      },
    ];
  }, [executionItems, language, payload]);

  const filteredExecutionItems = useMemo(() => {
    const query = payloadQuery.trim().toLowerCase();

    return executionItems.filter(item => {
      if (!query) return true;

      const searchable = [
        getText(item.title, language),
        getText(item.description, language),
        item.command,
      ].join(' ').toLowerCase();

      return searchable.includes(query);
    });
  }, [executionItems, language, payloadQuery]);

  if (!payload) {
    return (
      <div className="payload-not-found">
        <h2>{label('notFound', language)}</h2>
        <p>ID: {payloadId}</p>
      </div>
    );
  }

  const modeLabel = (() => {
    if (bypassMode === 'waf') return label('wafMode', language);
    return label('normalMode', language);
  })();

  const copyText = (text: string, index: string) => {
    void copy(resolveVariableText(text, globalVariables), index);
  };

  const copyVisible = () => {
    if (!filteredExecutionItems.length) return;
    copyText(filteredExecutionItems.map(item => item.command).join('\n\n'), 'all');
  };

  const renderCommandWithHighlights = (command: string) => {
    const parts = resolveVariableParts(command, globalVariables);
    const hasVariables = parts.some(part => part.key);

    if (!hasVariables) return <code>{parts.map(part => part.text).join('')}</code>;

    const elements: JSX.Element[] = parts.map((part, index) => {
      if (!part.key) return <span key={`text-${index}`}>{part.text}</span>;
      return (
        <span key={`var-${index}`} className="var-highlight" title={`${part.raw} -> ${part.value}`}>
          {part.text}
        </span>
      );
    });
    return <code>{elements}</code>;
  };

  return (
    <div className="payload-detail">
      {isMobile && (
        <button
          type="button"
          className="mobile-detail-back"
          onClick={() => setSelectedPayloadId(null)}
        >
          <span aria-hidden="true">←</span> {language === 'zh' ? '返回列表' : 'Back to list'}
        </button>
      )}
      <PayloadDetailHeader
        payload={payload}
        hasSubstantiveTutorial={hasSubstantiveTutorial}
        language={language}
        activeSection={activeSection}
        onSelectSection={setActiveSection}
        copiedKey={copiedIndex}
      />

      {detailMissing && (
        // 详情拉取失败（旧离线包 404 等）：如实告知当前只有列表态基础信息
        <p className="related-exploits-hint" role="note">
          {language === 'zh'
            ? '详情内容暂时不可用（离线包较旧或网络异常），当前展示基础信息。'
            : 'Detail content is unavailable (older offline package or network issue); showing basic info.'}
        </p>
      )}

      {detailPending ? (
        // 详情未到达前渲染列表态骨架：头部（名称/描述/分类）由列表投影即时呈现
        <div className="payload-detail-skeleton" role="status" aria-live="polite">
          <span className="skeleton-line w-40" aria-hidden="true" />
          <span className="skeleton-line w-90" aria-hidden="true" />
          <span className="skeleton-line w-75" aria-hidden="true" />
          <span className="skeleton-line w-60" aria-hidden="true" />
        </div>
      ) : (
        <>
          {activeSection === 'payloads' && (
            <>
              <ExecutionListPanel
                items={filteredExecutionItems}
                totalCount={executionItems.length}
                modeLabel={modeLabel}
                hasWafContent={hasWafContent}
                payloadQuery={payloadQuery}
                onQueryChange={event => setPayloadQueryState({ payloadId, value: event.target.value })}
                onClearQuery={() => setPayloadQueryState({ payloadId, value: '' })}
                copiedKey={copiedIndex}
                onCopy={copyText}
                onCopyVisible={copyVisible}
                onSelectSyntax={setSelectedSyntax}
                renderCommand={renderCommandWithHighlights}
              />
              {Boolean(payload?.relatedExploits?.length) && (
                <section className="related-exploits-card" aria-label={language === 'zh' ? '相关 EXP' : 'Related exploits'}>
                  <h3>{language === 'zh' ? '相关 EXP' : 'Related exploits'}</h3>
                  <p className="related-exploits-hint">
                    {language === 'zh' ? '按漏洞编号与影响产品自动关联的公开利用程序：' : 'Public exploits auto-linked by CVE and affected product:'}
                  </p>
                  <ul>
                    {(payload.relatedExploits ?? []).map(item => (
                      <li key={item.id}>
                        <a href={`#/exploit/${encodeURIComponent(item.id)}`}>{item.name}</a>
                        {/* E-11：来源统一同一 chip 形态（圆角描边 + 等宽内边距），仅配色按来源区分 */}
                        <span className={`related-exploits-source src-${item.source || 'curated'}`}>
                          {sourceLabel(item.source || 'curated', language)}
                        </span>
                      </li>
                    ))}
                  </ul>
                </section>
              )}
            </>
          )}

          {activeSection === 'chain' && (
            <AttackChainPanel
              steps={attackChainItems}
              language={language}
              copiedKey={copiedIndex}
              onCopy={copyText}
              renderCommand={renderCommandWithHighlights}
            />
          )}

          {activeSection === 'tutorial' && hasSubstantiveTutorial && payload.tutorial && (
            <TutorialPanel payload={payload} tutorial={payload.tutorial} language={language} />
          )}
        </>
      )}

      {selectedSyntax && (
        <SyntaxModal syntax={selectedSyntax.syntax} title={selectedSyntax.title} onClose={() => setSelectedSyntax(null)} />
      )}
    </div>
  );
}

export default PayloadDetail;
