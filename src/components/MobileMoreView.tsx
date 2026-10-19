import type { ReactNode } from 'react';
import { useLanguage, useNav, useSession, useStaticData } from '../appContext';
import { t, getText } from '../i18n';
import { protectedExternalLinks } from '../protectedLinks';
import { formatDownloadSize } from '../utils/format';
import { VariablesPanelBody } from './VariablesPanel';
import { Icon } from './Icon';
import type { PublicClientBuildInfo } from '../types';

interface MobileMoreViewProps {
  /** 编解码工作台内容（App 级 lazy slot，与桌面编码弹层共用同一份） */
  encodingTools: ReactNode;
  showClientDownloads: boolean;
  onOpenClientDownloads: () => void;
  clientBuildInfo: PublicClientBuildInfo | null;
}

// 移动端「更多」页（M1）：低频入口统一收口——WAF 模式、CTF 工具箱、客户端下载、主题、
// 全局变量、编解码工作台、站点信息。顶部更多/主题/编解码/下载入口在移动端全部退役，入口只此一处。
function MobileMoreView({ encodingTools, showClientDownloads, onOpenClientDownloads, clientBuildInfo }: MobileMoreViewProps) {
  const { bypassMode, setBypassMode, setActiveTab, setActiveView, setSelectedPayloadId, setSelectedToolId, setSelectedExploitId } = useNav();
  const { theme, setTheme } = useSession();
  const { settings } = useStaticData();
  const { language } = useLanguage();
  const ctfEnabled = settings.ctfEnabled !== false;

  const openCtf = () => {
    setActiveView('workspace');
    setActiveTab('ctf');
    setSelectedPayloadId(null);
    setSelectedToolId(null);
    setSelectedExploitId(null);
  };

  return (
    <div className="mobile-more">
      <h2 className="mobile-more-title">{language === 'zh' ? '更多' : 'More'}</h2>

      <section className="mobile-more-group" aria-label={language === 'zh' ? '模式与入口' : 'Modes and entries'}>
        <div className="mobile-more-row">
          <span className="mobile-more-row-label">{t('header.modeLabel', language)}</span>
          <div className="mobile-more-mode" role="group" aria-label={t('header.modeLabel', language)}>
            <button
              type="button"
              className={bypassMode === 'normal' ? 'active' : ''}
              aria-pressed={bypassMode === 'normal'}
              onClick={() => setBypassMode('normal')}
            >
              {t('header.modeNormal', language)}
            </button>
            <button
              type="button"
              className={bypassMode === 'waf' ? 'active warning' : ''}
              aria-pressed={bypassMode === 'waf'}
              onClick={() => setBypassMode('waf')}
            >
              {t('header.modeWaf', language)}
            </button>
          </div>
        </div>

        {ctfEnabled && (
          <button type="button" className="mobile-more-row mobile-more-entry" onClick={openCtf}>
            <span className="mobile-more-row-label"><Icon name="puzzle" size={16} /> {t('header.tabCtf', language)}</span>
            <span className="mobile-more-row-hint">
              {language === 'zh' ? '解题工具箱' : 'Toolkit'}
              <span className="mobile-more-chevron" aria-hidden="true">›</span>
            </span>
          </button>
        )}

        {showClientDownloads && (
          <button type="button" className="mobile-more-row mobile-more-entry" onClick={onOpenClientDownloads}>
            <span className="mobile-more-row-label"><Icon name="download" size={16} /> {language === 'zh' ? '客户端下载' : 'Download Client'}</span>
            <span className="mobile-more-row-hint">
              {formatDownloadSize(clientBuildInfo?.latest?.size ?? 0) || (language === 'zh' ? '离线版' : 'Offline')}
              <span className="mobile-more-chevron" aria-hidden="true">›</span>
            </span>
          </button>
        )}

        <div className="mobile-more-row">
          <span className="mobile-more-row-label">{language === 'zh' ? '主题' : 'Theme'}</span>
          <div className="mobile-more-mode" role="group" aria-label={language === 'zh' ? '主题切换' : 'Theme'}>
            <button
              type="button"
              className={theme === 'dark' ? 'active' : ''}
              aria-pressed={theme === 'dark'}
              onClick={() => setTheme('dark')}
            >
              {language === 'zh' ? '暗色' : 'Dark'}
            </button>
            <button
              type="button"
              className={theme === 'light' ? 'active' : ''}
              aria-pressed={theme === 'light'}
              onClick={() => setTheme('light')}
            >
              {language === 'zh' ? '亮色' : 'Light'}
            </button>
          </div>
        </div>
      </section>

      <section className="mobile-more-group mobile-more-panel" aria-label={t('header.variablesTitle', language)}>
        <h3>{t('header.variablesTitle', language)}</h3>
        <VariablesPanelBody />
      </section>

      {/* E-19：编解码双标题——外层 section h3 与 CodecWorkbench 自带 h2（encoding-header）重复，
          移动布局下不再渲染外层标题（aria-label 保留分区语义） */}
      <section className="mobile-more-group mobile-more-panel" aria-label={t('header.encoding', language)}>
        {encodingTools}
      </section>

      <section className="mobile-more-group mobile-more-site" aria-label={language === 'zh' ? '站点信息' : 'Site info'}>
        <h3>{language === 'zh' ? '站点信息' : 'Site info'}</h3>
        <p className="mobile-site-line">
          <span>{getText(settings.siteTitle, language) || t('header.logo', language)}</span>
          <span className="mobile-site-sub">{getText(settings.siteSubtitle, language)}</span>
        </p>
        {settings.projectUrl && (
          <a className="mobile-site-link" href={settings.projectUrl} target="_blank" rel="noopener noreferrer">
            GitHub
          </a>
        )}
        {settings.xeyeEnabled !== false && (
          <a
            className="mobile-site-link"
            href={protectedExternalLinks.xeye.href}
            target="_blank"
            rel="noopener"
            referrerPolicy="origin"
          >
            {protectedExternalLinks.xeye.label}
          </a>
        )}
      </section>
    </div>
  );
}

export default MobileMoreView;
