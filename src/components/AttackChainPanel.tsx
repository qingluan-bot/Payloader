import type { JSX } from 'react';
import { getText } from '../i18n';
import type { AttackChainStep } from '../types';
import { label } from './payloadDetailText';

interface AttackChainPanelProps {
  steps: AttackChainStep[];
  language: 'zh' | 'en';
  copiedKey: string | null;
  onCopy: (text: string, index: string) => void;
  renderCommand: (command: string) => JSX.Element;
}

function AttackChainPanel({ steps, language, copiedKey, onCopy, renderCommand }: AttackChainPanelProps) {
  return (
    <div className="attack-chain-section" role="tabpanel">
      <div className="chain-timeline">
        {steps.map((step, index) => {
          const copyId = `chain-${index}`;
          return (
            <article key={`${getText(step.title, language)}-${index}`} className="chain-step">
              <div className="chain-index">{String(index + 1).padStart(2, '0')}</div>
              <div className="chain-body">
                <h3>{getText(step.title, language)}</h3>
                <p>{getText(step.description, language)}</p>
                {step.payload ? (
                  <div className="code-block-wrapper chain-payload">
                    <div className="code-block">
                      <div className="code-block-head">
                        <span className="code-block-title">{label('chainPayload', language)}</span>
                        <button
                          type="button"
                          className={`copy-btn ${copiedKey === copyId ? 'copied' : ''}`}
                          onClick={() => onCopy(step.payload!, copyId)}
                        >
                          {copiedKey === copyId ? label('copied', language) : label('copy', language)}
                        </button>
                      </div>
                      <pre className="code-block-pre">{renderCommand(step.payload)}</pre>
                    </div>
                  </div>
                ) : null}
              </div>
            </article>
          );
        })}
      </div>
    </div>
  );
}

export default AttackChainPanel;
