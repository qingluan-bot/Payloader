// Minecraft NBT/level.dat 检查卡（杂项取证域，B3-5）：拖入 level.dat / .dat / .nbt 等文件后
// 自动判压解析（gzip/zlib/裸 NBT），展示 level.dat 摘要（种子/出生点/DataVersion 版本锚点/
// GameRules 非常规高亮/坐标编码字符线索/非标准顶层字段）+ 路径过滤树缩进转储。
// 引擎在 utils/ctf/mcNbt（节点/深度/解压体积三重护栏）。解析是异步（DecompressionStream），
// effect 内只走 async 回调 setState（react-hooks set-state-in-effect 红线口径）；换文件由父层 key remount。
import { useEffect, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { FlagAutoText } from '../codec/FlagAutoText';
import { copyToClipboard } from '../../utils/clipboard';
import {
  dumpNbt,
  levelDatSummary,
  parseNbtAuto,
} from '../../utils/ctf/mcNbt';
import type { NbtLevelSummary, NbtParseResult } from '../../utils/ctf/mcNbt';
import type { Language } from '../../i18n';

interface NbtInspectCardProps {
  fileName: string;
  bytes: Uint8Array;
  language: Language;
}

type ParseOutcome =
  | { state: 'parsing' }
  | { state: 'error'; message: string }
  | { state: 'done'; parsed: NbtParseResult; summary: NbtLevelSummary | null };

function NbtInspectCard({ fileName, bytes, language }: NbtInspectCardProps) {
  const zh = language === 'zh';
  // 初始即 parsing 态；换文件由父层 key（name:size）remount，状态自然清零——effect 内不做同步 setState。
  const [outcome, setOutcome] = useState<ParseOutcome>({ state: 'parsing' });
  const [path, setPath] = useState('');
  const [dumpText, setDumpText] = useState<string | null>(null);

  // 异步解析：setState 只出现在 await 之后的回调（set-state-in-effect 红线口径）。
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const parsed = await parseNbtAuto(bytes);
        let summary: NbtLevelSummary | null = null;
        if (parsed.root.Data) {
          try {
            summary = levelDatSummary(parsed.root);
          } catch {
            summary = null; // 有 Data 键但结构不标准：摘要缺省，转储仍可用
          }
        }
        if (!cancelled) setOutcome({ state: 'done', parsed, summary });
      } catch (error) {
        if (!cancelled) setOutcome({ state: 'error', message: error instanceof Error ? error.message : String(error) });
      }
    })();
    return () => { cancelled = true; };
  }, [bytes]);

  const runDump = () => {
    if (outcome.state !== 'done') return;
    try {
      setDumpText(dumpNbt(outcome.parsed.root, { path: path.trim() || undefined }));
    } catch (error) {
      setDumpText(null);
      notifications.show({
        message: zh ? `转储失败：${error instanceof Error ? error.message : String(error)}` : `Dump failed: ${error instanceof Error ? error.message : String(error)}`,
        color: 'red',
      });
    }
  };

  if (outcome.state === 'parsing') {
    return (
      <section id="ff-card-nbt" className="ff-card" aria-label={zh ? 'Minecraft NBT 解析' : 'Minecraft NBT'}>
        <div className="ff-card-head"><strong>{zh ? 'Minecraft NBT / level.dat' : 'Minecraft NBT / level.dat'}</strong></div>
        <p className="ff-note">{zh ? '正在解压解析…' : 'Inflating & parsing…'}</p>
      </section>
    );
  }
  if (outcome.state === 'error') {
    return (
      <section id="ff-card-nbt" className="ff-card" aria-label={zh ? 'Minecraft NBT 解析' : 'Minecraft NBT'}>
        <div className="ff-card-head"><strong>{zh ? 'Minecraft NBT / level.dat' : 'Minecraft NBT / level.dat'}</strong></div>
        <p className="ff-note">{outcome.message}</p>
      </section>
    );
  }

  const { parsed, summary } = outcome;
  const root = parsed.root;

  return (
    <section id="ff-card-nbt" className="ff-card" aria-label={zh ? 'Minecraft NBT 解析' : 'Minecraft NBT'}>
      <div className="ff-card-head">
        <strong>{zh ? 'Minecraft NBT / level.dat' : 'Minecraft NBT / level.dat'}</strong>
        <span className="ff-badge">
          {parsed.compression.toUpperCase()} · {zh ? `根 "${parsed.rootName || '(空)'}"` : `root "${parsed.rootName || '(empty)'}"`} · {parsed.byteLength.toLocaleString()} {zh ? '字节' : 'bytes'}
        </span>
      </div>

      {summary && (
        <>
          <div className="ff-tool">
            <span className="ff-label">{zh ? '世界种子' : 'World seed'}</span>
            <code className="ff-code">{summary.seed === null ? (zh ? '未找到' : 'not found') : `${summary.seed.toString(10)}${summary.seedSource ? ` (${summary.seedSource})` : ''}`}</code>
          </div>
          <div className="ff-tool">
            <span className="ff-label">{zh ? '出生点 / 版本' : 'Spawn / version'}</span>
            <code className="ff-code">
              {`Spawn = (${summary.spawn.x ?? '?'}, ${summary.spawn.y ?? '?'}, ${summary.spawn.z ?? '?'})`}
              {` · DataVersion = ${summary.dataVersion ?? '?'}`}
              {summary.dataVersionAnchor ? ` (${summary.dataVersionAnchor})` : ''}
              {summary.versionName ? ` · ${summary.versionName}` : ''}
            </code>
            {summary.asciiHints.map((hint, index) => (
              <p key={`ascii-${index}`} className="ff-note"><span className="ff-badge ff-badge-flag">{zh ? '坐标编码线索' : 'coordinate hint'}</span> {hint}</p>
            ))}
          </div>
          {summary.gameRules.length > 0 && (
            <div className="ff-tool">
              <span className="ff-label">{zh ? 'GameRules（非常规项排前并高亮，出题人改规则的落点）' : 'GameRules (unusual first — common tweak targets)'}</span>
              {summary.gameRules.map(rule => (
                <div key={rule.name} className="ff-row">
                  <span className={rule.unusual ? 'ff-badge ff-badge-warn' : 'ff-badge'}>{rule.name}</span>
                  <code className="ff-code" style={{ flex: 1 }}>{rule.value}</code>
                </div>
              ))}
            </div>
          )}
          {summary.topLevelExtra.length > 0 && (
            <div className="ff-tool">
              <span className="ff-label">{zh ? '非标准顶层字段（隐写/隐藏数据高发位）' : 'Non-standard top-level fields (stego hotspot)'}</span>
              {summary.topLevelExtra.map(name => (
                <div key={name} className="ff-row">
                  <span className="ff-badge ff-badge-warn">{name}</span>
                  {(() => {
                    const tag = root[name];
                    const preview = tag && (tag.type === 8 || tag.type === 1) ? String(tag.value) : zh ? '见下方转储' : 'see dump below';
                    return <code className="ff-code" style={{ flex: 1 }}><FlagAutoText text={preview} /></code>;
                  })()}
                </div>
              ))}
            </div>
          )}
          {summary.notes.map((note, index) => <p key={`note-${index}`} className="ff-note">• {note}</p>)}
        </>
      )}
      {!summary && (
        <p className="ff-note">
          {zh ? '未识别为标准 level.dat（根下无 Data Compound），按通用 NBT 树转储。' : 'Not a standard level.dat (no Data compound at root); showing a generic NBT tree dump.'}
        </p>
      )}

      <div className="ff-tool">
        <span className="ff-label">{zh ? '树转储（路径过滤如 Data.Player.Inventory；List 用数字段）' : 'Tree dump (path filter like Data.Player.Inventory; numeric segments for lists)'}</span>
        <div className="ff-row">
          <input
            className="ff-input"
            value={path}
            onChange={event => setPath(event.target.value)}
            placeholder="Data.Player.Inventory"
            aria-label={zh ? 'NBT 路径过滤' : 'NBT path filter'}
          />
          <button type="button" className="ff-button ff-button-primary" onClick={runDump}>
            {zh ? '转储' : 'Dump'}
          </button>
        </div>
        {dumpText && (
          <>
            <code className="ff-code"><FlagAutoText text={dumpText} /></code>
            <div className="ff-row">
              <button type="button" className="ff-button" onClick={() => { void copyToClipboard(dumpText); }}>
                {zh ? '复制转储' : 'Copy dump'}
              </button>
            </div>
          </>
        )}
      </div>
      <p className="ff-note">{zh ? `源文件：${fileName}` : `Source: ${fileName}`}</p>
    </section>
  );
}

export default NbtInspectCard;
