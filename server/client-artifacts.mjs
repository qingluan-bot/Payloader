import { basename, extname } from 'node:path';
import { CLIENT_BUILD_CONTRACT_VERSION } from './client-deployment-package.mjs';
import { clientProjectRoute, officialProjectUrl, publicProjectRoute } from './project-attribution.mjs';
import { clientTargetById, clientTargetOrder } from './client-pack.mjs';

const protectedXeyeUrl = 'https://xss.icu/';
const protectedXssToolId = 'xss-platform';
const clientRuntime = 'electron-offline-client';
const clientDistribution = 'multi-platform-desktop-client';
const clientBuildContractVersion = CLIENT_BUILD_CONTRACT_VERSION;
const clientMetadataVersion = 3;

const downloadMimeTypes = {
  '.exe': 'application/vnd.microsoft.portable-executable',
  '.AppImage': 'application/octet-stream',
  '.appimage': 'application/octet-stream',
  '.dmg': 'application/x-apple-diskimage',
  '.zip': 'application/zip',
  '.gz': 'application/gzip',
  '.deb': 'application/vnd.debian.binary-package',
  '.rpm': 'application/x-rpm',
};

const now = () => new Date().toISOString();

const sanitizeFileName = value => {
  const fileName = basename(String(value || ''));
  return /^Payloader-Client-\d{8}-\d{6}-[a-f0-9]{8}-(win|linux|mac)-[a-z0-9]+-[a-z0-9-]+(?:\.[A-Za-z0-9]+)+$/i.test(fileName)
    || /^Payloader-Client-\d{8}-\d{6}-[a-f0-9]{8}\.exe$/i.test(fileName)
    ? fileName
    : '';
};

const artifactPlatformPrefix = target => target.platform === 'macos' ? 'mac' : target.platform === 'windows' ? 'win' : target.platform;

const artifactFileName = (target, stamp, buildId) => (
  `Payloader-Client-${stamp}-${buildId.slice(0, 8)}-${artifactPlatformPrefix(target)}-${target.arch}-${target.builderTargets[0].toLowerCase()}${target.extension}`
);

const portableArtifactFileName = (target, shell, stamp, buildId) => (
  `Payloader-Client-${stamp}-${buildId.slice(0, 8)}-${artifactPlatformPrefix(target)}-${target.arch}-portable${shell.outputFormat === 'zip' ? '.zip' : '.tar.gz'}`
);

const artifactScore = item => {
  const platform = String(item?.platform || '');
  const arch = String(item?.arch || '');
  const targetRank = clientTargetOrder.get(String(item?.targetId || ''));
  if (typeof targetRank === 'number') return targetRank;
  if (platform === 'windows' && arch === 'x64') return 0;
  if (platform === 'windows' && arch === 'arm64') return 1;
  if (platform === 'windows' && arch === 'ia32') return 2;
  if (platform === 'macos' && arch === 'universal') return 3;
  if (platform === 'macos' && arch === 'arm64') return 4;
  if (platform === 'macos' && arch === 'x64') return 5;
  if (platform === 'linux' && arch === 'x64') return 6;
  if (platform === 'linux' && arch === 'arm64') return 7;
  if (platform === 'linux' && arch === 'armv7l') return 8;
  return 999;
};

const displayArtifactFormat = (value, fallback) => {
  const format = String(value || fallback || '').trim();
  return format === 'NSIS EXE' ? 'Windows Installer' : format;
};

const normalizeArtifact = item => {
  if (!item || typeof item !== 'object' || !item.fileName) return null;
  if (item.status && item.status !== 'success') return null;
  const target = clientTargetById.get(item.targetId) || {};
  const fileName = sanitizeFileName(item.fileName);
  if (!fileName) return null;
  const extension = extname(fileName);
  return {
    targetId: item.targetId || '',
    platform: item.platform || target.platform || 'windows',
    platformLabel: item.platformLabel || target.platformLabel || 'Windows',
    arch: item.arch || target.arch || 'x64',
    archLabel: item.archLabel || target.archLabel || 'Intel / AMD 64-bit',
    format: displayArtifactFormat(item.format, target.format || 'Windows Installer'),
    fileName,
    size: Number(item.size || 0),
    sha256: typeof item.sha256 === 'string' ? item.sha256 : '',
    generatedAt: item.generatedAt || item.finishedAt || item.startedAt || '',
    runtime: item.runtime || clientRuntime,
    distribution: item.distribution || clientDistribution,
    buildContractVersion: Number(item.buildContractVersion || 0),
    codeSigningConfigured: Boolean(item.codeSigningConfigured),
    signingStatus: item.signingStatus || (item.codeSigningConfigured ? 'configured' : 'unsigned'),
    mimeType: item.mimeType || downloadMimeTypes[extension] || 'application/octet-stream',
    downloadUrl: item.downloadUrl || `/api/client-build/download/${encodeURIComponent(fileName)}`,
    cpuFamily: item.cpuFamily || target.cpuFamily || target.archLabel || '',
    minOsVersion: item.minOsVersion || target.minOsVersion || '',
    installType: item.installType || target.installType || item.format || '',
    packageManager: item.packageManager || target.packageManager || '',
    buildSource: item.buildSource || 'native-host',
    shellVersion: item.shellVersion || '',
    shellSha256: item.shellSha256 || '',
    performanceNotes: Array.isArray(item.performanceNotes) ? item.performanceNotes : [],
    securityNotes: Array.isArray(item.securityNotes) ? item.securityNotes : [],
    notes: Array.isArray(item.notes) ? item.notes : [],
  };
};

const normalizeMetadata = metadata => {
  if (!metadata || typeof metadata !== 'object') return null;
  const rawItems = Array.isArray(metadata.items)
    ? metadata.items.length
      ? metadata.items
      : Array.isArray(metadata.targetResults)
        ? metadata.targetResults
            .filter(item => item && item.status === 'success' && item.fileName)
            .map(item => {
              const target = clientTargetById.get(item.id) || {};
              return {
                targetId: item.id || '',
                platform: target.platform || 'windows',
                platformLabel: target.platformLabel || 'Windows',
                arch: target.arch || 'x64',
                archLabel: target.archLabel || 'Intel / AMD 64-bit',
                format: target.format || 'Windows Installer',
                fileName: item.fileName,
                size: item.size || 0,
                sha256: item.sha256 || '',
                generatedAt: metadata.finishedAt || metadata.startedAt || '',
                runtime: metadata.runtime,
                distribution: metadata.distribution,
                buildContractVersion: metadata.buildContractVersion,
                codeSigningConfigured: metadata.codeSigningConfigured,
                signingStatus: metadata.codeSigningConfigured ? 'configured' : 'unsigned',
                cpuFamily: target.cpuFamily || '',
                minOsVersion: target.minOsVersion || '',
                installType: target.installType || target.format || '',
                packageManager: target.packageManager || '',
              };
            })
        : metadata.items
    : metadata.status === 'success' && metadata.fileName
      ? [{
          targetId: 'win-x64-nsis',
          platform: 'windows',
          platformLabel: 'Windows',
          arch: 'x64',
          archLabel: 'Intel / AMD 64-bit',
          format: 'Windows Installer',
          fileName: metadata.fileName,
          size: metadata.size,
          sha256: metadata.sha256,
          generatedAt: metadata.finishedAt || metadata.startedAt,
          runtime: metadata.runtime,
          distribution: metadata.distribution,
          buildContractVersion: metadata.buildContractVersion,
          codeSigningConfigured: metadata.codeSigningConfigured,
          signingStatus: metadata.codeSigningConfigured ? 'configured' : 'unsigned',
        }]
      : [];
  const items = rawItems.map(normalizeArtifact).filter(Boolean).sort((a, b) => artifactScore(a) - artifactScore(b));
  const latest = normalizeArtifact(metadata.latest) || items[0] || null;
  const defaultSuccessMessage = items.length
    ? `Ready to download ${items.length} client build${items.length === 1 ? '' : 's'}`
    : 'Build completed without recognized artifacts';
  return {
    ...metadata,
    metadataVersion: metadata.metadataVersion || (items.length ? clientMetadataVersion : 1),
    status: metadata.status || (items.length ? 'success' : 'idle'),
    message: metadata.status === 'success'
      ? (items.length
          ? (/Ready to download 0 client builds/i.test(String(metadata.message || ''))
              ? defaultSuccessMessage
              : String(metadata.message || defaultSuccessMessage))
          : String(metadata.message || defaultSuccessMessage))
      : metadata.message,
    latest,
    items,
  };
};

const metadataMatchesCurrentContract = metadata => (
  Boolean(metadata) &&
  metadata.status === 'success' &&
  metadata.buildContractVersion === clientBuildContractVersion &&
  metadata.runtime === clientRuntime &&
  metadata.distribution === clientDistribution
);

const normalizeSuccessfulMetadata = metadata => {
  const normalized = normalizeMetadata(metadata);
  return normalized?.status === 'success' ? normalized : null;
};

const normalizeFailureMetadata = metadata => {
  if (!metadata || typeof metadata !== 'object' || metadata.status !== 'failed') return null;
  return {
    ...metadata,
    status: 'failed',
    message: String(metadata.message || 'Build failed'),
    selectedTargets: Array.isArray(metadata.selectedTargets) ? metadata.selectedTargets : [],
    skippedTargets: Array.isArray(metadata.skippedTargets) ? metadata.skippedTargets : [],
    logs: Array.isArray(metadata.logs) ? metadata.logs.filter(Boolean).slice(-12) : [],
  };
};

const metadataTimestamp = metadata => {
  const timestamp = Date.parse(metadata?.reusedAt || metadata?.finishedAt || metadata?.startedAt || '');
  return Number.isFinite(timestamp) ? timestamp : null;
};

const failureAfterLatestSuccess = (failure, latest) => {
  if (!failure || !latest) return failure;
  const failureTimestamp = metadataTimestamp(failure);
  const successTimestamp = metadataTimestamp(latest);
  if (failureTimestamp !== null && successTimestamp !== null && failureTimestamp <= successTimestamp) {
    return null;
  }
  return failure;
};

const staleMetadataSummary = metadata => (metadata?.status === 'success' ? {
  buildContractVersion: metadata.buildContractVersion || 0,
  runtime: metadata.runtime || '',
  distribution: metadata.distribution || '',
  generatedAt: metadata.finishedAt || metadata.startedAt || metadata.latest?.generatedAt || '',
} : null);

const evaluateFreshness = (metadata, currentHashes, checkedAt = now()) => {
  const latest = normalizeSuccessfulMetadata(metadata);
  const currentSourceHash = String(currentHashes?.sourceHash || '');
  const currentPublicDataHash = String(currentHashes?.publicDataHash || '');
  const sourceCurrent = Boolean(latest?.sourceHash)
    && Boolean(currentSourceHash)
    && latest.sourceHash === currentSourceHash;
  const publicDataCurrent = Boolean(latest?.publicDataHash)
    && Boolean(currentPublicDataHash)
    && latest.publicDataHash === currentPublicDataHash;
  const reasons = [];
  if (!latest) {
    reasons.push('no-successful-build');
  } else {
    if (!metadataMatchesCurrentContract(latest)) reasons.push('build-contract-changed');
    if (!sourceCurrent) reasons.push('frontend-source-changed');
    if (!publicDataCurrent) reasons.push('public-data-changed');
  }
  return {
    isCurrent: Boolean(latest) && metadataMatchesCurrentContract(latest) && sourceCurrent && publicDataCurrent,
    sourceCurrent,
    publicDataCurrent,
    reasons,
    checkedAt,
    currentSourceHash,
    currentPublicDataHash,
  };
};

const freshnessMetadataKey = metadata => {
  const latest = normalizeSuccessfulMetadata(metadata);
  return JSON.stringify(latest ? [
    latest.id || '',
    latest.buildContractVersion || 0,
    latest.runtime || '',
    latest.distribution || '',
    latest.sourceHash || '',
    latest.publicDataHash || '',
  ] : ['no-successful-build']);
};

const normalizeAllowedExternalUrl = value => {
  const source = String(value || '').trim();
  if (source === officialProjectUrl || source === publicProjectRoute || source === clientProjectRoute) {
    return clientProjectRoute;
  }
  try {
    const url = new URL(source);
    if (url.protocol !== 'https:' || url.username || url.password || url.search) return '';
    const pathname = url.pathname.replace(/\/+$/, '') || '/';
    if (url.hostname === 'xss.icu' && pathname === '/' && !url.hash) {
      return protectedXeyeUrl;
    }
    return '';
  } catch {
    return '';
  }
};

const sanitizedReferences = value => {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map(normalizeAllowedExternalUrl).filter(Boolean))];
};

const sanitizeClientPayload = payload => {
  const next = { ...payload };
  const references = sanitizedReferences(next.references);
  if (references.length) {
    next.references = references;
  } else {
    delete next.references;
  }
  return next;
};

const sanitizeClientTool = tool => {
  const next = { ...tool };
  if (String(next.id || '') === protectedXssToolId) {
    next.externalUrl = protectedXeyeUrl;
    next.references = [protectedXeyeUrl];
    return next;
  }

  delete next.externalUrl;
  const references = sanitizedReferences(next.references);
  if (references.length) {
    next.references = references;
  } else {
    delete next.references;
  }
  return next;
};

const sanitizeClientPublicData = data => {
  const snapshot = data && typeof data === 'object' ? data : {};
  const settings = snapshot.settings && typeof snapshot.settings === 'object' ? snapshot.settings : {};
  return {
    ...snapshot,
    settings: {
      ...settings,
      // 离线客户端默认带 CTF 解题能力：客户端 CTF 工具全部纯前端本地运行，
      // 不含题目代理/端口扫描端点，服务端部署的管理员开关只约束在线实例。
      ctfEnabled: true,
      projectUrl: clientProjectRoute,
      logoUrl: referencedLogoUrl(snapshot),
    },
    payloads: Array.isArray(snapshot.payloads) ? snapshot.payloads.map(sanitizeClientPayload) : [],
    tools: Array.isArray(snapshot.tools) ? snapshot.tools.map(sanitizeClientTool) : [],
    navigation: Array.isArray(snapshot.navigation) ? snapshot.navigation : [],
    toolNavigation: Array.isArray(snapshot.toolNavigation) ? snapshot.toolNavigation : [],
  };
};

const referencedLogoUrl = data => {
  const logoUrl = String(data?.settings?.logoUrl || '').trim();
  return /^\/uploads\/logo\/logo-[a-zA-Z0-9.-]+\.(png|jpe?g|webp)$/.test(logoUrl) ? logoUrl : '';
};

export {
  protectedXeyeUrl,
  clientRuntime,
  clientDistribution,
  clientBuildContractVersion,
  clientMetadataVersion,
  downloadMimeTypes,
  now,
  sanitizeFileName,
  artifactFileName,
  portableArtifactFileName,
  artifactScore,
  normalizeArtifact,
  normalizeMetadata,
  metadataMatchesCurrentContract,
  normalizeSuccessfulMetadata,
  normalizeFailureMetadata,
  failureAfterLatestSuccess,
  staleMetadataSummary,
  evaluateFreshness,
  freshnessMetadataKey,
  sanitizeClientPayload,
  sanitizeClientPublicData,
  referencedLogoUrl,
};
