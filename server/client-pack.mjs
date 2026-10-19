import { statSync } from 'node:fs';
import { sep } from 'node:path';

const pathSeparator = sep;

const electronRuntimeConfig = (runtimeDir, enabled = true) => {
  if (!enabled) return {};
  const stats = statSync(runtimeDir, { throwIfNoEntry: false });
  return stats?.isDirectory() ? { electronDist: runtimeDir } : {};
};

const windowsNsisOptions = Object.freeze({
  oneClick: false,
  // 向导提供「为所有用户 / 仅为当前用户」选择页（默认所有用户），
  // 选所有用户时经 UAC 提权安装到 Program Files；per-user 装到用户目录。
  perMachine: true,
  allowElevation: true,
  allowToChangeInstallationDirectory: true,
  packElevateHelper: true,
  differentialPackage: false,
  useZip: false,
  include: 'installer.nsh',
  createDesktopShortcut: true,
  createStartMenuShortcut: true,
  runAfterFinish: false,
  deleteAppDataOnUninstall: false,
  artifactName: 'Payloader-Client-Setup-${version}-${arch}.${ext}',
});

const crossPlatformOverride = process.env.PAYLOADER_CLIENT_FORCE_CROSS_PLATFORM === 'true';

const clientTargetMatrix = Object.freeze([
  {
    id: 'win-x64-nsis',
    platform: 'windows',
    platformLabel: 'Windows',
    arch: 'x64',
    archLabel: 'Intel / AMD 64-bit',
    format: 'Windows Installer',
    extension: '.exe',
    builderPlatform: 'win',
    builderTargets: ['nsis'],
    builderArch: 'x64',
    mimeType: 'application/vnd.microsoft.portable-executable',
    hostPlatforms: ['win32'],
    recommended: true,
    cpuFamily: 'x86_64',
    minOsVersion: 'Windows 10/11 64-bit',
    installType: 'Assisted NSIS installer with user scope and directory choice',
  },
  {
    id: 'win-arm64-nsis',
    platform: 'windows',
    platformLabel: 'Windows',
    arch: 'arm64',
    archLabel: 'ARM64',
    format: 'Windows Installer',
    extension: '.exe',
    builderPlatform: 'win',
    builderTargets: ['nsis'],
    builderArch: 'arm64',
    mimeType: 'application/vnd.microsoft.portable-executable',
    hostPlatforms: ['win32'],
    recommended: true,
    cpuFamily: 'ARM64',
    minOsVersion: 'Windows 11 ARM64',
    installType: 'Assisted NSIS installer with user scope and directory choice',
  },
  {
    id: 'win-ia32-nsis',
    platform: 'windows',
    platformLabel: 'Windows',
    arch: 'ia32',
    archLabel: '32-bit x86',
    format: 'Windows Installer',
    extension: '.exe',
    builderPlatform: 'win',
    builderTargets: ['nsis'],
    builderArch: 'ia32',
    mimeType: 'application/vnd.microsoft.portable-executable',
    hostPlatforms: ['win32'],
    recommended: false,
    cpuFamily: 'x86 32-bit',
    minOsVersion: 'Windows 10 32-bit',
    installType: 'Assisted NSIS installer with user scope and directory choice',
  },
  {
    id: 'linux-x64-appimage',
    platform: 'linux',
    platformLabel: 'Linux',
    arch: 'x64',
    archLabel: 'Intel / AMD 64-bit',
    format: 'AppImage',
    extension: '.AppImage',
    builderPlatform: 'linux',
    builderTargets: ['AppImage'],
    builderArch: 'x64',
    mimeType: 'application/octet-stream',
    hostPlatforms: ['linux'],
    recommended: true,
    cpuFamily: 'x86_64',
    minOsVersion: 'glibc-based Linux x64',
    installType: 'Portable AppImage',
  },
  {
    id: 'linux-arm64-appimage',
    platform: 'linux',
    platformLabel: 'Linux',
    arch: 'arm64',
    archLabel: 'ARM64',
    format: 'AppImage',
    extension: '.AppImage',
    builderPlatform: 'linux',
    builderTargets: ['AppImage'],
    builderArch: 'arm64',
    mimeType: 'application/octet-stream',
    hostPlatforms: ['linux'],
    recommended: true,
    cpuFamily: 'ARM64 / aarch64',
    minOsVersion: 'glibc-based Linux ARM64',
    installType: 'Portable AppImage',
  },
  {
    id: 'linux-armv7l-appimage',
    platform: 'linux',
    platformLabel: 'Linux',
    arch: 'armv7l',
    archLabel: 'ARMv7 / armhf',
    format: 'AppImage',
    extension: '.AppImage',
    builderPlatform: 'linux',
    builderTargets: ['AppImage'],
    builderArch: 'armv7l',
    mimeType: 'application/octet-stream',
    hostPlatforms: ['linux'],
    recommended: false,
    cpuFamily: 'ARMv7 / armhf',
    minOsVersion: 'glibc-based Linux ARMv7',
    installType: 'Portable AppImage',
  },
  {
    id: 'linux-x64-deb',
    platform: 'linux',
    platformLabel: 'Linux',
    arch: 'x64',
    archLabel: 'Intel / AMD 64-bit',
    format: 'DEB',
    extension: '.deb',
    builderPlatform: 'linux',
    builderTargets: ['deb'],
    builderArch: 'x64',
    mimeType: 'application/vnd.debian.binary-package',
    hostPlatforms: ['linux'],
    recommended: true,
    cpuFamily: 'x86_64',
    minOsVersion: 'Debian/Ubuntu x64',
    installType: 'dpkg/apt package',
    packageManager: 'dpkg / apt',
  },
  {
    id: 'linux-arm64-deb',
    platform: 'linux',
    platformLabel: 'Linux',
    arch: 'arm64',
    archLabel: 'ARM64',
    format: 'DEB',
    extension: '.deb',
    builderPlatform: 'linux',
    builderTargets: ['deb'],
    builderArch: 'arm64',
    mimeType: 'application/vnd.debian.binary-package',
    hostPlatforms: ['linux'],
    recommended: true,
    cpuFamily: 'ARM64 / aarch64',
    minOsVersion: 'Debian/Ubuntu ARM64',
    installType: 'dpkg/apt package',
    packageManager: 'dpkg / apt',
  },
  {
    id: 'linux-armv7l-deb',
    platform: 'linux',
    platformLabel: 'Linux',
    arch: 'armv7l',
    archLabel: 'ARMv7 / armhf',
    format: 'DEB',
    extension: '.deb',
    builderPlatform: 'linux',
    builderTargets: ['deb'],
    builderArch: 'armv7l',
    mimeType: 'application/vnd.debian.binary-package',
    hostPlatforms: ['linux'],
    recommended: false,
    cpuFamily: 'ARMv7 / armhf',
    minOsVersion: 'Debian/Ubuntu armhf',
    installType: 'dpkg/apt package',
    packageManager: 'dpkg / apt',
  },
  {
    id: 'linux-x64-rpm',
    platform: 'linux',
    platformLabel: 'Linux',
    arch: 'x64',
    archLabel: 'Intel / AMD 64-bit',
    format: 'RPM',
    extension: '.rpm',
    builderPlatform: 'linux',
    builderTargets: ['rpm'],
    builderArch: 'x64',
    mimeType: 'application/x-rpm',
    hostPlatforms: ['linux'],
    recommended: true,
    cpuFamily: 'x86_64',
    minOsVersion: 'Fedora/RHEL x64',
    installType: 'rpm/dnf package',
    packageManager: 'rpm / dnf',
  },
  {
    id: 'linux-arm64-rpm',
    platform: 'linux',
    platformLabel: 'Linux',
    arch: 'arm64',
    archLabel: 'ARM64',
    format: 'RPM',
    extension: '.rpm',
    builderPlatform: 'linux',
    builderTargets: ['rpm'],
    builderArch: 'arm64',
    mimeType: 'application/x-rpm',
    hostPlatforms: ['linux'],
    recommended: true,
    cpuFamily: 'ARM64 / aarch64',
    minOsVersion: 'Fedora/RHEL ARM64',
    installType: 'rpm/dnf package',
    packageManager: 'rpm / dnf',
  },
  {
    id: 'mac-x64-dmg',
    platform: 'macos',
    platformLabel: 'macOS',
    arch: 'x64',
    archLabel: 'Intel 64-bit',
    format: 'DMG',
    extension: '.dmg',
    builderPlatform: 'mac',
    builderTargets: ['dmg'],
    builderArch: 'x64',
    mimeType: 'application/x-apple-diskimage',
    hostPlatforms: ['darwin'],
    recommended: true,
    requiresSigningNote: 'macOS distribution should be signed and notarized on a macOS host.',
    cpuFamily: 'x86_64',
    minOsVersion: 'macOS Intel',
    installType: 'DMG disk image',
  },
  {
    id: 'mac-arm64-dmg',
    platform: 'macos',
    platformLabel: 'macOS',
    arch: 'arm64',
    archLabel: 'Apple Silicon',
    format: 'DMG',
    extension: '.dmg',
    builderPlatform: 'mac',
    builderTargets: ['dmg'],
    builderArch: 'arm64',
    mimeType: 'application/x-apple-diskimage',
    hostPlatforms: ['darwin'],
    recommended: true,
    requiresSigningNote: 'macOS distribution should be signed and notarized on a macOS host.',
    cpuFamily: 'Apple Silicon ARM64',
    minOsVersion: 'macOS Apple Silicon',
    installType: 'DMG disk image',
  },
  {
    id: 'mac-universal-dmg',
    platform: 'macos',
    platformLabel: 'macOS',
    arch: 'universal',
    archLabel: 'Universal',
    format: 'DMG',
    extension: '.dmg',
    builderPlatform: 'mac',
    builderTargets: ['dmg'],
    builderArch: 'universal',
    mimeType: 'application/x-apple-diskimage',
    hostPlatforms: ['darwin'],
    recommended: true,
    requiresSigningNote: 'macOS universal DMG should be signed and notarized on a macOS host after x64 and arm64 validation.',
    cpuFamily: 'Intel + Apple Silicon',
    minOsVersion: 'macOS Universal',
    installType: 'Universal DMG disk image',
  },
]);
const clientTargetById = new Map(clientTargetMatrix.map(target => [target.id, target]));
const clientTargetOrder = new Map(clientTargetMatrix.map((target, index) => [target.id, index]));

const shellTarget = (catalog, target) => catalog?.targets?.[target.id] || null;

const normalizeTargetAvailability = (target, catalog = null) => {
  const shell = shellTarget(catalog, target);
  const nativeSupported = crossPlatformOverride || target.hostPlatforms.includes(process.platform);
  const supported = Boolean(shell) || nativeSupported;
  let reason = '';
  if (!supported) {
    reason = catalog?.error ? '官方套件不可用' : '缺少兼容壳或本机工具链';
  }
  const portable = shell
    ? shell.outputFormat === 'zip'
      ? { format: 'Portable ZIP', extension: '.zip', installType: 'Portable directory', mimeType: 'application/zip' }
      : { format: 'Portable TAR.GZ', extension: '.tar.gz', installType: 'Portable directory', mimeType: 'application/gzip' }
    : null;
  return {
    id: target.id,
    platform: target.platform,
    platformLabel: target.platformLabel,
    arch: target.arch,
    archLabel: target.archLabel,
    format: portable?.format || target.format,
    extension: portable?.extension || target.extension,
    recommended: target.recommended,
    supported,
    selectedByDefault: supported && target.recommended !== false,
    reason,
    source: shell ? 'official-shell' : nativeSupported ? 'native-host' : 'unavailable',
    shellVersion: shell ? String(catalog?.manifest?.appVersion || '') : '',
    shellSigned: shell ? Boolean(shell.signed) : false,
    cpuFamily: target.cpuFamily || target.archLabel,
    minOsVersion: target.minOsVersion || '',
    installType: portable?.installType || target.installType || target.format,
    packageManager: portable ? '' : target.packageManager || '',
    mimeType: portable?.mimeType || target.mimeType,
    requiresSigningNote: target.requiresSigningNote || '',
  };
};

const defaultTargetIds = catalog => clientTargetMatrix
  .filter(target => normalizeTargetAvailability(target, catalog).supported && target.recommended !== false)
  .map(target => target.id);

const normalizeRequestedTargets = (value, catalog = null) => {
  const requested = Array.isArray(value) ? value.map(item => String(item || '').trim()) : [];
  const ids = requested.length ? requested : defaultTargetIds(catalog);
  const seen = new Set();
  const selected = [];
  const skipped = [];
  for (const id of ids) {
    if (seen.has(id)) continue;
    seen.add(id);
    const target = clientTargetById.get(id);
    if (!target) {
      skipped.push({ id, status: 'unsupported', reason: 'Unknown client target.' });
      continue;
    }
    if (!normalizeTargetAvailability(target, catalog).supported) {
      skipped.push({
        id,
        status: 'unsupported',
        reason: normalizeTargetAvailability(target, catalog).reason,
      });
      continue;
    }
    selected.push(target);
  }
  return { selected, skipped };
};

export {
  pathSeparator,
  electronRuntimeConfig,
  windowsNsisOptions,
  crossPlatformOverride,
  clientTargetMatrix,
  clientTargetById,
  clientTargetOrder,
  shellTarget,
  normalizeTargetAvailability,
  defaultTargetIds,
  normalizeRequestedTargets,
};
