const codeSigningSettings = (sourceEnv = process.env) => {
  const cscLink = sourceEnv.PAYLOADER_WINDOWS_CSC_LINK || sourceEnv.PAYLOADER_CSC_LINK || sourceEnv.WIN_CSC_LINK || sourceEnv.CSC_LINK || '';
  const cscKeyPassword = sourceEnv.PAYLOADER_WINDOWS_CSC_KEY_PASSWORD
    || sourceEnv.PAYLOADER_CSC_KEY_PASSWORD
    || sourceEnv.WIN_CSC_KEY_PASSWORD
    || sourceEnv.CSC_KEY_PASSWORD
    || '';
  const certificateSubjectName = sourceEnv.PAYLOADER_WINDOWS_CERT_SUBJECT || sourceEnv.WIN_CSC_NAME || sourceEnv.CSC_NAME || '';
  const certificateSha1 = sourceEnv.PAYLOADER_WINDOWS_CERT_SHA1 || sourceEnv.WIN_CSC_SHA1 || '';
  const configured = Boolean(cscLink || certificateSubjectName || certificateSha1);
  const signtoolOptions = {
    ...(certificateSubjectName ? { certificateSubjectName } : {}),
    ...(certificateSha1 ? { certificateSha1 } : {}),
  };
  return {
    configured,
    env: {
      ...(cscLink ? { CSC_LINK: cscLink } : {}),
      ...(cscKeyPassword ? { CSC_KEY_PASSWORD: cscKeyPassword } : {}),
    },
    winConfig: Object.keys(signtoolOptions).length ? { signtoolOptions } : {},
  };
};

const signingEnvironmentAllowlist = Object.freeze([
  'APPLE_ID',
  'APPLE_APP_SPECIFIC_PASSWORD',
  'APPLE_TEAM_ID',
  'CSC_NAME',
]);

const artifactNotes = (target, signing) => [
  ...(target.requiresSigningNote ? [target.requiresSigningNote] : []),
  ...(target.platform === 'windows' && !signing.configured ? ['Unsigned Windows builds are more likely to receive reputation warnings until signed and distributed from a stable download page.'] : []),
  ...(target.id.includes('appimage') ? ['Linux AppImage may need executable permission after download: chmod +x Payloader-Client-*.AppImage.'] : []),
  ...(target.format === 'DEB' ? ['Install with dpkg or apt on Debian/Ubuntu-family systems after verifying SHA256.'] : []),
  ...(target.format === 'RPM' ? ['Install with rpm or dnf on Fedora/RHEL-family systems after verifying SHA256.'] : []),
];

export {
  codeSigningSettings,
  signingEnvironmentAllowlist,
  artifactNotes,
};
