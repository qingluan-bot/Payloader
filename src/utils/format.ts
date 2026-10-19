// 字节数人性化显示：客户端下载入口（桌面 HeaderActions / 移动端 MobileMoreView）共用
export const formatDownloadSize = (size: number) => {
  if (!Number.isFinite(size) || size <= 0) return '';
  if (size >= 1024 * 1024) return `${(size / 1024 / 1024).toFixed(1)} MB`;
  if (size >= 1024) return `${(size / 1024).toFixed(0)} KB`;
  return `${Math.round(size)} B`;
};
