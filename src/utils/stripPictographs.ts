// 库内策展名称（payload 分支/工具组等）历史上带 emoji 前缀，数据不做迁移，渲染层统一剥掉
// 前导图形符号让树与空态图标体系保持单色 SVG；剥完为空（纯符号名）时回退原文
export const stripLeadingPictographs = (name: string) => {
  // 按码点剥离是有意为之：FE0F 变体选择符/ZWJ 要独立于基字符剥掉，no-misleading-character-class 的"逐字形"担忧不适用
  // eslint-disable-next-line no-misleading-character-class
  const stripped = name.replace(/^[\s\u{1F000}-\u{1FAFF}\u{2190}-\u{2BFF}\u{2600}-\u{27BF}\u{FE0F}\u{200D}]+/u, '');
  return stripped || name;
};
