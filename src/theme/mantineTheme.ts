import { createTheme } from '@mantine/core';

// 主色板以 global.css 的 --accent (#4c8dff) 为基准展开十阶，
// index 3 与现有主色一致，供 Mantine 组件在深浅两种模式下取用。
const accent = [
  '#e7f0ff',
  '#ccdfff',
  '#a6c8ff',
  '#4c8dff',
  '#2f79f2',
  '#1a64d9',
  '#1454b8',
  '#104594',
  '#0c356e',
  '#082449',
] as const;

export const mantineTheme = createTheme({
  primaryColor: 'accent',
  primaryShade: 3,
  colors: { accent },
  defaultRadius: 'md',
  fontFamily: "'Segoe UI', 'Microsoft YaHei UI', Arial, sans-serif",
  fontFamilyMonospace: "'Cascadia Mono', 'Consolas', 'Courier New', monospace",
  headings: {
    fontFamily: "'Segoe UI', 'Microsoft YaHei UI', Arial, sans-serif",
  },
});
