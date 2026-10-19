import { lstatSync, readdirSync, rmdirSync, unlinkSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'

const rootDir = dirname(fileURLToPath(import.meta.url));
const distDir = resolve(rootDir, 'dist');

// 本机 Node 24.12/Windows 实测：fs.rmSync 递归删除对非 ASCII 根路径（D:/项目/…）
// 静默失效（ASCII 对照正常、unlinkSync/rmdirSync 均正常，同 node:sqlite 非 ASCII 路径坑族），
// 构建清理需手动递归。
const removeTreeDeep = (dir: string): void => {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (lstatSync(full).isDirectory()) removeTreeDeep(full);
    else unlinkSync(full);
  }
  rmdirSync(dir);
};

// P1-1：构建产物陈旧残留清零。rolldown-vite 8.1.4 实测 emptyOutDir 对本仓 dist 不生效
// （旧 hash chunk 跨构建堆积，曾达 54.7MB/183 文件并被 client-builder 全量打进安装包），
// 在 buildStart 显式清空；public/wasm 等静态资源由 publicDir 机制在输出阶段重新拷贝。
const cleanStaleDist: Plugin = {
  name: 'payloader:clean-stale-dist',
  apply: 'build',
  buildStart() {
    try {
      removeTreeDeep(distDir);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  },
};

export default defineConfig({
  plugins: [react(), cleanStaleDist],
  base: './',
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8081',
      '/admin': 'http://127.0.0.1:8081',
    },
  },
  build: {
    emptyOutDir: true,
    rollupOptions: {
      output: {
        // vendor 分包：框架与 UI 库独立成块，业务迭代发版后浏览器缓存仍命中
        // （rolldown-vite 的 manualChunks 只支持函数形式）。
        // P2-3 实测结论：编解码引擎的重第三方（crypto-js/bson/protobufjs/@noble 等）
        // rolldown 已自动按包拆为独立小 chunk 并行加载（crypto-js 68KB/protobufjs
        // 112KB/bson 64KB 各自缓存），manualChunks 合并成单块是净退化（粒度变粗、
        // 字节不变）；760KB 的 CodecWorkbench chunk 实为智能识别引擎闭包
        // （smartDecode→smartBase/smartHelpers/rsa/crypto/classical 全静态锚定），
        // 按域二次懒加载无可移出字节，不做。名单式合并勿再加回。
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined;
          if (/[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/.test(id)) return 'vendor-react';
          if (/[\\/]node_modules[\\/]@mantine[\\/]/.test(id)) return 'vendor-mantine';
          return undefined;
        },
      },
    },
  },
})
