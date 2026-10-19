// B-1 契约测试：Mantine Notifications 全局单例（一事一 toast 的结构保证）。
// 结论背景（2026-10 实测）：@mantine/notifications 9.6.1 的 <Notifications /> 自带一个 OptionalPortal，
// 内部按 6 个方位（top-center/left/right、bottom-center/left/right）各渲染一个 .mantine-Notifications-root
// ——运行时 body 下看到 6 个平级 root 是包设计行为，不是 portal 泄漏；生产构建单击一次 show 只出一条 toast。
// 官方文档记载的重复 toast 唯一常见根因是挂载了多个 <Notifications />（各自订阅同一 store，每条都渲染多份）。
// 本测试把"全局唯一挂载"钉成契约，防止未来任何组件再挂第二个实例：
// 浏览器人工验证点（回归时用）：生产构建任一 toast 触发后，
//   document.querySelectorAll('.mantine-Notifications-root').length === 6（6 方位 root，1 个 portal），
//   且同文案 .mantine-Notification-root 节点数 === 触发次数。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { readFileSync, readdirSync, existsSync } from 'node:fs';

const srcDir = path.join('src');

function walkTs(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walkTs(full, out);
    else if (/\.tsx?$/.test(entry.name)) out.push(full);
  }
  return out;
}

const allSourceFiles = walkTs(srcDir);
const read = file => readFileSync(file, 'utf8');

test('B-1：<Notifications /> 组件全站只允许 main.tsx 挂载一次（重复挂载 = 同文案 toast 渲染 N 份）', () => {
  const mounts = [];
  for (const file of allSourceFiles) {
    const source = read(file);
    const normalized = pathNormalize(file);
    // 排除 import 语句本身，只数 JSX 挂载点（<Notifications 或 <Notifications />
    const jsxUses = source.match(/<Notifications[\s/>]/g) ?? [];
    if (jsxUses.length > 0) mounts.push({ file: normalized, count: jsxUses.length });
  }
  assert.deepEqual(
    mounts,
    [{ file: 'src/main.tsx', count: 1 }],
    'Notifications 组件必须在 src/main.tsx 恰好挂载一次；其他任何组件不得 import 并渲染它（官方文档：多次挂载 → 同一 toast 重复出现）',
  );
});

test('B-1：MantineProvider 全站只在 main.tsx 挂载一次', () => {
  const mounts = [];
  for (const file of allSourceFiles) {
    const source = read(file);
    const jsxUses = source.match(/<MantineProvider[\s/>]/g) ?? [];
    if (jsxUses.length > 0) mounts.push({ file: pathNormalize(file), count: jsxUses.length });
  }
  assert.deepEqual(
    mounts,
    [{ file: 'src/main.tsx', count: 1 }],
    'MantineProvider 重复挂载会生成第二套 portal 容器与主题上下文',
  );
});

test('B-1：main.tsx 之外只允许 import notifications 命令式 API，不得引组件或 store 实例', () => {
  const offenders = [];
  for (const file of allSourceFiles) {
    if (pathNormalize(file) === 'src/main.tsx') continue;
    const source = read(file);
    for (const match of source.matchAll(/import\s*\{([^}]*)\}\s*from\s*'@mantine\/notifications'/g)) {
      const names = match[1].split(',').map(name => name.trim().split(/\s+as\s+/)[0]).filter(Boolean);
      for (const name of names) {
        if (name !== 'notifications') offenders.push(`${pathNormalize(file)} -> ${name}`);
      }
    }
  }
  assert.deepEqual(offenders, [], '业务组件只准调 notifications.show()；Notifications 组件/createNotificationsStore 只归 main.tsx');
});

test('B-1：已装 @mantine/notifications 的 6 方位 root 是包设计（版本升级后需重核 DOM 口径）', () => {
  const componentSource = path.join('node_modules', '@mantine', 'notifications', 'esm', 'Notifications.mjs');
  if (!existsSync(componentSource)) return; // 依赖未安装的环境（如纯 lint CI）跳过
  const source = readFileSync(componentSource, 'utf8');
  const positionRoots = source.match(/data-position/g) ?? [];
  assert.equal(
    positionRoots.length,
    6,
    'Notifications 组件应按 6 个方位各渲染一个 root（top-center/left/right、bottom-center/left/right）。'
    + '若此数变化，DOM 断言口径（.mantine-Notifications-root 期望数）需同步更新',
  );
});

function pathNormalize(file) {
  return file.split(path.sep).join('/');
}
