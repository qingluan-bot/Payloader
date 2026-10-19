// codec smartDecode 回归测试（A 域审计修复批次）：BUG-14 云影密码不再被 Pollux 抢占 top1。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const T = loadModule(path.join(srcDir, 'utils', 'codec', 'transform.ts'));

// C08 真题向量：云影密码（0 为分隔，1/2/4/8 段内求和），期望 yunyingdigitsok
const C08_CIPHER = '88810884108420888108108420421040810421081088408821084210821';

test('BUG-14 smart-decode 云影数字串：top1 直接解出云影而非 Pollux 乱码', async () => {
  const output = await T.transform('smart-decode', 'decode', C08_CIPHER, {});
  const text = String(output);
  assert.ok(text.includes('云影'), `top1 应为云影密码，实际: ${text.slice(0, 60).replace(/\n/g, ' ')}`);
  assert.ok(text.toLowerCase().includes('yunyingdigitsok'), `应解出明文 yunyingdigitsok，实际: ${text.slice(0, 120).replace(/\n/g, ' ')}`);
  assert.ok(!text.includes('Pollux'), '不应再以 Pollux 结果占据 top1');
});
