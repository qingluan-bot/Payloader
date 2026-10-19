// TLS 1.2 真实握手样本生成器（tests/tls-decrypt.test.mjs 的子进程）：
// 进程内伪造互联 Duplex 嗅探双向字节 → Node/OpenSSL 真实完成 TLS 1.2 AES-128-GCM 握手与
// 应用数据交换 → keylog 事件（NSS ssl.log 口径）+ 双向流字节落盘。
// 用法：node tls-sniff-child.mjs <outDir>；退出码 0 = 交换成功。
import tls from 'node:tls';
import fs from 'node:fs';
import path from 'node:path';
import { Duplex } from 'node:stream';
import { fileURLToPath } from 'node:url';

const outDir = process.argv[2];
const here = path.dirname(fileURLToPath(import.meta.url));

const REQUEST = 'GET /flag HTTP/1.1\r\nHost: localhost\r\nUser-Agent: tls-sniff-child\r\n\r\n';
const RESPONSE = 'HTTP/1.1 200 OK\r\nContent-Length: 23\r\n\r\nflag{tls_live_5d17_real}';

const c2s = [];
const s2c = [];
class Sniff extends Duplex {
  constructor(name, peer) {
    super();
    this.name = name;
    this.peer = peer;
  }

  _write(chunk, _enc, cb) {
    (this.name === 'client' ? c2s : s2c).push(Buffer.from(chunk));
    this.peer.push(chunk);
    cb();
  }

  _read() {}

  // 一端 end() 时向对端传播 EOF，让 TLS 会话自然关闭
  _final(cb) {
    this.peer.push(null);
    cb();
  }
}
const clientFake = new Sniff('client', null);
const serverFake = new Sniff('server', null);
clientFake.peer = serverFake;
serverFake.peer = clientFake;

const keylogLines = [];
const TLS_OPTS = {
  key: fs.readFileSync(path.join(here, 'test-key.pem')),
  cert: fs.readFileSync(path.join(here, 'test-cert.pem')),
  ciphers: 'AES128-GCM-SHA256',
  minVersion: 'TLSv1.2',
  maxVersion: 'TLSv1.2',
};

let finished = false;
const server = tls.createServer(TLS_OPTS, sock => {
  sock.on('data', () => {
    sock.write(RESPONSE);
    sock.end();
  });
  sock.on('error', () => {});
  sock.on('keylog', line => keylogLines.push(line.toString()));
});
server.on('tlsClientError', () => {});
server.listen(0, '127.0.0.1', () => {
  // 伪造 socket 直接注入 tls server（net.Server 的 connection 事件通道），全程无真实网络
  server.emit('connection', serverFake);
  const client = tls.connect({
    socket: clientFake,
    servername: 'localhost',
    rejectUnauthorized: false,
    ciphers: 'AES128-GCM-SHA256',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
  }, () => {
    client.write(REQUEST);
  });
  client.on('keylog', line => keylogLines.push(line.toString()));
  // 收到服务端应答即认为交换完成（TLS close_notify 在伪造 socket 上不传播 EOF，
  // 不等 'close' 事件，定时落盘退出保证确定性）。
  client.on('data', () => {
    if (finished) return;
    finished = true;
    setTimeout(() => {
      fs.writeFileSync(path.join(outDir, 'c2s.bin'), Buffer.concat(c2s));
      fs.writeFileSync(path.join(outDir, 's2c.bin'), Buffer.concat(s2c));
      fs.writeFileSync(path.join(outDir, 'keylog.log'), [...new Set(keylogLines)].join(''));
      process.exit(0);
    }, 150);
  });
  client.on('error', error => {
    console.error('client error:', error.message);
    process.exit(1);
  });
});
server.on('error', error => {
  console.error('server error:', error.message);
  process.exit(1);
});
