// GIF 帧 QR 自动链 Web Worker（验收遗留 P1 收口：深扫帧 autoRepairQr 粗扫假设数随黑像素
// 包围盒面积平方爆炸，单次调用数十秒～分钟级且引擎内不可分批，必须离线程执行；实测
// dont-blink.gif 864² 卡通画布单次深扫浏览器 ~12s、Node 最长 758s）。进度按 250ms 节流
// postMessage 回传，完成/异常即收口。协议：
// 请求 { bytes, options }（bytes 拷贝后 transfer）；
// 响应 { type:'progress', done, total } | { type:'done', result } | { type:'error', message }，
// GifQrScanResult 全部为 string/number/string[]/number[] 纯数据，可结构化克隆。
import { decodeGifQr } from './gifInspect';
import type { GifQrScanOptions, GifQrScanResult } from './gifInspect';

interface WorkerRequest {
  bytes: Uint8Array;
  options?: Pick<GifQrScanOptions, 'maxFrames' | 'maxDeepFrames' | 'batchSize'>;
}

type WorkerResponse =
  | { type: 'progress'; done: number; total: number }
  | { type: 'done'; result: GifQrScanResult }
  | { type: 'error'; message: string };

// 不引 webworker lib（与 DOM lib 同用会全局冲突）：以最小结构类型描述 worker 作用域
const workerScope = self as unknown as {
  onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null;
  postMessage(message: WorkerResponse): void;
};

workerScope.onmessage = (event: MessageEvent<WorkerRequest>) => {
  const { bytes, options } = event.data;
  let lastPost = 0;
  decodeGifQr(bytes, {
    maxFrames: options?.maxFrames,
    maxDeepFrames: options?.maxDeepFrames,
    batchSize: options?.batchSize,
    onProgress: progress => {
      const now = Date.now();
      if (now - lastPost < 250) return;
      lastPost = now;
      workerScope.postMessage({ type: 'progress', done: progress.done, total: progress.total });
    },
  }).then(result => {
    workerScope.postMessage({ type: 'done', result });
  }).catch(error => {
    workerScope.postMessage({ type: 'error', message: error instanceof Error ? error.message : String(error) });
  });
};
