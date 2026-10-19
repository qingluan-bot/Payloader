// GIF 帧 QR Worker 客户端（照 zipBruteWorkerClient 双降级模式）。
// 主线程只负责创建/终止 worker 与转发进度：bytes 拷贝后 transfer（主线程视图不动）。
// Worker 构造失败（file:// 协议/旧环境）或脚本加载失败自动降级主线程 async 引擎路径
// （分批 yield 版 decodeGifQr，能力不缺失只让步——深扫帧会阻塞主线程，与旧版一致）。
import { decodeGifQr } from './gifInspect';
import type { GifQrProgress, GifQrScanOptions, GifQrScanResult } from './gifInspect';

export interface GifQrWorkerOptions {
  onProgress?: (progress: GifQrProgress) => void;
}

// 传给 worker 的扫描参数（onProgress 不可跨线程，单独走消息通道）
type GifQrWorkerScanOptions = Pick<GifQrScanOptions, 'maxFrames' | 'maxDeepFrames' | 'batchSize'>;

export const decodeGifQrWorker = (
  bytes: Uint8Array,
  options?: GifQrWorkerScanOptions & GifQrWorkerOptions,
): Promise<GifQrScanResult> => {
  const onProgress = options?.onProgress;
  const scanOptions: GifQrWorkerScanOptions = {
    maxFrames: options?.maxFrames,
    maxDeepFrames: options?.maxDeepFrames,
    batchSize: options?.batchSize,
  };
  const runInProcess = () => decodeGifQr(bytes, { ...scanOptions, onProgress });

  let worker: Worker;
  try {
    worker = new Worker(new URL('./gifQrWorker.ts', import.meta.url), { type: 'module' });
  } catch {
    return runInProcess();
  }

  return new Promise<GifQrScanResult>((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      settled = true;
      worker.terminate();
    };
    worker.onmessage = (event: MessageEvent) => {
      // 收口后 terminate 不撤销已入主线程队列的消息事件：迟到消息直接丢弃（zipBrute reviewer P2-1 同款）
      if (settled) return;
      const data = event.data as
        | { type: 'progress'; done: number; total: number }
        | { type: 'done'; result: GifQrScanResult }
        | { type: 'error'; message: string };
      if (data.type === 'progress') {
        onProgress?.({ done: data.done, total: data.total });
        return;
      }
      if (data.type === 'done') {
        cleanup();
        resolve(data.result);
        return;
      }
      // worker 侧业务错误（非 GIF 等）：reject 给调用方按既有 catch 语义处理
      cleanup();
      reject(new Error(data.message));
    };
    worker.onerror = () => {
      // 脚本加载失败等硬错误：降级主线程路径重跑（不吞能力）；竞态下已收口则忽略。
      if (settled) return;
      settled = true;
      worker.terminate();
      void runInProcess().then(resolve, reject);
    };

    // bytes 拷贝后 transfer：原视图归主线程（父组件共享），worker 拿独立副本
    const payload = new Uint8Array(bytes);
    worker.postMessage({ bytes: payload, options: scanOptions }, [payload.buffer]);
  });
};
