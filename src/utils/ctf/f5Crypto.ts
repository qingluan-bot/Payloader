// F5 隐写前置件（批次 SI·A 线）：Java sun.security.provider.SecureRandom（SHA1PRNG）与
// F5 的 Permutation 置换复刻（规格取自 OpenJDK jdk8u SecureRandom.updateState 与 Westfeld
// F5 crypt/F5Random.java + crypt/Permutation.java，按算法规格重写非翻译源码）。
// SHA1PRNG 语义：state(20B) = SHA1(seed)；每块输出 = SHA1(state)，随后按 JDK updateState
// 推进——index 0→19 逐字节做【带符号 byte 加法】v = state[i] + output[i] + last（last 初值
// 1，为算术进位 v>>8，可为负），state[i] = v & 0xff；整块无任何字节发生变化则 state[0]++。
// 未消费字节进 remainder 下次先取。getNextValue：4 字节按 Java 带符号 byte 符号扩展组装
// int32，% max，负则 +max。
import { sha1Bytes } from './rarCrypt';

export class F5Random {
  private state = new Uint8Array(20);
  private remainder = new Uint8Array(0);
  private remainderIndex = 0;

  constructor(password: Uint8Array) {
    this.state.set(sha1Bytes(password));
  }

  private nextBlock(): void {
    const output = sha1Bytes(this.state);
    // 显式拷贝为独立缓冲：sha1Bytes 返回的视图类型携带 ArrayBufferLike，避免严格模式赋值摩擦
    this.remainder = new Uint8Array(output);
    this.remainderIndex = 0;
    // JDK updateState：index 0→19，state/output 均按带符号 byte 参与 int 加法，
    // last = v >> 8（算术移位，v 为负时 last 为负）；zf 记录"是否有字节发生变化"
    let last = 1;
    let zf = false;
    for (let index = 0; index < 20; index += 1) {
      const sum =
        ((this.state[index] << 24) >> 24) + ((output[index] << 24) >> 24) + last;
      const updated = sum & 0xff;
      zf = zf || this.state[index] !== updated;
      this.state[index] = updated;
      last = sum >> 8;
    }
    // JDK：整块无任何字节变化（state 未前进的退化情形）则 state[0]++ 强制前进
    if (!zf) this.state[0] += 1;
  }

  getNextByte(): number {
    if (this.remainderIndex >= this.remainder.length) this.nextBlock();
    const value = this.remainder[this.remainderIndex];
    this.remainderIndex += 1;
    return value;
  }

  // Java 符号扩展语义：byte 是带符号的，参与 | 与 << 时按 int 符号扩展（用 Int8 视图还原）
  getNextValue(maxValue: number): number {
    const b0 = (this.getNextByte() << 24) >> 24;
    const b1 = (this.getNextByte() << 24) >> 24;
    const b2 = (this.getNextByte() << 24) >> 24;
    const b3 = (this.getNextByte() << 24) >> 24;
    let retVal = (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) % maxValue;
    if (retVal < 0) retVal += maxValue;
    return retVal;
  }
}

// F5 Permutation：降序 Fisher–Yates（getNextValue 的参数是递减的 maxRandom，不是恒定 size）
export class F5Permutation {
  readonly shuffled: Int32Array;

  constructor(size: number, random: F5Random) {
    this.shuffled = new Int32Array(size);
    for (let index = 0; index < size; index += 1) this.shuffled[index] = index;
    let maxRandom = size;
    for (let index = 0; index < size; index += 1) {
      const randomIndex = random.getNextValue(maxRandom);
      maxRandom -= 1;
      const temp = this.shuffled[randomIndex];
      this.shuffled[randomIndex] = this.shuffled[maxRandom];
      this.shuffled[maxRandom] = temp;
    }
  }

  getShuffled(index: number): number {
    return this.shuffled[index];
  }
}
