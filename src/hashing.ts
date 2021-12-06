import { createHash } from "crypto";

export interface Hasher {
  hash(data: string): string;

  isValid(hash: string, data: string): boolean;
}

class CryptoHasher implements Hasher {
  hash(data: string): string {
    return createHash(this.getAlgoName()).update(data).digest("hex");
  }

  isValid(hash: string, data: string): boolean {
    return hash === this.hash(data);
  }

  getAlgoName(): string {
    throw new Error("NotImplemented");
  }
}

export class Md5Hasher extends CryptoHasher {
  constructor() {
    super();
    Object.setPrototypeOf(this, Md5Hasher.prototype);
  }

  getAlgoName(): string {
    return "md5";
  }
}

export class Sha1Hasher extends CryptoHasher {
  constructor() {
    super();
    Object.setPrototypeOf(this, Sha1Hasher.prototype);
  }

  getAlgoName(): string {
    return "sha1";
  }
}
