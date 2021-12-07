import { Hasher, Md5Hasher, Sha1Hasher } from "./hashing";
import { DateNow, Now } from "./now";

export class SecureLink {
  private readonly secret: string;
  private readonly hasher: Hasher;
  private readonly signatureArg: string;
  private readonly expiresArg: string;
  private readonly now: Now;

  constructor(
    secret: string,
    hasher: Hasher,
    signatureArg?: string,
    expiresArg?: string,
    now?: Now
  ) {
    this.secret = secret;
    this.hasher = hasher;
    this.signatureArg = signatureArg || "signature";
    this.expiresArg = expiresArg || "expires";
    this.now = now || new DateNow();
  }

  sign(url: URL, expiresAt?: number): void {
    if (expiresAt) {
      url.search = url.search
        ? `${url.search}&${this.expiresArg}=${expiresAt.toString()}`
        : `${this.expiresArg}=${expiresAt.toString()}`;
    }
    const signature = this.hasher.hash(this.getDataToSign(url));
    url.search = url.search
      ? `${url.search}&${this.signatureArg}=${signature}`
      : `${this.signatureArg}=${signature}`;
  }

  /**
   * @param {URL} url
   * @throws {InvalidSignatureError | LinkHasExpiredError}
   */
  validate(url: URL): void {
    const signature = url.searchParams.get(this.signatureArg);
    if (!signature) {
      throw new InvalidSignatureError();
    }
    if (!this.hasher.isValid(signature, this.getDataToSign(url))) {
      throw new InvalidSignatureError();
    }
    if (!url.searchParams.has(this.expiresArg)) {
      return;
    }
    const expires = +(url.searchParams.get(this.expiresArg) || 0);
    if (isNaN(expires)) {
      throw new LinkHasExpiredError();
    }
    if (expires < Math.round(this.now.now().getTime() / 1000)) {
      throw new LinkHasExpiredError();
    }
  }

  isValid(url: URL): boolean {
    try {
      this.validate(url);
    } catch (SecureLinkError) {
      return false;
    }
    return true;
  }

  private getDataToSign(url: URL): string {
    const regExp = new RegExp(
      `&${this.signatureArg}(\\=[^&]*)?(?=&|$)|^${this.signatureArg}(\\=[^&]*)?(&|$)`,
      "g"
    );
    // remove "?" + remove (&)signature=hash
    let search = url.search.slice(1).replace(regExp, "");
    if (search) {
      search = `?${search}`;
    }
    return `${url.pathname}${search} ${this.secret}`;
  }
}

export class SecureLinkError extends Error {
  constructor() {
    super();
    Object.setPrototypeOf(this, SecureLinkError.prototype);
  }
}

export class InvalidSignatureError extends SecureLinkError {
  constructor() {
    super();
    Object.setPrototypeOf(this, InvalidSignatureError.prototype);
  }
}

export class LinkHasExpiredError extends SecureLinkError {
  constructor() {
    super();
    Object.setPrototypeOf(this, LinkHasExpiredError.prototype);
  }
}

export { Now, DateNow };
export { Hasher, Md5Hasher, Sha1Hasher };
