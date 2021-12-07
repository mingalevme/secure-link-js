import { describe, it } from "mocha";
import { strict as assert } from "assert";
import { InvalidSignatureError, LinkHasExpiredError, SecureLink } from "../src";
import { Hasher, Md5Hasher, Sha1Hasher } from "../src";
import { DateNow } from "../src";

export class StaticSignatureHasher implements Hasher {
  private readonly signature: string;

  constructor(signature: string) {
    this.signature = signature;
  }

  hash(data: string): string {
    return this.signature;
  }

  isValid(hash: string, data: string): boolean {
    return hash === this.signature;
  }
}

describe("secure link", function () {
  it("should sign an expiring link", () => {
    const hasher = new StaticSignatureHasher("foobar");
    const service = new SecureLink("secret", hasher, "_sig", "_expires");
    const url = new URL("https://example.com/path/to/resource?foo=bar&bar=foo");
    service.sign(url, 1000);
    assert.strictEqual(
      url.toString(),
      "https://example.com/path/to/resource?foo=bar&bar=foo&_expires=1000&_sig=foobar"
    );
  });
  it("should sign a non-expiring link", () => {
    const hasher = new StaticSignatureHasher("foobar");
    const service = new SecureLink("secret", hasher, "_sig", "_expires");
    const url = new URL("https://example.com/path/to/resource?foo=bar&bar=foo");
    service.sign(url);
    assert.strictEqual(
      url.toString(),
      "https://example.com/path/to/resource?foo=bar&bar=foo&_sig=foobar"
    );
    assert.strictEqual(service.isValid(url), true);
  });
  it("should pass valid non-expiring link", () => {
    const hasher = new StaticSignatureHasher("foobar");
    const service = new SecureLink("secret", hasher, "_sig", "_expires");
    const url = new URL(
      "https://example.com/path/to/resource?bar=foo&foo=bar&_sig=foobar"
    );
    assert.strictEqual(service.isValid(url), true);
    service.validate(url);
  });
  it("should not pass link without a signature", () => {
    const hasher = new StaticSignatureHasher("foobar");
    const service = new SecureLink("secret", hasher, "_sig", "_expires");
    const url = new URL("https://example.com/path/to/resource?bar=foo&foo=bar");
    assert.strictEqual(service.isValid(url), false);
    assert.throws(() => {
      service.validate(url);
    }, InvalidSignatureError);
  });
  it("should not pass link with invalid signature", () => {
    const hasher = new StaticSignatureHasher("foobar");
    const service = new SecureLink("secret", hasher, "_sig", "_expires");
    const url = new URL(
      "https://example.com/path/to/resource?bar=foo&foo=bar&_sig=barfoo"
    );
    assert.strictEqual(service.isValid(url), false);
    assert.throws(() => {
      service.validate(url);
    }, InvalidSignatureError);
  });
  it("should pass valid expiring link", () => {
    const hasher = new StaticSignatureHasher("foobar");
    const service = new SecureLink("secret", hasher, "_sig", "_expires");
    const expiresAt = Math.round(new DateNow().now().getTime() / 1000) + 3600;
    const url = new URL(
      `https://example.com/path/to/resource?bar=foo&foo=bar&_expires=${expiresAt}&_sig=foobar`
    );
    assert.strictEqual(service.isValid(url), true);
    service.validate(url);
  });
  it("should not pass link with invalid expiration", () => {
    const hasher = new StaticSignatureHasher("foobar");
    const service = new SecureLink("secret", hasher, "_sig", "_expires");
    const url = new URL(
      "https://example.com/path/to/resource?bar=foo&foo=bar&_expires=foobar&_sig=foobar"
    );
    assert.strictEqual(service.isValid(url), false);
    assert.throws(() => {
      service.validate(url);
    }, LinkHasExpiredError);
  });
  it("should not pass expired link", () => {
    const hasher = new StaticSignatureHasher("foobar");
    const service = new SecureLink("secret", hasher, "_sig", "_expires");
    const expiresAt = Math.round(new DateNow().now().getTime() / 1000) - 3600;
    const url = new URL(
      `https://example.com/path/to/resource?bar=foo&foo=bar&_expires=${expiresAt}&_sig=foobar`
    );
    assert.strictEqual(service.isValid(url), false);
    assert.throws(() => {
      service.validate(url);
    }, LinkHasExpiredError);
  });
  it("should not change link", () => {
    const hasher = new StaticSignatureHasher("foobar");
    const service = new SecureLink("secret", hasher, "_sig", "_expires", new DateNow(new Date(0)));
    const url1 = new URL(
        `https://example.com/path/to/resource?url=https://github.com&foo=bar&bar&_expires=1`
    );
    service.sign(url1);
    assert.strictEqual(
        url1.toString(),
        "https://example.com/path/to/resource?url=https://github.com&foo=bar&bar&_expires=1&_sig=foobar"
    );
    assert.strictEqual(service.isValid(url1), true);
    assert.strictEqual(
        url1.toString(),
        "https://example.com/path/to/resource?url=https://github.com&foo=bar&bar&_expires=1&_sig=foobar"
    );
    const url2 = new URL(
        `https://example.com/path/to/resource?url=https%3A%2F%2Fgithub.com&foo=bar&bar&_expires=1`
    );
    service.sign(url2);
    assert.strictEqual(
        url2.toString(),
        "https://example.com/path/to/resource?url=https%3A%2F%2Fgithub.com&foo=bar&bar&_expires=1&_sig=foobar"
    );
    assert.strictEqual(service.isValid(url2), true);
    assert.strictEqual(
        url2.toString(),
        "https://example.com/path/to/resource?url=https%3A%2F%2Fgithub.com&foo=bar&bar&_expires=1&_sig=foobar"
    );
  });
});

describe("md5 hasher", function () {
  it("should hash", () => {
    const hasher = new Md5Hasher();
    assert.equal(hasher.hash("secret"), "5ebe2294ecd0e0f08eab7690d2a6ee69");
  });
  it("should pass VALID data", () => {
    const hasher = new Md5Hasher();
    assert.strictEqual(
      hasher.isValid("5ebe2294ecd0e0f08eab7690d2a6ee69", "secret"),
      true
    );
  });
  it("should not pass INVALID data", () => {
    const hasher = new Md5Hasher();
    assert.strictEqual(
      hasher.isValid("7022cd14c42ff272619d6beacdc9ffde", "secret"),
      false
    );
  });
});

describe("sha1 hasher", function () {
  it("should hash", () => {
    const hasher = new Sha1Hasher();
    assert.equal(
      hasher.hash("secret"),
      "e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4"
    );
  });
  it("should pass VALID data", () => {
    const hasher = new Sha1Hasher();
    assert.strictEqual(
      hasher.isValid("e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4", "secret"),
      true
    );
  });
  it("should not pass INVALID data", () => {
    const hasher = new Sha1Hasher();
    assert.strictEqual(
      hasher.isValid("8e2ad3b8e7ee8cdf34d66b120fae70625ab1a4ae", "secret"),
      false
    );
  });
});

describe("secure link + hashers", function () {
  const md5Hasher = new Md5Hasher();
  const sha1Hasher = new Sha1Hasher();
  const dataset = [md5Hasher, sha1Hasher];
  dataset.forEach(function (hasher: Hasher) {
    it("should work correctly with hasher: " + hasher.constructor.name, () => {
      const now = new DateNow(new Date(0));
      const service = new SecureLink("secret", hasher, "_sig", "_expires", now);
      const hash = hasher.hash(
        "/path/to/resource?bar=foo&foo=bar&_expires=1 secret"
      );
      const url = new URL(
        `https://example.com/path/to/resource?bar=foo&foo=bar`
      );
      service.sign(url, 1);
      assert.strictEqual(
        url.toString(),
        `https://example.com/path/to/resource?bar=foo&foo=bar&_expires=1&_sig=${hash}`
      );
      assert.strictEqual(service.isValid(url), true);
      service.validate(url);
    });

    it(
      "should trigger invalid signature error with hasher: " +
        hasher.constructor.name,
      () => {
        const now = new DateNow(new Date(0));
        const service = new SecureLink(
          "secret",
          hasher,
          "_sig",
          "_expires",
          now
        );
        const url = new URL(
          `https://example.com/path/to/resource?bar=foo&foo=bar`
        );
        assert.strictEqual(service.isValid(url), false);
        assert.throws(() => {
          service.validate(url);
        }, InvalidSignatureError);
      }
    );
  });
});
