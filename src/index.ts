import {Hasher} from './hashing'
import {DateNow, Now} from "./now"

export class SecureLink {
    private readonly secret: string
    private readonly hasher: Hasher
    private readonly signatureArg: string = null
    private readonly expiresArg: string = null
    private readonly now: Now

    constructor(secret: string, hasher: Hasher, signatureArg?: string, expiresArg?: string, now?: Now) {
        this.secret = secret
        this.hasher = hasher
        this.signatureArg = signatureArg || 'signature'
        this.expiresArg = expiresArg || 'expires'
        this.now = now || new DateNow()
    }

    sign(url: URL, expiresAt?: number): void {
        url.searchParams.sort()
        if (expiresAt) {
            // Add expiration to end of the qs
            url.searchParams.append(this.expiresArg, expiresAt.toString())
        }
        const signature = this.hasher.hash(this.getDataToSign(url))
        url.searchParams.append(this.signatureArg, signature)
    }

    /**
     * @param {URL} url
     * @throws {InvalidSignatureError | LinkHasExpiredError}
     */
    validate(url: URL): void {
        const clone = URL
        const signature = url.searchParams.get(this.signatureArg)
        if (!signature) {
            throw new InvalidSignatureError()
        }
        if (!this.hasher.isValid(signature, this.getDataToSign(url))) {
            throw new InvalidSignatureError()
        }
        if (!url.searchParams.has(this.expiresArg)) {
            return
        }
        const expires = +url.searchParams.get(this.expiresArg)
        if (isNaN(+expires)) {
            throw new LinkHasExpiredError()
        }
        if (expires < Math.round(this.now.now().getTime() / 1000)) {
            throw new LinkHasExpiredError()
        }
    }

    isValid(url: URL): boolean {
        try {
            this.validate(url)
        } catch (SecureLinkError) {
            return false
        }
        return true
    }

    private getDataToSign(url: URL): string {
        return `${url.pathname}${url.search} ${this.secret}`
    }
}

export class SecureLinkError extends Error {
    constructor() {
        super()
        Object.setPrototypeOf(this, SecureLinkError.prototype)
    }
}

export class InvalidSignatureError extends SecureLinkError {
    constructor() {
        super()
        Object.setPrototypeOf(this, InvalidSignatureError.prototype)
    }
}

export class LinkHasExpiredError extends SecureLinkError {
    constructor() {
        super()
        Object.setPrototypeOf(this, LinkHasExpiredError.prototype)
    }
}
