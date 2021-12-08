# secure-link-js
Sign and validate links (with query string)

![DockerHub](https://github.com/mingalevme/secure-link-js/actions/workflows/quality.yml/badge.svg)

## Usage example

```typescript
import { SecureLink, Md5Hasher, InvalidSignatureError, LinkHasExpiredError } from "@mingalevme/secure-link";

const hasher = new Md5Hasher();
const secureLink = new SecureLink('some-secret-string', hasher, '_sig', '_expires');

const url = new URL('https://github.com/mingalevme/secure-link-js');

secureLink.sign(url);
console.log(url.toString())
// Console: "https://github.com/mingalevme/secure-link-js?_sig=44f7e969164072bf613c2c9aad83fdc3"

console.log(secureLink.isValid(url))
// Console: true
url.searchParams.set('_sig', 'foobar')
console.log(secureLink.isValid(url))
// Console: false

try {
    secureLink.validate(url)
} catch (e) {
    if (e instanceof InvalidSignatureError) {
        console.log('Signature is invalid', url.toString())
    } else if (e instanceof LinkHasExpiredError) {
        console.log('Link is expired', url.toString())
    } else {
        console.log('Link is valid', url.toString())
    }
}
// Console: "Signature is invalid" "https://github.com/mingalevme/secure-link-js?_sig=foobar"

url.searchParams.delete('_sig')
secureLink.sign(url, 9999999999);
console.log(url.toString())
// Console: "https://github.com/mingalevme/secure-link-js?_expires=9999999999&_sig=fcacdf6e027d8ed726137b77435bff77"

console.log(secureLink.isValid(url))
// Console: true

secureLink.sign(url, 1000000000);

try {
    secureLink.validate(url)
} catch (e) {
    if (e instanceof InvalidSignatureError) {
        console.log('Signature is invalid', url.toString())
    } else if (e instanceof LinkHasExpiredError) {
        console.log('Link is expired', url.toString())
    } else {
        console.log('Link is valid', url.toString())
    }
}
// Console: "Signature is invalid" "https://github.com/mingalevme/secure-link-js?_expires=9999…_expires=1000000000&_sig=456d33904ef4017646827d17396c11ef"
```
