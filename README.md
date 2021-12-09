# Secure Link

Sign and validate url with query string.

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
// Console: "Link is expired" "https://github.com/mingalevme/secure-link-js?_expires=1000000000&_sig=f8ba8b5fa6af187364aa56dd95d6ba01"
```

## Signing a link without the library

Internally the library use the following string to get hash '${PATH_WITH_QUERY_STRING} ${SECRET}'.

For example, we're going to take the following url `https://github.com/mingalevme/secure-link-js?foo=bar` and `secret` as a secret.

### JavaScript / NodeJS

```javascript
node --require "crypto" -e "const {createHash} = require('crypto'); const sig = createHash('md5').update('/mingalevme/secure-link-js?foo=bar secret').digest('hex'); console.log(sig);"
// c8c2573e4a0b5dfcab2da94ad17f031c
```

### Shell

#### md5 (macOS)

```shell
echo -n "/mingalevme/secure-link-js?foo=bar secret" | md5
# c8c2573e4a0b5dfcab2da94ad17f031c
```

#### md5sum

```shell
echo -n "/mingalevme/secure-link-js?foo=bar secret" | md5sum | awk '{print $1}'
# c8c2573e4a0b5dfcab2da94ad17f031c
```

### PHP

```php
php -r "echo md5('/mingalevme/secure-link-js?foo=bar secret').PHP_EOL;"
# c8c2573e4a0b5dfcab2da94ad17f031c
```

### Python

```
python -c "import hashlib; sig = hashlib.md5('/mingalevme/secure-link-js?foo=bar secret'.encode('utf-8')).hexdigest(); print(sig)"
# c8c2573e4a0b5dfcab2da94ad17f031c
```
