`plume-sig`
==============
TypeScript implementation of the PLUME signature scheme.

## Installation
`npm install plume-sig`

## Usage

```js
import { computeAllInputs, PlumeVersion } from 'plume-sig';

return computeAllInputs(message, secretKey, uniqueRandomScalar);
```

The function returns the signature w.r.t. to given arguments as the object of the following structure.
### `plume`
`secp256k1` point
### `s`
`secp256k1` scalar hexstring
### `pk`
Public key of the signer; SEC1 encoded.
### `c`
SHA-256 hash. It's value depends on `PlumeVersion` of the signature.
### `rPoint`
`secp256k1` point representing the unique random scalar used for signing. V1 specific.
### `hashedToCurveR`
`secp256k1` point. V1 specific.

## Signature variants
The scheme comes in two variants. V2 is default for this implementation. It won't need V1 specific fields for it verification.

## License
MIT