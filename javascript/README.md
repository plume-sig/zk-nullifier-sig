This is wrapper around `plume_rustcrypto` crate to produce PLUME signatures in JS contexts using Wasm.

TODO add here couple of examples from systems which uses this.

# Getting Started

Get the package from NPM. The repository contains Rust code for generating Wasm and packaging it.

The package usage outline; see the details in subsections.
```js
// ...
let result = plume.sign(isV1, secretKeySec1Der, msg);
console.log(result.instance)
console.log(result.witness.digest_private);
// get all the other witness values
result.zeroize();
```

Please, refer to the JS-doc for types description, function signatures, and exceptions notes.

Values in the following examples are in line with the tests in the wrapped crate.
## producing the signature
```js
import * as plume from 'plume-sig';

let result = plume.sign(
  false, 
  new Uint8Array([48, 107, 2, 1, 1, 4, 32, 81, 155, 66, 61, 113, 95, 139, 88, 31, 79, 168, 238, 89, 244, 119, 26, 91, 68, 200, 19, 11, 78, 62, 172, 202, 84, 165, 109, 218, 114, 180, 100, 161, 68, 3, 66, 0, 4, 12, 236, 2, 142, 224, 141, 9, 224, 38, 114, 166, 131, 16, 129, 67, 84, 249, 234, 191, 255, 13, 230, 218, 204, 28, 211, 167, 116, 73, 96, 118, 174, 239, 244, 113, 251, 160, 64, 152, 151, 182, 164, 142, 136, 1, 173, 18, 249, 93, 0, 9, 183, 83, 207, 143, 81, 193, 40, 191, 107, 11, 210, 127, 189]),
  new Uint8Array([
    65, 110, 32, 101, 120, 97, 109, 112, 108, 101, 32, 97, 112, 112, 32, 109, 101, 115, 115, 97, 103, 101, 32, 115, 116, 114, 105, 110, 103
  ])
);
```
## getting the values
`PlumeSignature` holds two objects: `instance` with the public values is available for further processing, and `witness` with the private values provides access to all of them just via getters.
### `instance`
```js
// ...
console.log(result.instance)
/* {
  message: [
     65, 110,  32, 101, 120,  97, 109,
    112, 108, 101,  32,  97, 112, 112,
     32, 109, 101, 115, 115,  97, 103,
    101,  32, 115, 116, 114, 105, 110,
    103
  ],
  nullifier: [
      3,  87, 188,  62, 210, 129, 114, 239,
    138, 221, 228, 185, 224, 194, 204, 231,
     69, 252, 197, 166, 100, 115, 164,  92,
     30,  98, 111,  29,  12, 103, 229,  88,
     48
  ],
  s: [
    82, 142, 143, 187, 100, 82, 248, 34,
     0, 121, 123,  26, 115, 178, 148, 122,
   146,  82,  75, 214,  17,   8,  90, 146,
    15,  17, 119, 203, 128, 152,  19, 107
  ],
  is_v1: false
} */
```
### `witness`
```js
console.log(result.witness.pk)
/* Uint8Array(33) [
    3,  12, 236,   2, 142, 224, 141,   9,
  224,  38, 114, 166, 131,  16, 129,  67,
   84, 249, 234, 191, 255,  13, 230, 218,
  204,  28, 211, 167, 116,  73,  96, 118,
  174
] */
console.log(result.witness.digest_private)
console.log(result.witness.v1specific);
// undefined
```
#### the variant distinguishing
Note that for the `witness` the variant is specified by `v1specific`; if it's `undefined` then the object contains V2, otherwise it's V1.
```js
// ...
if (result.witness.v1specific) {
  console.log(result.witness.v1specific.r_point);
  console.log(result.witness.v1specific.hashed_to_curve_r);
}
```
Also there's the #conversion utility provided.
## zeroization
Depending on your context you might want to clear `witness` values from the Wasm memory after getting the values.
```js
// ...
result.zeroize();
```
# Conversion of `s` to `BigInt`
`s` and `digest_private` are canonical 32-byte big-endian scalars. Use `scalarBytesToBigint` when a JavaScript `BigInt` is required. The conversion may leave the value in memory, so do not use it for private values.
# Working with source files
This package is built with the tech provided by <https://github.com/rustwasm> which contains everything needed to work with it. Also the wrapper crate was initiated with `wasm-pack-template`.
# License
See <https://github.com/plume-sig/zk-nullifier-sig/blob/main/LICENSE>.
