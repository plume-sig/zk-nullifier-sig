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
     48, 107,   2,   1,   1,   4, 32,  51, 230,  85,  68, 129,
    138,   1, 100, 183,  88, 247, 98, 146, 145, 211, 106,  95,
    239, 188, 178,  48, 169, 159, 94, 215,   1, 144,  63,   9,
    125,  69, 216, 161,  68,   3, 66,   0,   4,  50,  19,  61,
     44,  42, 226,  58, 241,  87, 46, 105, 142, 188, 131, 170,
    240, 229,   2, 237, 102, 205, 67,  65,  81, 191,  10,  91,
    215,  89, 152,  15,  75, 170, 71, 184, 186, 137,  87, 138,
    241,  43, 170, 182,  20,   0, 42, 161, 149, 129, 159, 189,
    213, 144,  44,  29,
    ... 9 more items
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
# #conversion of `s` to `BigInt`
JS most native format for scalar is `BigInt`, but it's not really transportable or secure, so for uniformity of approach `s` in `PlumeSignature` is defined similar to `digest_private`; but if you want to have it as a `BigInt` there's `sec1DerScalarToBigint` helper funtion.
# Working with source files
This package is built with the tech provided by <https://github.com/rustwasm> which contains everything needed to work with it. Also the wrapper crate was initiated with `wasm-pack-template`.
# License
See <https://github.com/plume-sig/zk-nullifier-sig/blob/main/LICENSE>.