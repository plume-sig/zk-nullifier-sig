This is wrapper around `plume_rustcrypto` crate to produce PLUME signatures in JS contexts using Wasm.

TODO add here couple of examples from systems which uses this.

# Getting Started

Get the package from NPM. The repository contains Rust code for generating Wasm and packaging it.

The package usage outline; see the details in subsections.
```js
// ...
let result = plume.sign(true, secretKeySec1Der, msg);
console.log(result.nullifier);
result.zeroizePrivateParts();
```

Please, refer to the JS-doc for types description, function signatures, and exceptions notes.

Values in the following examples are in line with tests in the wrapped crate.
## producing the signature
```js
import * as plume from "TODO";

let result = plume.sign(
  false, 
  new Uint8Array([48, 107, 2, 1, 1, 4, 32, 81, 155, 66, 61, 113, 95, 139, 88, 31, 79, 168, 238, 89, 244, 119, 26, 91, 68, 200, 19, 11, 78, 62, 172, 202, 84, 165, 109, 218, 114, 180, 100, 161, 68, 3, 66, 0, 4, 12, 236, 2, 142, 224, 141, 9, 224, 38, 114, 166, 131, 16, 129, 67, 84, 249, 234, 191, 255, 13, 230, 218, 204, 28, 211, 167, 116, 73, 96, 118, 174, 239, 244, 113, 251, 160, 64, 152, 151, 182, 164, 142, 136, 1, 173, 18, 249, 93, 0, 9, 183, 83, 207, 143, 81, 193, 40, 191, 107, 11, 210, 127, 189]),
  new Uint8Array([
    65, 110, 32, 101, 120, 97, 109, 112, 108, 101, 32, 97, 112, 112, 32, 109, 101, 115, 115, 97, 103, 101, 32, 115, 116, 114, 105, 110, 103
  ])
);
```
## getters
`PlumeSignature` provide getters for each property of it, so you have access to any of them upon signing.
```js
// ...
console.log(result.nullifier);
console.log(result.s);
console.log(result.c);
console.log(result.pk);
console.log(result.message);
```
Note that variant is specified by `v1specific`; if it's `undefined` then the object contains V2, otherwise it's V1.
```js
// ...
console.log(result.v1specific.r_point);
console.log(result.v1specific.hashed_to_curve_r);
```
Also there's #convertion utility provided.
## zeroization
Depending on your context you might want to clear values of the result from Wasm memory after getting the values.
```js
// ...
result.zeroizePrivateParts();
result.zeroizeAll();
```

# #convertion of `s` to `BigInt`
JS most native format for scalar is `BigInt`, but it's not really transportable or secure, so for uniformity of approach `s` in `PlumeSignature` is defined similar to `c`; but if you want to have it as a `BigInt` there's `sec1DerScalarToBigint` helper funtion.

# Working with source files

This package is built with the tech provided by <https://github.com/rustwasm> which contains everything needed to work with it. Also the wrapper crate was initiated with `wasm-pack-template`.

Note that the wrapper crate has `verify` feature which can check the resulting signature.

# License
See <https://github.com/plume-sig/zk-nullifier-sig/blob/main/LICENSE>.