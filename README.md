# Verifiably Deterministic Signatures on ECDSA

This allows for the construction of deterministic nullifiers. We intend to deploy it as Privately Linked Unique Message Entities (PLUME).

## Implementations

- `rust-k256`: Rust, using the k256 library
- `rust-arkworks`: Rust, using arkworks
- `javascript`: JavaScript, using MIRACL

## Testing the circom circuit

First, clone this repository and navigate to the `circuits/` directory.

Install dependencies:

```bash
npm i
```

Run the tests:
```bash
npm run flatten-deps && \
npm run test
```

Be prepared to wait around 20-40 minutes for the tests to complete.

## TODO

- change SHA256 to Poseidon (wallets are onboard)
- improve `rust-k256` to use a similar interface as `rust-arkworks` - i.e.
  generate/accept arbitrary keypairs and `r` values, and not just hardcoded
  values

## Resources

### Paper
https://aayushg.com/thesis.pdf
https://eprint.iacr.org/2022/1255

### Slides
https://docs.google.com/presentation/d/1mKtOI4XgKrWBEPpKFAYkRjxZsBomwhy6Cc2Ia87hAnY/edit#slide=id.g13e97fbcd2c_0_76

### Blog Post
https://blog.aayushg.com/posts/nullifier

### ERC Draft
https://personae-labs.notion.site/ERC-Draft-f6d584dd2acd414cb6be834e9bdcfbda

### Demo
nullifier.xyz

### Circom Code (Partial)
https://github.com/geometryresearch/secp256k1_hash_to_curve/

### Talk
https://www.youtube.com/watch?v=6ajBnMdJGoY

### Nullifier Calculation Spec
https://hackmd.io/uZQbMHrVSbOHvoI_HrJJlw

### Circom Verification Spec
https://hackmd.io/VsojkopuSMuEA4vkYKSB8g?edit
