# PLUME: Verifiably Deterministic Signatures on ECDSA

This allows for the construction of deterministic nullifiers. We intend to deploy it as Privately Linked Unique Message Entities (PLUME).

## Implementations

- `rust-k256`: Rust, using the k256 library
- `rust-arkworks`: Rust, using arkworks
- `javascript`: JavaScript, using MIRACL

## TODO

- zk verifier circuits (WIP Circom here: https://github.com/geometryresearch/secp256k1_hash_to_curve/tree/main/circuits)
- change SHA512 to Poseidon (wallets are onboard)
- improve `rust-k256` to use a similar interface as `rust-arkworks` - i.e.
  generate/accept arbitrary keypairs and `r` values, and not just hardcoded
  values
- rewrite in halo2
- reduce number of arguments to c via Wei Dai's + [Poseidons](https://www.notion.so/mantanetwork/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff?pvs=4) suggestions

## Resources

### Paper
https://aayushg.com/thesis.pdf
https://eprint.iacr.org/2022/1255

### Slides
https://docs.google.com/presentation/d/1mKtOI4XgKrWBEPpKFAYkRjxZsBomwhy6Cc2Ia87hAnY/edit#slide=id.g13e97fbcd2c_0_76

### Blog Post
https://blog.aayushg.com/posts/nullifier

### ERC Draft
https://ivy-docs.notion.site/PLUME-ERC-Draft-5558bbd43b674bcb881f5c535ced5893

### Demo
https://nullifier.xyz

### Talk
https://www.youtube.com/watch?v=6ajBnMdJGoY

### Circom Proofs
https://github.com/zk-nullifier-sig/zk-nullifier-sig/pull/7
6.5 million constraints. Mostly dominated by EC operations, but the hashes are very expensive too.

sha256 ~1.5M
hash_to_curve ~0.5M
a/b^c ~1.5 each (this is the sub circuit for the first 2 verification equations)
the remaining 1.5M is probably dominated by calculating g^s and h^s

#### Hash to Curve Circom Code
https://github.com/geometryresearch/secp256k1_hash_to_curve/

### Nullifier Calculation Spec
https://hackmd.io/uZQbMHrVSbOHvoI_HrJJlw

### Circom Verification Spec
https://hackmd.io/VsojkopuSMuEA4vkYKSB8g?edit
