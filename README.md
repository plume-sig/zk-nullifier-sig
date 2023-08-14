# PLUME: Verifiably Deterministic Signatures on ECDSA

This repository provides libraries for the construction of deterministic nullifiers on Ethereum keys, a soon-to-be ERC. We call them Privately Linked Unique Message Entities (or PLUMEs). We hope that wallets integrate the javascript, rust, or (work-in-progress) C repositories for both software and hardware signature generation, and dapps integrate the zk proof in the circuits/ directory.

If you would like to get a grant to create PLUME applications or help to fix bugs and upgrade to a V3, we have grants available from Ethereum Foundation PSE and Gitcoin Grants, and would give grants for any PRs to the repository! There are ideas both below in the README, or in the issues in Github. Feel free to pick one up, and dm on Twitter or email [VII](https://vii.dev) to help! This work was generously funded and supported by 0xPARC, Gitcoin donors, and EF PSE, and exists only due to the valuable work by contributors to this Github such as Richard L, Blake MS, Piotr R, Vu V, Weijie K, Vivek B, and our auditors, as well as all of the folks [acknowledged in the research paper](https://aayushg.com/thesis.pdf).   

## Contributions

If you'd like to contribute, we offer $50 bounties in Eth/DAI for resolving any of the bugs in our issues! Each of them is quite small. That includes [#28](https://github.com/plume-sig/zk-nullifier-sig/issues/28), [#24](https://github.com/plume-sig/zk-nullifier-sig/issues/24), [#23](https://github.com/plume-sig/zk-nullifier-sig/issues/23), [#22](https://github.com/plume-sig/zk-nullifier-sig/issues/22), [#20](https://github.com/plume-sig/zk-nullifier-sig/issues/20), [#19](https://github.com/plume-sig/zk-nullifier-sig/issues/19), [#18](https://github.com/plume-sig/zk-nullifier-sig/issues/18), [#17](https://github.com/plume-sig/zk-nullifier-sig/issues/17), [#16](https://github.com/plume-sig/zk-nullifier-sig/issues/16), [#15](https://github.com/plume-sig/zk-nullifier-sig/issues/15), [#14](https://github.com/plume-sig/zk-nullifier-sig/issues/14),and [#13](https://github.com/plume-sig/zk-nullifier-sig/issues/13).

## Implementations

- `rust-k256`: Rust, using the k256 library
- `rust-arkworks`: Rust, using arkworks
- `javascript`: JavaScript, using MIRACL

## Testing the circom circuit

First, clone this repository and navigate to the `javascript/` directory.

Install dependencies:

```bash
npm i
```

Then, navigate to the `circuits/` directory and install the dependencies there:

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

- Incorporate the [V2 proposed by poseidon](https://www.notion.so/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff) to be a codepath both in the wallet [WIP PR](https://github.com/zk-nullifier-sig/zk-nullifier-sig/pull/9) and in the circom (task still open)
- improve `rust-k256` to use a similar interface as `rust-arkworks` - i.e. generate/accept arbitrary keypairs and `r` values, and not just hardcoded values
- rewrite in halo2 (WIP by blakemscurr and vuvoth, dm to contribute via a grant!)
- reduce number of arguments to c via Wei Dai's + [Poseidons](https://www.notion.so/mantanetwork/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff?pvs=4) suggestions
- build stealthdrop MVP, the first anonymous airdrop to any Ethereum keys via PLUME by forking [stealthdrop][url](https://docs.google.com/presentation/d/10ZGJvYpIqpON5O4uDf2pdk-PnT8fEVyPOoRqC3VmFn0/edit)
- Edit: Poseidon will be too slow in Ledger and is a newer hash function -- given that we have reasonably efficient sha256 hashing with [zkevm sha256](https://github.com/Brechtpd/zkevm-circuits/tree/sha256), we do not intend to switch the hash function

## Resources

### Paper
Thesis [most up to date version]: https://aayushg.com/thesis.pdf  
Paper [slightly out of date]: https://eprint.iacr.org/2022/1255

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
See [this PR](https://github.com/zk-nullifier-sig/zk-nullifier-sig/pull/7).   
6.5 million constraints. Mostly dominated by EC operations, but the hashes are very expensive too.  

sha256 ~1.5M. 
hash_to_curve ~0.5M. 
a/b^c ~1.5 each (this is the sub circuit for the first 2 verification equations). 
the remaining 1.5M is probably dominated by calculating g^s and h^s. 

#### Hash to Curve Circom Code
https://github.com/geometryresearch/secp256k1_hash_to_curve/

### Nullifier Calculation Spec
https://hackmd.io/uZQbMHrVSbOHvoI_HrJJlw

### Circom Verification Spec
https://hackmd.io/VsojkopuSMuEA4vkYKSB8g?edit
