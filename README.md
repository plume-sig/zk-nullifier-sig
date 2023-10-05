# PLUME: Verifiably Deterministic Signatures on ECDSA

This repository provides libraries for the construction of deterministic nullifiers on Ethereum keys, [ERC 7524]([https://ethereum-magicians.org/t/erc-7524-plume-signature-in-wallets/15902](https://github.com/ethereum/EIPs/pull/7775)). We call them Privately Linked Unique Message Entities (or PLUMEs). We hope that wallets integrate the javascript, rust, or C repositories for both software and hardware signature generation, and dapps integrate the zk proof in the circuits/ directory.

If you would like to get a grant to create PLUME applications or improve the library, we have grants available from Ethereum Foundation PSE and Gitcoin Grants, and would give grants for any PRs to the repository! There are projects ideas both below in the README, as well as bountied every issue in Github has a $50 bounty on it. Feel free to pick one up, and dm us on Twitter/Telegram (@yush_g) or email [Provenant Research](https://provenant.dev) to help! This work was generously funded and supported by 0xPARC, Gitcoin donors, and EF PSE, and exists only due to the valuable work by contributors to this Github such as yush_g, Oren Yomtov, Richard Liu, Blake M Scurr, Piotr Roslaniec, Vu Voth, Weijie Koh, and Vivek Bhupatiraju who directly contributed to the code. Thanks to Poseidon Labs for a V2 proposal and Weiking Chen for a V3 proposal, and our auditors (0xbok), as well as all of the folks [acknowledged in the research paper](https://aayushg.com/thesis.pdf) and [blog post](https://blog.aayushg.com/posts/plume).

## Contributions

If you'd like to contribute, we offer $50 bounties in Eth/DAI for resolving any of the bugs in our issues! Each of them is quite small. That includes [#28](https://github.com/plume-sig/zk-nullifier-sig/issues/28), [#24](https://github.com/plume-sig/zk-nullifier-sig/issues/24), [#22](https://github.com/plume-sig/zk-nullifier-sig/issues/22), [#19](https://github.com/plume-sig/zk-nullifier-sig/issues/19), [#15](https://github.com/plume-sig/zk-nullifier-sig/issues/15), [#14](https://github.com/plume-sig/zk-nullifier-sig/issues/14),and [#13](https://github.com/plume-sig/zk-nullifier-sig/issues/13).

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

If you encounter an error `No prebuilt binaries found`, try switching to node ` v18.17.0` (using [`n`](https://github.com/tj/n), for example) to work around our dependency's [build issue](https://github.com/WiseLibs/better-sqlite3/issues/1027).

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

- [DONE] Incorporate the [V2 proposed by poseidon](https://www.notion.so/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff) to be a codepath both in the wallet [WIP PR](https://github.com/zk-nullifier-sig/zk-nullifier-sig/pull/9) and in the circom
- Improve `rust-k256` to use a similar interface as `rust-arkworks` - i.e. generate/accept arbitrary keypairs and `r` values, and not just hardcoded values
- Rewrite in halo2 (WIP by blakemscurr and vuvoth)
  - [$500 Bounty] Implement hash to curve in halo2
- Reduce number of arguments to c via Wei Dai's + [Poseidons](https://www.notion.so/mantanetwork/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff?pvs=4) suggestions (potentially just g^sk, h[m, pk], g^r is fine) and write a proof in the Algebraic Group Model for the change.
- [$500 Bounty] Fix stealthdrop MVP, the first anonymous airdrop to any Ethereum keys via PLUMEs -- [repo](https://github.com/stealthdrop/stealthdrop/) and [slides](https://docs.google.com/presentation/d/10ZGJvYpIqpON5O4uDf2pdk-PnT8fEVyPOoRqC3VmFn0/edit).
- Edit: Poseidon hash will be too slow in Ledger and is a newer hash function -- given that we have reasonably efficient sha256 hashing with [halo2 zkevm sha256](https://github.com/Brechtpd/zkevm-circuits/tree/sha256) as well as efficient EVM computation in the V2 proposal, we do not intend to switch the hash function away from SHA256.

## Resources

### Paper
Thesis [most up to date version]: https://aayushg.com/thesis.pdf  
Paper [slightly out of date]: https://eprint.iacr.org/2022/1255

### Slides
[http://slides.plume.run](https://docs.google.com/presentation/d/1mKtOI4XgKrWBEPpKFAYkRjxZsBomwhy6Cc2Ia87hAnY/edit#slide=id.g13e97fbcd2c_0_76)

### Blog Post
https://blog.aayushg.com/posts/nullifier

### ERC Draft
[http://erc.plume.run][https://www.notion.so/vi-institute/PLUME-ERC-Draft-5558bbd43b674bcb881f5c535ced5893]

### Demo
https://nullifier.xyz

### Talk
https://www.youtube.com/watch?v=6ajBnMdJGoY

### Circom Proof Data

For the V1,
See [this PR](https://github.com/zk-nullifier-sig/zk-nullifier-sig/pull/7).   
6.5 million constraints. Mostly dominated by EC operations, but the hashes are very expensive too.  

sha256 ~1.5M. 
hash_to_curve ~0.5M. 
a/b^c ~1.5 each (this is the sub circuit for the first 2 verification equations). 
the remaining 1.5M is probably dominated by calculating g^s and h^s. 

For the V2,
the sha256 is 0 cost in the circuit, but is added to the verification cost. This takes in-circuit constraints down to 5M and adds the sha to the verification.

#### Hash to Curve Circom Code
https://github.com/geometryresearch/secp256k1_hash_to_curve/
https://geometry.xyz/notebook/Hashing-to-the-secp256k1-Elliptic-Curve

We are giving a $500 grant for an implementation of this in halo2.

### Nullifier Calculation Spec
https://hackmd.io/uZQbMHrVSbOHvoI_HrJJlw

### Circom Verification Spec
https://hackmd.io/VsojkopuSMuEA4vkYKSB8g?edit
