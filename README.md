[![DeepWiki Docs](https://deepwiki.com/badge.svg)](https://deepwiki.com/plume-sig/zk-nullifier-sig)

# PLUME: Verifiably Deterministic Signatures on ECDSA

This repository provides libraries for the construction of deterministic nullifiers on Ethereum keys, [ERC 7524]([https://ethereum-magicians.org/t/erc-7524-plume-signature-in-wallets/15902](https://github.com/ethereum/EIPs/pull/7775)). We call them Privately Linked Unique Message Entities (or PLUMEs). PLUMEs enable zk voting, anonymous proof of solvency, and anonymous message board moderation to be possible with Ethereum keys directly, and so we think it is a critical primitive to push forward blockchain adoption. To understand how this primitive works and the reason for design decisions, we recommend checking out [our blog post](https://blog.aayushg.com/posts/plume).

We hope that wallets integrate the javascript, rust, or C repositories for both software and hardware signature generation, and dapps integrate the zk proof in the circuits/ directory.

## Installation

To install our [npm package](https://www.npmjs.com/package/plume-sig) for JS/TS, do
```
yarn add plume-sig
```

To install our [Cargo package](https://crates.io/crates/plume_rustcrypto) for Rust, do
```
cargo add plume_rustcrypto
```

Docs and usage guides are linked to from the packages.

## Contributions and Grants

If you would like to get a grant to create PLUME applications or improve the library, we have grants available from Ethereum Foundation PSE and Gitcoin Grants, and would give grants for any PRs to the repository! There are projects ideas both below in the README, as well as bountied every issue in Github has a $50 bounty on it. Feel free to pick one up, and dm us on Twitter/Telegram (@yush_g) for guidance and help, or join the discussion in the public channel in the [PSE Discord](https://discord.gg/pse) for progress updates and community questions! This work was generously funded and supported by 0xPARC, Gitcoin donors, and EF PSE, and exists only due to the valuable work by contributors to this Github such as yush_g, Oren Yomtov, Richard Liu, Blake M Scurr, Piotr Roslaniec, Vu Voth, Weijie Koh, and Vivek Bhupatiraju who directly contributed to the code. Thanks to Poseidon Labs for a [V2 proposal](https://www.notion.so/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff) and Weiking Chen for his filed issues, and our auditors (0xbok), as well as all of the folks [acknowledged in the research paper](https://aayushg.com/thesis.pdf) and [blog post](https://blog.aayushg.com/posts/plume).

If you'd like to contribute, we offer $50 bounties in Eth/DAI for resolving any of the bugs in our issues! Each of them is quite small. That includes 
[#28](https://github.com/plume-sig/zk-nullifier-sig/issues/28), [#24](https://github.com/plume-sig/zk-nullifier-sig/issues/24), 
[#14](https://github.com/plume-sig/zk-nullifier-sig/issues/14), and [#13](https://github.com/plume-sig/zk-nullifier-sig/issues/13).

## Implementations

Historically the initial suite -- `k256` with SHA-2 -- lives in this repo. Other suites can be found in the adjacent repos.
### SECP256K1
with SHA-2
#### verification
- <circuits/circom>. The first implementation, well suited for Groth-16 backends.
- `noir` - Unaudited implementation by [Distributed Lab](https://github.com/distributed-lab) and [Aztec Labs](https://aztec-labs.com/). Defaults to the [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) proving backend.
#### signing
- <./rust-k256>: Rust, using `k256` library.
- <./rust-arkworks>: Rust, using `arkworks`.
- <./javascript>: TypeScript bindings for the crate from <./rust-k256>.
#### Poseidon
Repo `k256_poseidon` contains some code replacing SHA-2 for Aztec Poseidon-2 hash.
### Pallas
#### [`mina-signer`](https://www.npmjs.com/package/mina-signer)
provides the method `createNullifier`.
#### verification
[`o1js`](https://www.npmjs.com/package/o1js) provides [the dedicated class which offers `verify` method](https://docs.minaprotocol.com/zkapps/o1js-reference/classes/Nullifier#verify) and other useful items.
### BN254
See `bn254` repo for the suite implementation.

### Wallet Implementations

- Mina: Uses it for nullifiers in their code [here](https://github.com/o1-labs/o1js/blob/main/src/lib/nullifier.ts) and [here](https://github.com/o1-labs/o1js/blob/main/src/mina-signer/src/nullifier.ts). They use Poseidon for the hash function instead, which makes it slower to generate in hardware wallets, but faster to prove. Their [docs for this scheme are here](https://docs.minaprotocol.com/zkapps/o1js-reference/classes/Nullifier).
- Taho: We have an [open PR](https://github.com/tahowallet/extension/pull/3638) that we are waiting on them to merge!
- Rabby: We have an [open PR](https://github.com/RabbyHub/Rabby/pull/2047) that we are waiting on them to merge!
- Metamask: We have an open PR set ([rpc](https://github.com/MetaMask/eth-json-rpc-middleware/pull/198
), [api](https://github.com/MetaMask/api-specs/pull/120), [core](https://github.com/MetaMask/metamask-extension/pull/17482)) that we are waiting on them to merge! Snaps [dropped support for secret key access](https://github.com/MetaMask/snaps/issues/1665) so a Metamask Snap is no longer a tenable path, although we did have a snap as well.
- Aztec: Noir implementation [finished here](https://github.com/distributed-lab/noir-plume), still pending audit.
- Ledger: This [app](https://github.com/base0010/plume-ledger-app/tree/sswu) compiles and generates PLUME signatures on embedded hardware and works on Ledgers. Test via the [Ledger app builder](https://github.com/LedgerHQ/ledger-app-builder).
- ZK Snap: The "holy grail of private voting", according to Ameen, co-author of the private voting report. Uses PLUME as a [core component of an end-to-end private voting system](https://twitter.com/AeriusLabs/status/1753052458249785836).

### Audits
We have been audited by [PSE Security](https://github.com/0xbok) for these three implementations V1 and V2 implementations, as well as for V1 circuits in circom. We expect the halo2 circuits to be runnable on mobile (once we have audited that code circa ~April and put up a recursive proving infrastructure setup).

The Circom implementation was audited by [PSE Security](https://github.com/0xbok) for the Rust and Javascript implementations, both V1 and V2, as well as for V1 circuits. We expect the `halo2` circuits to be runnable on mobile (once we have audited that code circa ~April and put up a recursive proving infrastructure setup).

## Testing
### Circom

Circom uses the great `circom-tester` library by [iden3](https://github.com/iden3/circom_tester). Prepare your testing environment by cloning this repository and navigating to the <circuits/circom/test/javascript/> directory. Then install the dependencies.
```bash
pnpm i
```

If you encounter an error "No prebuilt binaries found", try switching to Nodejs `v18.17.0` (using [`n`](https://github.com/tj/n), for example) to work around our dependency's [build issue](https://github.com/WiseLibs/better-sqlite3/issues/1027).

Then, navigate to the <circuits/circom> directory and install the dependencies there.
```bash
pnpm i
```

Run the tests.
```bash
pnpm run flatten-deps && \
pnpm run test
```

Be prepared to wait around 20-40 minutes for the tests to complete.

## Open Work

We invite contributors to collaborate on this effort. There are great tasks for beginners (the issues), a halo2 intermediate level (circuits), cryptography intermediate level (the v1 improvement to make it v2 compatible below), and on the application layer (building apps that use PLUME).  

- Create a V3
  - Reduce number of arguments to c in V1 via Wei Dai's + [Poseidons](https://www.notion.so/mantanetwork/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff?pvs=4) suggestions (potentially just g^sk, h[m, pk], g^r is fine) that are currently used in the V2, and write a proof in the Algebraic Group Model for the change.
- [$500 Bounty] Fix stealthdrop Circom MVP, the first anonymous airdrop to any Ethereum keys via PLUMEs -- [repo](https://github.com/stealthdrop/stealthdrop/) and [slides](https://docs.google.com/presentation/d/10ZGJvYpIqpON5O4uDf2pdk-PnT8fEVyPOoRqC3VmFn0/edit).
- [$500 Bounty] Implement ZK voting via PLUMEs, as described in [Poseidons proposal](https://www.notion.so/mantanetwork/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff?pvs=4).
- [$500 bounty] Implement the ZK circuits in Noir to integrate them into Aztec.

## Resources

### Paper
Thesis [most up to date version]: https://aayushg.com/thesis.pdf  
Paper [slightly out of date]: https://eprint.iacr.org/2022/1255

### Slides
[http://slides.plume.run](https://docs.google.com/presentation/d/1mKtOI4XgKrWBEPpKFAYkRjxZsBomwhy6Cc2Ia87hAnY/edit#slide=id.g13e97fbcd2c_0_76)

### Blog Post
[blog.aayushg.com/nullifier](https://blog.aayushg.com/nullifier)

This describes the construction as well as explains our choices for the various hash/hash-to-curve functions.

### ERC 7524
[Official ERC: erc.plume.run](https://erc.plume.run)

[Discussion](https://ethereum-magicians.org/t/erc-7524-plume-signature-in-wallets/15902/2)

[ERC 7524 Taho Wallet Integration](https://github.com/tahowallet/extension/pull/3638)

### Demo
https://nullifier.xyz

### Talk
https://www.youtube.com/watch?v=6ajBnMdJGoY

### Circom Proof Data

For the V1,
See [this PR](https://github.com/zk-nullifier-sig/zk-nullifier-sig/pull/7).   
6.5 million constraints. Mostly dominated by EC operations, but the hashes are very expensive too.  

sha256 ~1.5M.
`hash_to_curve` ~0.5M.
a/b^c ~1.5 each (this is the sub circuit for the first 2 verification equations).
the remaining 1.5M is probably dominated by calculating g^s and h^s.

For the V2,
the sha256 is 0 cost in the circuit, but is added to the verification cost. This takes in-circuit constraints down to 5M and adds the sha to the verification.

#### Hash to Curve Circom Code and Explainer
<https://github.com/geometryresearch/secp256k1_hash_to_curve/>
<https://geometry.dev/notebook/Hashing-to-the-secp256k1-Elliptic-Curve>

### Nullifier Calculation Spec
<https://hackmd.io/uZQbMHrVSbOHvoI_HrJJlw>

### Circom Verification Spec
<https://hackmd.io/VsojkopuSMuEA4vkYKSB8g?edit>

### V2 Spec and Discussion
[notion.so/mantanetwork/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff](https://www.notion.so/mantanetwork/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff?pvs=4)

This includes some discussion on justifications for the V2 signature calculation, as well as concrete ways to use PLUME proofs + Proof of ECDSA to do nullifiers and voting respectively.
