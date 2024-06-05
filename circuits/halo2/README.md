# halo2-plume

Plume signature verification circuits in halo2.

## Build

You can install and build our library with the following commands.

```bash
git clone https://github.com/shreyas-londhe/zk-nullifier-sig.git -b feat/plume-halo2
cd zk-nullifier-sig/circuits/halo2
cargo build
```

## Test

You can run the tests by executing `cargo test --release`.

## Usage

You can refer to the test at `src/lib.rs` for an example of how to use the Plume verification circuit in your halo2 circuit.

## WASM Prover in Browser

You can generate a proof on browser with our wasm prover. For more information, please see `wasm/README.md`.
