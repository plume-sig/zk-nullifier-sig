# Plume Verification Frontend

Nextjs frontend example showcasing the use of [plume-wasm](https://www.npmjs.com/package/plume-wasm) to generate a proof on browser.

## Prerequisites

You need a custom build of [Taho wallet](https://taho.xyz) to generate the nullifier.

- Download this [zip](https://storage.googleapis.com/plume-keys/taho-plume.zip) and extract it.
- Follow [this](https://knowledge.workspace.google.com/kb/load-unpacked-extensions-000005962) guide to load the extension.
- Setup the wallet with a dummy account.

Once you have the wallet setup, you can follow the instructions below to test.

## Try it out

To test the browser proof generation, you can follow the instructions below.

```bash
git clone https://github.com/shreyas-londhe/zk-nullifier-sig.git -b feat/plume-halo2
cd zk-nullifier-sig/circuits/halo2/example-frontend
npm install
npm run dev
```

This will start the frontend at [http://localhost:3000](http://localhost:3000).

Note: The console will display the time taken to generate the proof.
