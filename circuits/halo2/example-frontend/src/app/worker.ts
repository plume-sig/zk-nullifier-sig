import { fetchMerkleData, getKzgParams } from "./utils";
import init, {
  initThreadPool,
  initPanicHook,
  Halo2Wasm,
  Circuit,
} from "plume-wasm";

self.onmessage = async (e) => {
  const { action, data } = e.data;
  if (action === "runMain") {
    const { provingKey, verifyingKey, plume, option } = data;
    try {
      await init();
      console.log("Wasm initialized");

      initPanicHook();
      console.log("Panic hook initialized");

      await initThreadPool(navigator.hardwareConcurrency);
      console.log("Thread pool initialized");

      const halo2wasm = new Halo2Wasm();
      console.log("Halo2Wasm instance created");

      halo2wasm.config({
        k: 15,
        numAdvice: 69,
        numLookupAdvice: 8,
        numInstance: 1,
        numLookupBits: 14,
        numVirtualInstance: 1,
      });
      console.log("Halo2Wasm configured");

      const circuit = new Circuit(halo2wasm);
      console.log("circuit instance created");

      circuit.plumeVerify({
        nullifier: plume.nullifier,
        s: plume.s,
        c: plume.c,
        message: plume.message,
        publicKey: plume.publicKey,
      });
      console.log("PlumeVerify completed");

      if (option === "merkle") {
        const { merkleProof, proofHelper, root } = await fetchMerkleData(
          "https://storage.googleapis.com/plume-keys/merkle_tree_8.json",
          0,
        );

        circuit.merkleVerify({
          root,
          publicKey: plume.publicKey,
          proof: merkleProof,
          proofHelper,
        });
        console.log("MerkleVerify completed");
      }

      halo2wasm.useInstances();
      console.log("Using instances");

      let instanceValues = halo2wasm.getInstanceValues(0);
      console.log("Instance values:", instanceValues);

      let params = await getKzgParams(15);
      if (params instanceof Uint8Array) {
        halo2wasm.loadParams(params);
        console.log("KZG params loaded");
      } else {
        console.error("Invalid KZG params format");
      }

      halo2wasm.loadVk(verifyingKey);
      console.log("Verification key loaded");

      halo2wasm.loadPk(provingKey);
      console.log("Proving key loaded");

      const proofStart = performance.now();
      let proof = halo2wasm.prove();
      const proofEnd = performance.now();
      console.log(
        "Proof generated:",
        proof,
        "in",
        (proofEnd - proofStart) / 1000,
        "seconds",
      );

      const verifyStart = performance.now();
      halo2wasm.verify(proof);
      const verifyEnd = performance.now();
      console.log(
        "Proof verified in",
        (verifyEnd - verifyStart) / 1000,
        "seconds",
      );

      self.postMessage({
        status: "success",
        message: "Proof generated and verified successfully",
      });
    } catch (error) {
      console.error("Error running main function:", error);
      self.postMessage({
        status: "error",
        message: "Error running main function",
      });
    }
  }
};
