self.onmessage = async (e) => {
  if (e.data.action === "runMain") {
    try {
      const {
        default: init,
        initThreadPool,
        initPanicHook,
        Halo2Wasm,
        MyCircuit,
      } = await import("../../wasm/pkg/wasm");

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
        numAdvice: 412,
        numLookupAdvice: 11,
        numInstance: 1,
        numLookupBits: 14,
        numVirtualInstance: 1,
      });
      console.log("Halo2Wasm configured");

      let stats = halo2wasm.getCircuitStats();
      console.log("Circuit stats:", stats);

      const myCircuit = new MyCircuit(halo2wasm);
      console.log("MyCircuit instance created");

      myCircuit.run();
      console.log("MyCircuit run method called");

      halo2wasm.useInstances();
      console.log("Instances used");

      let instanceValues = halo2wasm.getInstanceValues(0);
      console.log("instanceValues:", instanceValues);

      let instances = halo2wasm.getInstances(0);
      console.log("instances:", instances);

      let params = await getKzgParams(15);
      console.log("KZG params:", params);

      if (params instanceof Uint8Array) {
        halo2wasm.loadParams(params);
        console.log("KZG params loaded");
      } else {
        console.error("Invalid KZG params format");
      }

      halo2wasm.mock();
      console.log("Mock called");

      const start = performance.now();
      halo2wasm.genVk();
      const end = performance.now();
      console.log("Verification key generated in", end - start, "milliseconds");

      const pkStart = performance.now();
      halo2wasm.genPk();
      const pkEnd = performance.now();
      console.log("Proving key generated in", pkEnd - pkStart, "milliseconds");

      const proofStart = performance.now();
      let proof = halo2wasm.prove();
      const proofEnd = performance.now();
      console.log(
        "Proof generated:",
        proof,
        "in",
        proofEnd - proofStart,
        "milliseconds",
      );

      const verifyStart = performance.now();
      halo2wasm.verify(proof);
      const verifyEnd = performance.now();
      console.log("Proof verified in", verifyEnd - verifyStart, "milliseconds");

      console.log("Main function completed successfully");
      self.postMessage({
        status: "success",
        message: "Main function executed successfully",
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

const fetchAndConvertToUint8Array = (url: string) => {
  return new Promise((resolve, reject) => {
    // Check if running in Node.js environment
    if (
      typeof process !== "undefined" &&
      process.versions &&
      process.versions.node
    ) {
      const https = require("https");
      https.get(url, (res: any) => {
        let chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          let binaryData = Buffer.concat(chunks);
          resolve(new Uint8Array(binaryData));
        });
        res.on("error", reject);
      });
    }
    // Check if running in browser or web worker environment
    else if (typeof window !== "undefined" || typeof self !== "undefined") {
      fetch(url)
        .then((response) => response.arrayBuffer())
        .then((buffer) => {
          resolve(new Uint8Array(buffer));
        })
        .catch(reject);
    } else {
      reject(new Error("Environment not supported"));
    }
  });
};

const getKzgParams = async (k: number) => {
  if (k < 6 || k > 19) {
    throw new Error(`k=${k} is not supported`);
  }
  return await fetchAndConvertToUint8Array(
    `https://axiom-crypto.s3.amazonaws.com/challenge_0085/kzg_bn254_${k}.srs`,
  );
};
