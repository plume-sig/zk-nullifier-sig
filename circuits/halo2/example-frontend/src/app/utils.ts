export const fetchAndConvertToUint8Array = (url: string) => {
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

export const getKzgParams = async (k: number) => {
  if (k < 6 || k > 19) {
    throw new Error(`k=${k} is not supported`);
  }
  return await fetchAndConvertToUint8Array(
    `https://axiom-crypto.s3.amazonaws.com/challenge_0085/kzg_bn254_${k}.srs`,
  );
};
