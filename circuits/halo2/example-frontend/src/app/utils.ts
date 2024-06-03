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

export const getMerkleData = (merkleTree: string[][], leafIndex: number) => {
  const proof = [];
  const proofHelper = [];
  let index = leafIndex;

  for (let level = 0; level < merkleTree.length - 1; level++) {
    const isRightNode = index % 2 === 1;
    const siblingIndex = isRightNode ? index - 1 : index + 1;

    if (siblingIndex < merkleTree[level].length) {
      proof.push(merkleTree[level][siblingIndex]);
      proofHelper.push(isRightNode ? "0x0" : "0x1");
    }

    index = Math.floor(index / 2);
  }

  const root = merkleTree[merkleTree.length - 1][0];

  return { proof, proofHelper, root };
};

export const fetchMerkleData = async (url: string, leafIndex: number) => {
  const response = await fetch(url);
  const data = await response.json();

  let {
    proof: merkleProof,
    proofHelper,
    root,
  } = getMerkleData(data, leafIndex);

  console.log("proof", merkleProof);
  console.log("proofHelper", proofHelper);
  console.log("root", root);

  return { merkleProof, proofHelper, root };
};
