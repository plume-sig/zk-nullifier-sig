import hashToCurve from "./utils/hashToCurve";
import secp256k1 from "secp256k1";

export function computeH(publicKey, message) {
  // TODO
}

export function computeC(g, pk, h, nul, g_r, z) {
  // TODO
}

const testSecretKey =
  "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464";

const testPublicKey = secp256k1.publicKeyCreate(testSecretKey);
console.log({ testPublicKey });

const testR =
  "93b9323b629f251b8f3fc2dd11f4672c5544e8230d493eceea98a90bda789808";

const testM = "An example app message string";

const testBytesToHash = [
  65, 110, 32, 101, 120, 97, 109, 112, 108, 101, 32, 97, 112, 112, 32, 109, 101,
  115, 115, 97, 103, 101, 32, 115, 116, 114, 105, 110, 103, 3, 12, 236, 2, 142,
  224, 141, 9, 224, 38, 114, 166, 131, 16, 129, 67, 84, 249, 234, 191, 255, 13,
  230, 218, 204, 28, 211, 167, 116, 73, 96, 118, 174,
];

const h = hashToCurve(testBytesToHash);
console.log("h.x:", h.x.toString());
console.log("h.y:", h.y.toString());

// Expected
// h.x: bcac2d0e12679f23c218889395abcdc01f2affbc49c54d1136a2190db0800b65
// h.y: 3bcfb339c974c0e757d348081f90a123b0a91a53e32b3752145d87f0cd70966e
