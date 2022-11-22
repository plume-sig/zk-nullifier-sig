import {
  privateKeyTweakMul as multiplyOnCurve,
  publicKeyCreate,
} from "secp256k1";
import { hexToUint8Array, messageToUint8Array } from "./utils/encoding";
import hashToCurve from "./utils/hashToCurve";

export function computeHashMPk(message: Uint8Array, publicKey: Uint8Array) {
  // Concatenate message and publicKey
  const input = new Uint8Array(message.length + publicKey.length);
  input.set(message);
  input.set(publicKey, message.length);
  return hashToCurve(Array.from(input));
}

export function computeNullifier(h, secretKey) {
  // return multiplyOnCurve(h, secretKey);
}

export function computeC(g, pk, h, nul, g_r, z) {
  // TODO
}

const testSecretKey = hexToUint8Array(
  "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"
);

const testPublicKey = publicKeyCreate(testSecretKey);

const testR = hexToUint8Array(
  "93b9323b629f251b8f3fc2dd11f4672c5544e8230d493eceea98a90bda789808"
);

const testMessage = messageToUint8Array("An example app message string");

const hashMPk = computeHashMPk(testMessage, Buffer.from(testPublicKey));
console.log(`h.x: ${hashMPk.x.toString()}`);
console.log(`h.y: ${hashMPk.y.toString()}`);

// Expected
// h.x: bcac2d0e12679f23c218889395abcdc01f2affbc49c54d1136a2190db0800b65
// h.y: 3bcfb339c974c0e757d348081f90a123b0a91a53e32b3752145d87f0cd70966e
