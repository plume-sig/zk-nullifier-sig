import { CURVE, getPublicKey, Point } from "@noble/secp256k1";
import {
  concatUint8Arrays,
  hexToBigInt,
  hexToUint8Array,
  messageToUint8Array,
  uint8ArrayToBigInt,
} from "./utils/encoding";
import hashToCurve from "./utils/hashToCurve";
import { sha512 } from "js-sha512";

export function computeHashMPk(message: Uint8Array, publicKey: Uint8Array) {
  // Concatenate message and publicKey
  const preimage = new Uint8Array(message.length + publicKey.length);
  preimage.set(message);
  preimage.set(publicKey, message.length);
  return hashToCurve(Array.from(preimage));
}

export function multiplyPoint(h, secretKey: Uint8Array) {
  const hashPoint = new Point(
    BigInt("0x" + h.x.toString()),
    BigInt("0x" + h.y.toString())
  );
  return hashPoint.multiply(
    BigInt("0x" + Buffer.from(secretKey).toString("hex"))
  );
}

export function computeC(
  publicKeyBytes: Uint8Array,
  hashMPk,
  nullifier: Point,
  gPowR: Point,
  hashMPkPowR: Point
) {
  const gBytes = Point.BASE.toRawBytes(true);
  const hashMPkBytes = new Point(
    BigInt("0x" + hashMPk.x.toString()),
    BigInt("0x" + hashMPk.y.toString())
  ).toRawBytes(true);
  const nullifierBytes = nullifier.toRawBytes(true);
  const gPowRBytes = gPowR.toRawBytes(true);
  const hashMPkPowRBytes = hashMPkPowR.toRawBytes(true);
  const preimage = concatUint8Arrays([
    gBytes,
    publicKeyBytes,
    hashMPkBytes,
    nullifierBytes,
    gPowRBytes,
    hashMPkPowRBytes,
  ]);
  return sha512(preimage).slice(0, 64);
}

const testSecretKey = hexToUint8Array(
  "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"
);

const testPublicKey = getPublicKey(testSecretKey, true);

const testR = hexToUint8Array(
  "93b9323b629f251b8f3fc2dd11f4672c5544e8230d493eceea98a90bda789808"
);

const testMessage = messageToUint8Array("An example app message string");

const hashMPk = computeHashMPk(testMessage, Buffer.from(testPublicKey));
console.log(`h.x: ${hashMPk.x.toString()}`);
console.log(`h.y: ${hashMPk.y.toString()}`);
const nullifier = multiplyPoint(hashMPk, Buffer.from(testSecretKey));
console.log(`nullifier.x: ${nullifier.x.toString(16)}`);
console.log(`nullifier.y: ${nullifier.y.toString(16)}`);
const hashMPkPowR = multiplyPoint(hashMPk, Buffer.from(testR));
console.log(`hashMPkPowR.x: ${hashMPkPowR.x.toString(16)}`);
console.log(`hashMPkPowR.y: ${hashMPkPowR.y.toString(16)}`);
const testGPowR = Point.fromPrivateKey(testR);
console.log(`gPowR.x: ${testGPowR.x.toString(16)}`);
console.log(`gPowR.y: ${testGPowR.y.toString(16)}`);
const c = computeC(testPublicKey, hashMPk, nullifier, testGPowR, hashMPkPowR);
console.log(`c: ${c}`);
const skC = (uint8ArrayToBigInt(testSecretKey) * hexToBigInt(c)) % CURVE.P;
console.log(`sk_c: ${skC.toString(16)}`); // rust is cfc9fec33fd8c45f44c7f04f8bd06df4aab949474dd8655346440f52452d672b
const s = ((skC + uint8ArrayToBigInt(testR)) % CURVE.P).toString(16);
console.log(`s: ${s}`); // rust is 638330fea277e97ad407b32c9dc4d522454f5483abd903e6710a59d14f6fbdf2

/**
 * Expected console output
 *
 * h.x: bcac2d0e12679f23c218889395abcdc01f2affbc49c54d1136a2190db0800b65
 * h.y: 3bcfb339c974c0e757d348081f90a123b0a91a53e32b3752145d87f0cd70966e
 * nullifier.x: "57bc3ed28172ef8adde4b9e0c2cce745fcc5a66473a45c1e626f1d0c67e55830"
 * nullifier.y: "6a2f41488d58f33ae46edd2188e111609f9f3ae67ea38fa891d6087fe59ecb73"
 * hashMPkPowR.x: 6d017c6f63c59fa7a5b1e9a654e27d2869579f4d152131db270558fccd27b97c
 * hashMPkPowR.y: 586c43fb5c99818c564a8f80a88a65f83e3f44d3c6caf5a1a4e290b777ac56ed
 * gPowR.x: 9d8ca4350e7e2ad27abc6d2a281365818076662962a28429590e2dc736fe9804
 * gPowR.y: ff08c30b8afd4e854623c835d9c3aac6bcebe45112472d9b9054816a7670c5a1
 * c: 7da1ad3f63c6180beefd0d6a8e3c87620b54f1b1d2c8287d104da9e53b6b5524
 * sk_c: b61c26065618db1f927ed3e53ba9013aa93dcbe6e0880e0db0142f7f3cfb853f
 * s: 49d55841b8b8003b21be96c24d9d6866fe82b409edd14cdc9aacd88c17742118
 */
