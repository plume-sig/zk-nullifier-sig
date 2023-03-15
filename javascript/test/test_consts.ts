import { CURVE, getPublicKey, Point } from "@noble/secp256k1";
import {
  computeC,
  computeGPowR,
  computeHashMPk,
  computeHashMPkPowR,
  computeNullifer,
  computeS,
} from "../src";
import {
  hexToUint8Array,
  messageToUint8Array,
} from "../src/utils/encoding";

export const testSecretKey = hexToUint8Array(
    "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"
);

export const testPublicKeyPoint = Point.fromPrivateKey(testSecretKey);
export const testPublicKey = getPublicKey(testSecretKey, true);

export const testR = hexToUint8Array(
  "93b9323b629f251b8f3fc2dd11f4672c5544e8230d493eceea98a90bda789808"
);
export const testMessageString = "An example app message string";
export const testMessage = messageToUint8Array(testMessageString);
export const hashMPk = computeHashMPk(testMessage, Buffer.from(testPublicKey));
export const nullifier = computeNullifer(hashMPk, testSecretKey);
export const hashMPkPowR = computeHashMPkPowR(hashMPk, testR);
export const gPowR = computeGPowR(testR);
export const c = computeC(
  testPublicKey,
  hashMPk,
  nullifier as unknown as Point,
  gPowR,
  hashMPkPowR
);
export const s = computeS(testR, testSecretKey, c);
