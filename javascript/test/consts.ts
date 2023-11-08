import { getPublicKey, Point } from "@noble/secp256k1";
import {
  computeC_V1,
  computeC_V2,
  computeRPoint,
  computeHashToCurve,
  computeHashToCurveR,
  computeNullifer,
  computeS,
} from "../src/signals";
import { hexToUint8Array, messageToUint8Array } from "../src/utils/encoding";

export const testSecretKey = hexToUint8Array(
  "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464",
);

export const testPublicKeyPoint = Point.fromPrivateKey(testSecretKey);
export const testPublicKey = getPublicKey(testSecretKey, true);

export const testR = hexToUint8Array(
  "93b9323b629f251b8f3fc2dd11f4672c5544e8230d493eceea98a90bda789808",
);
export const testMessageString = "An example app message string";
export const testMessage = messageToUint8Array(testMessageString);
export const hashMPk = computeHashToCurve(
  testMessage,
  Buffer.from(testPublicKey),
);
export const nullifier = computeNullifer(hashMPk, testSecretKey);
export const hashedToCurveR = computeHashToCurveR(hashMPk, testR);
export const rPoint = computeRPoint(testR);
export const c_v1 = computeC_V1(
  testPublicKey,
  hashMPk,
  nullifier as unknown as Point,
  rPoint,
  hashedToCurveR,
);
export const s_v1 = computeS(testR, testSecretKey, c_v1);

export const c_v2 = computeC_V2(nullifier, rPoint, hashedToCurveR);
export const s_v2 = computeS(testR, testSecretKey, c_v2);
