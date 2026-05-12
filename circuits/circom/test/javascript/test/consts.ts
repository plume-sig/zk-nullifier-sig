import { getPublicKey, Point } from "@noble/secp256k1";
import sharedVectors from "../../../../../test-vectors/plume-signatures.json";
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

export const testVector = sharedVectors.vectors[0];

export const testSecretKey = hexToUint8Array(testVector.secret_key);

export const testPublicKeyPoint = Point.fromPrivateKey(testSecretKey);
export const testPublicKey = getPublicKey(testSecretKey, true);

export const testR = hexToUint8Array(testVector.nonce);
export const testMessageString = testVector.message;
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
