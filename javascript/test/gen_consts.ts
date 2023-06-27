// Run with: npx ts-node gen_consts.ts > test_consts.json

import { getPublicKey, Point } from "@noble/secp256k1";
import {
  computeC_V1,
  computeC_V2,
  computeGPowR,
  computeHashMPk,
  computeHashMPkPowR,
  computeNullifer,
  computeS,
} from "../src/signals";
import { hexToUint8Array, messageToUint8Array } from "../src/utils/encoding";

const testSecretKey = hexToUint8Array(
  "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"
);

const testPublicKeyPoint = Point.fromPrivateKey(testSecretKey);
const testPublicKey = getPublicKey(testSecretKey, true);

const testR = hexToUint8Array(
  "93b9323b629f251b8f3fc2dd11f4672c5544e8230d493eceea98a90bda789808"
);
const testMessageString = "An example app message string";
const testMessage = messageToUint8Array(testMessageString);
let hashMPk = computeHashMPk(testMessage, Buffer.from(testPublicKey));
const hashMPkPoint = new Point(BigInt("0x" + hashMPk.x.toString()), BigInt("0x" + hashMPk.y.toString()));
const nullifier = computeNullifer(hashMPk, testSecretKey);
const hashMPkPowR = computeHashMPkPowR(hashMPk, testR);
const gPowR = computeGPowR(testR);
const c_v1 = computeC_V1(
  testPublicKey,
  hashMPk,
  nullifier as unknown as Point,
  gPowR,
  hashMPkPowR
);
const s_v1 = computeS(testR, testSecretKey, c_v1);

const c_v2 = computeC_V2(nullifier, gPowR, hashMPkPowR);
const s_v2 = computeS(testR, testSecretKey, c_v2);

(BigInt.prototype as any).toJSON = function () {
    return this.toString();
};
export const consts = {
    testSecretKey: testSecretKey,
    testPublicKeyPoint: testPublicKeyPoint,
    testPublicKey: testPublicKey,
    testR: testR,
    testMessageString: testMessageString,
    testMessage: testMessage,
    hashMPk: hashMPkPoint,
    nullifier: nullifier,
    hashMPkPowR: hashMPkPowR,
    gPowR: gPowR,
    c_v1: c_v1,
    s_v1: s_v1,
    c_v2: c_v2,
    s_v2: s_v2
};

console.log(JSON.stringify(consts, undefined, 2));