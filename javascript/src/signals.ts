import { CURVE, getPublicKey, Point, utils } from "@noble/secp256k1";
import {
  concatUint8Arrays,
  hexToBigInt,
  hexToUint8Array,
  messageToUint8Array,
  uint8ArrayToBigInt,
} from "./utils/encoding";
import hashToCurve from "./utils/hashToCurve";
import { HashedPoint, multiplyPoint } from "./utils/curve";
const { sha256 } =require('js-sha256');

// PLUME version
export enum PlumeVersion {
  V1 = 1,
  V2,
}

export function computeHashMPk(
  message: Uint8Array,
  publicKey: Uint8Array
): HashedPoint {
  // Concatenate message and publicKey
  const preimage = new Uint8Array(message.length + publicKey.length);
  preimage.set(message);
  preimage.set(publicKey, message.length);
  return hashToCurve(Array.from(preimage));
}

export function computeC_V2(
  nullifier: Point,
  gPowR: Point,
  hashMPkPowR: Point
) {
  const nullifierBytes = nullifier.toRawBytes(true);
  const gPowRBytes = gPowR.toRawBytes(true);
  const hashMPkPowRBytes = hashMPkPowR.toRawBytes(true);
  const preimage = concatUint8Arrays([
    nullifierBytes,
    gPowRBytes,
    hashMPkPowRBytes,
  ]);
  return sha256.create().update(preimage).hex();
}

export function computeC_V1(
  publicKeyBytes: Uint8Array,
  hashMPk: HashedPoint,
  nullifier: Point,
  gPowR: Point,
  hashMPkPowR: Point
) {
  const gBytes = Point.BASE.toRawBytes(true);
  const hashMPkBytes = new Point(
    hexToBigInt(hashMPk.x.toString()),
    hexToBigInt(hashMPk.y.toString())
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
  return sha256.create().update(preimage).hex();
}

export function computeNullifer(hashMPk: HashedPoint, secretKey: Uint8Array) {
  return multiplyPoint(hashMPk, secretKey);
}

export function computeGPowR(r: Uint8Array) {
  return Point.fromPrivateKey(r);
}

export function computeHashMPkPowR(hashMPk: HashedPoint, r: Uint8Array) {
  return multiplyPoint(hashMPk, r);
}

export function computeS(r: Uint8Array, secretKey: Uint8Array, c: string) {
  const skC = (uint8ArrayToBigInt(secretKey) * hexToBigInt(c)) % CURVE.n;
  return ((skC + uint8ArrayToBigInt(r)) % CURVE.n).toString(16);
}

/**
 * Computes and returns the Plume and other signals for the prover.
 * @param {string | Uint8Array} message - Message to sign, in either string or UTF-8 array format.
 * @param {string | Uint8Array} secretKey - ECDSA secret key to sign with.
 * @param {string| Uint8Array} r - Optional seed for randomness.
 * @returns Object containing Plume and other signals - public key, s, c, gPowR, and hashMPKPowR.
 */
export function computeAllInputs(
  message: string | Uint8Array,
  secretKey: string | Uint8Array,
  r?: string | Uint8Array,
  version: PlumeVersion = PlumeVersion.V1
) {
  const secretKeyBytes =
    typeof secretKey === "string" ? hexToUint8Array(secretKey) : secretKey;
  const messageBytes =
    typeof message === "string" ? messageToUint8Array(message) : message;
  const publicKeyBytes = getPublicKey(secretKeyBytes, true);
  let rBytes;
  if (r) {
    rBytes = typeof r === "string" ? hexToUint8Array(r) : r;
  } else {
    rBytes = utils.randomPrivateKey();
  }
  const hashMPK = computeHashMPk(messageBytes, publicKeyBytes);
  const nullifier = computeNullifer(hashMPK, secretKeyBytes);
  const hashMPKPowR = computeHashMPkPowR(hashMPK, rBytes);
  const gPowR = computeGPowR(rBytes);
  const c =
    version == PlumeVersion.V1
      ? computeC_V1(publicKeyBytes, hashMPK, nullifier, gPowR, hashMPKPowR)
      : computeC_V2(nullifier, gPowR, hashMPKPowR);
  const s = computeS(rBytes, secretKeyBytes, c);
  return {
    plume: nullifier,
    s,
    publicKey: publicKeyBytes,
    c,
    gPowR,
    hashMPKPowR,
  };
}
