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
import { sha256 } from "js-sha256";

// PLUME version
export enum PlumeVersion {
  V1 = 1,
  V2 = 2,
}

export function computeHashToCurve(
  message: Uint8Array,
  pk: Uint8Array,
): HashedPoint {
  // Concatenate message and publicKey
  const preimage = new Uint8Array(message.length + pk.length);
  preimage.set(message);
  preimage.set(pk, message.length);
  return hashToCurve(Array.from(preimage));
}

export function computeC_V2(
  nullifier: Point,
  rPoint: Point,
  hashedToCurveR: Point,
) {
  const nullifierBytes = nullifier.toRawBytes(true);
  const preimage = concatUint8Arrays([
    nullifierBytes,
    rPoint.toRawBytes(true),
    hashedToCurveR.toRawBytes(true),
  ]);
  return sha256.create().update(preimage).hex();
}

export function computeC_V1(
  pkBytes: Uint8Array,
  hashedToCurve: HashedPoint,
  nullifier: Point,
  rPoint: Point,
  hashedToCurveR: Point,
) {
  const nullifierBytes = nullifier.toRawBytes(true);
  const preimage = concatUint8Arrays([
    Point.BASE.toRawBytes(true),
    pkBytes,
    new Point(
      hexToBigInt(hashedToCurve.x.toString()),
      hexToBigInt(hashedToCurve.y.toString()),
    ).toRawBytes(true),
    nullifierBytes,
    rPoint.toRawBytes(true),
    hashedToCurveR.toRawBytes(true),
  ]);
  return sha256.create().update(preimage).hex();
}

export function computeNullifer(hashedToCurve: HashedPoint, sk: Uint8Array) {
  return multiplyPoint(hashedToCurve, sk);
}

export function computeRPoint(rScalar: Uint8Array) {
  return Point.fromPrivateKey(rScalar);
}

export function computeHashToCurveR(
  hashedToCurve: HashedPoint,
  rScalar: Uint8Array,
) {
  return multiplyPoint(hashedToCurve, rScalar);
}

export function computeS(rScalar: Uint8Array, sk: Uint8Array, c: string) {
  return (
    (((uint8ArrayToBigInt(sk) * hexToBigInt(c)) % CURVE.n) +
      uint8ArrayToBigInt(rScalar)) %
    CURVE.n
  ).toString(16);
}

/**
 * Computes and returns the Plume and other signals for the prover.
 * @param {string | Uint8Array} message - Message to sign, in either string or UTF-8 array format.
 * @param {string | Uint8Array} sk - ECDSA secret key to sign with.
 * @param {string| Uint8Array} rScalar - Optional seed for randomness.
 * @returns Object containing Plume and other signals - public key, s, c, gPowR, and hashMPKPowR.
 */
export function computeAllInputs(
  message: string | Uint8Array,
  sk: string | Uint8Array,
  rScalar?: string | Uint8Array,
  version: PlumeVersion = PlumeVersion.V2,
) {
  const skBytes = typeof sk === "string" ? hexToUint8Array(sk) : sk;
  const messageBytes =
    typeof message === "string" ? messageToUint8Array(message) : message;
  const pkBytes = getPublicKey(skBytes, true);

  let rScalarBytes: Uint8Array;
  if (rScalar) {
    rScalarBytes =
      typeof rScalar === "string" ? hexToUint8Array(rScalar) : rScalar;
  } else {
    rScalarBytes = utils.randomPrivateKey();
  }

  const hashedToCurve = computeHashToCurve(messageBytes, pkBytes);
  const nullifier = computeNullifer(hashedToCurve, skBytes);
  const hashedToCurveR = computeHashToCurveR(hashedToCurve, rScalarBytes);
  const rPoint = computeRPoint(rScalarBytes);
  const c =
    version == PlumeVersion.V1
      ? computeC_V1(pkBytes, hashedToCurve, nullifier, rPoint, hashedToCurveR)
      : computeC_V2(nullifier, rPoint, hashedToCurveR);
  const s = computeS(rScalarBytes, skBytes, c);

  return {
    plume: nullifier,
    s,
    pk: pkBytes,
    c,
    rPoint,
    hashedToCurveR,
  };
}
