import { Point } from "@noble/secp256k1";
import { concatUint8Arrays, hexToBigInt } from "./utils/encoding";
import hashToCurve from "./utils/hashToCurve";
import { HashedPoint, multiplyPoint } from "./utils/curve";
import { createHash } from "node:crypto";

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

export function computeC(
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
  return createHash("sha256")
    .update(preimage)
    .digest('hex')
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
