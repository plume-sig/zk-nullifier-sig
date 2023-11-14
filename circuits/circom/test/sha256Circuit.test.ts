import crypto from "crypto";
import path from "path";

import { Point } from "@noble/secp256k1";
import { wasm as wasm_tester } from "circom_tester";
import { bufToSha256PaddedBitArr } from "secp256k1_hash_to_curve_circom/ts/utils";

import {
  c_v1,
  rPoint,
  hashMPk,
  hashedToCurveR,
  nullifier,
  testSecretKey,
} from "../../../javascript/test/consts";
import {
  hexToBigInt,
  concatUint8Arrays,
} from "../../../javascript/src/utils/encoding";

import { pointToCircuitValue } from "../utils";

jest.setTimeout(2_000_000);

describe("SHA256 Circuit", () => {
  const hashMPkPoint = new Point(
    hexToBigInt(hashMPk.x.toString()),
    hexToBigInt(hashMPk.y.toString()),
  );

  const sha_preimage_points: Point[] = [
    Point.BASE,
    Point.fromPrivateKey(testSecretKey),
    hashMPkPoint,
    nullifier,
    rPoint,
    hashedToCurveR,
  ];

  const v1_sha256_preimage_bits = bufToSha256PaddedBitArr(
    Buffer.from(
      concatUint8Arrays(
        sha_preimage_points.map((point) => point.toRawBytes(true)),
      ),
    ),
  );
  const v1_sha256_preimage_bit_length = parseInt(
    v1_sha256_preimage_bits.slice(-64),
    2,
  );

  const v1_binary_c = BigInt("0x" + c_v1)
    .toString(2)
    .split("")
    .map(Number);

  test("Correct sha256 value", async () => {
    const coordinates = [];
    sha_preimage_points.forEach((point) => {
      const cv = pointToCircuitValue(point);
      coordinates.push(cv[0]);
      coordinates.push(cv[1]);
    });

    const p = path.join(__dirname, "./circuits/12_point_sha_256_test.circom");
    const circuit = await wasm_tester(p, { json: true, sym: true });

    const w = await circuit.calculateWitness(
      { coordinates, preimage_bit_length: v1_sha256_preimage_bit_length },
      true,
    );
    await circuit.checkConstraints(w);
    await circuit.assertOut(w, { out: v1_binary_c });
  });
});
