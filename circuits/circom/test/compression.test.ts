import path from "path";

import { Point } from "@noble/secp256k1";
import { wasm as wasm_tester } from "circom_tester";

import {
  rPoint,
  hashMPk,
  hashedToCurveR,
  nullifier,
  testSecretKey,
} from "../../../javascript/test/consts";
import { hexToBigInt } from "../../../javascript/src/utils/encoding";

import { pointToCircuitValue } from "../utils";

jest.setTimeout(20_000);

describe("Compression Circuit", () => {
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

  test("Correct compressed values are calculated", async () => {
    const p = path.join(__dirname, "./circuits/compression_test.circom");
    const circuit = await wasm_tester(p, { json: true, sym: true });

    for (let i = 0; i < sha_preimage_points.length; i++) {
      const w = await circuit.calculateWitness(
        { uncompressed: pointToCircuitValue(sha_preimage_points[i]) },
        true,
      );

      await circuit.checkConstraints(w);
      await circuit.assertOut(w, {
        compressed: Array.from(sha_preimage_points[i].toRawBytes(true)),
      });
    }
  });

  test("Compressed points are permitted if they are valid", async () => {
    const p = path.join(
      __dirname,
      "./circuits/compression_verification_test.circom",
    );
    const circuit = await wasm_tester(p, { json: true, sym: true });

    for (let i = 0; i < sha_preimage_points.length; i++) {
      for (let j = 0; j <= i; j++) {
        const inputs = {
          uncompressed: pointToCircuitValue(sha_preimage_points[i]),
          compressed: Array.from(sha_preimage_points[j].toRawBytes(true)),
        };

        if (i === j) {
          const w = await circuit.calculateWitness(inputs, true);
          await circuit.checkConstraints(w);
        } else {
          await expect(circuit.calculateWitness(inputs)).rejects.toThrow(
            "Assert Failed",
          );
        }
      }
    }
  });
});
