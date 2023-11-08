import crypto from "crypto";
import path from "path";

import { Point } from "@noble/secp256k1";
import { wasm as wasm_tester } from "circom_tester";
import { generate_inputs_from_array } from "secp256k1_hash_to_curve_circom/ts/generate_inputs";
import { bufToSha256PaddedBitArr } from "secp256k1_hash_to_curve_circom/ts/utils";
import { utils } from "ffjavascript";

import {
  c_v1,
  c_v2,
  rPoint,
  hashMPk,
  hashedToCurveR,
  nullifier,
  s_v1,
  s_v2,
  testMessage,
  testPublicKey,
  testSecretKey,
} from "../../../javascript/test/consts";
import {
  hexToBigInt,
  concatUint8Arrays,
} from "../../../javascript/src/utils/encoding";

import {
  circuitValueToScalar,
  pointToCircuitValue,
  scalarToCircuitValue,
} from "../utils";

jest.setTimeout(2_000_000);

describe("Nullifier Circuit", () => {
  const public_key_bytes = Array.from(testPublicKey);
  const message_bytes = Array.from(testMessage);

  const hashMPkPoint = new Point(
    hexToBigInt(hashMPk.x.toString()),
    hexToBigInt(hashMPk.y.toString()),
  );
  const hash_to_curve_inputs = utils.stringifyBigInts(
    generate_inputs_from_array(message_bytes.concat(public_key_bytes)),
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

  test("hash_to_curve outputs same value", async () => {
    const p = path.join(__dirname, "hash_to_curve_test.circom");
    const circuit = await wasm_tester(p, { json: true, sym: true });
    const w = await circuit.calculateWitness(
      {
        ...hash_to_curve_inputs,
      },
      true,
    );
    await circuit.checkConstraints(w);
    await circuit.assertOut(w, { out: pointToCircuitValue(hashMPkPoint) });
  });

  test("Correct sha256 value", async () => {
    const coordinates = [];
    sha_preimage_points.forEach((point) => {
      const cv = pointToCircuitValue(point);
      coordinates.push(cv[0]);
      coordinates.push(cv[1]);
    });

    const p = path.join(__dirname, "12_point_sha_256_test.circom");
    const circuit = await wasm_tester(p, { json: true, sym: true });

    const w = await circuit.calculateWitness(
      { coordinates, preimage_bit_length: v1_sha256_preimage_bit_length },
      true,
    );
    await circuit.checkConstraints(w);
    await circuit.assertOut(w, { out: v1_binary_c });
  });

  test("Correct compressed values are calculated", async () => {
    const p = path.join(__dirname, "compression_test.circom");
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

  test("Compressed points are permitted iff they are valid", async () => {
    const p = path.join(__dirname, "compression_verification_test.circom");
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

  test("V1 circuit works", async () => {
    const p = path.join(__dirname, "v1_test.circom");
    const circuit = await wasm_tester(p);

    const { msg: _, ...htci } = hash_to_curve_inputs;
    const w = await circuit.calculateWitness({
      // Main circuit inputs
      c: scalarToCircuitValue(hexToBigInt(c_v1)),
      s: scalarToCircuitValue(hexToBigInt(s_v1)),
      plume_message: message_bytes,
      pk: pointToCircuitValue(Point.fromPrivateKey(testSecretKey)),
      nullifier: pointToCircuitValue(nullifier),
      ...htci,
      sha256_preimage_bit_length: v1_sha256_preimage_bit_length,
    });
    await circuit.checkConstraints(w);
  });

  test("V2 circuit works", async () => {
    const p = path.join(__dirname, "v2_test.circom");
    const circuit = await wasm_tester(p);

    const { msg: _, ...htci } = hash_to_curve_inputs;

    const w = await circuit.calculateWitness({
      // Main circuit inputs
      c: scalarToCircuitValue(hexToBigInt(c_v2)),
      s: scalarToCircuitValue(hexToBigInt(s_v2)),
      plume_message: message_bytes,
      pk: pointToCircuitValue(Point.fromPrivateKey(testSecretKey)),
      nullifier: pointToCircuitValue(nullifier),
      ...htci,
    });
    await circuit.checkConstraints(w);
    /* assertOut builds a huge json string containing the whole witness and fails 
    with "Cannot create a string longer than 0x1fffffe8 characters" */
    /* Instead we just slice into the witness, and the outputs start at 1 
    (where 0 always equals 1 due to a property of the underlying proof system) */
    expect(w.slice(1, 5)).toEqual(pointToCircuitValue(rPoint)[0]);
    expect(w.slice(5, 9)).toEqual(pointToCircuitValue(rPoint)[1]);
    expect(w.slice(9, 13)).toEqual(pointToCircuitValue(hashedToCurveR)[0]);
    expect(w.slice(13, 17)).toEqual(pointToCircuitValue(hashedToCurveR)[1]);

    // In v2 we check the challenge point c outside the circuit
    /* Note, in a real application you would get the nullifier, 
    g^r, and h^r as public outputs/inputs of the proof */
    expect(
      crypto
        .createHash("sha256")
        .update(
          concatUint8Arrays([
            nullifier.toRawBytes(true),
            rPoint.toRawBytes(true),
            hashedToCurveR.toRawBytes(true),
          ]),
        )
        .digest("hex"),
    ).toEqual(c_v2);
  });

  // This tests that our circuit correctly computes g^s/(g^sk)^c = g^r, and that the first two equations are
  // implicitly verified correctly.
  test("a/b^c subcircuit", async () => {
    const p = path.join(__dirname, "a_div_b_pow_c_test.circom");
    const circuit = await wasm_tester(p);

    // Verify that gPowS/pkPowC = gPowR outside the circuit, as a sanity check
    const gPowS = Point.fromPrivateKey(s_v1);
    const pkPowC = Point.fromPrivateKey(testSecretKey).multiply(
      hexToBigInt(c_v1),
    );
    console.log(gPowS instanceof Point, pkPowC instanceof Point);
    expect(gPowS.add(pkPowC.negate()).equals(rPoint)).toBe(true);

    // Verify that circuit calculates g^s / pk^c = g^r
    const w = await circuit.calculateWitness({
      a: pointToCircuitValue(gPowS),
      b: pointToCircuitValue(Point.fromPrivateKey(testSecretKey)),
      c: scalarToCircuitValue(hexToBigInt(c_v1)),
    });
    await circuit.checkConstraints(w);
    await circuit.assertOut(w, { out: pointToCircuitValue(rPoint) });
  });

  test("bigint <-> register conversion", async () => {
    [
      132467823045762934876529873465987623452222345n,
      57574748379385798237094756982679876233455n,
      55757457845857572n,
      1n,
    ].forEach((value) => {
      expect(circuitValueToScalar(scalarToCircuitValue(value))).toBe(value);
    });
  });
});
