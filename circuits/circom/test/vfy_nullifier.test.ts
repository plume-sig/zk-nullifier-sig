import { join } from 'path';
import { wasm as wasm_tester } from 'circom_tester'
import { describe, expect, test } from '@jest/globals';
import { hexToBigInt } from "../../javascript/src/utils/encoding";
import { c_v1, c_v2, gPowR, hashMPk, hashMPkPowR, nullifier, s_v1, s_v2, testMessage, testPublicKey, testPublicKeyPoint, testR, testSecretKey } from "../../javascript/test/test_consts"
import { Point } from "../../javascript/node_modules/@noble/secp256k1";
import { generate_inputs_from_array } from "secp256k1_hash_to_curve_circom/ts/generate_inputs";
import { bufToSha256PaddedBitArr } from "secp256k1_hash_to_curve_circom/ts/utils";
import { utils } from "ffjavascript"
import { concatUint8Arrays } from '../../javascript/src/utils/encoding';
import { circuitValueToScalar, pointToCircuitValue, scalarToCircuitValue } from '../utils';
import { createHash } from "node:crypto";
import { computeS } from "../../javascript/src/signals";

jest.setTimeout(2_000_000);

describe("Nullifier Circuit", () => {
  const public_key_bytes = Array.from(testPublicKey);
  const message_bytes = Array.from(testMessage);

  const hashMPkPoint = new Point(
    hexToBigInt(hashMPk.x.toString()),
    hexToBigInt(hashMPk.y.toString())
  )
  const hash_to_curve_inputs = utils.stringifyBigInts(generate_inputs_from_array(message_bytes.concat(public_key_bytes)));

  var sha_preimage_points: Point[] = [
    Point.BASE,
    testPublicKeyPoint,
    hashMPkPoint,
    nullifier,
    gPowR,
    hashMPkPowR,
  ]

  const v1_sha256_preimage_bits = bufToSha256PaddedBitArr(Buffer.from(
    concatUint8Arrays(sha_preimage_points.map((point) => point.toRawBytes(true)))
  ));
  const v1_sha256_preimage_bit_length = parseInt(v1_sha256_preimage_bits.slice(-64), 2)

  const v1_binary_c = BigInt("0x" + c_v1).toString(2).split('').map(Number);

  test("hash_to_curve outputs same value", async () => {
    const p = join(__dirname, 'hash_to_curve_test.circom')
    const circuit = await wasm_tester(p, {"json":true, "sym": true})
    const w = await circuit.calculateWitness({
      ...hash_to_curve_inputs,
    }, true)
    await circuit.checkConstraints(w)
    await circuit.assertOut(w, {out: pointToCircuitValue(hashMPkPoint)});
  })

  test("Correct sha256 value", async () => {
    var coordinates = [];
    sha_preimage_points.forEach((point) => {
      const cv = pointToCircuitValue(point);
      coordinates.push(cv[0]);
      coordinates.push(cv[1]);
    })

    const p = join(__dirname, '12_point_sha_256_test.circom')
    const circuit = await wasm_tester(p, {"json":true, "sym": true})

    const w = await circuit.calculateWitness({coordinates, preimage_bit_length: v1_sha256_preimage_bit_length}, true)
    await circuit.checkConstraints(w);
    await circuit.assertOut(w, {out: v1_binary_c})
  })

  test("Correct compressed values are calculated", async () => {
    const p = join(__dirname, 'compression_test.circom')
    const circuit = await wasm_tester(p, {"json":true, "sym": true})

    for (var i = 0; i < sha_preimage_points.length; i++) {
      const w = await circuit.calculateWitness({uncompressed: pointToCircuitValue(sha_preimage_points[i])}, true)
      await circuit.checkConstraints(w);
      await circuit.assertOut(w, {compressed: Array.from(sha_preimage_points[i].toRawBytes(true))})
    }
  })

  test("Compressed points are permitted iff they are valid", async () => {
    const p = join(__dirname, 'compression_verification_test.circom')
    const circuit = await wasm_tester(p, {"json":true, "sym": true})

    for (var i = 0; i < sha_preimage_points.length; i++) {
      for (var j = 0; j <= i; j++) {
        const inputs = {
          uncompressed: pointToCircuitValue(sha_preimage_points[i]),
          compressed: Array.from(sha_preimage_points[j].toRawBytes(true)),
        }

        if (i === j) {
          const w = await circuit.calculateWitness(inputs, true)
          await circuit.checkConstraints(w);
        } else {
          await expect(async () => { await circuit.calculateWitness(inputs) }).rejects.toThrow('Assert Failed')
        }
      }
    }
  })

  test("V1 circuit works", async () => {
    const p = join(__dirname, 'v1_test.circom')
    const circuit = await wasm_tester(p)

    const {msg: _, ...htci} = hash_to_curve_inputs;
    const w = await circuit.calculateWitness({
      // Main circuit inputs
      c: scalarToCircuitValue(hexToBigInt(c_v1)),
      s: scalarToCircuitValue(hexToBigInt(s_v1)),
      msg: message_bytes,
      public_key: pointToCircuitValue(testPublicKeyPoint),
      nullifier: pointToCircuitValue(nullifier),
      ...htci,
      sha256_preimage_bit_length: v1_sha256_preimage_bit_length,
      
    })
    await circuit.checkConstraints(w)
  })

  test("V2 circuit works", async () => {
    const p = join(__dirname, 'v2_test.circom')
    const circuit = await wasm_tester(p)

    const {msg: _, ...htci} = hash_to_curve_inputs;

    const w = await circuit.calculateWitness({
      // Main circuit inputs
      c: scalarToCircuitValue(hexToBigInt(c_v2)),
      s: scalarToCircuitValue(hexToBigInt(s_v2)),
      msg: message_bytes,
      public_key: pointToCircuitValue(testPublicKeyPoint),
      nullifier: pointToCircuitValue(nullifier),
      ...htci,
    })
    await circuit.checkConstraints(w)
    // assertOut builds a huge json string containing the whole witness and fails with "Cannot create a string longer than 0x1fffffe8 characters"
    // Instead we just slice into the witness, and the outputs start at 1 (where 0 always equals 1 due to a property of the underlying proof system)
    expect(w.slice(1, 5)).toEqual(pointToCircuitValue(gPowR)[0])
    expect(w.slice(5, 9)).toEqual(pointToCircuitValue(gPowR)[1])
    expect(w.slice(9, 13)).toEqual(pointToCircuitValue(hashMPkPowR)[0])
    expect(w.slice(13, 17)).toEqual(pointToCircuitValue(hashMPkPowR)[1])

    // In v2 we check the challenge point c outside the circuit
    // Note, in a real application you would get the nullifier, g^r, and h^r as public outputs/inputs of the proof
    expect(createHash("sha256")
    .update(concatUint8Arrays([nullifier.toRawBytes(true), gPowR.toRawBytes(true), hashMPkPowR.toRawBytes(true)]))
    .digest('hex')).toEqual(c_v2)
  })

  // This tests that our circuit correctly computes g^s/(g^sk)^c = g^r, and that the first two equations are
  // implicitly verified correctly.
  test("a/b^c subcircuit", async () => {
    const p = join(__dirname, 'a_div_b_pow_c_test.circom')
    const circuit = await wasm_tester(p)
    
    // Verify that gPowS/pkPowC = gPowR outside the circuit, as a sanity check
    const gPowS = Point.fromPrivateKey(s_v1);
    const pkPowC = testPublicKeyPoint.multiply(hexToBigInt(c_v1))
    expect(gPowS.add(pkPowC.negate()).equals(gPowR)).toBe(true);

    // Verify that circuit calculates g^s / pk^c = g^r
    const w = await circuit.calculateWitness({ 
      a: pointToCircuitValue(gPowS),
      b: pointToCircuitValue(testPublicKeyPoint),
      c: scalarToCircuitValue(hexToBigInt(c_v1)),
    })
    await circuit.checkConstraints(w)
    await circuit.assertOut(w, {out: pointToCircuitValue(gPowR)});
  });

  test("bigint <-> register conversion", async () => {
    [
      132467823045762934876529873465987623452222345n,
      57574748379385798237094756982679876233455n,
      55757457845857572n,
      1n,
    ].forEach((value) => {
      expect(circuitValueToScalar(scalarToCircuitValue(value))).toBe(value);
    })

  })
})
