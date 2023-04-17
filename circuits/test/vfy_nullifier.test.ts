import { join } from 'path';
import { wasm as wasm_tester } from 'circom_tester'
import { describe, expect, test } from '@jest/globals';
import { hexToBigInt } from "../../javascript/src/utils/encoding";
import { c, gPowR, hashMPk, hashMPkPowR, nullifier, s, testMessage, testPublicKey, testPublicKeyPoint, testSecretKey } from "../../javascript/test/test_consts"
import { Point } from "../../javascript/node_modules/@noble/secp256k1";
import { generate_inputs_from_array } from "secp256k1_hash_to_curve_circom/ts/generate_inputs";
import { bufToSha256PaddedBitArr } from "secp256k1_hash_to_curve_circom/ts/utils";
import { utils } from "ffjavascript"
import { concatUint8Arrays } from '../../javascript/src/utils/encoding';
import { circuitValueToScalar, pointToCircuitValue, scalarToCircuitValue } from '../utils';

jest.setTimeout(2_000_000);

describe("Nullifier Circuit", () => {
  const public_key_bytes = Array.from(testPublicKey);
  const message_bytes = Array.from(testMessage);

  const hashMPkPoint = new Point(
    hexToBigInt(hashMPk.x.toString()),
    hexToBigInt(hashMPk.y.toString())
  )
  const hash_to_curve_inputs = utils.stringifyBigInts(generate_inputs_from_array(message_bytes.concat(public_key_bytes)));

  var points: Point[] = [
    Point.BASE,
    testPublicKeyPoint,
    hashMPkPoint,
    nullifier,
    gPowR,
    hashMPkPowR,
  ]

  test("hash_to_curve outputs same value", async () => {
    const p = join(__dirname, 'hash_to_curve_test.circom')
    const circuit = await wasm_tester(p, {"json":true, "sym": true})
    const w = await circuit.calculateWitness({
      ...hash_to_curve_inputs,
    }, true)
    await circuit.checkConstraints(w)
    await circuit.assertOut(w, {out: pointToCircuitValue(hashMPkPoint)});
  })

  test("Correct compressed values are calculated", async () => {
    const p = join(__dirname, 'compression_test.circom')
    const circuit = await wasm_tester(p, {"json":true, "sym": true})

    for (var i = 0; i < points.length; i++) {
      const w = await circuit.calculateWitness({uncompressed: pointToCircuitValue(points[i])}, true)
      await circuit.checkConstraints(w);
      await circuit.assertOut(w, {compressed: Array.from(points[i].toRawBytes(true))})
    }
  })

  test("Compressed points are permitted iff they are valid", async () => {
    const p = join(__dirname, 'compression_verification_test.circom')
    const circuit = await wasm_tester(p, {"json":true, "sym": true})

    for (var i = 0; i < points.length; i++) {
      for (var j = 0; j <= i; j++) {
        const inputs = {
          uncompressed: pointToCircuitValue(points[i]),
          compressed: Array.from(points[j].toRawBytes(true)),
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

  test("Circuit verifies valid nullifier", async () => {
    const p = join(__dirname, 'vfy_test.circom')
    const circuit = await wasm_tester(p)

    const {msg: _, ...htci} = hash_to_curve_inputs;

    const w = await circuit.calculateWitness({
      // Main circuit inputs
      c: scalarToCircuitValue(hexToBigInt(c)),
      s: scalarToCircuitValue(hexToBigInt(s)),
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
  })

  // This tests that our circuit correctly computes g^s/(g^sk)^c = g^r, and that the first two equations are
  // implicitly verified correctly.
  test("a/b^c subcircuit", async () => {
    const p = join(__dirname, 'a_div_b_pow_c_test.circom')
    const circuit = await wasm_tester(p)
    
    // Verify that gPowS/pkPowC = gPowR outside the circuit, as a sanity check
    const gPowS = Point.fromPrivateKey(s);
    const pkPowC = testPublicKeyPoint.multiply(hexToBigInt(c))
    expect(gPowS.add(pkPowC.negate()).equals(gPowR)).toBe(true);

    // Verify that circuit calculates g^s / pk^c = g^r
    const w = await circuit.calculateWitness({ 
      a: pointToCircuitValue(gPowS),
      b: pointToCircuitValue(testPublicKeyPoint),
      c: scalarToCircuitValue(hexToBigInt(c)),
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