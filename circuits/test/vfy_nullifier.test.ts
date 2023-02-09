import { join } from 'path';
import { wasm as wasm_tester } from 'circom_tester'
import { describe, expect, test } from '@jest/globals';
import * as enclave from "../../javascript/src/index";
import { testSecretKey, testPublicKey, testR, testMessage, testMessageString } from "../../javascript/test/signals.test";
import { uint8ArrayToBigInt, hexToBigInt, hexToUint8Array, messageToUint8Array } from "../../javascript/src/utils/encoding";
import { CURVE, Point } from "@noble/secp256k1";
import { generate_inputs_from_array, generate_inputs } from "secp256k1_hash_to_curve_circom/ts/generate_inputs";
import { bufToSha256PaddedBitArr, strToSha256PaddedBitArr } from "secp256k1_hash_to_curve_circom/ts/utils";
import { utils } from "ffjavascript"
import { concatUint8Arrays } from '../../javascript/src/utils/encoding';


jest.setTimeout(1_000_000);

describe("Nullifier Circuit", () => {
  const hashMPk = enclave.computeHashMPk(testMessage, Buffer.from(testPublicKey));
  const nullifier = enclave.computeNullifer(hashMPk, testSecretKey);
  const gPowR = enclave.computeGPowR(testR)
  const hashMPkPowR = enclave.computeHashMPkPowR(hashMPk, testR);
  const c = enclave.computeC(
    testPublicKey,
    hashMPk,
    nullifier, // TODO: as unknown as Point - why is this used in signals test?
    gPowR,
    hashMPkPowR
  );

  const skMultC = (uint8ArrayToBigInt(testSecretKey) * hexToBigInt(c)) % CURVE.n;
  const s = ((skMultC + uint8ArrayToBigInt(testR)) % CURVE.n);

  const public_key_bytes = Array.from(testPublicKey);
  const message_bytes = Array.from(testMessage);

  const hashMPkPoint = new Point(
    hexToBigInt(hashMPk.x.toString()),
    hexToBigInt(hashMPk.y.toString())
  )
  const hashMPkBytes = hashMPkPoint.toRawBytes(true);

  test("hash to curve outputs same value", async () => {
    const inputs = utils.stringifyBigInts(generate_inputs_from_array(message_bytes.concat(public_key_bytes)));

    const p = join(__dirname, 'hash_to_curve_test.circom')
    const circuit = await wasm_tester(p, {"json":true, "sym": true})
    const w = await circuit.calculateWitness({
      ...inputs,
    }, true)
    await circuit.checkConstraints(w)
    await circuit.assertOut(w, {out: pointToCircuitValue(hashMPkPoint)});
  })

  test.only("compression validates points", async () => {
    const p = join(__dirname, 'compression_test.circom')
    const circuit = await wasm_tester(p, {"json":true, "sym": true})

    var points: Point[] = [
      Point.BASE,
      Point.fromPrivateKey(testSecretKey),
      hashMPkPoint,
      nullifier,
      gPowR,
      hashMPkPowR,
    ]

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

  test("circuit verifies valid nullifier", async () => {
    const p = join(__dirname, 'vfy_test.circom')
    console.log("about to compile")
    const circuit = await wasm_tester(p)
    console.log("compiled")

    console.log("about to calculate witness")

    const {msg: _, ...hash_to_curve_inputs} = utils.stringifyBigInts(generate_inputs_from_array(message_bytes.concat(public_key_bytes)));

    // Calculate padded bit string for sha256 circuit
      const preimage = concatUint8Arrays([
        Point.BASE.toRawBytes(false).slice(1),
        Point.fromPrivateKey(testSecretKey).toRawBytes(false).slice(1),
        hashMPkBytes.slice(1),
        nullifier.toRawBytes(false).slice(1),
        gPowR.toRawBytes(false).slice(1),
        hashMPkPowR.toRawBytes(false).slice(1),
      ])
    const padded_bit_string = bufToSha256PaddedBitArr(Buffer.from(Array.from(preimage)));

    const w = await circuit.calculateWitness({
      // Main circuit inputs 
      c: scalarToCircuitValue(hexToBigInt(c)),
      s: scalarToCircuitValue(s),
      msg: message_bytes,
      public_key: pointToCircuitValue(Point.fromPrivateKey(testSecretKey)),
      public_key_bytes,
      nullifier: pointToCircuitValue(nullifier),
      hash_padded_bits: [...padded_bit_string].map(Number),
      ...hash_to_curve_inputs,
    })
    console.log("calculated witness")
    await circuit.checkConstraints(w)
  })

  // This tests that our circuit correctly computes g^s/(g^sk)^c = g^r, and that the first two equations are
  // implicitly verified correctly.
  test("a/b^c subcircuit", async () => {
    const p = join(__dirname, 'a_div_b_pow_c_test.circom')
    const circuit = await wasm_tester(p)
    
    // Verify that gPowS/pkPowC = gPowR outside the circuit, as a sanity check
    const gPowS = Point.fromPrivateKey(s);
    const pkPowC = Point.fromPrivateKey(testSecretKey).multiply(hexToBigInt(c))
    expect(gPowS.add(pkPowC.negate()).equals(gPowR)).toBe(true);

    // Verify that circuit calculates g^s / pk^c = g^r
    const w = await circuit.calculateWitness({ 
      a: pointToCircuitValue(gPowS),
      b: pointToCircuitValue(Point.fromPrivateKey(testSecretKey)),
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

function circuitValueToScalar(registers: bigint[]) {
  if (registers.length != 4) {
    throw new Error(`Circuit values have 4 registers, got ${registers.length}`)
  }
  return registersToBigint(registers, 64n);
}

function scalarToCircuitValue(value: bigint):bigint[] {
  return bigIntToRegisters(value, 64n, 4n);
}

function pointToCircuitValue(p: Point):bigint[][] {
  return [
    scalarToCircuitValue(p.x),
    scalarToCircuitValue(p.y),
  ]
}

function circuitValueToPoint(coordinates: bigint[][]):Point {
  if (coordinates.length != 2) {
    throw new Error(`Elliptic curve points have 2 coordinates, got ${coordinates.length}`);
  }
  return new Point(circuitValueToScalar(coordinates[0]), circuitValueToScalar[1]);
}

function bigIntToRegisters(value: bigint, bits_per_register: bigint, register_count: bigint): bigint[] {
  const register_size = 2n ** bits_per_register;
  if (value >= register_size ** register_count) {
    throw new Error(`BigInt ${value} can't fit into ${register_count} registers of ${bits_per_register} bits.`);
  }

  var registers: bigint[] = [];
  for (var i = 0; i < register_count; i++) {
    registers[i] = (value / register_size ** BigInt(i)) % register_size;
  }

  return registers;
}

function registersToBigint(registers: bigint[], bits_per_register: bigint): bigint {
  const register_size = 2n ** bits_per_register;
  let value = 0n;
  let e = 1n;
  for (var i = 0; i < registers.length; i++) {
    value += registers[i] * e;
    e *= register_size;
  }

  return value;
}
