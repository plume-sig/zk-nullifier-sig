import { join } from 'path';
import { wasm as wasm_tester } from 'circom_tester'
import {describe, expect, test} from '@jest/globals';
import * as enclave from "../../javascript/src/index";
import { testSecretKey, testPublicKey, testR, testMessage } from "../../javascript/test/signals.test";
import { uint8ArrayToBigInt, hexToBigInt, hexToUint8Array } from "../../javascript/src/utils/encoding";
import { CURVE, Point } from "@noble/secp256k1";
import { HashedPoint, multiplyPoint } from "../../javascript/src/utils/curve";

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

  const skMultC = (uint8ArrayToBigInt(testSecretKey) * hexToBigInt(c)) % CURVE.P;
  const s = ((skMultC + uint8ArrayToBigInt(testR)) % CURVE.P);

  test("enclave generating correct values", () => {
    expect(c).toEqual("7da1ad3f63c6180beefd0d6a8e3c87620b54f1b1d2c8287d104da9e53b6b5524"); // same value as specified in signals.test.ts
    expect(s.toString(16)).toEqual("49d55841b8b8003b21be96c24d9d6866fe82b409edd14cdc9aacd88c17742118");
  })

  // This tests that our circuit correctly computes g^s/(g^sk)^c = g^r, and that the first two equations are
  // implicitly verified correctly.
  test("a/b^c subcircuit", async () => {
    // const p = join(__dirname, 'a_div_b_pow_c_test.circom')
    // const circuit = await wasm_tester(p)

    const gPowS = Point.fromPrivateKey(s);
    const pkPowC = Point.fromPrivateKey(testSecretKey).multiply(hexToBigInt(c))

    // Verify that gPowS/pkPowC = gPowR outside the circuit, as a sanity check
    console.log(gPowR);
    console.log(gPowS.add(pkPowC.negate()));
    expect(gPowS.add(pkPowC.negate()).equals(gPowR)).toBe(true);

    // const w = await circuit.calculateWitness(
    //   { a: gPowS, b: , c:  },
    // )
    // await circuit.checkConstraints(w)
  });
})
