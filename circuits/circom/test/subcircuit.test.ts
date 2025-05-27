import path from "path";

import { Point } from "@noble/secp256k1";
import { wasm as wasm_tester } from "circom_tester";

import {
  c_v1,
  rPoint,
  s_v1,
  testSecretKey,
} from "javascript/test/consts";
import { hexToBigInt } from "javascript/src/utils/encoding";

import { pointToCircuitValue, scalarToCircuitValue } from "../utils";

jest.setTimeout(2_000_000);

// This tests that our circuit correctly computes g^s/(g^sk)^c = g^r, and that the first two equations are
// implicitly verified correctly.
describe("a/b^c subcircuit", () => {
  test("should check circuit calculation", async () => {
    const p = path.join(__dirname, "./circuits/a_div_b_pow_c_test.circom");
    const circuit = await wasm_tester(p);

    // Verify that gPowS/pkPowC = gPowR outside the circuit, as a sanity check
    const gPowS = Point.fromPrivateKey(s_v1);
    const pkPowC = Point.fromPrivateKey(testSecretKey).multiply(
      hexToBigInt(c_v1),
    );
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
});
