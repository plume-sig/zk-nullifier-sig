import crypto from "crypto";
import path from "path";

import { Point } from "@noble/secp256k1";
import { wasm as wasm_tester } from "circom_tester";
import { generate_inputs_from_array } from "secp256k1_hash_to_curve_circom/ts/generate_inputs";
import { utils } from "ffjavascript";

import {
  c_v2,
  rPoint,
  hashedToCurveR,
  nullifier,
  s_v2,
  testMessage,
  testPublicKey,
  testSecretKey,
} from "javascript/test/consts";
import {
  hexToBigInt,
  concatUint8Arrays,
} from "javascript/src/utils/encoding";

import { pointToCircuitValue, scalarToCircuitValue } from "../utils";

jest.setTimeout(4_000_000);

describe("V2 Circuit", () => {
  const public_key_bytes = Array.from(testPublicKey);
  const message_bytes = Array.from(testMessage);

  const hash_to_curve_inputs = utils.stringifyBigInts(
    generate_inputs_from_array(message_bytes.concat(public_key_bytes)),
  );

  test("V2 circuit works", async () => {
    const p = path.join(__dirname, "./circuits/v2_test.circom");
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
});
