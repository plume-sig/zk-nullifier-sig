import path from "path";

import { Point } from "@noble/secp256k1";
import { wasm as wasm_tester } from "circom_tester";
import { generate_inputs_from_array } from "secp256k1_hash_to_curve_circom/ts/generate_inputs";
import { bufToSha256PaddedBitArr } from "secp256k1_hash_to_curve_circom/ts/utils";
import { utils } from "ffjavascript";

import {
  c_v1,
  rPoint,
  hashMPk,
  hashedToCurveR,
  nullifier,
  s_v1,
  testMessage,
  testPublicKey,
  testSecretKey,
} from "../../../javascript/test/consts";
import {
  hexToBigInt,
  concatUint8Arrays,
} from "../../../javascript/src/utils/encoding";

import { pointToCircuitValue, scalarToCircuitValue } from "../utils";

jest.setTimeout(4_000_000);

describe("V1 Circuit", () => {
  const public_key_bytes = Array.from(testPublicKey);
  const message_bytes = Array.from(testMessage);

  const hash_to_curve_inputs = utils.stringifyBigInts(
    generate_inputs_from_array(message_bytes.concat(public_key_bytes)),
  );

  test("V1 circuit works", async () => {
    const p = path.join(__dirname, "./circuits/v1_test.circom");
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
    });
    await circuit.checkConstraints(w);
  });
});