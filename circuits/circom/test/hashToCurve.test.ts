import path from "path";

import { Point } from "@noble/secp256k1";
import { wasm as wasm_tester } from "circom_tester";
import { generate_inputs_from_array } from "secp256k1_hash_to_curve_circom/ts/generate_inputs";
import { utils } from "ffjavascript";

import {
  hashMPk,
  testMessage,
  testPublicKey,
} from "javascript/test/consts";
import { hexToBigInt } from "javascript/src/utils/encoding";

import { pointToCircuitValue } from "../utils";

jest.setTimeout(2_000_000);

describe("Hash to curve", () => {
  const public_key_bytes = Array.from(testPublicKey);
  const message_bytes = Array.from(testMessage);

  const hashMPkPoint = new Point(
    hexToBigInt(hashMPk.x.toString()),
    hexToBigInt(hashMPk.y.toString()),
  );

  const hash_to_curve_inputs = utils.stringifyBigInts(
    generate_inputs_from_array(message_bytes.concat(public_key_bytes)),
  );

  test("should outputs same value", async () => {
    const p = path.join(__dirname, "./circuits/hash_to_curve_test.circom");
    const circuit = await wasm_tester(p, { json: true, sym: true });
    const w = await circuit.calculateWitness({ ...hash_to_curve_inputs }, true);
    await circuit.checkConstraints(w);
    await circuit.assertOut(w, { out: pointToCircuitValue(hashMPkPoint) });
  });
});
