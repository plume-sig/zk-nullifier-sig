import { circuitValueToScalar, scalarToCircuitValue } from "../utils";

describe("Conversion", () => {
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
