import {
  hexToBigInt,
  hexToUint8Array,
  uint8ArrayToBigInt,
  uint8ArrayToHex,
} from "../src/utils/encoding";

const TEST_VALS = [
  {
    hex: "a413bc5f",
    uint8: Uint8Array.from([164, 19, 188, 95]),
    bigint: 2752756831n,
  },
  {
    hex: "f09f8fb3efb88fe2808df09f8c88",
    uint8: Uint8Array.from([
      240, 159, 143, 179, 239, 184, 143, 226, 128, 141, 240, 159, 140, 136,
    ]),
    bigint: 4880420056602345253094210752449672n,
  },
];

describe("encoding", () => {
  it("hexToUint8Array", () => {
    expect(hexToUint8Array(TEST_VALS[0].hex)).toEqual(TEST_VALS[0].uint8);
    expect(hexToUint8Array(TEST_VALS[1].hex)).toEqual(TEST_VALS[1].uint8);
  });

  it("uint8ArrayToHex", () => {
    expect(uint8ArrayToHex(TEST_VALS[0].uint8)).toEqual(TEST_VALS[0].hex);
    expect(uint8ArrayToHex(TEST_VALS[1].uint8)).toEqual(TEST_VALS[1].hex);
  });

  it("hexToBigInt", () => {
    expect(hexToBigInt(TEST_VALS[0].hex)).toEqual(TEST_VALS[0].bigint);
    expect(hexToBigInt(TEST_VALS[1].hex)).toEqual(TEST_VALS[1].bigint);
  });

  it("uint8ArrayToBigInt", () => {
    expect(uint8ArrayToBigInt(TEST_VALS[0].uint8)).toEqual(TEST_VALS[0].bigint);
    expect(uint8ArrayToBigInt(TEST_VALS[1].uint8)).toEqual(TEST_VALS[1].bigint);
  });
});
