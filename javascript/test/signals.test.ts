import { CURVE, getPublicKey, Point } from "@noble/secp256k1";
import {
  computeC,
  computeGPowR,
  computeHashMPk,
  computeHashMPkPowR,
  computeNullifer,
} from "../src";
import {
  hexToBigInt,
  hexToUint8Array,
  messageToUint8Array,
  uint8ArrayToBigInt,
} from "../src/utils/encoding";

const testSecretKey = hexToUint8Array(
  "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"
);

const testPublicKey = getPublicKey(testSecretKey, true);

const testR = hexToUint8Array(
  "93b9323b629f251b8f3fc2dd11f4672c5544e8230d493eceea98a90bda789808"
);
const testMessage = messageToUint8Array("An example app message string");

describe("signals", () => {
  it("generates hash(m, pk)", () => {
    const hashMPk = computeHashMPk(testMessage, Buffer.from(testPublicKey));
    expect(hashMPk.x.toString()).toEqual(
      "bcac2d0e12679f23c218889395abcdc01f2affbc49c54d1136a2190db0800b65"
    );
    expect(hashMPk.y.toString()).toEqual(
      "3bcfb339c974c0e757d348081f90a123b0a91a53e32b3752145d87f0cd70966e"
    );
  });

  const mockHashedMPk = {
    x: {
      toString: () =>
        "bcac2d0e12679f23c218889395abcdc01f2affbc49c54d1136a2190db0800b65",
    },
    y: {
      toString: () =>
        "3bcfb339c974c0e757d348081f90a123b0a91a53e32b3752145d87f0cd70966e",
    },
  };

  const mockNullifer = new Point(
    BigInt(
      "0x57bc3ed28172ef8adde4b9e0c2cce745fcc5a66473a45c1e626f1d0c67e55830"
    ),
    BigInt("0x6a2f41488d58f33ae46edd2188e111609f9f3ae67ea38fa891d6087fe59ecb73")
  );

  it("generates nullifier (hash(m, pk))^sk", () => {
    const nullifier = computeNullifer(mockHashedMPk, testSecretKey);
    expect(nullifier.x.toString(16)).toEqual(
      "57bc3ed28172ef8adde4b9e0c2cce745fcc5a66473a45c1e626f1d0c67e55830"
    );
    expect(nullifier.y.toString(16)).toEqual(
      "6a2f41488d58f33ae46edd2188e111609f9f3ae67ea38fa891d6087fe59ecb73"
    );
  });

  it("generates c and intermediate values correctly", () => {
    const hashMPkPowR = computeHashMPkPowR(mockHashedMPk, testR);
    expect(hashMPkPowR.x.toString(16)).toEqual(
      "6d017c6f63c59fa7a5b1e9a654e27d2869579f4d152131db270558fccd27b97c"
    );
    expect(hashMPkPowR.y.toString(16)).toEqual(
      "586c43fb5c99818c564a8f80a88a65f83e3f44d3c6caf5a1a4e290b777ac56ed"
    );

    const gPowR = computeGPowR(testR);
    expect(gPowR.x.toString(16)).toEqual(
      "9d8ca4350e7e2ad27abc6d2a281365818076662962a28429590e2dc736fe9804"
    );
    expect(gPowR.y.toString(16)).toEqual(
      "ff08c30b8afd4e854623c835d9c3aac6bcebe45112472d9b9054816a7670c5a1"
    );

    const c = computeC(
      testPublicKey,
      mockHashedMPk,
      mockNullifer as unknown as Point,
      gPowR,
      hashMPkPowR
    );
    expect(c).toEqual(
      "7da1ad3f63c6180beefd0d6a8e3c87620b54f1b1d2c8287d104da9e53b6b5524"
    );
  });

  const mockC =
    "7da1ad3f63c6180beefd0d6a8e3c87620b54f1b1d2c8287d104da9e53b6b5524";

  it("generates an s signal", () => {
    const skC =
      (uint8ArrayToBigInt(testSecretKey) * hexToBigInt(mockC)) % CURVE.P;
    const s = ((skC + uint8ArrayToBigInt(testR)) % CURVE.P).toString(16);
    expect(s).toEqual(
      "49d55841b8b8003b21be96c24d9d6866fe82b409edd14cdc9aacd88c17742118"
    );
  });
});

// TODO: Add custom verification function
