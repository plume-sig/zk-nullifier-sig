import {
  hashMPk,
  nullifier,
  hashedToCurveR,
  rPoint,
  c_v1,
  s_v1,
  c_v2,
  s_v2,
  testPublicKey,
  testSecretKey,
  testMessage,
  testR,
} from "./consts";

import { computeAllInputs } from "../src";
import { PlumeVersion } from "../src/signals";

describe("signals", () => {
  it("generates hash(m, pk)", () => {
    expect(hashMPk.x.toString()).toEqual(
      "bcac2d0e12679f23c218889395abcdc01f2affbc49c54d1136a2190db0800b65",
    );
    expect(hashMPk.y.toString()).toEqual(
      "3bcfb339c974c0e757d348081f90a123b0a91a53e32b3752145d87f0cd70966e",
    );
  });

  it("generates nullifier (hash(m, pk))^sk", () => {
    expect(nullifier.x.toString(16)).toEqual(
      "57bc3ed28172ef8adde4b9e0c2cce745fcc5a66473a45c1e626f1d0c67e55830",
    );
    expect(nullifier.y.toString(16)).toEqual(
      "6a2f41488d58f33ae46edd2188e111609f9f3ae67ea38fa891d6087fe59ecb73",
    );
  });

  describe("Plume V1", () => {
    it("generates c and intermediate values correctly", () => {
      expect(hashedToCurveR.x.toString(16)).toEqual(
        "6d017c6f63c59fa7a5b1e9a654e27d2869579f4d152131db270558fccd27b97c",
      );

      expect(hashedToCurveR.y.toString(16)).toEqual(
        "586c43fb5c99818c564a8f80a88a65f83e3f44d3c6caf5a1a4e290b777ac56ed",
      );

      expect(rPoint.x.toString(16)).toEqual(
        "9d8ca4350e7e2ad27abc6d2a281365818076662962a28429590e2dc736fe9804",
      );
      expect(rPoint.y.toString(16)).toEqual(
        "ff08c30b8afd4e854623c835d9c3aac6bcebe45112472d9b9054816a7670c5a1",
      );

      expect(c_v1).toEqual(
        "c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83254",
      );
    });

    it("generates an s signal", () => {
      expect(s_v1).toEqual(
        "e69f027d84cb6fe5f761e333d12e975fb190d163e8ea132d7de0bd6079ba28ca",
      );
    });

    it("generates all signals", () => {
      const { plume, s, pk, c, rPoint, hashedToCurveR } = computeAllInputs(
        testMessage,
        testSecretKey,
        testR,
        PlumeVersion.V1,
      );

      expect(pk).toEqual(testPublicKey);
      expect(rPoint.x.toString(16)).toEqual(
        "9d8ca4350e7e2ad27abc6d2a281365818076662962a28429590e2dc736fe9804",
      );
      expect(rPoint.y.toString(16)).toEqual(
        "ff08c30b8afd4e854623c835d9c3aac6bcebe45112472d9b9054816a7670c5a1",
      );
      expect(plume.x.toString(16)).toEqual(
        "57bc3ed28172ef8adde4b9e0c2cce745fcc5a66473a45c1e626f1d0c67e55830",
      );
      expect(plume.y.toString(16)).toEqual(
        "6a2f41488d58f33ae46edd2188e111609f9f3ae67ea38fa891d6087fe59ecb73",
      );
      expect(hashedToCurveR.x.toString(16)).toEqual(
        "6d017c6f63c59fa7a5b1e9a654e27d2869579f4d152131db270558fccd27b97c",
      );
      expect(c).toEqual(
        "c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83254",
      );
      expect(s).toEqual(
        "e69f027d84cb6fe5f761e333d12e975fb190d163e8ea132d7de0bd6079ba28ca",
      );
      expect(hashedToCurveR.y.toString(16)).toEqual(
        "586c43fb5c99818c564a8f80a88a65f83e3f44d3c6caf5a1a4e290b777ac56ed",
      );
    });
  });

  describe("Plume V2", () => {
    it("generates c and intermediate values correctly", () => {
      expect(hashedToCurveR.x.toString(16)).toEqual(
        "6d017c6f63c59fa7a5b1e9a654e27d2869579f4d152131db270558fccd27b97c",
      );

      expect(hashedToCurveR.y.toString(16)).toEqual(
        "586c43fb5c99818c564a8f80a88a65f83e3f44d3c6caf5a1a4e290b777ac56ed",
      );

      expect(rPoint.x.toString(16)).toEqual(
        "9d8ca4350e7e2ad27abc6d2a281365818076662962a28429590e2dc736fe9804",
      );

      expect(rPoint.y.toString(16)).toEqual(
        "ff08c30b8afd4e854623c835d9c3aac6bcebe45112472d9b9054816a7670c5a1",
      );

      expect(c_v2).toEqual(
        "3dbfb717705010d4f44a70720c95e74b475bd3a783ab0b9e8a6b3b363434eb96",
      );
    });

    it("generates an s signal", () => {
      expect(s_v2).toEqual(
        "528e8fbb6452f82200797b1a73b2947a92524bd611085a920f1177cb8098136b",
      );
    });

    it("generates all signals", () => {
      const { plume, s, pk, c, rPoint, hashedToCurveR } = computeAllInputs(
        testMessage,
        testSecretKey,
        testR,
        PlumeVersion.V2,
      );

      expect(pk).toEqual(testPublicKey);
      expect(rPoint.x.toString(16)).toEqual(
        "9d8ca4350e7e2ad27abc6d2a281365818076662962a28429590e2dc736fe9804",
      );
      expect(rPoint.y.toString(16)).toEqual(
        "ff08c30b8afd4e854623c835d9c3aac6bcebe45112472d9b9054816a7670c5a1",
      );
      expect(plume.x.toString(16)).toEqual(
        "57bc3ed28172ef8adde4b9e0c2cce745fcc5a66473a45c1e626f1d0c67e55830",
      );
      expect(plume.y.toString(16)).toEqual(
        "6a2f41488d58f33ae46edd2188e111609f9f3ae67ea38fa891d6087fe59ecb73",
      );
      expect(hashedToCurveR.x.toString(16)).toEqual(
        "6d017c6f63c59fa7a5b1e9a654e27d2869579f4d152131db270558fccd27b97c",
      );
      expect(c).toEqual(
        "3dbfb717705010d4f44a70720c95e74b475bd3a783ab0b9e8a6b3b363434eb96",
      );
      expect(s).toEqual(
        "528e8fbb6452f82200797b1a73b2947a92524bd611085a920f1177cb8098136b",
      );
      expect(hashedToCurveR.y.toString(16)).toEqual(
        "586c43fb5c99818c564a8f80a88a65f83e3f44d3c6caf5a1a4e290b777ac56ed",
      );
    });
  });
});
