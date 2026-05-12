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
  testVector,
} from "./consts";

import { computeAllInputs } from "../src";
import { PlumeVersion } from "../src/signals";

describe("signals", () => {
  it("generates hash(m, pk)", () => {
    expect(hashMPk.x.toString()).toEqual(testVector.expected.hash_m_pk.x);
    expect(hashMPk.y.toString()).toEqual(testVector.expected.hash_m_pk.y);
  });

  it("generates nullifier (hash(m, pk))^sk", () => {
    expect(nullifier.x.toString(16)).toEqual(testVector.expected.nullifier.x);
    expect(nullifier.y.toString(16)).toEqual(testVector.expected.nullifier.y);
  });

  describe("Plume V1", () => {
    it("generates c and intermediate values correctly", () => {
      expect(hashedToCurveR.x.toString(16)).toEqual(
        testVector.expected.hashed_to_curve_r.x,
      );

      expect(hashedToCurveR.y.toString(16)).toEqual(
        testVector.expected.hashed_to_curve_r.y,
      );

      expect(rPoint.x.toString(16)).toEqual(testVector.expected.r_point.x);
      expect(rPoint.y.toString(16)).toEqual(testVector.expected.r_point.y);

      expect(c_v1).toEqual(testVector.expected.v1.c);
    });

    it("generates an s signal", () => {
      expect(s_v1).toEqual(testVector.expected.v1.s);
    });

    it("generates all signals", () => {
      const { plume, s, pk, c, rPoint, hashedToCurveR } = computeAllInputs(
        testMessage,
        testSecretKey,
        testR,
        PlumeVersion.V1,
      );

      expect(pk).toEqual(testPublicKey);
      expect(rPoint.x.toString(16)).toEqual(testVector.expected.r_point.x);
      expect(rPoint.y.toString(16)).toEqual(testVector.expected.r_point.y);
      expect(plume.x.toString(16)).toEqual(testVector.expected.nullifier.x);
      expect(plume.y.toString(16)).toEqual(testVector.expected.nullifier.y);
      expect(hashedToCurveR.x.toString(16)).toEqual(
        testVector.expected.hashed_to_curve_r.x,
      );
      expect(c).toEqual(testVector.expected.v1.c);
      expect(s).toEqual(testVector.expected.v1.s);
      expect(hashedToCurveR.y.toString(16)).toEqual(
        testVector.expected.hashed_to_curve_r.y,
      );
    });
  });

  describe("Plume V2", () => {
    it("generates c and intermediate values correctly", () => {
      expect(hashedToCurveR.x.toString(16)).toEqual(
        testVector.expected.hashed_to_curve_r.x,
      );

      expect(hashedToCurveR.y.toString(16)).toEqual(
        testVector.expected.hashed_to_curve_r.y,
      );

      expect(rPoint.x.toString(16)).toEqual(testVector.expected.r_point.x);

      expect(rPoint.y.toString(16)).toEqual(testVector.expected.r_point.y);

      expect(c_v2).toEqual(testVector.expected.v2.c);
    });

    it("generates an s signal", () => {
      expect(s_v2).toEqual(testVector.expected.v2.s);
    });

    it("generates all signals", () => {
      const { plume, s, pk, c, rPoint, hashedToCurveR } = computeAllInputs(
        testMessage,
        testSecretKey,
        testR,
        PlumeVersion.V2,
      );

      expect(pk).toEqual(testPublicKey);
      expect(rPoint.x.toString(16)).toEqual(testVector.expected.r_point.x);
      expect(rPoint.y.toString(16)).toEqual(testVector.expected.r_point.y);
      expect(plume.x.toString(16)).toEqual(testVector.expected.nullifier.x);
      expect(plume.y.toString(16)).toEqual(testVector.expected.nullifier.y);
      expect(hashedToCurveR.x.toString(16)).toEqual(
        testVector.expected.hashed_to_curve_r.x,
      );
      expect(c).toEqual(testVector.expected.v2.c);
      expect(s).toEqual(testVector.expected.v2.s);
      expect(hashedToCurveR.y.toString(16)).toEqual(
        testVector.expected.hashed_to_curve_r.y,
      );
    });
  });
});
