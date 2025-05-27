import hashToCurve from "../src/utils/hashToCurve";

describe("hashToCurve", () => {
  it("successfully hashes correct values", () => {
    const testPreimage = [
      65, 110, 32, 101, 120, 97, 109, 112, 108, 101, 32, 97, 112, 112, 32, 109,
      101, 115, 115, 97, 103, 101, 32, 115, 116, 114, 105, 110, 103, 3, 12, 236,
      2, 142, 224, 141, 9, 224, 38, 114, 166, 131, 16, 129, 67, 84, 249, 234,
      191, 255, 13, 230, 218, 204, 28, 211, 167, 116, 73, 96, 118, 174,
    ];

    const hash = hashToCurve(testPreimage);

    expect(hash.x.toString()).toEqual(
      "bcac2d0e12679f23c218889395abcdc01f2affbc49c54d1136a2190db0800b65",
    );
    expect(hash.y.toString()).toEqual(
      "3bcfb339c974c0e757d348081f90a123b0a91a53e32b3752145d87f0cd70966e",
    );
  });
});
