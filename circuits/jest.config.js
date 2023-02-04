module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  transform: {
    "^.+\\.ts?$": "ts-jest",
  },
  transformIgnorePatterns: [
    "<rootDir>/node_modules/(?!(secp256k1_hash_to_curve_circom)/)",
  ],
};
