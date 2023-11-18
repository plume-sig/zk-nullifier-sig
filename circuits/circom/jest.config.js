module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  transform: {
    "^.+\\.ts?$": "ts-jest",
  },
  transformIgnorePatterns: [
    "<rootdir>/node_modules/.pnpm/(?!(secp256k1_hash_to_curve_circom)@)",
  ],
};
