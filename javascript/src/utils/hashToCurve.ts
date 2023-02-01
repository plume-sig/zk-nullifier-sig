import { CTX } from "amcl-js";
import { asciitobytes } from "./encoding";

// Refactored from miracl-core
const ctx = new CTX("SECP256K1") as any;
const ro = "QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";
const hlen = ctx.ECP.HASH_TYPE;

function ceil(a, b) {
  return Math.floor((a - 1) / b + 1);
}

function hashToField(ctx, hash, hlen, DST, M, ctr) {
  var u = [];
  var q = new ctx.BIG(0);
  q.rcopy(ctx.ROM_FIELD.Modulus);
  var k = q.nbits();
  var r = new ctx.BIG(0);
  r.rcopy(ctx.ROM_CURVE.CURVE_Order);
  var m = r.nbits();
  var L = ceil(k + ceil(m, 2), 8);
  var OKM = ctx.HMAC.XMD_Expand(hash, hlen, L * ctr, DST, M);
  var fd = [];
  for (var i = 0; i < ctr; i++) {
    for (var j = 0; j < L; j++) fd[j] = OKM[i * L + j];
    var dx = ctx.DBIG.fromBytes(fd);
    var w = new ctx.FP(dx.mod(q));
    u[i] = new ctx.FP(w);
  }
  return u;
}

function hashToPairing(ctx, M, ro, hlen) {
  const DSTRO = asciitobytes(ro);
  const u = hashToField(ctx, ctx.HMAC.MC_SHA2, hlen, DSTRO, M, 2);
  const P = ctx.ECP.map2point(u[0]);
  const P1 = ctx.ECP.map2point(u[1]);
  P.add(P1);
  P.cfp();
  P.affine();
  return P;
}

export default function hashToCurve(bytes: number[]) {
  return hashToPairing(ctx, bytes, ro, hlen);
}
