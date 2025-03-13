use std::embedded_curve_ops::EmbeddedCurvePoint as Point;
use std::embedded_curve_ops::EmbeddedCurveScalar as Scalar;
use ec;
use noir_bigcurve::BigCurve;
use noir_bigcurve::curves::bn254::{BN254, BN254_Fq_Params};
use nodash::pack_bytes;

global SQRT_NEG_3: Field = 8815841940592487684786734430012312169832938914291687956923;
// global q_MINUS_1_OVER_2 = 10944121435919637611123202872628637544274182200208017171849102093287904247808; // For Grumpkin's q (AltBN's r) - i.e. q is the native noir `Field` size
global KNOWN_NON_RESIDUE: Field = 5;

pub(crate) fn poseidon2_hash<let N: u32>(inputs: [Field; N]) -> Field {
    std::hash::poseidon2::Poseidon2::hash(inputs, N)
}

pub fn hash_to_curve<let N: u32>(msg: [u8; N]) -> Point {
    let u: (Field, Field) = hash_to_field(msg);

    // Note: It's usually scalars Fr that are mapped to curves. Here, we're actually mapping Noir `Field` types, which are grumpkin's base field Fq elements. Grumpkin's |Fr| > |Fq| = |`Field`|.
    let Q0 = map_to_curve(u.0);
    let Q1 = map_to_curve(u.1);

    // Q: do we need to "map twice then add", if we're not using the "isogeny" approach to hashing to curve?
    Q0 + Q1
}


pub(crate) fn hash_to_field<let N: u32>(msg: [u8; N]) -> (Field, Field) {
    let mut m: Field = poseidon2_hash(pack_bytes(msg));
    let u_0: Field = poseidon2_hash([m, 0]);
    let u_1: Field = poseidon2_hash([m, 1]);
    (u_0, u_1)
}


unconstrained fn __sqrt(x: Field) -> (bool, Field) {
    let is_sq = ec::is_square(x);
    let mut maybe_sqrt = 0;
    if is_sq {
        maybe_sqrt = ec::sqrt(x);
        assert(maybe_sqrt * maybe_sqrt == x); // to catch bugs
    } else {
        // If x a non-residue, x * KNOWN_NON_RESIDUE will be a residue, since -1 * -1 = 1 when considering their legendre symbols.
        let demo_not_square = x * KNOWN_NON_RESIDUE;
        maybe_sqrt = ec::sqrt(demo_not_square);
        assert(maybe_sqrt * maybe_sqrt == demo_not_square); // to catch bugs
    }
    (is_sq, maybe_sqrt)
}

fn sqrt(x: Field) -> (bool, Field) {
    let (is_sq, maybe_sqrt) = unsafe {
        __sqrt(x)
    };
    let mut out: (bool, Field) = (false, 0);
    if is_sq {
        let sqrt = maybe_sqrt;
        assert(sqrt * sqrt == x);
        out = (true, sqrt);
    } else {
        let not_sqrt = maybe_sqrt;
        let demo_not_square = x * KNOWN_NON_RESIDUE;
        // Given that this is square, it implies x is not square.
        assert(not_sqrt * not_sqrt == demo_not_square);
    }
    out
}

// Doesn't need to be called or constrained, because it's mathematically proven to be true. We're just checking for bugs, here:
unconstrained fn __check_at_least_one_sq(is_sq_y1: bool, is_sq_y2: bool, is_sq_y3: bool) {
    assert(is_sq_y1 | is_sq_y2 | is_sq_y3, "This error should be unreachable");
}

// Uses a more efficient method from https://www.di.ens.fr/~fouque/pub/latincrypt12.pdf that works for BN curves
pub(crate) fn map_to_curve(t: Field) -> Point {
    let b = -17; // TODO: put in constants file

    // TODO: hard-code the constant result if t = 0 (see the recommendation for the point to use, in the paper).
    // Having said that, it's unlikely - in the case of plume - for an input to ever be 0, so maybe it's not worth implementing that edge case?
    assert(t != 0, "0 not yet supported");

    let t_2 = t * t;

    let zeta = (-1 + SQRT_NEG_3) / 2;
    let d = (1 + b + t_2);
    let v = zeta - (SQRT_NEG_3 * t_2) / d;
    let y = d / (SQRT_NEG_3 * t);

    let x1 = v;
    let s1 = x1 * x1 * x1 + b;
    let x2 = -1 - v;
    let s2 = x2 * x2 * x2 + b;
    let x3 = 1 + y * y;
    let s3 = x3 * x3 * x3 + b;

    let (is_sq_y1, y1) = sqrt(s1);
    let (is_sq_y2, y2) = sqrt(s2);
    let (is_sq_y3, y3) = sqrt(s3);

    unsafe {
        __check_at_least_one_sq(is_sq_y1, is_sq_y2, is_sq_y3);
    }

    if is_sq_y1 {
        Point { x: x1, y: y1, is_infinite: false }
    } else if is_sq_y2 {
        Point { x: x2, y: y2, is_infinite: false }
    } else {
        Point { x: x3, y: y3, is_infinite: false }
    }
}

