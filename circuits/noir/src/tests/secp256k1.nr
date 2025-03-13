use crate::curves::secp256k1::hash_to_curve;
use crate::Plume;
use noir_bigcurve::curves::secp256k1::{
    Secp256k1, Secp256k1_Params, Secp256k1Fq, Secp256k1Fr, Secp256k1Scalar,
};
use noir_bigcurve::scalar_field::ScalarField;

#[test]
fn test_plume_v2_secp256k1() {
    let msg = [115, 105, 103, 110, 84, 104, 105, 115];

    let c2 = Secp256k1Fq::from_be_bytes([
        25, 48, 148, 152, 196, 123, 193, 9, 209, 58, 83, 106, 175, 140, 40, 48, 149, 237, 34, 2,
        125, 148, 106, 54, 114, 7, 22, 131, 174, 188, 105, 208,
    ]);
    let c2: Secp256k1Scalar = ScalarField::from_bignum(c2);

    let s2 = Secp256k1Fq::from_be_bytes([
        232, 126, 194, 99, 71, 55, 87, 146, 72, 134, 247, 82, 158, 229, 140, 149, 111, 138, 153, 2,
        105, 222, 70, 22, 34, 41, 70, 212, 47, 29, 185, 219,
    ]);
    let s2: Secp256k1Scalar = ScalarField::from_bignum(s2);

    let sk = Secp256k1Fq::from_be_bytes([
        172, 9, 116, 190, 195, 154, 23, 227, 107, 164, 166, 180, 210, 56, 255, 148, 75, 172, 180,
        120, 203, 237, 94, 252, 174, 120, 77, 123, 244, 242, 255, 128,
    ]);
    let sk: Secp256k1Scalar = ScalarField::from_bignum(sk);

    let pk = Secp256k1::one().mul(sk);

    let H = Secp256k1 {
        x: Secp256k1Fq::from_slice([
            0x2affbc49c54d1136a2190db0800b65,
            0x2d0e12679f23c218889395abcdc01f,
            0xbcac,
        ]),
        y: Secp256k1Fq::from_slice([
            0xa91a53e32b3752145d87f0cd70966e,
            0xb339c974c0e757d348081f90a123b0,
            0x3bcf,
        ]),
        is_infinity: false,
    };
    let nullifier = H.mul(sk);

    let plume = Plume::new(msg, c2, s2, pk, nullifier, hash_to_curve);
    let (_, _) = plume.plume_v2();
}

