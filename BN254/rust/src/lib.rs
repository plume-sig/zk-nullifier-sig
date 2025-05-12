use ark_bn254::{Fr, G1Affine};
use num_bigint::BigUint;

pub fn hash_to_curve(msg: &[u8]) -> G1Affine {
    assert!(msg.len() <= u32::MAX); // feels useless in reality because of verification costs, but added to mirror the origin yet

    let u = hash_to_field(msg);

    // "Note: It's usually scalars Fr that are mapped to curves. Here, we're actually mapping Noir `Field` types, which are grumpkin's base field Fq elements. Grumpkin's |Fr| > |Fq| = |`Field`|."
    let Q0 = map_to_curve(u.0);
    let Q1 = map_to_curve(u.1);

    Q0 + Q1
}

pub(crate) fn hash_to_field<N: u32>(msg: [u8; N]) -> (Fr, Fr) {
    let mut m: Field = poseidon2_hash(pack_bytes(msg));
    let u_0: Field = poseidon2_hash([m, 0]);
    let u_1: Field = poseidon2_hash([m, 1]);
    (u_0, u_1)
}

fn pack_bytes<N: u32>(bytes: [u8; N]) -> [Fr; N / 31 + 1] {
    let bytes_padded = 
        pad_end::<(N / 31 + 1) * 31>(bytes, 0);
    let mut res = [0 as Field; N / 31 + 1];
    for i in 0..N / 31 + 1 {
        let chunk = bytes_padded.slice::<31>(i * 31);
        res[i] = field_from_bytes(chunk);
    }
    res
}

fn pad_end<N: u32, M: u32>(self_: [T; N], pad_value: T) -> [T; M] {
    assert(M >= N, "pad_end: array too long");
    let mut res = [pad_value; M];
    for i in 0..N {
        res[i] = self[i];
    }
    res
}

fn field_from_bytes(bytes: &[u8]) -> BigUint {
    let n = bytes.len();
    assert!(n < 32, "field_from_bytes: N must be less than 32");
    let mut as_field = BigUint::ZERO;
    let mut offset = BigUint::from(1);
    for i in 0..n {
        as_field += (bytes[i] as BigUint) * offset;
        offset *= 256;
    }
    as_field
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use ark_bn254::{g1::G1Affine, Fq, Fr, G1Projective};

    use super::*;

    #[test]
    fn test_plume_v2_bn254() {
        let msg: [u8; 8] = [115, 105, 103, 110, 84, 104, 105, 115];

        // let sk_f = 0x1234;

        let sk = Fr::from(0x1234.into());
        let sk_n: ScalarWithOps = field_to_bignum_unsafe(sk_f);
        let r_n: ScalarWithOps = BN254Fq::from_slice([0x1234, 0x1234, 0x12]);
        let r = Fr::from(
            u64::from_le_bytes([0x1234u32.to_le_bytes(), 0x1234u32.to_le_bytes(), 0x12u32.to_le_bytes()].concat().try_into().unwrap())
        );
        let r: Scalar = bignum_to_scalar(r_n);

        let G = G1Affine::new(
            1.into(), 
            // Fq::from_str("17631683881184975370165255887551781615748388533673675138860").unwrap()
            <num_bigint::BigUint as std::str::FromStr>::from_str("17631683881184975370165255887551781615748388533673675138860").unwrap().into()
        );
        
        let Pk = &G.into() * &sk;
        let H = compute_H::<8, 8 + 2>(msg, Pk);

        let Nullifier: Point = unsafe { compute_nullifier(sk, H) };

        let rG: Point = scalar_mul(r, G);
        let rH: Point = scalar_mul(r, H);

        let rG: Point = scalar_mul(r, G);
        let rH: Point = scalar_mul(r, H);

        let A = Pk;
        let B = Nullifier;
        let A2 = rG;
        let B2 = rH;

        let c_f: Field = poseidon2_points::<6, 2 * 6>([G, H, A, B, A2, B2]);
        let c_n: ScalarWithOps = field_to_bignum_unsafe(c_f);
        let c = BN254Scalar::from_bignum(c_n);

        let s_n: ScalarWithOps = r_n + (sk_n * c_n);
        let s = BN254Scalar::from_bignum(s_n);

        let pk = BN254 { x: field_to_bignum_unsafe(Pk.x), y: field_to_bignum_unsafe(Pk.y), is_infinity: Pk.is_infinite };
        let nullifier = BN254 { x: field_to_bignum_unsafe(Nullifier.x), y: field_to_bignum_unsafe(Nullifier.y), is_infinity: Nullifier.is_infinite };
        
        let plume = Plume::new(msg, c, s, pk, nullifier, hash_to_curve_bn254);
        let (_, _) = plume.plume_v2();
    }
}
