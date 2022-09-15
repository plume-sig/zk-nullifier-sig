use secp256k1::curves::Affine;
use secp256k1::curves::Secp256k1Parameters;
use secp256k1::fields::Fq;
use crate::sig::VerifiableUnpredictableFunction;
use crate::hash_to_curve::{
    hash_to_curve,
    k256_affine_to_arkworks_secp256k1_affine,
};
use ark_std::rand;
use crate::sig::DeterministicNullifierSignatureScheme;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ec::models::short_weierstrass_jacobian::GroupAffine;
use ark_ff::bytes::{ToBytes, FromBytes};
use ark_ff::biginteger;
use rand::{prelude::ThreadRng, thread_rng};
use k256::{ProjectivePoint, Scalar};

type Parameters = crate::sig::Parameters<Secp256k1Parameters>;

fn test_template() -> (ThreadRng, Affine) {
    let rng = thread_rng();
    let g = Affine::prime_subgroup_generator();

    (rng, g)
}

type Scheme<'a> = DeterministicNullifierSignatureScheme::<'a, secp256k1::Projective, Fq, Secp256k1Parameters>;

#[test]
pub fn test_k256_affine_to_arkworks_secp256k1_affine() {
    for i in 1..50 {
        let i_u64 = i as u64;
        let k256_scalar = Scalar::from(i_u64);
        let ark_scalar = Fq::from(i_u64);

        // Compute g^i_u64
        let k256_pt = ProjectivePoint::GENERATOR.to_affine() * k256_scalar;
        let ark_pt = Affine::prime_subgroup_generator().mul(ark_scalar);

        // Convert k256_pt to an arkworks point
        let converted_pt = k256_affine_to_arkworks_secp256k1_affine::<
            secp256k1::fields::Fq,
            Secp256k1Parameters
        >(k256_pt.to_affine());

        // The points should match
        assert_eq!(ark_pt.into_affine(), converted_pt);
    }
}

fn hex_to_fr(
    hex: &str,
) -> secp256k1::fields::Fr {
    let num_field_bytes = 320;
    let mut sk_bytes_vec = vec![0u8; num_field_bytes];
    let mut sk_bytes = hex::decode(hex).unwrap();

    sk_bytes.reverse();

    for (i, _) in sk_bytes.clone().iter().enumerate() {
        let _ = std::mem::replace(&mut sk_bytes_vec[i], sk_bytes[i]);
    }

    secp256k1::fields::Fr::read(sk_bytes_vec.as_slice()).unwrap()
}

fn coord_to_hex(
    coord: biginteger::BigInteger320
) -> String {
    let mut coord_bytes = vec![];
    let _ = coord.write(&mut coord_bytes);
    coord_bytes.reverse();

    String::from(hex::encode(coord_bytes))
}

fn hardcoded_sk() -> String {
   "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464".to_string()
}

fn hardcoded_r() -> String {
   "93b9323b629f251b8f3fc2dd11f4672c5544e8230d493eceea98a90bda789808".to_string()
}

pub fn hardcoded_msg() -> String {
    "An example app message string".to_string()
}

#[test]
pub fn test_keygen() {
    let (mut rng, g) = test_template();
    let pp = Parameters{ g };

    let (pk, sk) = Scheme::keygen(&pp, &mut rng).unwrap();

    let expected_pk = g.mul(sk);
    assert_eq!(pk, expected_pk);
}

#[test]
pub fn test_sign_and_verify() {
    let (mut rng, g) = test_template();
    let pp = Parameters{ g };

    let message = b"Message";
    let keypair = Scheme::keygen(&pp, &mut rng).unwrap();

    let sig = Scheme::sign(
        &pp,
        &mut rng,
        (&keypair.0, &keypair.1),
        message
    ).unwrap();

    let is_valid = Scheme::verify_non_zk(
        &pp,
        &keypair.0,
        &sig,
        message,
    );
    assert!(is_valid.unwrap());
}

pub fn compute_h() -> GroupAffine::<Secp256k1Parameters> {
    let msg = hardcoded_msg();
    let message = msg.as_bytes();
 
    let sk = hex_to_fr(&hardcoded_sk());
    let (_, g) = test_template();
    let pk_projective = g.mul(sk);
    let pk = GroupAffine::<Secp256k1Parameters>::from(pk_projective);

    let h = hash_to_curve::<secp256k1::fields::Fq, Secp256k1Parameters>(message, &pk);
    h
}

#[test]
pub fn test_against_zk_nullifier_sig_pk() {
    // Check the pubkey generated from the hardcoded secret key
    let sk = hex_to_fr(&hardcoded_sk());

    let (_, g) = test_template();
    let pk_projective = g.mul(sk);
    let pk = GroupAffine::<Secp256k1Parameters>::from(pk_projective);
    
    assert_eq!(coord_to_hex(pk.x.into()), "00000000000000000cec028ee08d09e02672a68310814354f9eabfff0de6dacc1cd3a774496076ae");
    assert_eq!(coord_to_hex(pk.y.into()), "0000000000000000eff471fba0409897b6a48e8801ad12f95d0009b753cf8f51c128bf6b0bd27fbd");
}

#[test]
pub fn test_against_zk_nullifier_sig_g_r() {
    // Test g^r using the hardcoded r
    let r = secp256k1::fields::Fr::from(hex_to_fr(&hardcoded_r()));
    let (_, g) = test_template();
    let g_r_projective = g.mul(r);
    let g_r = GroupAffine::<Secp256k1Parameters>::from(g_r_projective);
    assert_eq!(coord_to_hex(g_r.x.into()), "00000000000000009d8ca4350e7e2ad27abc6d2a281365818076662962a28429590e2dc736fe9804");
    assert_eq!(coord_to_hex(g_r.y.into()), "0000000000000000ff08c30b8afd4e854623c835d9c3aac6bcebe45112472d9b9054816a7670c5a1");
}

//TODO: add test vectors for hash_to_curve
#[test]
pub fn test_against_zk_nullifier_sig_h() {
    let h = compute_h();

    assert_eq!(coord_to_hex(h.x.into()), "000000000000000027cdee7f388ba2981f4ef3a499abdd7506281bdc4f535109ec66e0e80824a37b");
    assert_eq!(coord_to_hex(h.y.into()), "00000000000000008beb2fe7adeecadb3e99be05c3979bcf734c2caa768aaed09a26cb48d1236f42");
}

#[test]
pub fn test_against_zk_nullifier_sig_h_r() {
    let h = compute_h();

    // Test h^r using the hardcoded r
    let r = secp256k1::fields::Fr::from(hex_to_fr(&hardcoded_r()));
    let h_r_projective = h.mul(r);
    let h_r = GroupAffine::<Secp256k1Parameters>::from(h_r_projective);
    assert_eq!(coord_to_hex(h_r.x.into()), "0000000000000000adf22a767a1f43b8dc4e77ce00c4eea54a63b10126e03e5f418d460e1fe1b2c2");
    assert_eq!(coord_to_hex(h_r.y.into()), "0000000000000000d9bc5ce25d1fd63dd56fe6b7b2260747758c0bdda4b0e09a4028eed29a8049d8");
}

#[test]
pub fn test_against_zk_nullifier_sig_h_sk() {
    let h = compute_h();
    let sk = hex_to_fr(&hardcoded_sk());

    // Test h^r using the hardcoded sk
    let h_sk_projective = h.mul(sk);
    let h_sk = GroupAffine::<Secp256k1Parameters>::from(h_sk_projective);
    assert_eq!(coord_to_hex(h_sk.x.into()), "000000000000000015db23237364493d346e7ecf367c65c3861ba088e53a757deb5e8eaaa3e24e3f");
    assert_eq!(coord_to_hex(h_sk.y.into()), "0000000000000000c3623b03cd7d92136dba28f6077e28c8fb731cc585e61fcb26d5c8f0f3b83fd0");
}

#[test]
pub fn test_against_zk_nullifier_sig_c_and_s() {
    let r = secp256k1::fields::Fr::from(hex_to_fr(&hardcoded_r()));
    let message = hardcoded_msg();
    let message = message.as_bytes();
    let sk = hex_to_fr(&hardcoded_sk());
    let (_, g) = test_template();
    let pp = Parameters{ g };
    let pk_projective = g.mul(sk);
    let pk = GroupAffine::<Secp256k1Parameters>::from(pk_projective);

    let keypair = (pk, sk);
    let sig = Scheme::sign_with_r(
        &pp,
        (&keypair.0, &keypair.1),
        message,
        r
    ).unwrap();

    assert_eq!(coord_to_hex(sig.c.into()), "00000000000000009de4daa951b8728db267eea9aa54ae48f8496bfde11387e91a39b261782a2b43");
    assert_eq!(coord_to_hex(sig.s.into()), "0000000000000000b4e19b36312e7489b708e9e277280ae51ca0bbf350add3b93c897902040fdd76");
}
