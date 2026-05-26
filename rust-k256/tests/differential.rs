use k256::{
    elliptic_curve::{
        hash2curve::{ExpandMsgXmd, GroupDigest},
        point::NonIdentity,
        sec1::ToEncodedPoint,
    },
    sha2::{Digest, Sha256},
    Secp256k1,
};
use plume_arkworks::{
    self as ark, sign_with_r as ark_sign_with_r, BigInteger, CurveGroup,
    PlumeVersion as ArkVersion, PrimeField, SWCurveConfig,
};
use plume_rustcrypto::{NonZeroScalar, PlumeSignature, PlumeSignatureV1Fields, SecretKey, DST};
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn random_valid_secret_key_bytes(rng: &mut ChaCha20Rng) -> [u8; 32] {
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if SecretKey::from_slice(&bytes).is_ok() {
            return bytes;
        }
    }
}

fn ark_fr_to_bytes_be(fr: &ark::secp256k1::Fr) -> [u8; 32] {
    let bytes = (*fr).into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let start = out.len().saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes);
    out
}

fn ark_point_bytes(point: &ark::secp256k1::Affine) -> Vec<u8> {
    ark::sec1_affine(point)
        .expect("point should be non-zero")
        .to_vec()
}

fn k256_point_bytes(point: &impl ToEncodedPoint<k256::Secp256k1>) -> Vec<u8> {
    point.to_encoded_point(true).as_bytes().to_vec()
}

fn sign_with_r_like_k256(
    secret_key: &SecretKey,
    msg: &[u8],
    r_secret: &SecretKey,
    v1: bool,
) -> PlumeSignature {
    let r_point = r_secret.public_key();
    let pk = secret_key.public_key();
    let pk_bytes = pk.to_encoded_point(true).to_bytes();

    let hashed_to_curve = NonIdentity::new(
        Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[msg, &pk_bytes], &[DST])
            .expect("hash_to_curve should work for test vectors"),
    )
    .expect("hash_to_curve should not map to identity for test vectors");

    let r_scalar = r_secret.to_nonzero_scalar();
    let hashed_to_curve_r = hashed_to_curve * r_scalar;
    let nullifier = hashed_to_curve * secret_key.to_nonzero_scalar();
    let hashed_to_curve_point = hashed_to_curve.to_point().to_affine();
    let nullifier_point = nullifier.to_point().to_affine();
    let hashed_to_curve_r_point = hashed_to_curve_r.to_point().to_affine();

    let mut hasher = Sha256::new();
    if v1 {
        hasher.update(
            k256::ProjectivePoint::GENERATOR
                .to_encoded_point(true)
                .as_bytes(),
        );
        hasher.update(pk_bytes);
        hasher.update(hashed_to_curve_point.to_encoded_point(true).as_bytes());
    }
    hasher.update(nullifier_point.to_encoded_point(true).as_bytes());
    hasher.update(r_point.to_encoded_point(true).as_bytes());
    hasher.update(hashed_to_curve_r_point.to_encoded_point(true).as_bytes());

    let c = hasher.finalize();
    let c_scalar = NonZeroScalar::from_repr(c).expect("SHA-256 output cannot be zero");
    let s_scalar = NonZeroScalar::new(*r_scalar + *(c_scalar * secret_key.to_nonzero_scalar()))
        .expect("signature scalar should not be zero");

    PlumeSignature {
        message: msg.to_owned(),
        pk: pk.into(),
        nullifier: nullifier_point,
        c: c_scalar,
        s: s_scalar,
        v1specific: if v1 {
            Some(PlumeSignatureV1Fields {
                r_point: r_point.into(),
                hashed_to_curve_r: hashed_to_curve_r_point,
            })
        } else {
            None
        },
    }
}

fn assert_ark_k256_equal(
    k_sig: &PlumeSignature,
    a_sig: &(ark::PlumeSignaturePublic, ark::PlumeSignaturePrivate),
    ark_pk: &ark::secp256k1::Affine,
    version: bool,
) {
    assert_eq!(k_sig.message, a_sig.0.message);
    assert_eq!(k256_point_bytes(&k_sig.pk), ark_point_bytes(ark_pk));
    assert_eq!(
        k256_point_bytes(&k_sig.nullifier),
        ark_point_bytes(&a_sig.0.nullifier)
    );
    assert_eq!(
        k_sig.c.to_bytes().as_slice(),
        ark_fr_to_bytes_be(&a_sig.1.digest_private).as_ref()
    );
    assert_eq!(
        k_sig.s.to_bytes().as_slice(),
        ark_fr_to_bytes_be(&a_sig.0.s).as_ref()
    );

    match version {
        true => {
            let k_v1 = k_sig.v1specific.as_ref().expect("v1 fields must exist");
            assert_eq!(
                k256_point_bytes(&k_v1.r_point),
                ark_point_bytes(&a_sig.1.r_point)
            );
            assert_eq!(
                k256_point_bytes(&k_v1.hashed_to_curve_r),
                ark_point_bytes(&a_sig.1.hashed_to_curve_r)
            );
            assert_eq!(a_sig.0.variant, Some(ArkVersion::V1));
            assert_eq!(a_sig.1.variant, ArkVersion::V1);
        }
        false => {
            assert!(k_sig.v1specific.is_none());
            assert_eq!(a_sig.0.variant, Some(ArkVersion::V2));
            assert_eq!(a_sig.1.variant, ArkVersion::V2);
        }
    }
}

#[test]
fn differential_signing_matches_rust_arkworks() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    for case in 0..12u8 {
        let message_len = 8 + (case as usize % 24);
        let mut message = vec![0u8; message_len];
        rng.fill_bytes(&mut message);

        let sk_bytes = random_valid_secret_key_bytes(&mut rng);
        let r_bytes = random_valid_secret_key_bytes(&mut rng);

        let secret_key = SecretKey::from_slice(&sk_bytes).expect("valid secret key");
        let r_secret = SecretKey::from_slice(&r_bytes).expect("valid nonce key");

        let ark_sk = ark::secp256k1::Fr::from_be_bytes_mod_order(&sk_bytes);
        let ark_r = ark::secp256k1::Fr::from_be_bytes_mod_order(&r_bytes);
        let ark_pk = (ark::secp256k1::Config::GENERATOR * ark_sk).into_affine();

        assert_eq!(
            k256_point_bytes(&secret_key.public_key()),
            ark_point_bytes(&ark_pk)
        );

        for version in [true, false] {
            let k_sig = sign_with_r_like_k256(&secret_key, &message, &r_secret, version);
            let a_sig = ark_sign_with_r(
                (&ark_pk, &ark_sk),
                &message,
                ark_r,
                match version {
                    true => ArkVersion::V1,
                    false => ArkVersion::V2,
                },
            )
            .expect("arkworks signing should succeed");

            assert_ark_k256_equal(&k_sig, &a_sig, &ark_pk, version);
        }
    }
}
