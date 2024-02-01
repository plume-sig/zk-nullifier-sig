<tests/common/mod.rs> contains some comments related to the both `tests` among the stuff they share, so give it look if you want to see some comments.

```rust
fn test_signature<'a>(version: PlumeVersion) -> PlumeSignature<'a> {
    // Fixed key nullifier, secret key, and random value for testing
    // Normally a secure enclave would generate these values, and output to a wallet implementation
    let (
        pk, nullifier, c, r_sk_c, g_r, 
        hash_m_pk_pow_r
    ) = test_gen_signals(M, version);

    // The signer's secret key. It is only accessed within the secure enclave.
    let sk = gen_test_scalar_sk();

    // The user's public key: g^sk.
    let pk = &G * &sk;

    // Test encode_pt()
    let g_as_bytes = encode_pt(&G);
    assert_eq!(
        hex::encode(g_as_bytes),
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
    // Test byte_array_to_scalar()
    let scalar = byte_array_to_scalar(&c); // TODO this `fn` looks suspicious as in reproducing const time ops
    assert_eq!(
        hex::encode(scalar.to_bytes()),
        "c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83254"
    );
    // Test the hash-to-curve algorithm
    let h = hash_to_secp(b"abc");
    assert_eq!(
        hex::encode(h.to_affine().to_encoded_point(false).x().unwrap()),
        "3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b"
    );
    assert_eq!(
        hex::encode(h.to_affine().to_encoded_point(false).y().unwrap()),
        "7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6"
    );

    // Print nullifier
    println!(
        "nullifier.x: {:?}",
        hex::encode(nullifier.to_affine().to_encoded_point(false).x().unwrap())
    );
    println!(
        "nullifier.y: {:?}",
        hex::encode(nullifier.to_affine().to_encoded_point(false).y().unwrap())
    );
    // Print c
    println!("c: {:?}", hex::encode(&c));
    // Print r_sk_c
    println!("r_sk_c: {:?}", hex::encode(r_sk_c.to_bytes()));
    // Print g_r
    println!(
        "g_r.x: {:?}",
        hex::encode(
            g_r.unwrap()
                .to_affine()
                .to_encoded_point(false)
                .x()
                .unwrap()
        )
    );
    println!(
        "g_r.y: {:?}",
        hex::encode(
            g_r.unwrap()
                .to_affine()
                .to_encoded_point(false)
                .y()
                .unwrap()
        )
    );
    // Print hash_m_pk_pow_r
    println!(
        "hash_m_pk_pow_r.x: {:?}",
        hex::encode(
            hash_m_pk_pow_r
                .unwrap()
                .to_affine()
                .to_encoded_point(false)
                .x()
                .unwrap()
        )
    );
    println!(
        "hash_m_pk_pow_r.y: {:?}",
        hex::encode(
            hash_m_pk_pow_r
                .unwrap()
                .to_affine()
                .to_encoded_point(false)
                .y()
                .unwrap()
        )
    );

    PlumeSignature::<'a> {
        message: M,
        pk: &pk,
        nullifier: &nullifier,
        c: &c,
        s: &r_sk_c,
        v1: match version {
            PlumeVersion::V1 => Some(PlumeSignatureV1Fields {
                r_point: &g_r.unwrap(),
                hashed_to_curve_r: &hash_m_pk_pow_r.unwrap(),
            }),
            PlumeVersion::V2 => None,
        },
    }
}

// Verify the signals, normally this would happen in ZK with only the nullifier public, which would have a zk verifier instead
// The wallet should probably run this prior to snarkify-ing as a sanity check
// `M` and nullifier should be public, so we can verify that they are correct
```