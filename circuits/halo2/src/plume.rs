use halo2_base::{
    gates::{GateChip, GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::halo2curves::secp256k1::Secp256k1Affine,
    utils::BigPrimeField,
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::{big_is_even, ProperCrtUint},
    ecc::EcPoint,
    fields::FieldChip,
    secp256k1::{hash_to_curve::hash_to_curve, sha256::Sha256Chip, Secp256k1Chip},
};

#[derive(Clone, Debug)]
pub struct PlumeInput<F: BigPrimeField> {
    // Public
    nullifier: EcPoint<F, ProperCrtUint<F>>,
    s: ProperCrtUint<F>,
    // Private
    c: ProperCrtUint<F>,
    pk: EcPoint<F, ProperCrtUint<F>>,
    m: Vec<AssignedValue<F>>, // bytes
}

impl<F: BigPrimeField> PlumeInput<F> {
    pub fn new(
        nullifier: EcPoint<F, ProperCrtUint<F>>,
        s: ProperCrtUint<F>,
        c: ProperCrtUint<F>,
        pk: EcPoint<F, ProperCrtUint<F>>,
        m: Vec<AssignedValue<F>>,
    ) -> Self {
        Self {
            nullifier,
            s,
            c,
            pk,
            m,
        }
    }
}

fn bytes_le_to_limb<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    bytes: &[AssignedValue<F>],
) -> AssignedValue<F> {
    let mut limb = ctx.load_zero();

    for (i, byte) in bytes.iter().enumerate() {
        let shift = ctx.load_constant(F::from_u128(1u128 << ((i as u128) * 8u128)));
        let shifted_byte = gate.mul(ctx, *byte, shift);

        limb = gate.add(ctx, limb, shifted_byte);
    }

    limb
}

fn limbs_to_bytes32_be<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    limbs: &[AssignedValue<F>],
    max_limb_bits: usize,
) -> Vec<AssignedValue<F>> {
    let total_bytes = (limbs.len() * max_limb_bits) / 8;
    let mut bytes = Vec::<AssignedValue<F>>::with_capacity(total_bytes);

    for limb in limbs.iter().rev() {
        let limb_bytes = limb.value().to_bytes_le();
        let mut limb_bytes = limb_bytes[0..11]
            .iter()
            .map(|byte| ctx.load_witness(F::from(*byte as u64)))
            .collect::<Vec<_>>();
        let _limb = bytes_le_to_limb(ctx, gate, &limb_bytes);

        assert_eq!(limb.value(), _limb.value());
        ctx.constrain_equal(&_limb, limb);

        limb_bytes.reverse();
        bytes.append(&mut limb_bytes);
    }

    bytes[1..].to_vec()
}

pub fn compress_point<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    pt: &EcPoint<F, ProperCrtUint<F>>,
) -> Vec<AssignedValue<F>> {
    let x = pt.x();
    let y = pt.y();

    let mut compressed_pt = Vec::<AssignedValue<F>>::with_capacity(33);

    let is_y_even = big_is_even::positive(
        range,
        ctx,
        y.as_ref().truncation.clone(),
        y.as_ref().truncation.max_limb_bits,
    );

    let tag = range.gate().select(
        ctx,
        QuantumCell::Constant(F::from(2u64)),
        QuantumCell::Constant(F::from(3u64)),
        is_y_even,
    );

    compressed_pt.push(tag);
    compressed_pt.append(&mut limbs_to_bytes32_be(
        ctx,
        range.gate(),
        x.as_ref().limbs(),
        x.as_ref().truncation.max_limb_bits,
    ));

    compressed_pt
}

pub fn verify_plume<F: BigPrimeField>(
    ctx: &mut Context<F>,
    secp256k1_chip: &Secp256k1Chip<'_, F>,
    sha256_chip: &Sha256Chip<F>,
    fixed_window_bits: usize,
    var_window_bits: usize,
    input: PlumeInput<F>,
) {
    let PlumeInput {
        nullifier,
        s,
        c,
        pk,
        m,
    } = input;

    let base_chip = secp256k1_chip.field_chip();
    let range = base_chip.range();

    // 1. compute hash[m, pk]
    let compressed_pk = compress_point(ctx, range, &pk);
    let message = [m.as_slice(), compressed_pk.as_slice()].concat();
    let hashed_message = hash_to_curve(ctx, secp256k1_chip, sha256_chip, message.as_slice());

    // 2. compute g^s
    let g = secp256k1_chip.load_private::<Secp256k1Affine>(
        ctx,
        (
            Secp256k1Affine::generator().x,
            Secp256k1Affine::generator().y,
        ),
    );
    let gs = secp256k1_chip.fixed_base_scalar_mult(
        ctx,
        &Secp256k1Affine::generator(),
        s.limbs().to_vec(),
        base_chip.limb_bits,
        fixed_window_bits,
    );

    // 3. compute pk^c
    let pkc = secp256k1_chip.scalar_mult::<Secp256k1Affine>(
        ctx,
        pk,
        c.limbs().to_vec(),
        base_chip.limb_bits,
        var_window_bits,
    );

    // 4. compute g^s / pk^c
    let pkc_inv = secp256k1_chip.negate(ctx, pkc);
    let gs_pkc = secp256k1_chip.add_unequal(ctx, &gs, &pkc_inv, false);

    // 5. compute hash[m, pk]^s
    let hashed_message_s = secp256k1_chip.scalar_mult::<Secp256k1Affine>(
        ctx,
        hashed_message.clone(),
        s.limbs().to_vec(),
        base_chip.limb_bits,
        var_window_bits,
    );

    // 6. compute nullifier^c
    let nullifierc = secp256k1_chip.scalar_mult::<Secp256k1Affine>(
        ctx,
        nullifier.clone(),
        c.limbs().to_vec(),
        base_chip.limb_bits,
        var_window_bits,
    );

    // 7. compute hash[m, pk]^s / (nullifier)^c
    let nullifierc_inv = secp256k1_chip.negate(ctx, nullifierc);
    let hashed_message_s_nullifierc =
        secp256k1_chip.add_unequal(ctx, &hashed_message_s, &nullifierc_inv, false);

    // 8. compute hash2(g, pk, hash[m, pk], nullifier, g^s / pk^c, hash[m, pk]^s / nullifier^c)
    let input = [
        compress_point(ctx, range, &g).as_slice(),
        compressed_pk.as_slice(),
        compress_point(ctx, range, &hashed_message).as_slice(),
        compress_point(ctx, range, &nullifier).as_slice(),
        compress_point(ctx, range, &gs_pkc).as_slice(),
        compress_point(ctx, range, &hashed_message_s_nullifierc).as_slice(),
    ]
    .concat()
    .iter()
    .map(|val| QuantumCell::Existing(*val))
    .collect::<Vec<_>>();

    let final_hash = sha256_chip.digest(ctx, input).unwrap();

    // 9. constraint hash2(g, pk, hash[m, pk], nullifier, g^s / pk^c, hash[m, pk]^s / nullifier^c) == c
    let c_bytes = limbs_to_bytes32_be(
        ctx,
        range.gate(),
        c.limbs(),
        c.as_ref().truncation.max_limb_bits,
    );
    c_bytes
        .iter()
        .zip(final_hash.iter())
        .for_each(|(c_byte, hash_byte)| {
            assert_eq!(c_byte.value(), hash_byte.value());
            ctx.constrain_equal(c_byte, hash_byte);
        });
}

#[cfg(test)]
mod test {
    use halo2_base::{
        halo2_proofs::halo2curves::{
            bn256::Fr,
            secp256k1::{Secp256k1, Secp256k1Affine},
            secq256k1::{Fp, Fq},
            CurveAffine,
        },
        utils::{testing::base_test, ScalarField},
    };
    use halo2_ecc::{
        ecc::EccChip,
        fields::FieldChip,
        secp256k1::{sha256::Sha256Chip, FpChip, FqChip},
    };
    use k256::{
        elliptic_curve::{
            group::Curve,
            hash2curve::{ExpandMsgXmd, GroupDigest},
            sec1::ToEncodedPoint,
            Field, PrimeField,
        },
        sha2::{Digest, Sha256 as K256Sha256},
        Secp256k1 as K256Secp256k1,
    };
    use rand::rngs::OsRng;

    use crate::plume::PlumeInput;

    use super::verify_plume;

    fn compress_point(point: &Secp256k1Affine) -> [u8; 33] {
        let mut x = point.x.to_bytes();
        x.reverse();
        let y_is_odd = if point.y.is_odd().unwrap_u8() == 1u8 {
            3u8
        } else {
            2u8
        };
        let mut compressed_pk = [0u8; 33];
        compressed_pk[0] = y_is_odd;
        compressed_pk[1..].copy_from_slice(&x);

        compressed_pk
    }

    fn hash_to_curve(message: &[u8], compressed_pk: &[u8; 33]) -> Secp256k1Affine {
        let hashed_to_curve = K256Secp256k1::hash_from_bytes::<ExpandMsgXmd<K256Sha256>>(
            &[[message, compressed_pk].concat().as_slice()],
            &[b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"],
        )
        .unwrap()
        .to_affine();
        let hashed_to_curve = hashed_to_curve
            .to_encoded_point(false)
            .to_bytes()
            .into_vec();
        assert_eq!(hashed_to_curve.len(), 65);

        let mut x = hashed_to_curve[1..33].to_vec();
        x.reverse();
        let mut y = hashed_to_curve[33..].to_vec();
        y.reverse();

        Secp256k1Affine::from_xy(
            Fq::from_bytes_le(x.as_slice()),
            Fq::from_bytes_le(y.as_slice()),
        )
        .unwrap()
    }

    fn verify_nullifier(
        message: &[u8],
        nullifier: &Secp256k1Affine,
        pk: &Secp256k1Affine,
        s: &Fp,
        c: &Fp,
    ) {
        let compressed_pk = compress_point(&pk);
        let hashed_to_curve = hash_to_curve(message, &compressed_pk);
        let hashed_to_curve_s_nullifier_c = (hashed_to_curve * s - nullifier * c).to_affine();
        let gs_pkc = (Secp256k1::generator() * s - pk * c).to_affine();

        let mut sha_hasher = K256Sha256::new();
        sha_hasher.update(
            vec![
                compress_point(&Secp256k1::generator().to_affine()),
                compressed_pk,
                compress_point(&hashed_to_curve),
                compress_point(&nullifier),
                compress_point(&gs_pkc),
                compress_point(&hashed_to_curve_s_nullifier_c),
            ]
            .concat(),
        );

        let mut _c = sha_hasher.finalize();
        _c.reverse();
        let _c = Fp::from_bytes_le(_c.as_slice());

        assert_eq!(*c, _c);
    }

    fn gen_test_nullifier(sk: &Fp, message: &[u8]) -> (Secp256k1Affine, Fp, Fp) {
        let pk = (Secp256k1::generator() * sk).to_affine();
        let compressed_pk = compress_point(&pk);

        let hashed_to_curve = hash_to_curve(message, &compressed_pk);

        let hashed_to_curve_sk = (hashed_to_curve * sk).to_affine();

        let r = Fp::random(OsRng);
        let g_r = (Secp256k1::generator() * r).to_affine();
        let hashed_to_curve_r = (hashed_to_curve * r).to_affine();

        let mut sha_hasher = K256Sha256::new();
        sha_hasher.update(
            vec![
                compress_point(&Secp256k1::generator().to_affine()),
                compressed_pk,
                compress_point(&hashed_to_curve),
                compress_point(&hashed_to_curve_sk),
                compress_point(&g_r),
                compress_point(&hashed_to_curve_r),
            ]
            .concat(),
        );

        let mut c = sha_hasher.finalize();
        c.reverse();

        let c = Fp::from_bytes_le(c.as_slice());
        let s = r + sk * c;

        (hashed_to_curve_sk, s, c)
    }

    #[test]
    fn test_plume_verify() {
        #[derive(Clone, Debug)]
        struct TestPlumeInput {
            nullifier: (Fq, Fq),
            s: Fp,
            c: Fp,
            pk: (Fq, Fq),
            m: Vec<Fr>,
        }

        // Inputs
        let m = b"An example app message string"
            .iter()
            .map(|b| Fr::from(*b as u64))
            .collect::<Vec<_>>();

        let sk = Fp::random(OsRng);
        let pk = (Secp256k1::generator() * sk).to_affine();
        let (nullifier, s, c) = gen_test_nullifier(&sk, b"An example app message string");
        verify_nullifier(b"An example app message string", &nullifier, &pk, &s, &c);

        let test_data = TestPlumeInput {
            nullifier: (nullifier.x, nullifier.y),
            s,
            c,
            pk: (pk.x, pk.y),
            m: m.clone(),
        };

        let bench = false;

        if !bench {
            base_test()
                .k(14)
                .lookup_bits(13)
                .expect_satisfied(true)
                .run(|ctx, range| {
                    let fp_chip = FpChip::<Fr>::new(range, 88, 3);
                    let fq_chip = FqChip::<Fr>::new(range, 88, 3);
                    let ecc_chip = EccChip::<Fr, FpChip<Fr>>::new(&fp_chip);

                    let sha256_chip = Sha256Chip::new(range);

                    let nullifier =
                        ecc_chip.load_private_unchecked(ctx, (nullifier.x, nullifier.y));
                    let s = fq_chip.load_private(ctx, s);
                    let c = fq_chip.load_private(ctx, c);
                    let pk = ecc_chip.load_private_unchecked(ctx, (pk.x, pk.y));
                    let m = m.iter().map(|m| ctx.load_witness(*m)).collect::<Vec<_>>();

                    let plume_input = PlumeInput {
                        nullifier,
                        s,
                        c,
                        pk,
                        m,
                    };

                    verify_plume::<Fr>(ctx, &ecc_chip, &sha256_chip, 4, 4, plume_input)
                });
        } else {
            let stats = base_test()
                .k(15)
                .lookup_bits(14)
                .expect_satisfied(true)
                .bench_builder(
                    test_data.clone(),
                    test_data.clone(),
                    |pool, range, test_data: TestPlumeInput| {
                        let ctx = pool.main();

                        let fp_chip = FpChip::<Fr>::new(range, 88, 3);
                        let fq_chip = FqChip::<Fr>::new(range, 88, 3);
                        let ecc_chip = EccChip::<Fr, FpChip<Fr>>::new(&fp_chip);

                        let sha256_chip = Sha256Chip::new(range);

                        let nullifier = ecc_chip.load_private_unchecked(
                            ctx,
                            (test_data.nullifier.0, test_data.nullifier.1),
                        );
                        let s = fq_chip.load_private(ctx, test_data.s);
                        let c = fq_chip.load_private(ctx, test_data.c);
                        let pk =
                            ecc_chip.load_private_unchecked(ctx, (test_data.pk.0, test_data.pk.1));
                        let m = test_data
                            .m
                            .iter()
                            .map(|m| ctx.load_witness(*m))
                            .collect::<Vec<_>>();

                        let plume_input = PlumeInput {
                            nullifier,
                            s,
                            c,
                            pk,
                            m,
                        };

                        verify_plume::<Fr>(ctx, &ecc_chip, &sha256_chip, 4, 4, plume_input)
                    },
                );

            println!("config params = {:?}", stats.config_params);
            println!("vk time = {:?}", stats.vk_time.time.elapsed());
            println!("pk time = {:?}", stats.pk_time.time.elapsed());
            println!("proof time = {:?}", stats.proof_time.time.elapsed());
            println!("proof size = {:?}", stats.proof_size);
            println!("verify time = {:?}", stats.verify_time.time.elapsed());
        }
    }
}
