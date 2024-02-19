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
struct PlumeInput<F: BigPrimeField> {
    // Public
    nullifier: EcPoint<F, ProperCrtUint<F>>,
    s: ProperCrtUint<F>,
    // Private
    c: ProperCrtUint<F>,
    pk: EcPoint<F, ProperCrtUint<F>>,
    m: Vec<AssignedValue<F>>, // bytes
}

fn bytes_le_to_limb<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    bytes: &[AssignedValue<F>],
) -> AssignedValue<F> {
    // TODO: Add assert to ensure that bytes len is less than to max number of bytes a limb holds
    let mut limb = ctx.load_zero();

    for (i, byte) in bytes.iter().enumerate() {
        let shift = ctx.load_constant(F::from_u128(1u128 << ((i as u128) * 8u128)));
        let shifted_byte = gate.mul(ctx, *byte, shift);

        limb = gate.add(ctx, limb, shifted_byte);
    }

    limb
}

fn limbs_to_bytes_be<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    limbs: &[AssignedValue<F>],
    max_limb_bits: usize,
) -> Vec<AssignedValue<F>> {
    let total_bytes = (limbs.len() * max_limb_bits) / 8;
    let mut bytes = Vec::<AssignedValue<F>>::with_capacity(total_bytes);

    for limb in limbs.iter().rev() {
        let mut limb_bytes = limb.value().to_bytes_le();
        limb_bytes.reverse();
        let mut limb_bytes_trimmed = limb_bytes
            .iter()
            .skip_while(|&x| *x == 0)
            .cloned()
            .collect::<Vec<_>>();
        limb_bytes_trimmed.reverse();
        let mut limb_bytes_assigned = limb_bytes_trimmed
            .iter()
            .map(|byte| ctx.load_witness(F::from(*byte as u64)))
            .collect::<Vec<_>>();
        let _limb = bytes_le_to_limb(ctx, gate, &limb_bytes_assigned);

        assert_eq!(limb.value(), _limb.value());
        ctx.constrain_equal(&_limb, limb);

        limb_bytes_assigned.reverse();
        bytes.append(&mut limb_bytes_assigned);
    }

    bytes
}

fn compress_point<F: BigPrimeField>(
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
    compressed_pt.append(&mut limbs_to_bytes_be(
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
    let message = vec![m.as_slice(), compressed_pk.as_slice()].concat();
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
    let input = vec![
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
    let c_bytes = limbs_to_bytes_be(
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
            bn256::Fr, secp256k1::Secp256k1Affine, secq256k1::Fq as Fp, CurveAffine,
        },
        utils::{testing::base_test, ScalarField},
    };
    use halo2_ecc::{
        ecc::EccChip,
        fields::FieldChip,
        secp256k1::{sha256::Sha256Chip, FpChip},
    };
    use num_bigint::BigUint;
    use num_traits::Num;

    use crate::plume::PlumeInput;

    use super::verify_plume;

    #[test]
    fn test_plume_verify() {
        // Test data
        // m: "416e206578616d706c6520617070206d65737361676520737472696e67"
        // pk.x: "0cec028ee08d09e02672a68310814354f9eabfff0de6dacc1cd3a774496076ae"
        // pk.y: "eff471fba0409897b6a48e8801ad12f95d0009b753cf8f51c128bf6b0bd27fbd"
        // nullifier.x: "57bc3ed28172ef8adde4b9e0c2cce745fcc5a66473a45c1e626f1d0c67e55830"
        // nullifier.y: "6a2f41488d58f33ae46edd2188e111609f9f3ae67ea38fa891d6087fe59ecb73"
        // c: "c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83255"
        // s: "383a44baf62afb3e16b18c222b230e7b5226bc9044efb19e8863044183f69bed"

        // Inputs
        let m = b"An example app message string"
            .iter()
            .map(|b| Fr::from(*b as u64))
            .collect::<Vec<_>>();

        let pk = Secp256k1Affine::from_xy(
            Fp::from_bytes_le(
                BigUint::from_str_radix(
                    "0cec028ee08d09e02672a68310814354f9eabfff0de6dacc1cd3a774496076ae",
                    16,
                )
                .unwrap()
                .to_bytes_le()
                .as_slice(),
            ),
            Fp::from_bytes_le(
                BigUint::from_str_radix(
                    "eff471fba0409897b6a48e8801ad12f95d0009b753cf8f51c128bf6b0bd27fbd",
                    16,
                )
                .unwrap()
                .to_bytes_le()
                .as_slice(),
            ),
        )
        .unwrap();

        let nullifier = Secp256k1Affine::from_xy(
            Fp::from_bytes_le(
                BigUint::from_str_radix(
                    "57bc3ed28172ef8adde4b9e0c2cce745fcc5a66473a45c1e626f1d0c67e55830",
                    16,
                )
                .unwrap()
                .to_bytes_le()
                .as_slice(),
            ),
            Fp::from_bytes_le(
                BigUint::from_str_radix(
                    "6a2f41488d58f33ae46edd2188e111609f9f3ae67ea38fa891d6087fe59ecb73",
                    16,
                )
                .unwrap()
                .to_bytes_le()
                .as_slice(),
            ),
        )
        .unwrap();

        let c = Fp::from_bytes_le(
            BigUint::from_str_radix(
                "c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83255",
                16,
            )
            .unwrap()
            .to_bytes_le()
            .as_slice(),
        );

        let s = Fp::from_bytes_le(
            BigUint::from_str_radix(
                "383a44baf62afb3e16b18c222b230e7b5226bc9044efb19e8863044183f69bed",
                16,
            )
            .unwrap()
            .to_bytes_le()
            .as_slice(),
        );

        base_test()
            .k(14)
            .lookup_bits(13)
            .expect_satisfied(true)
            .run(|ctx, range| {
                let fp_chip = FpChip::<Fr>::new(range, 88, 3);
                let ecc_chip = EccChip::<Fr, FpChip<Fr>>::new(&fp_chip);

                let sha256_chip = Sha256Chip::new(range);

                let nullifier = ecc_chip.load_private_unchecked(ctx, (nullifier.x, nullifier.y));
                let s = fp_chip.load_private(ctx, s);
                let c = fp_chip.load_private(ctx, c);
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
    }
}
