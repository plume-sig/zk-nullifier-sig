use halo2_base::{
    utils::{BigPrimeField, CurveAffineExt},
    AssignedValue, Context,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    ecc::{fixed_base, scalar_multiply, EcPoint, EccChip},
    fields::fp::FpChip,
};

#[derive(Clone, Debug)]
struct PlumeInput<F: BigPrimeField> {
    // Public
    nullifier: EcPoint<F, ProperCrtUint<F>>,
    s: ProperCrtUint<F>,
    // Private
    c: ProperCrtUint<F>,
    pk: EcPoint<F, ProperCrtUint<F>>,
    m: Vec<AssignedValue<F>>,
    // Test Inputs
    _gs: EcPoint<F, ProperCrtUint<F>>,
    _pkc: EcPoint<F, ProperCrtUint<F>>,
    _pkc_inv: EcPoint<F, ProperCrtUint<F>>,
    _gs_pkc: EcPoint<F, ProperCrtUint<F>>,
    _nullifierc: EcPoint<F, ProperCrtUint<F>>,
    _nullifierc_inv: EcPoint<F, ProperCrtUint<F>>,
}

fn verify_plume<F: BigPrimeField, CF: BigPrimeField, SF: BigPrimeField, GA>(
    ctx: &mut Context<F>,
    chip: &EccChip<F, FpChip<F, CF>>,
    fixed_window_bits: usize,
    var_window_bits: usize,
    input: PlumeInput<F>,
) where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
{
    let PlumeInput {
        nullifier,
        s,
        c,
        pk,
        m,
        _gs,
        _pkc,
        _pkc_inv,
        _gs_pkc,
        _nullifierc,
        _nullifierc_inv,
    } = input;

    let base_chip = chip.field_chip;

    // 1. compute hash[m, pk]test_plume_verify
    // TODO

    // 2. compute g^s
    let gs = fixed_base::scalar_multiply(
        base_chip,
        ctx,
        &GA::generator(),
        s.limbs().to_vec(),
        base_chip.limb_bits,
        fixed_window_bits,
    );
    assert_eq_points(gs.clone(), _gs.clone());

    // 3. compute pk^c
    let pkc = scalar_multiply::<_, _, GA>(
        base_chip,
        ctx,
        pk,
        c.limbs().to_vec(),
        base_chip.limb_bits,
        var_window_bits,
    );
    assert_eq_points(pkc.clone(), _pkc.clone());

    // 4. compute g^s / pk^c
    let pkc_inv = chip.negate(ctx, pkc);
    assert_eq_points(pkc_inv.clone(), _pkc_inv.clone());

    let gs_pkc = chip.add_unequal(ctx, &gs, &pkc_inv, false);
    assert_eq_points(gs_pkc.clone(), _gs_pkc.clone());

    // 5. compute hash[m, pk]^s
    // TODO

    // 6. compute nullifier^c
    let nullifierc = scalar_multiply::<_, _, GA>(
        base_chip,
        ctx,
        nullifier.clone(),
        c.limbs().to_vec(),
        base_chip.limb_bits,
        var_window_bits,
    );
    assert_eq_points(nullifierc.clone(), _nullifierc.clone());

    // 7. compute hash[m, pk]^s / (nullifier)^c
    let nullifierc_inv = chip.negate(ctx, nullifierc);
    assert_eq_points(nullifierc_inv.clone(), _nullifierc_inv.clone());
    // TODO

    // 8. compute hash2(g, pk, hash[m, pk], nullifier, g^s / pk^c, hash[m, pk]^s / nullifier^c)
    // TODO

    // 9. constraint hash2(g, pk, hash[m, pk], nullifier, g^s / pk^c, hash[m, pk]^s / nullifier^c) == c
    // TODO
}

// TODO: Test helpers, will be removed
fn assert_eq_points<F: BigPrimeField>(
    a: EcPoint<F, ProperCrtUint<F>>,
    b: EcPoint<F, ProperCrtUint<F>>,
) {
    assert_eq!(a.x.value(), b.x.value());
    assert_eq!(a.y.value(), b.y.value());
}

// TODO: Test helpers, will be removed
fn assert_eq_limbs<F: BigPrimeField>(a: ProperCrtUint<F>, b: ProperCrtUint<F>) {
    a.limbs().iter().zip(b.limbs().iter()).for_each(|(a, b)| {
        assert_eq!(a.value(), b.value());
    });
}

#[cfg(test)]
mod test {
    use halo2_base::{
        halo2_proofs::{
            arithmetic::Field,
            halo2curves::{
                bn256::Fr,
                secp256k1::{Fp, Fq, Secp256k1Affine},
                CurveAffine,
            },
        },
        utils::testing::base_test,
    };
    use halo2_ecc::{
        ecc::EccChip,
        fields::FieldChip,
        secp256k1::{FpChip, FqChip},
    };
    use rand::{random, rngs::OsRng};

    use crate::plume::PlumeInput;

    use super::verify_plume;

    #[test]
    fn test_plume_verify() {
        // Inputs
        let nullifier = Secp256k1Affine::from(
            Secp256k1Affine::generator()
                * <Secp256k1Affine as CurveAffine>::ScalarExt::from(random::<u64>()),
        );
        let s = <Secp256k1Affine as CurveAffine>::ScalarExt::from(random::<u64>());
        let c = <Secp256k1Affine as CurveAffine>::ScalarExt::from(random::<u64>());
        let pk = Secp256k1Affine::from(
            Secp256k1Affine::generator()
                * <Secp256k1Affine as CurveAffine>::ScalarExt::from(random::<u64>()),
        );
        let m = (0..10).map(|_| Fr::random(OsRng)).collect::<Vec<_>>();

        // Outputs
        let gs = Secp256k1Affine::from(Secp256k1Affine::generator() * s);
        let pkc = Secp256k1Affine::from(pk * c);
        let pkc_inv = Secp256k1Affine::from(-pkc);
        let gs_pkc = Secp256k1Affine::from(gs + pkc_inv);
        let nullifierc = Secp256k1Affine::from(nullifier * c);
        let nullifierc_inv = Secp256k1Affine::from(-nullifierc);

        base_test()
            .k(14)
            .lookup_bits(13)
            .expect_satisfied(true)
            .run(|ctx, range| {
                let fp_chip = FpChip::<Fr>::new(range, 88, 3);
                let fq_chip = FqChip::<Fr>::new(range, 88, 3);
                let ecc_chip = EccChip::<Fr, FpChip<Fr>>::new(&fp_chip);

                let nullifier = ecc_chip.load_private_unchecked(ctx, (nullifier.x, nullifier.y));
                let s = fq_chip.load_private(ctx, s);
                let c = fq_chip.load_private(ctx, c);
                let pk = ecc_chip.load_private_unchecked(ctx, (pk.x, pk.y));
                let m = m.iter().map(|m| ctx.load_witness(*m)).collect::<Vec<_>>();

                // Test Inputs
                let _gs = ecc_chip.load_private_unchecked(ctx, (gs.x, gs.y));
                let _pkc = ecc_chip.load_private_unchecked(ctx, (pkc.x, pkc.y));
                let _pkc_inv = ecc_chip.load_private_unchecked(ctx, (pkc_inv.x, pkc_inv.y));
                let _gs_pkc = ecc_chip.load_private_unchecked(ctx, (gs_pkc.x, gs_pkc.y));
                let _nullifierc =
                    ecc_chip.load_private_unchecked(ctx, (nullifierc.x, nullifierc.y));
                let _nullifierc_inv =
                    ecc_chip.load_private_unchecked(ctx, (nullifierc_inv.x, nullifierc_inv.y));

                let plume_input = PlumeInput::<Fr> {
                    nullifier,
                    s,
                    c,
                    pk,
                    m,
                    _gs,
                    _pkc,
                    _pkc_inv,
                    _gs_pkc,
                    _nullifierc,
                    _nullifierc_inv,
                };

                verify_plume::<Fr, Fp, Fq, Secp256k1Affine>(ctx, &ecc_chip, 4, 4, plume_input)
            });
    }
}
