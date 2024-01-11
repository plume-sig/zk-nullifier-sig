use halo2_base::{
    gates::RangeChip,
    utils::{BigPrimeField, CurveAffineExt},
    Context,
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
    m: ProperCrtUint<F>,
}

fn verify_plume<F: BigPrimeField, CF: BigPrimeField, SF: BigPrimeField, GA>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    chip: &EccChip<F, FpChip<F, CF>>,
    limb_bits: usize,
    num_limbs: usize,
    max_bits: usize,
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
    } = input;

    let base_chip = chip.field_chip;
    let scalar_chip =
        FpChip::<F, SF>::new(base_chip.range, base_chip.limb_bits, base_chip.num_limbs);

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
    println!("reached 4");

    // 3. compute pk^c
    let pkc = scalar_multiply::<_, _, GA>(
        base_chip,
        ctx,
        pk,
        c.limbs().to_vec(),
        base_chip.limb_bits,
        var_window_bits,
    );
    println!("reached 5");

    // 4. compute g^s / pk^c
    let pkc_inv = chip.negate(ctx, pkc);
    // let gs_pkc = ecc_chip.add_unequal(ctx, &gs, &pkc_inv, false);
    println!("reached 6");

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
    println!("reached 7");

    // 7. compute hash[m, pk]^s / (nullifier)^c
    let nullifierc_inv = chip.negate(ctx, nullifierc);
    println!("reached 8")
    // TODO

    // 8. compute hash2(g, pk, hash[m, pk], nullifier, g^s / pk^c, hash[m, pk]^s / nullifier^c)
    // TODO

    // 9. constraint hash2(g, pk, hash[m, pk], nullifier, g^s / pk^c, hash[m, pk]^s / nullifier^c) == c
    // TODO
}
