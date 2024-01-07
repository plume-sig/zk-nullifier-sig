use halo2_base::{
    gates::RangeChip, halo2_proofs::halo2curves::secp256k1::Secp256k1Affine, utils::BigPrimeField,
    AssignedValue, Context,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    ecc::{EcPoint, EccChip},
    secp256k1::FpChip,
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

fn verify_plume<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    limb_bits: usize,
    num_limbs: usize,
    max_bits: usize,
    window_bits: usize,
    input: PlumeInput<F>,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let PlumeInput {
        nullifier,
        s,
        c,
        pk,
        m,
    } = input;

    let fp_chip = FpChip::<F>::new(range, limb_bits, num_limbs);
    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);

    // 1. compute hash[m, pk]
    // TODO

    // 2. compute g^s
    let gs = ecc_chip.fixed_base_scalar_mult(
        ctx,
        &Secp256k1Affine::generator(),
        s.limbs().to_vec(),
        max_bits,
        window_bits,
    );

    // 3. compute pk^c
    let pkc =
        ecc_chip.scalar_mult::<Secp256k1Affine>(ctx, pk, c.limbs().to_vec(), max_bits, window_bits);

    // 4. compute g^s / pk^c
    let pkc_inv = ecc_chip.negate(ctx, pkc);
    let gs_pkc = ecc_chip.add_unequal(ctx, &gs, &pkc_inv, false);

    // 5. compute hash[m, pk]^s
    // TODO

    // 6. compute nullifier^c
    let nullifierc = ecc_chip.scalar_mult::<Secp256k1Affine>(
        ctx,
        nullifier.clone(),
        c.limbs().to_vec(),
        max_bits,
        window_bits,
    );

    // 7. compute hash[m, pk]^s / (nullifier)^c
    let nullifierc_inv = ecc_chip.negate(ctx, nullifierc);
    // TODO

    // 8. compute hash2(g, pk, hash[m, pk], nullifier, g^s / pk^c, hash[m, pk]^s / nullifier^c)
    // TODO

    // 9. constraint hash2(g, pk, hash[m, pk], nullifier, g^s / pk^c, hash[m, pk]^s / nullifier^c) == c
    // TODO
}
