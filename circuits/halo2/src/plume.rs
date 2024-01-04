use halo2_base::{
    gates::circuit::builder::BaseCircuitBuilder, utils::BigPrimeField, AssignedValue,
};
use halo2_ecc::{ecc::EcPoint, fields::FieldChip, secp256k1::FpChip};

#[derive(Clone, Debug)]
struct PlumeInput<'v, F: BigPrimeField> {
    // Public
    nullifier: EcPoint<F, <FpChip<'v, F> as FieldChip<F>>::FieldPoint>,
    s: F,
    // Private
    c: F,
    pk: EcPoint<F, <FpChip<'v, F> as FieldChip<F>>::FieldPoint>,
    g: EcPoint<F, <FpChip<'v, F> as FieldChip<F>>::FieldPoint>,
    m: F,
}

fn verify_plume<F: BigPrimeField>(
    builder: &mut BaseCircuitBuilder<F>,
    input: PlumeInput<F>,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    // 1. compute hash[m, pk]
    // 2. compute g^s
    // 3. compute pk^c
    // 4. compute g^s / pk^c
    // 5. compute hash[m, pk]^s
    // 6. compute nullifier^c
    // 7. compute hash[m, pk]^s / (nullifier)^c
    // 8. compute hash2(g, pk, hash[m, pk], nullifier, g^s / pk^c, hash[m, pk]^s / nullifier^c)
}
