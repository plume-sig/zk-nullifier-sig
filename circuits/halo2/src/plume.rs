use halo2_base::{
  gates::circuit::builder::BaseCircuitBuilder,
  utils::BigPrimeField,
  AssignedValue,
};
use halo2_ecc::{ ecc::EcPoint, fields::FieldChip, secp256k1::FpChip };

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
  make_public: &mut Vec<AssignedValue<F>>
) {}
