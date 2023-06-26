use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{modulus, CurveAffineExt},
    AssignedValue, Context,
    QuantumCell::Existing,
};
use halo2_ecc::bigint::{big_less_than, CRTInteger};
use halo2_ecc::ecc::fixed_base;
use halo2_ecc::ecc::{ec_add_unequal, scalar_multiply, EcPoint, EccChip};
use halo2_ecc::fields::fp::FpChip;
use halo2_ecc::fields::PrimeField;
use halo2_ecc::fields::{fp::FpConfig, FieldChip};

// Hashes a bitstring to a point on an elliptic curve
// Spec: https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html
// Circom Reference Implementation: https://github.com/geometryresearch/secp256k1_hash_to_curve/
pub fn HashToCurve<'a, F: PrimeField, CF: PrimeField, SF: PrimeField, GA>(
    chip: &EccChip<F, FpChip<F, CF>>,
    ctx: &mut Context<F>,
    var_window_bits: usize, // TODO: what is this?
    message: &[Vec<u8>],
    PLACEHOLDER_TODO_REMOVE: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
) -> EcPoint<F, <FpChip<'a, F, CF> as FieldChip<F>>::FieldPoint>
where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
{
    PLACEHOLDER_TODO_REMOVE
}

pub fn HashToField<'a, F: PrimeField, CF: PrimeField, SF: PrimeField, GA>(
    chip: &EccChip<F, FpChip<F, CF>>,
    ctx: &mut Context<F>,
    var_window_bits: usize, // TODO: what is this?
    message: &[Vec<u8>],
    PLACEHOLDER_TODO_REMOVE: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
) -> EcPoint<F, <FpChip<'a, F, CF> as FieldChip<F>>::FieldPoint>
where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
{
    PLACEHOLDER_TODO_REMOVE
}
