use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{modulus, CurveAffineExt, PrimeField},
    AssignedValue, Context,
    QuantumCell::Existing,
};
use halo2_ecc::bigint::{big_less_than, CRTInteger};
use halo2_ecc::fields::{fp::FpConfig, FieldChip};

use halo2_ecc::ecc::fixed_base;
use halo2_ecc::ecc::{ec_add_unequal, scalar_multiply, EcPoint};

// Hashes a bitstring to a point on an elliptic curve
// Spec: https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html
// Circom Reference Implementation: https://github.com/geometryresearch/secp256k1_hash_to_curve/
pub fn HashToCurve<'v, F: PrimeField, CF: PrimeField, SF: PrimeField, GA>(
    base_chip: &FpConfig<F, CF>,
    ctx: &mut Context<'v, F>,
    var_window_bits: usize, // TODO: what is this?
    message: &[Vec<u8>],
    placeholder: EcPoint<F, <FpConfig<F, CF> as FieldChip<F>>::FieldPoint<'v>>,
) -> EcPoint<F, <FpConfig<F, CF> as FieldChip<F>>::FieldPoint<'v>>
where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
{
    placeholder
}
