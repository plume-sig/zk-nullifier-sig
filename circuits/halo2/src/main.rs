use crate::fields::{fp::FpConfig, FieldChip};
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

// Computes a/b^c where a and b are EC points, and c is a scalar
// Both of the main equations in PLUME are of this form
// Equivalent to https://github.com/plume-sig/zk-nullifier-sig/blob/3288b7b9115e86e63a5a5df616d0affc89811f9e/circuits/verify_nullifier.circom#L265
//
// TODO: what is v? I'm just cargo culting it rn
// F is the prime field of the circuit we're working in. I.e., the field of the proof system
// CF is the coordinate field of secp256k1 (TODO: make CF, SF, and GA *non generic* since we're only using secp256k1)
// SF is the scalar field of secp256k1
// p = coordinate field modulus
// n = scalar field modulus
pub fn a_div_b_pow_c<'v, F: PrimeField, CF: PrimeField, SF: PrimeField, GA>(
    base_chip: &FpConfig<F, CF>,
    ctx: &mut Context<'v, F>,
    var_window_bits: usize, // TODO: what is this?
    a: &EcPoint<F, <FpConfig<F, CF> as FieldChip<F>>::FieldPoint<'v>>,
    b: &EcPoint<F, <FpConfig<F, CF> as FieldChip<F>>::FieldPoint<'v>>,
    c: &CRTInteger<'v, F>,
) -> EcPoint<F, <FpConfig<F, CF> as FieldChip<F>>::FieldPoint<'v>>
where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
{
    let b_pow_c = scalar_multiply::<F, _>(
        base_chip,
        ctx,
        b,
        &c.truncation.limbs,
        base_chip.limb_bits,
        var_window_bits,
    );

    // Calculates inverse of b^c by finding the modular inverse of its y coordinate
    let scalar_chip = FpConfig::<F, SF>::construct(
        base_chip.range.clone(),
        base_chip.limb_bits,
        base_chip.num_limbs,
        modulus::<SF>(),
    );

    let b_pow_c_inv = EcPoint::construct(b_pow_c.x.clone(), base_chip.negate(ctx, &b_pow_c.y)); // TODO: use ECC chip's negate method - I just found it easier to copy the code short term

    // Calculates a * (b^c)-1
    ec_add_unequal(base_chip, ctx, a, &b_pow_c_inv, false)
}

fn main() {
    println!("Hello, world!");
}
