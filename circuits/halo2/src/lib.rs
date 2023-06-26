use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{modulus, CurveAffineExt},
    AssignedValue, Context,
    QuantumCell::Existing,
};
use halo2_ecc::bigint::ProperCrtUint;
use halo2_ecc::fields::{fp::FpConfig, FieldChip};

use halo2_ecc::ecc::fixed_base;
use halo2_ecc::ecc::{ec_add_unequal, scalar_multiply, EcPoint, EccChip};
use halo2_ecc::fields::fp::FpChip;
use halo2_ecc::fields::PrimeField;

mod hash_to_curve;
#[cfg(test)]
mod tests;

use hash_to_curve::HashToCurve;

// The verification procedure for a v2 PLUME nullifier
// Details on PLUME v2 changes: https://www.notion.so/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff (as compared to v1, i.e., https://blog.aayushg.com/posts/nullifier/)
pub fn plume_v2<'a, F: PrimeField, CF: PrimeField, SF: PrimeField, GA>(
    chip: &EccChip<F, FpChip<F, CF>>,
    ctx: &mut Context<F>,
    c: ProperCrtUint<F>,
    s: ProperCrtUint<F>,
    // msg: TODO
    pub_key: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
    nullifier: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
    var_window_bits: usize,   // TODO: what is this?
    fixed_window_bits: usize, // TODO: what is this?
) -> (
    EcPoint<F, <FpChip<'a, F, CF> as FieldChip<F>>::FieldPoint>,
    EcPoint<F, <FpChip<'a, F, CF> as FieldChip<F>>::FieldPoint>,
)
where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
{
    let base_chip = chip.field_chip;

    // calculate g^s
    let g = GA::generator();
    // let g_pow_s = fixed_base::scalar_multiply(
    //     chip,
    //     ctx,
    //     &GA::generator(),
    //     u1.limbs().to_vec(),
    //     base_chip.limb_bits,
    //     fixed_window_bits,
    // );
    let g_pow_s = fixed_base::scalar_multiply(
        base_chip,
        ctx,
        &g,
        s.limbs().to_vec(),
        base_chip.limb_bits, // TODO: guesswork - is this right??
        fixed_window_bits,   // TODO: cargoculted - is this right??
    );

    // calculate g_pow_r, thereby verifying equation 1
    let g_pow_r = a_div_b_pow_c::<F, CF, SF, GA>(chip, ctx, var_window_bits, g_pow_s, pub_key, &c);

    // hash message to curve
    // TODO: compress public key and concatenate it with the message

    let h = HashToCurve::<F, CF, SF, GA>(chip, ctx, var_window_bits, &[], g_pow_r.clone());

    // calculate h_pow_s
    let h_pow_s = scalar_multiply::<_, _, GA>(
        base_chip,
        ctx,
        h,
        s.limbs().to_vec(),
        base_chip.limb_bits, // TODO: guesswork - is this right??
        var_window_bits,     // TODO: cargoculted - is this right??
    );

    // calculate h_pow_r, thereby verifying equation 2
    let h_pow_r =
        a_div_b_pow_c::<F, CF, SF, GA>(chip, ctx, var_window_bits, h_pow_s, nullifier, &c);

    // output g_pow_r and h_pow_r for hash verification outside the circuit
    (g_pow_r, h_pow_r)
}

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
pub fn a_div_b_pow_c<'a, F: PrimeField, CF: PrimeField, SF: PrimeField, GA>(
    chip: &EccChip<F, FpChip<F, CF>>,
    ctx: &mut Context<F>,
    var_window_bits: usize, // TODO: what is this?
    a: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
    b: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
    c: &ProperCrtUint<F>,
) -> EcPoint<F, <FpChip<'a, F, CF> as FieldChip<F>>::FieldPoint>
where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
{
    let base_chip = chip.field_chip;

    let b_pow_c = scalar_multiply::<_, _, GA>(
        base_chip,
        ctx,
        b,
        c.limbs().to_vec(),
        base_chip.limb_bits,
        var_window_bits,
    );

    // Calculates inverse of b^c by finding the modular inverse of its y coordinate
    let b_pow_c_inv = chip.negate(ctx, b_pow_c);

    // Calculates a * (b^c)-1
    chip.add_unequal(ctx, a, b_pow_c_inv, false)
}
