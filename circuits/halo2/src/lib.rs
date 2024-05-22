pub mod utils;

use halo2_base::{
  gates::{ GateChip, GateInstructions, RangeChip, RangeInstructions },
  halo2_proofs::halo2curves::{ bn256::Fr, secp256k1::{ Fp, Fq, Secp256k1Affine } },
  poseidon::hasher::PoseidonHasher,
  utils::BigPrimeField,
  AssignedValue,
  Context,
  QuantumCell,
};
use halo2_ecc::{
  bigint::{ big_is_even, ProperCrtUint },
  ecc::EcPoint,
  fields::FieldChip,
  secp256k1::{ hash_to_curve::{ hash_to_curve, util::fe_to_bytes_le }, Secp256k1Chip },
};
#[derive(Clone, Debug, Default)]
pub struct PlumeCircuitInput {
  pub nullifier: (Fp, Fp),
  pub s: Fq,
  pub c: Fq,
  pub pk: (Fp, Fp),
  pub m: Vec<Fr>,
}

#[derive(Clone, Debug)]
pub struct PlumeInput<F: BigPrimeField> {
  // Public
  pub nullifier: EcPoint<F, ProperCrtUint<F>>,
  pub s: ProperCrtUint<F>,
  // Private
  pub c: ProperCrtUint<F>,
  pub pk: EcPoint<F, ProperCrtUint<F>>,
  pub m: Vec<AssignedValue<F>>, // bytes
}

fn bytes_le_to_limb<F: BigPrimeField>(
  ctx: &mut Context<F>,
  gate: &GateChip<F>,
  bytes: &[AssignedValue<F>]
) -> AssignedValue<F> {
  let byte_base = (0..bytes.len())
    .map(|i| QuantumCell::Constant(gate.pow_of_two()[i * 8]))
    .collect::<Vec<_>>();

  gate.inner_product(ctx, bytes.to_vec(), byte_base)
}

fn limbs_to_bytes32_be<F: BigPrimeField>(
  ctx: &mut Context<F>,
  range: &RangeChip<F>,
  limbs: &[AssignedValue<F>],
  max_limb_bits: usize
) -> Vec<AssignedValue<F>> {
  let total_bytes = (limbs.len() * max_limb_bits) / 8;
  let mut bytes = Vec::<AssignedValue<F>>::with_capacity(total_bytes);

  for limb in limbs.iter().rev() {
    let limb_bytes = limb.value().to_bytes_le();
    let mut limb_bytes = limb_bytes[0..11]
      .iter()
      .map(|byte| {
        let byte = ctx.load_witness(F::from(*byte as u64));
        range.range_check(ctx, byte, 8);
        byte
      })
      .collect::<Vec<_>>();
    let _limb = bytes_le_to_limb(ctx, range.gate(), &limb_bytes);

    assert_eq!(limb.value(), _limb.value());
    ctx.constrain_equal(&_limb, limb);

    limb_bytes.reverse();
    bytes.append(&mut limb_bytes);
  }

  bytes[1..].to_vec()
}

pub fn compress_point<F: BigPrimeField>(
  ctx: &mut Context<F>,
  range: &RangeChip<F>,
  pt: &EcPoint<F, ProperCrtUint<F>>
) -> Vec<AssignedValue<F>> {
  let x = pt.x();
  let y = pt.y();

  let mut compressed_pt = Vec::<AssignedValue<F>>::with_capacity(33);

  let is_y_even = big_is_even::positive(
    range,
    ctx,
    y.as_ref().truncation.clone(),
    y.as_ref().truncation.max_limb_bits
  );

  let tag = range
    .gate()
    .select(
      ctx,
      QuantumCell::Constant(F::from(2u64)),
      QuantumCell::Constant(F::from(3u64)),
      is_y_even
    );

  compressed_pt.push(tag);
  compressed_pt.append(
    &mut limbs_to_bytes32_be(ctx, range, x.as_ref().limbs(), x.as_ref().truncation.max_limb_bits)
  );

  compressed_pt
}

pub fn verify_plume<F: BigPrimeField>(
  ctx: &mut Context<F>,
  secp256k1_chip: &Secp256k1Chip<'_, F>,
  poseidon_hasher: &PoseidonHasher<F, 3, 2>,
  fixed_window_bits: usize,
  var_window_bits: usize,
  input: PlumeInput<F>
) {
  let PlumeInput { nullifier, s, c, pk, m } = input;

  let base_chip = secp256k1_chip.field_chip();
  let range = base_chip.range();
  let gate = range.gate();

  // 1. compute hash[m, pk]
  let compressed_pk = compress_point(ctx, range, &pk);
  let message = [m.as_slice(), compressed_pk.as_slice()].concat();
  let hashed_message = hash_to_curve(ctx, secp256k1_chip, poseidon_hasher, message.as_slice());

  // 2. compute g^s
  let g = secp256k1_chip.load_private::<Secp256k1Affine>(ctx, (
    Secp256k1Affine::generator().x,
    Secp256k1Affine::generator().y,
  ));
  let gs = secp256k1_chip.fixed_base_scalar_mult(
    ctx,
    &Secp256k1Affine::generator(),
    s.limbs().to_vec(),
    base_chip.limb_bits,
    fixed_window_bits
  );

  // 3. compute pk^c
  let pkc = secp256k1_chip.scalar_mult::<Secp256k1Affine>(
    ctx,
    pk,
    c.limbs().to_vec(),
    base_chip.limb_bits,
    var_window_bits
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
    var_window_bits
  );

  // 6. compute nullifier^c
  let nullifierc = secp256k1_chip.scalar_mult::<Secp256k1Affine>(
    ctx,
    nullifier.clone(),
    c.limbs().to_vec(),
    base_chip.limb_bits,
    var_window_bits
  );

  // 7. compute hash[m, pk]^s / (nullifier)^c
  let nullifierc_inv = secp256k1_chip.negate(ctx, nullifierc);
  let hashed_message_s_nullifierc = secp256k1_chip.add_unequal(
    ctx,
    &hashed_message_s,
    &nullifierc_inv,
    false
  );

  // 8. compute hash2(g, pk, hash[m, pk], nullifier, g^s / pk^c, hash[m, pk]^s / nullifier^c)
  let input = [
    compress_point(ctx, range, &g).as_slice(),
    compressed_pk.as_slice(),
    compress_point(ctx, range, &hashed_message).as_slice(),
    compress_point(ctx, range, &nullifier).as_slice(),
    compress_point(ctx, range, &gs_pkc).as_slice(),
    compress_point(ctx, range, &hashed_message_s_nullifierc).as_slice(),
  ].concat();

  let final_hash = poseidon_hasher.hash_fix_len_array(ctx, gate, &input);
  let final_hash_bytes = fe_to_bytes_le(ctx, range, final_hash);

  // 9. constraint hash2(g, pk, hash[m, pk], nullifier, g^s / pk^c, hash[m, pk]^s / nullifier^c) == c
  let mut c_bytes = limbs_to_bytes32_be(ctx, range, c.limbs(), c.as_ref().truncation.max_limb_bits);
  c_bytes.reverse();
  c_bytes
    .iter()
    .zip(final_hash_bytes.iter())
    .for_each(|(c_byte, hash_byte)| {
      assert_eq!(c_byte.value(), hash_byte.value());
      ctx.constrain_equal(c_byte, hash_byte);
    });
}

#[cfg(test)]
mod test {
  use halo2_base::{
    gates::RangeInstructions,
    halo2_proofs::halo2curves::bn256::Fr,
    poseidon::hasher::{ spec::OptimizedPoseidonSpec, PoseidonHasher },
    utils::testing::base_test,
  };
  use halo2_ecc::{ ecc::EccChip, fields::FieldChip, secp256k1::{ FpChip, FqChip } };

  use crate::{ utils::generate_test_data, PlumeInput };

  use super::verify_plume;

  #[test]
  fn test_plume_verify() {
    // Inputs
    let msg_str =
      b"vulputate ut pharetra tis amet aliquam id diam maecenas ultricies mi eget mauris pharetra et adasdds";

    let test_data = generate_test_data(msg_str);

    base_test()
      .k(16)
      .lookup_bits(15)
      .expect_satisfied(true)
      .run(|ctx, range| {
        let fp_chip = FpChip::<Fr>::new(range, 88, 3);
        let fq_chip = FqChip::<Fr>::new(range, 88, 3);
        let ecc_chip = EccChip::<Fr, FpChip<Fr>>::new(&fp_chip);

        let mut poseidon_hasher = PoseidonHasher::<Fr, 3, 2>::new(
          OptimizedPoseidonSpec::new::<8, 57, 0>()
        );
        poseidon_hasher.initialize_consts(ctx, range.gate());

        let nullifier = ecc_chip.load_private_unchecked(ctx, (
          test_data.nullifier.0,
          test_data.nullifier.1,
        ));
        let s = fq_chip.load_private(ctx, test_data.s);
        let c = fq_chip.load_private(ctx, test_data.c);
        let pk = ecc_chip.load_private_unchecked(ctx, (test_data.pk.0, test_data.pk.1));
        let m = test_data.m
          .iter()
          .map(|m| ctx.load_witness(*m))
          .collect::<Vec<_>>();

        let plume_input = PlumeInput {
          nullifier,
          s,
          c,
          pk,
          m,
        };

        verify_plume::<Fr>(ctx, &ecc_chip, &poseidon_hasher, 4, 4, plume_input)
      });
  }
}