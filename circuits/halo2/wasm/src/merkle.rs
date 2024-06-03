use halo2_wasm::halo2_base::{
  gates::{ GateChip, GateInstructions },
  poseidon::hasher::PoseidonHasher,
  utils::BigPrimeField,
  AssignedValue,
  Context,
};

pub fn dual_mux<F: BigPrimeField>(
  ctx: &mut Context<F>,
  gate: &GateChip<F>,
  a: &AssignedValue<F>,
  b: &AssignedValue<F>,
  switch: &AssignedValue<F>
) -> [AssignedValue<F>; 2] {
  gate.assert_bit(ctx, *switch);

  let a_sub_b = gate.sub(ctx, *a, *b);
  let b_sub_a = gate.sub(ctx, *b, *a);

  let left = gate.mul_add(ctx, a_sub_b, *switch, *b); // left = (a-b)*s + b;
  let right = gate.mul_add(ctx, b_sub_a, *switch, *a); // right = (b-a)*s + a;

  [left, right]
}

pub fn verify_merkle_proof<F: BigPrimeField, const T: usize, const RATE: usize>(
  ctx: &mut Context<F>,
  gate: &GateChip<F>,
  hasher: &PoseidonHasher<F, T, RATE>,
  root: &AssignedValue<F>,
  leaf: &AssignedValue<F>,
  proof: &[AssignedValue<F>],
  helper: &[AssignedValue<F>]
) {
  let mut computed_hash = ctx.load_witness(*leaf.value());

  for (proof_element, helper) in proof.iter().zip(helper.iter()) {
    let inp = dual_mux(ctx, gate, &computed_hash, proof_element, helper);
    computed_hash = hasher.hash_fix_len_array(ctx, gate, &inp);
  }
  ctx.constrain_equal(&computed_hash, root);
}
