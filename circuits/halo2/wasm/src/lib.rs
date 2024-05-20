mod utils;

use halo2_wasm::{
  halo2_base::{
    gates::{ circuit::builder::BaseCircuitBuilder, RangeChip, RangeInstructions },
    poseidon::hasher::{ spec::OptimizedPoseidonSpec, PoseidonHasher },
  },
  halo2_ecc::secp256k1::{ FpChip, FqChip },
  halo2lib::ecc::{ Bn254Fr as Fr, EccChip, FieldChip },
  Halo2Wasm,
};
use plume_halo2::{ verify_plume, PlumeInput };
use serde::{ Deserialize, Serialize };
use tsify::Tsify;
use std::{ cell::RefCell, rc::Rc };
use wasm_bindgen::prelude::*;
use utils::{ parse_compressed_point, parse_scalar };

#[derive(Tsify, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct PlumeVerifyInput {
  // Public
  pub nullifier: String,
  pub s: String,

  // Private
  pub c: String,
  pub message: String,
  pub public_key: String,
}

#[wasm_bindgen]
pub struct PlumeVerify {
  range: RangeChip<Fr>,
  builder: Rc<RefCell<BaseCircuitBuilder<Fr>>>,
}

#[wasm_bindgen]
impl PlumeVerify {
  #[wasm_bindgen(constructor)]
  pub fn new(circuit: &Halo2Wasm) -> Self {
    let builder = Rc::clone(&circuit.circuit);
    let lookup_bits = match builder.borrow_mut().lookup_bits() {
      Some(x) => x,
      None => panic!("Lookup bits not found"),
    };
    let lookup_manager = builder.borrow_mut().lookup_manager().clone();
    let range = RangeChip::<Fr>::new(lookup_bits, lookup_manager);
    PlumeVerify {
      range,
      builder: Rc::clone(&circuit.circuit),
    }
  }

  pub fn run(&mut self, input: PlumeVerifyInput) {
    let nullifier = parse_compressed_point(input.nullifier);
    let s = parse_scalar(input.s);
    let c = parse_scalar(input.c);
    let pk = parse_compressed_point(input.public_key);
    let m = input.message
      .as_bytes()
      .iter()
      .map(|m| Fr::from(*m as u64))
      .collect::<Vec<_>>();

    let mut builder_borrow = self.builder.borrow_mut();
    let ctx = builder_borrow.main(0);
    let range = &self.range;

    let fp_chip = FpChip::<Fr>::new(&range, 88, 3);
    let fq_chip = FqChip::<Fr>::new(&range, 88, 3);
    let ecc_chip = EccChip::<Fr, FpChip<Fr>>::new(&fp_chip);

    let mut poseidon_hasher = PoseidonHasher::<Fr, 3, 2>::new(
      OptimizedPoseidonSpec::new::<8, 57, 0>()
    );
    poseidon_hasher.initialize_consts(ctx, range.gate());

    let nullifier = ecc_chip.load_private_unchecked(ctx, (nullifier.x, nullifier.y));
    let s = fq_chip.load_private(ctx, s);
    let c = fq_chip.load_private(ctx, c);
    let pk = ecc_chip.load_private_unchecked(ctx, (pk.x, pk.y));
    let m = m
      .iter()
      .map(|m| ctx.load_witness(*m))
      .collect::<Vec<_>>();

    let plume_input = PlumeInput::<Fr> {
      nullifier: nullifier.clone(),
      s,
      c,
      pk,
      m,
    };

    verify_plume::<Fr>(ctx, &ecc_chip, &poseidon_hasher, 4, 4, plume_input);

    builder_borrow.assigned_instances[0].append(&mut nullifier.x().limbs().to_vec());
    builder_borrow.assigned_instances[0].append(&mut nullifier.y().limbs().to_vec());
  }
}
