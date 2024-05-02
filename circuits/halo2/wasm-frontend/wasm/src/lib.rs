use halo2_wasm::{
  halo2_base::{
    gates::{ circuit::builder::BaseCircuitBuilder, RangeChip, RangeInstructions },
    halo2_proofs::halo2curves::group::Curve,
    poseidon::hasher::{ spec::OptimizedPoseidonSpec, PoseidonHasher },
  },
  halo2_ecc::secp256k1::{ FpChip, FqChip },
  halo2_proofs::{ arithmetic::Field, halo2curves::secp256k1::Secp256k1 },
  halo2lib::ecc::{ Bn254Fr as Fr, EccChip, FieldChip, Secp256k1Fq as Fq },
  Halo2Wasm,
};
use plume_halo2::{
  plume::{ verify_plume, PlumeInput },
  utils::{ gen_test_nullifier, verify_nullifier },
};
use rand::rngs::OsRng;
use std::{ cell::RefCell, rc::Rc };
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct MyCircuit {
  range: RangeChip<Fr>,
  builder: Rc<RefCell<BaseCircuitBuilder<Fr>>>,
}

#[wasm_bindgen]
impl MyCircuit {
  #[wasm_bindgen(constructor)]
  pub fn new(circuit: &Halo2Wasm) -> Self {
    let builder = Rc::clone(&circuit.circuit);
    let lookup_bits = match builder.borrow_mut().lookup_bits() {
      Some(x) => x,
      None => panic!("Lookup bits not found"),
    };
    let lookup_manager = builder.borrow_mut().lookup_manager().clone();
    let range = RangeChip::<Fr>::new(lookup_bits, lookup_manager);
    MyCircuit {
      range,
      builder: Rc::clone(&circuit.circuit),
    }
  }

  pub fn run(&mut self) {
    let mut builder_borrow = self.builder.borrow_mut();
    let ctx = builder_borrow.main(0);
    let range = &self.range;

    let msg_str = b"An example app message string";
    let m = msg_str
      .iter()
      .map(|b| Fr::from(*b as u64))
      .collect::<Vec<_>>();

    let sk = Fq::random(OsRng);
    let pk = (Secp256k1::generator() * sk).to_affine();
    let (nullifier, s, c) = gen_test_nullifier(&sk, msg_str);
    verify_nullifier(msg_str, &nullifier, &pk, &s, &c);

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
      nullifier,
      s,
      c,
      pk,
      m,
    };

    verify_plume::<Fr>(ctx, &ecc_chip, &poseidon_hasher, 4, 4, plume_input)
  }
}
