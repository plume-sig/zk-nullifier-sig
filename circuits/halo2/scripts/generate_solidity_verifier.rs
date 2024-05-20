use std::path::Path;

use halo2_base::{
  gates::{
    circuit::{ builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig },
    RangeInstructions,
  },
  halo2_proofs::{
    circuit::{ Layouter, SimpleFloorPlanner },
    halo2curves::{ bn256::Fr, secp256k1::{ Fq, Secp256k1, Secp256k1Affine } },
    plonk::{ keygen_vk, Circuit, ConstraintSystem, Error },
  },
  poseidon::hasher::PoseidonHasher,
  utils::{ fs::gen_srs, BigPrimeField },
};
use halo2_ecc::{ ecc::EccChip, fields::FieldChip, secp256k1::{ FpChip, FqChip } };
use k256::elliptic_curve::Field;
use plume_halo2::{ verify_plume, PlumeInput, utils::{ gen_test_nullifier, verify_nullifier } };
use rand::rngs::OsRng;
use snark_verifier_sdk::{ evm::gen_evm_verifier_shplonk, halo2::OptimizedPoseidonSpec, CircuitExt };

pub struct PlumeVerifyCircuit<F: BigPrimeField> {
  inner: BaseCircuitBuilder<F>,
}

impl<F: BigPrimeField> Circuit<F> for PlumeVerifyCircuit<F> {
  type Config = BaseConfig<F>;
  type FloorPlanner = SimpleFloorPlanner;
  type Params = BaseCircuitParams;

  fn params(&self) -> Self::Params {
    self.inner.params()
  }

  fn without_witnesses(&self) -> Self {
    unimplemented!()
  }

  fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
    BaseCircuitBuilder::configure_with_params(meta, params)
  }

  fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
    unreachable!()
  }

  fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
    self.inner.synthesize(config, layouter)
  }
}

impl<F: BigPrimeField> CircuitExt<F> for PlumeVerifyCircuit<F> {
  fn num_instance(&self) -> Vec<usize> {
    vec![6]
  }

  fn instances(&self) -> Vec<Vec<F>> {
    vec![
      self.inner.assigned_instances[0]
        .iter()
        .map(|instance| *instance.value())
        .collect()
    ]
  }
}

fn main() {
  const K: usize = 15;

  let msg_str =
    b"vulputate ut pharetra tis amet aliquam id diam maecenas ultricies mi eget mauris pharetra et adasdds";
  let m = msg_str
    .iter()
    .map(|b| Fr::from(*b as u64))
    .collect::<Vec<_>>();

  let sk = Fq::random(OsRng);
  let pk = Secp256k1Affine::from(Secp256k1::generator() * sk);
  let (nullifier, s, c) = gen_test_nullifier(&sk, msg_str);
  verify_nullifier(msg_str, &nullifier, &pk, &s, &c);

  let mut builder = BaseCircuitBuilder::<Fr>
    ::default()
    .use_k(K)
    .use_lookup_bits(K - 1);
  let range = &builder.range_chip();
  let ctx = builder.main(0);

  let fp_chip = FpChip::<Fr>::new(range, 88, 3);
  let fq_chip = FqChip::<Fr>::new(range, 88, 3);
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

  let plume_input = PlumeInput {
    nullifier,
    s,
    c,
    pk,
    m,
  };

  verify_plume::<Fr>(ctx, &ecc_chip, &poseidon_hasher, 4, 4, plume_input);

  let config = builder.calculate_params(Some(10));
  println!("config = {:?}", config);

  let params = gen_srs(K as u32);

  let vk = keygen_vk(&params, &builder).unwrap();

  let _ = gen_evm_verifier_shplonk::<PlumeVerifyCircuit<Fr>>(
    &params,
    &vk,
    vec![6],
    Some(Path::new("build/PlumeVerifier.sol"))
  );
}
