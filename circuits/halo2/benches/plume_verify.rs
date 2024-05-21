use ark_std::{ end_timer, start_timer };
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::circuit::{ builder::RangeCircuitBuilder, CircuitBuilderStage };
use halo2_base::gates::flex_gate::MultiPhaseThreadBreakPoints;
use halo2_base::gates::RangeInstructions;
use halo2_base::poseidon::hasher::{ PoseidonHasher, spec::OptimizedPoseidonSpec };
use halo2_base::{
  halo2_proofs::{ halo2curves::bn256::{ Bn256, Fr }, plonk::*, poly::kzg::commitment::ParamsKZG },
  utils::testing::gen_proof,
};
use halo2_ecc::ecc::EccChip;
use halo2_ecc::fields::FieldChip;
use halo2_ecc::secp256k1::{ FpChip, FqChip };
use plume_halo2::utils::generate_test_data;
use plume_halo2::{ verify_plume, PlumeCircuitInput, PlumeInput };
use rand::rngs::OsRng;

use criterion::{ criterion_group, criterion_main };
use criterion::{ BenchmarkId, Criterion };

use pprof::criterion::{ Output, PProfProfiler };

const K: u32 = 15;

fn plume_verify_bench(
  stage: CircuitBuilderStage,
  input: PlumeCircuitInput,
  config_params: Option<BaseCircuitParams>,
  break_points: Option<MultiPhaseThreadBreakPoints>
) -> RangeCircuitBuilder<Fr> {
  let k = K as usize;
  let lookup_bits = k - 1;
  let mut builder = match stage {
    CircuitBuilderStage::Prover => {
      RangeCircuitBuilder::prover(config_params.unwrap(), break_points.unwrap())
    }
    _ => RangeCircuitBuilder::from_stage(stage).use_k(k).use_lookup_bits(lookup_bits),
  };

  let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
  let range = builder.range_chip();
  let ctx = builder.main(0);

  let fp_chip = FpChip::<Fr>::new(&range, 88, 3);
  let fq_chip = FqChip::<Fr>::new(&range, 88, 3);
  let ecc_chip = EccChip::<Fr, FpChip<Fr>>::new(&fp_chip);

  let mut poseidon_hasher = PoseidonHasher::<Fr, 3, 2>::new(
    OptimizedPoseidonSpec::new::<8, 57, 0>()
  );
  poseidon_hasher.initialize_consts(ctx, range.gate());

  let nullifier = ecc_chip.load_private_unchecked(ctx, (input.nullifier.0, input.nullifier.1));
  let s = fq_chip.load_private(ctx, input.s);
  let c = fq_chip.load_private(ctx, input.c);
  let pk = ecc_chip.load_private_unchecked(ctx, (input.pk.0, input.pk.1));
  let m = input.m
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

  end_timer!(start0);
  if !stage.witness_gen_only() {
    builder.calculate_params(Some(20));
  }
  builder
}

fn bench(c: &mut Criterion) {
  let plume_verify_input = generate_test_data(
    b"vulputate ut pharetra tis amet aliquam id diam maecenas ultricies mi eget mauris pharetra et adasdds"
  );
  let circuit = plume_verify_bench(
    CircuitBuilderStage::Keygen,
    plume_verify_input.clone(),
    None,
    None
  );
  let config_params = circuit.params();

  let params = ParamsKZG::<Bn256>::setup(K, OsRng);
  let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
  let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");
  let break_points = circuit.break_points();

  let mut group = c.benchmark_group("plonk-prover");
  group.sample_size(10);
  group.bench_with_input(
    BenchmarkId::new("plume verify", K),
    &(&params, &pk, &plume_verify_input),
    |bencher, &(params, pk, voter_input)| {
      let input = voter_input.clone();
      bencher.iter(|| {
        let circuit = plume_verify_bench(
          CircuitBuilderStage::Prover,
          input.clone(),
          Some(config_params.clone()),
          Some(break_points.clone())
        );

        gen_proof(params, pk, circuit);
      })
    }
  );
  group.finish()
}

criterion_group! {
  name = benches;
  config = Criterion::default().with_profiler(PProfProfiler::new(10, Output::Flamegraph(None)));
  targets = bench
}
criterion_main!(benches);
