#![allow(non_snake_case)]
use ark_std::{end_timer, start_timer};
use halo2_base::gates::builder::{
    CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
};
use halo2_base::halo2_proofs::halo2curves::secp256k1::Secp256k1Compressed;
use halo2_base::halo2_proofs::halo2curves::CurveAffineExt;
use halo2_base::halo2_proofs::{
    arithmetic::CurveAffine,
    dev::MockProver,
    halo2curves::bn256::Fr,
    halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
};
use halo2_base::safe_types::RangeChip;
use halo2_base::utils::fe_to_biguint;
use halo2_base::Context;
use halo2_ecc::ecc::EcPoint;
use halo2_ecc::fields::FpStrategy;
use halo2_ecc::secp256k1::FpChip;
use halo2_ecc::secp256k1::FqChip;
use halo2_ecc::{
    ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
    fields::{FieldChip, PrimeField},
};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::fs::File;
use test_case::test_case;

use super::a_div_b_pow_c;

#[test]
fn test_a_div_b_pow_c() {
    let params = get_params();
    let test_data = get_test_data();

    let gPowS = test_data.s_v1;

    let circuit = a_div_b_pow_c_circuit(
        gPowS,
        test_data.testPublicKeyPoint,
        test_data.c_v1,
        test_data.gPowS,
        params,
        CircuitBuilderStage::Mock,
        None,
    );
    MockProver::run(params.degree, &circuit, vec![])
        .unwrap()
        .assert_satisfied();
}

fn a_div_b_pow_c_circuit(
    a: Point,
    b: Point,
    c: Fq,
    expected: Point,
    params: CircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };
    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    a_div_b_pow_c_test(builder.main(0), params, a, b, c, expected);

    let circuit = match stage {
        CircuitBuilderStage::Mock => {
            builder.config(params.degree as usize, Some(20));
            RangeCircuitBuilder::mock(builder)
        }
        CircuitBuilderStage::Keygen => {
            builder.config(params.degree as usize, Some(20));
            RangeCircuitBuilder::keygen(builder)
        }
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(builder, break_points.unwrap()),
    };
    end_timer!(start0);
    circuit
}

fn a_div_b_pow_c_test<F: PrimeField, CF: PrimeField>(
    ctx: &mut Context<F>,
    params: CircuitParams,
    a: Secp256k1Affine,
    b: Secp256k1Affine,
    c: Fq,
    expected: Secp256k1Affine,
) {
    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<F>::default(params.lookup_bits);
    let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<F>::new(&range, params.limb_bits, params.num_limbs);

    let c = fq_chip.load_private(ctx, c);

    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);
    let a = ecc_chip.assign_point(ctx, a);
    let b = ecc_chip.assign_point(ctx, b);
    let res = a_div_b_pow_c::<F, Fp, Fq, Secp256k1Affine>(&ecc_chip, ctx, 4, a, b, &c);

    let (x, y) = expected.into_coordinates();
    assert_eq!(res.x().value(), fe_to_biguint(&x));
    assert_eq!(res.y().value(), fe_to_biguint(&y));
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct CircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

fn get_params() -> CircuitParams {
    let path = "a_div_b_pow_c_circuit.config";
    serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap()
}

#[derive(Clone, Debug, Deserialize)]
struct Point {
    x: String,
    y: String,
}

#[derive(Clone, Debug, Deserialize)]
struct TestData {
    testSecretKey: [u8; 32],
    testPublicKeyPoint: Point,
    #[serde(with = "BigArray")]
    testPublicKey: [u8; 33],
    testR: [u8; 32],
    testMessageString: String,
    testMessage: [u8; 28],
    hashMPk: Point,
    nullifier: Point,
    hashMPkPowR: Point,
    gPowR: Point,
    c_v1: String,
    s_v1: String,
    c_v2: String,
    s_v2: String,
}
fn get_test_data() -> TestData {
    let path = "../../javascript/test/test_consts.json";
    serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap()
}
