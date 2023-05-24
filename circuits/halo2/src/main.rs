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

// The verification procedure for a v2 PLUME nullifier
// Details on PLUME v2 changes: https://www.notion.so/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff (as compared to v1, i.e., https://blog.aayushg.com/posts/nullifier/)
pub fn plume_v2<'v, F: PrimeField, CF: PrimeField, SF: PrimeField, GA>(
    base_chip: &FpConfig<F, CF>,
    ctx: &mut Context<'v, F>,
    var_window_bits: usize, // TODO: what is this?
    c: &CRTInteger<'v, F>,
    s: &CRTInteger<'v, F>,
    // msg: TODO
    pub_key: &EcPoint<F, <FpConfig<F, CF> as FieldChip<F>>::FieldPoint<'v>>,
    nullifier: &EcPoint<F, <FpConfig<F, CF> as FieldChip<F>>::FieldPoint<'v>>,
) -> (
    EcPoint<F, <FpConfig<F, CF> as FieldChip<F>>::FieldPoint<'v>>,
    EcPoint<F, <FpConfig<F, CF> as FieldChip<F>>::FieldPoint<'v>>,
)
where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
{
    // calculate g^s
    let g = GA::generator();
    let g_pow_s = fixed_base::scalar_multiply(
        base_chip,
        ctx,
        &g,
        &s.truncation.limbs,
        s.truncation.max_limb_bits, // TODO: guesswork - is this right??
        var_window_bits,            // TODO: cargoculted - is this right??
    );

    // calculate g_pow_r, thereby verifying equation 1
    let g_pow_r =
        a_div_b_pow_c::<F, CF, SF, GA>(base_chip, ctx, var_window_bits, &g_pow_s, pub_key, c);

    // hash message to curve
    // compress public key
    let h = &g_pow_r; // *THIS IS JUST A SIMPLE STANDIN WITH THE RIGHT TYPE. TODO: calculate this correctly by implementing hash_to_curve

    // calculate h_pow_s
    let h_pow_s = scalar_multiply(
        base_chip,
        ctx,
        h,
        &s.truncation.limbs,
        s.truncation.max_limb_bits, // TODO: guesswork - is this right??
        var_window_bits,            // TODO: cargoculted - is this right??
    );

    // calculate h_pow_r, thereby verifying equation 2
    let h_pow_r =
        a_div_b_pow_c::<F, CF, SF, GA>(base_chip, ctx, var_window_bits, &h_pow_s, nullifier, c);

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

// mod test {
//     #![allow(non_snake_case)]
//     use halo2_base::{utils::PrimeField, SKIP_FIRST_PASS};
//     // use serde::{Deserialize, Serialize};
//     use std::fs::File;
//     use std::marker::PhantomData;
//     use std::{env::var, io::Write};

//     use halo2_base::halo2_proofs::{
//         arithmetic::CurveAffine,
//         circuit::*,
//         dev::MockProver,
//         halo2curves::bn256::{Bn256, Fr, G1Affine},
//         halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
//         plonk::*,
//         poly::commitment::ParamsProver,
//         transcript::{Blake2bRead, Blake2bWrite, Challenge255},
//     };

//     use halo2_base::utils::{biguint_to_fe, fe_to_biguint, modulus};
//     use halo2_ecc::fields::fp::FpConfig;
//     use halo2_ecc::{
//         ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
//         fields::{fp::FpStrategy, FieldChip},
//     };

//     type FpChip<F> = FpConfig<F, Fp>;

//     struct CircuitParams {
//         strategy: FpStrategy,
//         degree: u32,
//         num_advice: usize,
//         num_lookup_advice: usize,
//         num_fixed: usize,
//         lookup_bits: usize,
//         limb_bits: usize,
//         num_limbs: usize,
//     }

//     pub struct ECDSACircuit<F> {
//         pub r: Option<Fq>,
//         pub s: Option<Fq>,
//         pub msghash: Option<Fq>,
//         pub pk: Option<Secp256k1Affine>,
//         pub G: Secp256k1Affine,
//         pub _marker: PhantomData<F>,
//     }
//     impl<F: PrimeField> Default for ECDSACircuit<F> {
//         fn default() -> Self {
//             Self {
//                 r: None,
//                 s: None,
//                 msghash: None,
//                 pk: None,
//                 G: Secp256k1Affine::generator(),
//                 _marker: PhantomData,
//             }
//         }
//     }

//     impl<F: PrimeField> Circuit<F> for ECDSACircuit<F> {
//         type Config = FpChip<F>;
//         type FloorPlanner = SimpleFloorPlanner;

//         fn without_witnesses(&self) -> Self {
//             Self::default()
//         }

//         fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//             let path = var("ECDSA_CONFIG")
//                 .unwrap_or_else(|_| "./src/secp256k1/configs/ecdsa_circuit.config".to_string());
//             let params: CircuitParams = serde_json::from_reader(
//                 File::open(&path).unwrap_or_else(|_| panic!("{path:?} file should exist")),
//             )
//             .unwrap();

//             FpChip::<F>::configure(
//                 meta,
//                 params.strategy,
//                 &[params.num_advice],
//                 &[params.num_lookup_advice],
//                 params.num_fixed,
//                 params.lookup_bits,
//                 params.limb_bits,
//                 params.num_limbs,
//                 modulus::<Fp>(),
//                 0,
//                 params.degree as usize,
//             )
//         }

//         fn synthesize(
//             &self,
//             fp_chip: Self::Config,
//             mut layouter: impl Layouter<F>,
//         ) -> Result<(), Error> {
//             fp_chip.range.load_lookup_table(&mut layouter)?;

//             let limb_bits = fp_chip.limb_bits;
//             let num_limbs = fp_chip.num_limbs;
//             let _num_fixed = fp_chip.range.gate.constants.len();
//             let _lookup_bits = fp_chip.range.lookup_bits;
//             let _num_advice = fp_chip.range.gate.num_advice;

//             let mut first_pass = SKIP_FIRST_PASS;
//             // ECDSA verify
//             layouter.assign_region(
//                 || "ECDSA",
//                 |region| {
//                     if first_pass {
//                         first_pass = false;
//                         return Ok(());
//                     }

//                     let mut aux = fp_chip.new_context(region);
//                     let ctx = &mut aux;

//                     let (r_assigned, s_assigned, m_assigned) = {
//                         let fq_chip = FpConfig::<F, Fq>::construct(
//                             fp_chip.range.clone(),
//                             limb_bits,
//                             num_limbs,
//                             modulus::<Fq>(),
//                         );

//                         let m_assigned = fq_chip.load_private(
//                             ctx,
//                             FpConfig::<F, Fq>::fe_to_witness(
//                                 &self.msghash.map_or(Value::unknown(), Value::known),
//                             ),
//                         );

//                         let r_assigned = fq_chip.load_private(
//                             ctx,
//                             FpConfig::<F, Fq>::fe_to_witness(
//                                 &self.r.map_or(Value::unknown(), Value::known),
//                             ),
//                         );
//                         let s_assigned = fq_chip.load_private(
//                             ctx,
//                             FpConfig::<F, Fq>::fe_to_witness(
//                                 &self.s.map_or(Value::unknown(), Value::known),
//                             ),
//                         );
//                         (r_assigned, s_assigned, m_assigned)
//                     };

//                     let ecc_chip = EccChip::<F, FpChip<F>>::construct(fp_chip.clone());
//                     let pk_assigned = ecc_chip.load_private(
//                         ctx,
//                         (
//                             self.pk.map_or(Value::unknown(), |pt| Value::known(pt.x)),
//                             self.pk.map_or(Value::unknown(), |pt| Value::known(pt.y)),
//                         ),
//                     );
//                     // test ECDSA
//                     let ecdsa = ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
//                         &ecc_chip.field_chip,
//                         ctx,
//                         &pk_assigned,
//                         &r_assigned,
//                         &s_assigned,
//                         &m_assigned,
//                         4,
//                         4,
//                     );

//                     // IMPORTANT: this copies cells to the lookup advice column to perform range check lookups
//                     // This is not optional.
//                     fp_chip.finalize(ctx);

//                     #[cfg(feature = "display")]
//                     if self.r.is_some() {
//                         println!("ECDSA res {ecdsa:?}");

//                         ctx.print_stats(&["Range"]);
//                     }
//                     Ok(())
//                 },
//             )
//         }
//     }

//     #[cfg(test)]
//     #[test]
//     fn test_secp256k1_ecdsa() {
//         let mut folder = std::path::PathBuf::new();
//         folder.push("./src/secp256k1");
//         folder.push("configs/ecdsa_circuit.config");
//         let params_str = std::fs::read_to_string(folder.as_path())
//             .expect("src/secp256k1/configs/ecdsa_circuit.config file should exist");
//         let params: CircuitParams = serde_json::from_str(params_str.as_str()).unwrap();
//         let K = params.degree;

//         // generate random pub key and sign random message
//         let G = Secp256k1Affine::generator();
//         let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);
//         let pubkey = Secp256k1Affine::from(G * sk);
//         let msg_hash = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);

//         let k = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);
//         let k_inv = k.invert().unwrap();

//         let r_point = Secp256k1Affine::from(G * k).coordinates().unwrap();
//         let x = r_point.x();
//         let x_bigint = fe_to_biguint(x);
//         let r = biguint_to_fe::<Fq>(&(x_bigint % modulus::<Fq>()));
//         let s = k_inv * (msg_hash + (r * sk));

//         let circuit = ECDSACircuit::<Fr> {
//             r: Some(r),
//             s: Some(s),
//             msghash: Some(msg_hash),
//             pk: Some(pubkey),
//             G,
//             _marker: PhantomData,
//         };

//         let prover = MockProver::run(K, &circuit, vec![]).unwrap();
//         //prover.assert_satisfied();
//         assert_eq!(prover.verify(), Ok(()));
//     }
// }
