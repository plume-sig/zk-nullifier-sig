use halo2_base::{
  halo2_proofs::halo2curves::secp256k1::Secp256k1Affine,
  utils::BigPrimeField,
  AssignedValue,
  Context,
};
use halo2_ecc::{ bigint::ProperCrtUint, ecc::EcPoint, secp256k1::Secp256k1Chip };

#[derive(Clone, Debug)]
struct PlumeInput<F: BigPrimeField> {
  // Public
  nullifier: EcPoint<F, ProperCrtUint<F>>,
  s: ProperCrtUint<F>,
  // Private
  c: ProperCrtUint<F>,
  pk: EcPoint<F, ProperCrtUint<F>>,
  m: Vec<AssignedValue<F>>, // bytes
}

fn verify_plume<F: BigPrimeField>(
  ctx: &mut Context<F>,
  secp256k1_chip: &Secp256k1Chip<'_, F>,
  fixed_window_bits: usize,
  var_window_bits: usize,
  input: PlumeInput<F>
) {
  let PlumeInput { nullifier, s, c, pk, m } = input;

  let base_chip = secp256k1_chip.field_chip();

  // 1. compute hash[m, pk]test_plume_verify
  //   let pk_x_bytes = pk.x().
  // TODO

  // 2. compute g^s
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
  // TODO

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
  // TODO

  // 8. compute hash2(g, pk, hash[m, pk], nullifier, g^s / pk^c, hash[m, pk]^s / nullifier^c)
  // TODO

  // 9. constraint hash2(g, pk, hash[m, pk], nullifier, g^s / pk^c, hash[m, pk]^s / nullifier^c) == c
  // TODO
}

// TODO: Test helpers, will be removed
fn assert_eq_points<F: BigPrimeField>(
  a: EcPoint<F, ProperCrtUint<F>>,
  b: EcPoint<F, ProperCrtUint<F>>
) {
  assert_eq!(a.x.value(), b.x.value());
  assert_eq!(a.y.value(), b.y.value());
}

// TODO: Test helpers, will be removed
fn assert_eq_limbs<F: BigPrimeField>(a: ProperCrtUint<F>, b: ProperCrtUint<F>) {
  a.limbs()
    .iter()
    .zip(b.limbs().iter())
    .for_each(|(a, b)| {
      assert_eq!(a.value(), b.value());
    });
}

#[cfg(test)]
mod test {
  use halo2_base::{
    halo2_proofs::halo2curves::{
      bn256::Fr,
      ff::PrimeField,
      secp256k1::Secp256k1Affine,
      secq256k1::Fq as Fp,
      CurveAffine,
    },
    utils::{ testing::base_test, ScalarField },
  };
  use halo2_ecc::{ ecc::EccChip, fields::FieldChip, secp256k1::{ FpChip, FqChip } };
  use num_bigint::BigUint;
  use num_traits::Num;
  use rand::{ random, rngs::OsRng };

  use crate::plume::PlumeInput;

  use super::verify_plume;

  #[test]
  fn test_plume_verify() {
    // Test data
    // m: "416e206578616d706c6520617070206d65737361676520737472696e67"
    // pk.x: "0cec028ee08d09e02672a68310814354f9eabfff0de6dacc1cd3a774496076ae"
    // pk.y: "eff471fba0409897b6a48e8801ad12f95d0009b753cf8f51c128bf6b0bd27fbd"
    // nullifier.x: "57bc3ed28172ef8adde4b9e0c2cce745fcc5a66473a45c1e626f1d0c67e55830"
    // nullifier.y: "6a2f41488d58f33ae46edd2188e111609f9f3ae67ea38fa891d6087fe59ecb73"
    // c: "c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83254"
    // s: "383a44baf62afb3e16b18c222b230e7b5226bc9044efb19e8863044183f69bed"

    // Inputs
    let m = BigUint::from_str_radix(
      "416e206578616d706c6520617070206d65737361676520737472696e67",
      16
    )
      .unwrap()
      .to_bytes_le()
      .iter()
      .map(|bytes| Fr::from_u128(*bytes as u128))
      .collect::<Vec<_>>();

    let pk = Secp256k1Affine::from_xy(
      Fp::from_bytes_le(
        BigUint::from_str_radix(
          "0cec028ee08d09e02672a68310814354f9eabfff0de6dacc1cd3a774496076ae",
          16
        )
          .unwrap()
          .to_bytes_le()
          .as_slice()
      ),
      Fp::from_bytes_le(
        BigUint::from_str_radix(
          "eff471fba0409897b6a48e8801ad12f95d0009b753cf8f51c128bf6b0bd27fbd",
          16
        )
          .unwrap()
          .to_bytes_le()
          .as_slice()
      )
    ).unwrap();

    let nullifier = Secp256k1Affine::from_xy(
      Fp::from_bytes_le(
        BigUint::from_str_radix(
          "57bc3ed28172ef8adde4b9e0c2cce745fcc5a66473a45c1e626f1d0c67e55830",
          16
        )
          .unwrap()
          .to_bytes_le()
          .as_slice()
      ),
      Fp::from_bytes_le(
        BigUint::from_str_radix(
          "6a2f41488d58f33ae46edd2188e111609f9f3ae67ea38fa891d6087fe59ecb73",
          16
        )
          .unwrap()
          .to_bytes_le()
          .as_slice()
      )
    ).unwrap();

    let c = Fp::from_bytes_le(
      BigUint::from_str_radix(
        "c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83254",
        16
      )
        .unwrap()
        .to_bytes_le()
        .as_slice()
    );

    let s = Fp::from_bytes_le(
      BigUint::from_str_radix(
        "383a44baf62afb3e16b18c222b230e7b5226bc9044efb19e8863044183f69bed",
        16
      )
        .unwrap()
        .to_bytes_le()
        .as_slice()
    );

    base_test()
      .k(14)
      .lookup_bits(13)
      .expect_satisfied(true)
      .run(|ctx, range| {
        let fp_chip = FpChip::<Fr>::new(range, 88, 3);
        let ecc_chip = EccChip::<Fr, FpChip<Fr>>::new(&fp_chip);

        let nullifier = ecc_chip.load_private_unchecked(ctx, (nullifier.x, nullifier.y));
        let s = fp_chip.load_private(ctx, s);
        let c = fp_chip.load_private(ctx, c);
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

        verify_plume::<Fr>(ctx, &ecc_chip, 4, 4, plume_input)
      });
  }
}
