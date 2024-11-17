use ark_ff::{
    // biginteger::BigInteger320 as BigInteger,
    fields::{
        // FftParameters,
        // Fp320,
        // Fp320Parameters,
        // FpParameters,
        Fp256,
        MontBackend,
        MontConfig,
    },
};
/*
   ~~Supported BigInteger sizes:~~
   ~~256, 320, 384, 448, 768, 832~~
*/

#[derive(MontConfig)]
#[modulus = "115792089237316195423570985008687907852837564279074904382605163141518161494337"]
#[generator = "7"]
#[small_subgroup_base = "3"]
#[small_subgroup_power = "1"]
pub struct FrConfig;
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;

// pub struct FrParameters;

// impl Fp320Parameters for FrParameters {}

// impl FftParameters for FrParameters {
//     type BigInt = BigInteger;

//     const TWO_ADICITY: u32 = 6;

//     const TWO_ADIC_ROOT_OF_UNITY: Self::BigInt = BigInteger::new([
//         0x0112cb0f605a214a, 0x92225daffb794500, 0x7e42003a6ccb6212, 0x55980b07bc222114, 0x0000000000000000,
//     ]);
// }

// impl FpParameters for FrParameters {
//     #[rustfmt::skip]
//     const MODULUS: BigInteger = BigInteger::new([
//         0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff, 0x0000000000000000,
//     ]);

//     const MODULUS_BITS: u32 = 256;

//     const CAPACITY: u32 = Self::MODULUS_BITS - 1;

//     /// The number of bits that must be shaved from the beginning of
//     /// the representation when randomly sampling.
//     const REPR_SHAVE_BITS: u32 = 64;

//     /// Let `M` be the power of 2^64 nearest to `Self::MODULUS_BITS`. Then
//     /// `R = M % Self::MODULUS`.
//     /// R = M % MODULUS
//     #[rustfmt::skip]
//     const R: BigInteger = BigInteger::new([
//         0x0000000000000000, 0x402da1732fc9bebf, 0x4551231950b75fc4, 0x0000000000000001, 0x0000000000000000,
//     ]);

//     /// R2 = R * R % MODULUS
//     #[rustfmt::skip]
//     const R2: BigInteger = BigInteger::new([
//         0x1e004f504dfd7f79, 0x08fcf59774a052ea, 0x27c4120fc94e1653, 0x3c1a6191e5702644, 0x0000000000000000,
//     ]);

//     /// INV = -MODULUS^{-1} mod 2^64
//     const INV: u64 = 5408259542528602431;

//     /// A multiplicative generator of the field, in Montgomery form (g * R % modulus).
//     /// `Self::GENERATOR` is an element having multiplicative order
//     /// `Self::MODULUS - 1`. In other words, the generator is the lowest value such that
//     /// MultiplicativeOrder(generator, p) = p - 1 where p is the modulus.
//     #[rustfmt::skip]
//     const GENERATOR: BigInteger = BigInteger::new([
//         0x0000000000000000, 0xc13f6a264e843739, 0xe537f5b135039e5d, 0x0000000000000008, 0x0000000000000000,
//     ]);

//     #[rustfmt::skip]
//     const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger::new([
//         0xdfe92f46681b20a0, 0x5d576e7357a4501d, 0xffffffffffffffff, 0x7fffffffffffffff, 0x0000000000000000,
//     ]);

//     #[rustfmt::skip]
//     const T: BigInteger = BigInteger::new([
//         0xeeff497a3340d905, 0xfaeabb739abd2280, 0xffffffffffffffff, 0x03ffffffffffffff, 0x0000000000000000,
//     ]);

//     #[rustfmt::skip]
//     const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger::new([
//         0x777fa4bd19a06c82, 0xfd755db9cd5e9140, 0xffffffffffffffff, 0x01ffffffffffffff, 0x0000000000000000,
//     ]);
// }
