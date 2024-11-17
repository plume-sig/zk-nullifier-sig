use ark_ff::{
    // biginteger::BigInteger320 as BigInteger,
    fields::{* /* MontConfig */},
};
use ark_ff_macros::MontConfig;
/*
   ~~Supported BigInteger sizes:~~
   ~~256, 320, 384, 448, 768, 832~~
*/

#[derive(MontConfig)]
#[modulus = "115792089237316195423570985008687907853269984665640564039457584007908834671663"]
#[generator = "3"]
#[small_subgroup_base = "3"]
#[small_subgroup_power = "1"]
pub struct FqConfig;
pub type Fq = Fp256<MontBackend<FqConfig, 4>>;

// pub struct FqParameters;

/* impl Fp320Parameters for FqParameters {}

impl FftParameters for FqParameters {
    type BigInt = BigInteger;

    const TWO_ADICITY: u32 = 1;

    const TWO_ADIC_ROOT_OF_UNITY: Self::BigInt = BigInteger::new([
        0xfffffffefffffc2f, 0xfffffffefffffc2e, 0xffffffffffffffff, 0xffffffffffffffff, 0x0000000000000000,
    ]);
}

impl FpParameters for FqParameters {
    #[rustfmt::skip]
    const MODULUS: BigInteger = BigInteger::new([
        0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x0000000000000000,
    ]);

    const MODULUS_BITS: u32 = 256;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    /// The number of bits that must be shaved from the beginning of
    /// the representation when randomly sampling.
    const REPR_SHAVE_BITS: u32 = 64;

    /// Let `M` be the power of 2^64 nearest to `Self::MODULUS_BITS`. Then
    /// `R = M % Self::MODULUS`.
    /// R = M % MODULUS
    #[rustfmt::skip]
    const R: BigInteger = BigInteger::new([
        0x0000000000000000, 0x00000001000003d1, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    ]);

    /// R2 = R * R % MODULUS
    #[rustfmt::skip]
    const R2: BigInteger = BigInteger::new([
        0x0000000000000000, 0x0000000000000000, 0x000007a2000e90a1, 0x0000000000000001, 0x0000000000000000,
    ]);

    /// INV = -MODULUS^{-1} mod 2^64
    const INV: u64 = 15580212934572586289;

    /// A multiplicative generator of the field, in Montgomery form (g * R % modulus).
    /// `Self::GENERATOR` is an element having multiplicative order
    /// `Self::MODULUS - 1`. In other words, the generator is the lowest value such that
    /// MultiplicativeOrder(generator, p) = p - 1 where p is the modulus.
    #[rustfmt::skip]
    const GENERATOR: BigInteger = BigInteger::new([
        0x0000000000000000, 0x0000000300000b73, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    ]);

    #[rustfmt::skip]
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger::new([
        0xffffffff7ffffe17, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffffff, 0x0000000000000000,
    ]);

    #[rustfmt::skip]
    const T: BigInteger = BigInteger::new([
        0xffffffff7ffffe17, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffffff, 0x0000000000000000,
    ]);

    #[rustfmt::skip]
    const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger::new([
        0xffffffffbfffff0b, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffffffff, 0x0000000000000000,
    ]);
} */
