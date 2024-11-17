mod expander;
use ark_ff::{field_hashers::HashToField, Field, PrimeField};
use core::marker::PhantomData;
use expander::{Expander, ExpanderXmd};
use sha2::digest::{core_api::BlockSizeUser, FixedOutputReset};

pub struct FixedFieldHasher<H: FixedOutputReset + Default + Clone, const SEC_PARAM: usize = 128> {
    expander: ExpanderXmd<H>,
    len_per_base_elem: usize,
}

impl<F: Field, H: FixedOutputReset + BlockSizeUser + Default + Clone, const SEC_PARAM: usize>
    HashToField<F> for FixedFieldHasher<H, SEC_PARAM>
{
    fn new(dst: &[u8]) -> Self {
        // The final output of `hash_to_field` will be an array of field
        // elements from F::BaseField, each of size `len_per_elem`.
        let len_per_base_elem = get_len_per_elem::<F, SEC_PARAM>();

        let expander = ExpanderXmd {
            hasher: PhantomData,
            dst: dst.to_vec(),
            block_size: H::block_size(),
        };

        FixedFieldHasher {
            expander,
            len_per_base_elem,
        }
    }

    fn hash_to_field<const N: usize>(&self, message: &[u8]) -> [F; N] {
        let m = F::extension_degree() as usize;

        // The user requests `N` of elements of F_p^m to output per input msg,
        // each field element comprising `m` BasePrimeField elements.
        let len_in_bytes = N * m * self.len_per_base_elem;
        let uniform_bytes = self.expander.expand(message, len_in_bytes);

        let cb = |i| {
            let base_prime_field_elem = |j| {
                let elm_offset = self.len_per_base_elem * (j + i * m);
                F::BasePrimeField::from_be_bytes_mod_order(
                    &uniform_bytes[elm_offset..][..self.len_per_base_elem],
                )
            };
            F::from_base_prime_field_elems((0..m).map(base_prime_field_elem)).unwrap()
        };
        ark_std::array::from_fn::<F, N, _>(cb)
    }
}

const fn get_len_per_elem<F: Field, const SEC_PARAM: usize>() -> usize {
    // ceil(log(p))
    let base_field_size_in_bits = F::BasePrimeField::MODULUS_BIT_SIZE as usize;
    // ceil(log(p)) + security_parameter
    let base_field_size_with_security_padding_in_bits = base_field_size_in_bits + SEC_PARAM;
    // ceil( (ceil(log(p)) + security_parameter) / 8)
    let bytes_per_base_field_elem =
        ((base_field_size_with_security_padding_in_bits + 7) / 8) as u64;
    bytes_per_base_field_elem as usize
}
