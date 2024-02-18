use k256::{elliptic_curve::{point::AffineCoordinates}, FieldBytes};
use rand_core::CryptoRng;
use signature::RandomizedSigner;
use plume_rustcrypto::{PlumeSigner, SecretKey};

const R: &[u8] =
    &hex_literal::hex!("93b9323b629f251b8f3fc2dd11f4672c5544e8230d493eceea98a90bda789808");

struct Mock{}
impl rand_core::RngCore for Mock {
    fn next_u32(&mut self) -> u32 {
        todo!()
    }

    fn next_u64(&mut self) -> u64 {
        todo!()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // let r = [
        //     4,
        //     152,
        //     254,
        //     54,
        //     199,
        //     45,
        //     14,
        //     89,
        //     41,
        //     132,
        //     162,
        //     98,
        //     41,
        //     102,
        //     118,
        //     128,
        //     129,
        //     101,
        //     19,
        //     40,
        //     42,
        //     109,
        //     188,
        //     122,
        //     210,
        //     42,
        //     126,
        //     14,
        //     53,
        //     164,
        //     140,
        //     157,
        //     0,
        //     0,
        //     0,
        //     0,
        //     0,
        //     0,
        //     0,
        //     0,
        // ];
        assert!(dest.len() == R.len());
        assert!(dest.len() == 32);
        dest.iter_mut().enumerate().for_each(|(i, x)| *x = R[/* 31 -  */i]);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        todo!()
    }
}
impl CryptoRng for Mock {}
// impl rand_core::CryptoRngCore for Mock {
//     fn as_rngcore(&mut self) -> &mut dyn rand_core::RngCore {
//         todo!()
//     }
// }

#[test]
pub fn test_sign_and_verify() {
    let r_scalar = SecretKey::random(&mut Mock{});
    // dbg!(FieldBytes::from(r_scalar.public_key().as_affine().x()));
    
    // made just with seeding current `plume_arkworks` and using it as the reference

    let message = b"An example app message string";
    let mut key_mat = hex_literal::hex!(
        "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"
    );
    // key_mat.reverse();
    let sk = SecretKey::from_bytes(
        &key_mat.into()
    ).unwrap();
    let pk_projective = sk.public_key();
    // println!("{:x}", pk_projective.as_affine().x());
    // dbg!("{}", pk_projective.as_affine().y_is_odd());
    // let pk = GroupAffine::<Secp256k1Parameters>::from(pk_projective);

    let sig = PlumeSigner::new(&sk, true)
        .sign_with_rng(&mut Mock{}, message);
    dbg!(sig);

}