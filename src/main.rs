use ring::{
    digest::{digest, SHA256}, // test, test_file,
    error::{self, Unspecified},
    rand,
    signature::{self, EcdsaKeyPair, EcdsaSigningAlgorithm, Signature},
};

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}

// Assumes no malicious inputs.
trait NullifierSig {
    fn nullifier_sig_sign(&self, m: String) -> Result<&[u8; 256], error::Unspecified>;
    fn nullifier_sig_verify(&self, sig: &[u8; 256], m: String) -> Result<bool, error::Unspecified>;
}

impl NullifierSig for EcdsaKeyPair {
    fn nullifier_sig_sign(&self, message: String) -> Result<&[u8; 256], error::Unspecified> {
        // Calculate e=HASH(m). (HASH ~= SHA-2, with the output converted to an integer.)
        // The digest (truncated message hash) is calculated the same as ECDSA
        let m = message.as_bytes();
        let alg = &SHA256;
        let rng = rand::SystemRandom::new();
        let h = digest(alg, m);
        let r: [u8; 256] = rand::generate(&rng).unwrap().expose();
        print_type_of(&r);
        return Ok(&[0; 256]);
        // let z = Self::from_be_bytes_reduced(z);
        // Ok((Signature::from_scalars(z, z)?, None))
    }
    fn nullifier_sig_verify(
        &self,
        sig: &[u8; 256],
        message: String,
    ) -> Result<bool, error::Unspecified> {
        return Ok(true);
    }
}
fn main() {
    let message = String::from("example message");
    let message_verify = message.clone();
    let alg: &&EcdsaSigningAlgorithm = &&signature::ECDSA_P256_SHA256_ASN1_SIGNING;
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
    let test_keypair = signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8_bytes.as_ref()).unwrap();
    let nullifier_signature = test_keypair.nullifier_sig_sign(message).unwrap();

    let verified = test_keypair
        .nullifier_sig_verify(nullifier_signature, message_verify)
        .unwrap();

    println!("verified: {}", verified);
}
