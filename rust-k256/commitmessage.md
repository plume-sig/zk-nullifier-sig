```rust
        ...
        [ProjectivePoint::GENERATOR.to_encoded_point(true).as_bytes(), &pk_bytes, enc!(hashed_to_curve)].map(|b| hashers[0].update(b));
        for b in [enc!(nullifier), enc![r_point], enc!(hashed_to_curve_r)] {
            hashers[0].update(b);
            hashers[1].update(b);
        }
        
        let c = hashers.map(|h| h.finalize());
        let c_scalar = c.clone().map(|c_i| NonZeroScalar::reduce_nonzero(U256::from_be_byte_array(c_i)));
        // Compute s = r + sk ⋅ c
        let s_scalar = c_scalar.map(|c_scalar_i| NonZeroScalar::new(*r_scalar + *(self.to_nonzero_scalar() * c_scalar_i))
            .expect("something is terribly wrong if the nonce is equal to negated product of the secret and the hash"));
        
        Ok(PlumeSignatureCombined{
            message: msg.to_owned(),
            pk: pk.into(),
            nullifier: nullifier.to_point(),
            v2_c: c[1],
            v2_s: *s_scalar[1],
            v1_c: c[0],
            v1_s: *s_scalar[0],
            v1_r_point: r_point.into(),
            v1_hashed_to_curve_r: hashed_to_curve_r.to_point(),
        })
    }
}
/// Struct holding mandatory signature data for ... PLUME signature
#[derive(Debug)]
pub struct PlumeSignatureCombined {
    /// The message that was signed.
    pub message: Vec<u8>,
    /// The public key used to verify the signature.
    pub pk: ProjectivePoint,
    /// The nullifier.
    pub nullifier: ProjectivePoint,
    /// Part of the signature data.
    pub v2_c: Output<Sha256>,
    /// Part of the signature data, a scalar value.
    pub v2_s: Scalar,
    /// Part of the signature data.
    pub v1_c: Output<Sha256>,
    /// Part of the signature data, a scalar value.
    pub v1_s: Scalar,
    /// Part of the V1 signature data, a curve point.  
    pub v1_r_point: ProjectivePoint,
    /// Part of the V1 signature data, a curve point.
    pub v1_hashed_to_curve_r: ProjectivePoint,
}
impl PlumeSignatureCombined {
    pub fn separate(self) -> (PlumeSignature, PlumeSignature) {
        let (pk, nullifier) = (self.pk, self.nullifier); 
        (
            PlumeSignature{ 
                message: self.message.clone(), pk, nullifier, c: self.v1_c, s: self.v1_s, v1specific: Some(
                    PlumeSignatureV1Fields{ r_point: self.v1_r_point, hashed_to_curve_r: self.v1_hashed_to_curve_r }
                ) 
            }, 
            PlumeSignature{ message: self.message, pk, nullifier, c: self.v2_c, s: self.v2_s, v1specific: None }, 
        )
    }
}
```
_____________________________________
```rust
pub enum PlumeSignature{
    V1(PlumeSignatureV1),
    V2(PlumeSignatureV2),
}
pub struct PlumeSignatureV1 {
    v2: PlumeSignatureV2,
    v1: PlumeSignatureV1Fields
}
/// Struct holding mandatory signature data for a PLUME signature.
pub struct PlumeSignatureV2 {
    /// The message that was signed.
    pub message: Vec<u8>,
    /// The public key used to verify the signature.
    pub pk: ProjectivePoint,
    /// The nullifier.
    pub nullifier: ProjectivePoint,
    /// Part of the signature data.
    pub c: Output<Sha256>,
    /// Part of the signature data, a scalar value.
    pub s: Scalar,
    // /// Optional signature data for variant 1 signatures.
    // pub v1: Option<PlumeSignatureV1Fields>,
}
/// struct holding additional signature data used in variant 1 of the protocol.
#[derive(Debug)]
pub struct PlumeSignatureV1Fields {
    /// Part of the signature data, a curve point.  
    pub r_point: ProjectivePoint,
    /// Part of the signature data, a curve point.
    pub hashed_to_curve_r: ProjectivePoint,
}

impl signature::RandomizedSigner<PlumeSignatureV1> for SecretKey {}
impl signature::RandomizedSigner<PlumeSignatureV2> for SecretKey {}
```