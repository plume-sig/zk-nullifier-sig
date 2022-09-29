mod error;
mod hash_to_curve;
#[cfg(test)]
mod tests;

pub mod sig {
    use crate::error::CryptoError;
    use crate::hash_to_curve;
    use ark_ec::{AffineCurve, ProjectiveCurve, models::SWModelParameters};
    use ark_ec::short_weierstrass_jacobian::GroupAffine;
    use ark_ff::{PrimeField, ToBytes};
    use ark_std::{
        marker::PhantomData,
        UniformRand,
        rand::Rng,
    };
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Read, Write};
    use sha2::{Sha512, Digest};
    use secp256k1::sec1::Sec1EncodePoint;

    pub struct DeterministicNullifierSignatureScheme<'a, C: ProjectiveCurve, Fq: ark_ff::PrimeField, P: ark_ec::SWModelParameters> {
        _group: PhantomData<C>,
        _field: PhantomData<Fq>,
        _parameters: PhantomData<P>,
        _message_lifetime: PhantomData<&'a ()>,
    }

    pub fn affine_to_bytes<P: SWModelParameters>(
        point: &GroupAffine<P>
    ) -> Vec::<u8> {
        let encoded = point.to_encoded_point(true);
        let b = hex::decode(encoded).unwrap();
        b.to_vec()
    }

    fn compute_h<'a, C: ProjectiveCurve, Fq: PrimeField, P: SWModelParameters>(
        pk: &GroupAffine<P>,
        message: &'a [u8],
    ) -> Result<GroupAffine<P>, CryptoError> {
        //let pk_affine_bytes_vec = affine_to_bytes::<P>(pk);
        //let m_pk = [message, pk_affine_bytes_vec.as_slice()].concat();
        //hash_to_curve::try_and_increment::<C>(m_pk.as_slice())
        Ok(hash_to_curve::hash_to_curve::<Fq, P>(message, pk))
    }

    fn compute_c<P: SWModelParameters>(
        g: &GroupAffine<P>,
        pk: &GroupAffine<P>,
        h: &GroupAffine<P>,
        nul: &GroupAffine<P>,
        g_r: &GroupAffine<P>,
        z: &GroupAffine<P>,
    ) -> P::ScalarField {
        // Compute c = sha512([g, pk, h, nul, g^r, z])
        let g_bytes = affine_to_bytes::<P>(g);
        let pk_bytes = affine_to_bytes::<P>(pk);
        let h_bytes = affine_to_bytes::<P>(h);
        let nul_bytes = affine_to_bytes::<P>(nul);
        let g_r_bytes = affine_to_bytes::<P>(g_r);
        let z_bytes = affine_to_bytes::<P>(z);

        let c_preimage_vec = [
            g_bytes,
            pk_bytes,
            h_bytes,
            nul_bytes,
            g_r_bytes,
            z_bytes,
        ].concat();

        let mut sha512_hasher = Sha512::new();
        sha512_hasher.update(c_preimage_vec.as_slice());
        let sha512_hasher_result = sha512_hasher.finalize();

        // Take the first 32 bytes
        let mut first_32 = Vec::<u8>::with_capacity(32);
        for i in 0..32 {
            first_32.push(sha512_hasher_result[i]);
        }

        // Convert digest bytes to a scalar
        let c = first_32.as_slice();
        let c_be = P::ScalarField::from_be_bytes_mod_order(c);

        P::ScalarField::from(c_be)
    }

    pub trait VerifiableUnpredictableFunction {
        type Message: ToBytes;
        type Parameters: CanonicalSerialize + CanonicalDeserialize;
        type PublicKey: CanonicalSerialize + CanonicalDeserialize;
        type SecretKey: CanonicalSerialize + CanonicalDeserialize;
        type Signature: CanonicalSerialize + CanonicalDeserialize;

        /// Generate a public key and a private key.
        fn keygen<R: Rng>(
            pp: &Self::Parameters,
            rng: &mut R,
        ) -> Result<(Self::PublicKey, Self::SecretKey), CryptoError>;

        /// Sign a message.
        fn sign<R: Rng>(
            pp: &Self::Parameters,
            rng: &mut R,
            keypair: (&Self::PublicKey, &Self::SecretKey),
            message: Self::Message,
        ) -> Result<Self::Signature, CryptoError>;

        /// Sign a message using an specified r value
        fn sign_with_r(
            pp: &Self::Parameters,
            keypair: (&Self::PublicKey, &Self::SecretKey),
            message: Self::Message,
            r: Self::SecretKey,
        ) -> Result<Self::Signature, CryptoError>;

        fn verify_non_zk(
            pp: &Self::Parameters,
            pk: &Self::PublicKey,
            sig: &Self::Signature,
            message: Self::Message,
        ) -> Result<bool, CryptoError>;
    }

    #[derive(Copy, Clone, ark_serialize_derive::CanonicalSerialize, ark_serialize_derive::CanonicalDeserialize)]
    pub struct Parameters<P: SWModelParameters> {
        pub g: GroupAffine<P>,
    }

    #[derive(Copy, Clone, ark_serialize_derive::CanonicalSerialize, ark_serialize_derive::CanonicalDeserialize)]
    pub struct Signature<P: SWModelParameters> {
        pub z: GroupAffine<P>,
        pub g_r: GroupAffine<P>,
        pub s: P::ScalarField,
        pub c: P::ScalarField,
        pub nul: GroupAffine<P>,
    }

    impl<'a, C: ProjectiveCurve, Fq: PrimeField, P: SWModelParameters> VerifiableUnpredictableFunction for DeterministicNullifierSignatureScheme<'a, C, Fq, P> {
        type Message = &'a [u8];
        type Parameters = Parameters<P>;
        type PublicKey = GroupAffine<P>;
        type SecretKey = P::ScalarField;
        type Signature = Signature<P>;

        fn keygen<R: Rng>(
            pp: &Self::Parameters,
            rng: &mut R,
        ) -> Result<(Self::PublicKey, Self::SecretKey), CryptoError> {
            let secret_key = Self::SecretKey::rand(rng).into();
            let public_key = pp.g.mul(secret_key).into();
            Ok((public_key, secret_key))
        }
        
        fn sign_with_r(
            pp: &Self::Parameters,
            keypair: (&Self::PublicKey, &Self::SecretKey),
            message: Self::Message,
            r: P::ScalarField,
        ) -> Result<Self::Signature, CryptoError> {
            let g = pp.g;
            let g_r = g.mul(r).into_affine();

            // Compute h = htc([m, pk])
            let h = compute_h::<C, Fq, P>(&keypair.0, &message).unwrap();
            
            // Compute z = h^r
            let z = h.mul(r).into_affine();

            // Compute nul = h^sk
            let nul = h.mul(*keypair.1).into_affine();

            // Compute c = sha512([g, pk, h, nul, g^r, z])
            let c_scalar: P::ScalarField = compute_c::<P>(
                &g,
                keypair.0,
                &h,
                &nul,
                &g_r,
                &z,
            );

            // Compute s = r + sk ⋅ c
            let sk_c = keypair.1.into_repr().into() * c_scalar.into_repr().into();
            let s = r.into_repr().into() + sk_c;

            let s_scalar = P::ScalarField::from(s);

            let signature = Signature {
                z,
                s: s_scalar,
                g_r,
                c: c_scalar,
                nul
            };
            Ok(signature)
        }

        fn sign<R: Rng>(
            pp: &Self::Parameters,
            rng: &mut R,
            keypair: (&Self::PublicKey, &Self::SecretKey),
            message: Self::Message,
        ) -> Result<Self::Signature, CryptoError> {
            // Pick a random r from Fp
            let r: P::ScalarField = Self::SecretKey::rand(rng).into();

            Self::sign_with_r(pp, keypair, message, r)
        }

        fn verify_non_zk(
            pp: &Self::Parameters,
            pk: &Self::PublicKey,
            sig: &Self::Signature,
            message: Self::Message,
        ) -> Result<bool, CryptoError> {
            // Compute h = htc([m, pk])
            let h = compute_h::<C, Fq, P>(pk, message).unwrap();

            // Compute c' = sha512([g, pk, h, nul, g^r, z])
            let c_scalar: P::ScalarField = compute_c::<P>(
                &pp.g,
                pk,
                &h,
                &sig.nul,
                &sig.g_r,
                &sig.z,
            );

            // Reject if g^s ⋅ pk^{-c} != g^r
            let g_s = pp.g.mul(sig.s);
            let pk_c = pk.mul(sig.c);
            let g_s_pk_c = g_s - pk_c;

            if sig.g_r != g_s_pk_c {
                return Ok(false);
            }

            // Reject if h^s ⋅ nul^{-c} = z
            let h_s = h.mul(sig.s);
            let nul_c = sig.nul.mul(sig.c);
            let h_s_nul_c = h_s - nul_c;

            if sig.z != h_s_nul_c {
                return Ok(false)
            }

            // Reject if c != c'
            if c_scalar != sig.c {
                return Ok(false);
            }
            
            Ok(true)
        }
    }
}
