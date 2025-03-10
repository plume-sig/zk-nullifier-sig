use nodash::array::pack_bytes;
use noir_bigcurve::{BigCurve, BigCurveTrait, CurveParamsTrait};
use noir_bigcurve::BigNumTrait;
use noir_bigcurve::scalar_field::ScalarField;
use std::hash::poseidon2::Poseidon2::hash;

comptime global COMPRESSED_SIZE_BYTES: u32 = 33;

mod tests;
mod curves;
mod utils;

pub struct Plume<CurveParams, BN, let NScalarSlices: u32, let L: u32> {
    msg: [u8; L],
    c: ScalarField<NScalarSlices>,
    s: ScalarField<NScalarSlices>,
    pk: BigCurve<BN, CurveParams>,
    nullifier: BigCurve<BN, CurveParams>,
    hash_to_curve: fn([u8; L + COMPRESSED_SIZE_BYTES]) -> BigCurve<BN, CurveParams>,
}

trait PlumeVerifier<CurveParams, BN, let NScalarSlices: u32, let L: u32> {
    fn new(
        msg: [u8; L],
        c: ScalarField<NScalarSlices>,
        s: ScalarField<NScalarSlices>,
        pk: BigCurve<BN, CurveParams>,
        nullifier: BigCurve<BN, CurveParams>,
        hash_to_curve: fn([u8; L + COMPRESSED_SIZE_BYTES]) -> BigCurve<BN, CurveParams>,
    ) -> Plume<CurveParams, BN, NScalarSlices, L>;
    fn plume_v1(self) -> Field;
    fn plume_v2(self) -> (BigCurve<BN, CurveParams>, BigCurve<BN, CurveParams>);
    fn check_ec_equations(
        self,
    ) -> (BigCurve<BN, CurveParams>, BigCurve<BN, CurveParams>, BigCurve<BN, CurveParams>);
    fn form_plume_msg(self) -> [u8; L + COMPRESSED_SIZE_BYTES];
    fn compress_ec_point(self, point: BigCurve<BN, CurveParams>) -> [u8; COMPRESSED_SIZE_BYTES];
    fn poseidon_12_coordinates(
        self,
        h: BigCurve<BN, CurveParams>,
        gr: BigCurve<BN, CurveParams>,
        hr: BigCurve<BN, CurveParams>,
    ) -> Field;
}

impl<CurveParams, BN, let NScalarSlices: u32, let L: u32> PlumeVerifier<CurveParams, BN, NScalarSlices, L> for Plume<CurveParams, BN, NScalarSlices, L>
where
    BN: BigNumTrait,
    CurveParams: CurveParamsTrait<BN>,
{
    fn new(
        msg: [u8; L],
        c: ScalarField<NScalarSlices>,
        s: ScalarField<NScalarSlices>,
        pk: BigCurve<BN, CurveParams>,
        nullifier: BigCurve<BN, CurveParams>,
        hash_to_curve: fn([u8; L + COMPRESSED_SIZE_BYTES]) -> BigCurve<BN, CurveParams>,
    ) -> Plume<CurveParams, BN, NScalarSlices, L> {
        let plume = Plume { msg, c, s, pk, nullifier, hash_to_curve };
        plume
    }

    fn plume_v1(self) -> Field {
        let (r_point, hashed_to_curve_r, hashed_to_curve) = self.check_ec_equations();

        self.poseidon_12_coordinates(hashed_to_curve, r_point, hashed_to_curve_r)
    }

    fn plume_v2(self) -> (BigCurve<BN, CurveParams>, BigCurve<BN, CurveParams>) {
        let (r_point, hashed_to_curve_r, _) = self.check_ec_equations();

        (r_point, hashed_to_curve_r)
    }

    fn check_ec_equations(
        self,
    ) -> (BigCurve<BN, CurveParams>, BigCurve<BN, CurveParams>, BigCurve<BN, CurveParams>) {
        let s_point = BigCurve::one().mul(self.s);
        let r_point = s_point - self.pk.mul(self.c);

        let plume_msg = self.form_plume_msg();
        let hashed_to_curve = (self.hash_to_curve)(plume_msg);
        let h_pow_s = hashed_to_curve.mul(self.s);
        let hashed_to_curve_r = h_pow_s - self.nullifier.mul(self.c);

        (r_point, hashed_to_curve_r, hashed_to_curve)
    }

    fn form_plume_msg(self) -> [u8; L + COMPRESSED_SIZE_BYTES] {
        let mut plume_msg = [0; L + COMPRESSED_SIZE_BYTES];

        for i in 0..self.msg.len() {
            plume_msg[i] = self.msg[i];
        }

        let compressed_pk = self.compress_ec_point(self.pk);
        for i in 0..COMPRESSED_SIZE_BYTES {
            plume_msg[self.msg.len() + i] = compressed_pk[i];
        }

        plume_msg
    }

    fn compress_ec_point(self, point: BigCurve<BN, CurveParams>) -> [u8; COMPRESSED_SIZE_BYTES] {
        let x_bn: BN = point.x;
        let x: [u8; 32] = x_bn.to_le_bytes();
        let mut compressed = [0 as u8; COMPRESSED_SIZE_BYTES];

        let y_bn: BN = point.y;
        let y: [u8; 32] = y_bn.to_le_bytes();
        let sign = y[0] & 1;
        compressed[0] = sign + 2; // convention to encode `y` as 02 or 03
        for i in 0..32 {
            compressed[32 - i] = x[i];
        }

        compressed
    }

    fn poseidon_12_coordinates(
        self,
        h: BigCurve<BN, CurveParams>,
        gr: BigCurve<BN, CurveParams>,
        hr: BigCurve<BN, CurveParams>,
    ) -> Field {
        let mut compressed = [[0 as u8; COMPRESSED_SIZE_BYTES]; 6];
        compressed[0] = self.compress_ec_point(BigCurve::one());
        compressed[1] = self.compress_ec_point(self.pk);
        compressed[2] = self.compress_ec_point(h);
        compressed[3] = self.compress_ec_point(self.nullifier);
        compressed[4] = self.compress_ec_point(gr);
        compressed[5] = self.compress_ec_point(hr);

        // Concatenate
        let mut res = [0 as u8; COMPRESSED_SIZE_BYTES * 6];
        for i in 0..6 {
            for j in 0..COMPRESSED_SIZE_BYTES {
                res[i * COMPRESSED_SIZE_BYTES + j] = compressed[i][j];
            }
        }

        let packed_res = pack_bytes(res);

        hash(packed_res, packed_res.len())
    }
}

