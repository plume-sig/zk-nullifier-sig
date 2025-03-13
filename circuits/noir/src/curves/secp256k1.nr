use nodash::array::pack_bytes;
use std::hash::poseidon2::Poseidon2::hash;
use noir_bigcurve::curves::secp256k1::{
    Secp256k1, Secp256k1_Params, Secp256k1Fq, Secp256k1Fr, Secp256k1Scalar,
};
use noir_bigcurve::scalar_field::ScalarField;
use bignum::BigNum;
use noir_bigcurve::BigCurve;

comptime global DST_PRIME: [u8; 50] = [
    81, 85, 85, 88, 45, 86, 48, 49, 45, 67, 83, 48, 50, 45, 119, 105, 116, 104, 45, 115, 101, 99,
    112, 50, 53, 54, 107, 49, 95, 88, 77, 68, 58, 83, 72, 65, 45, 50, 53, 54, 95, 83, 83, 87, 85,
    95, 82, 79, 95, 49,
];

global K1_0: Secp256k1Fq = Secp256k1Fq::from_slice([
    0xe38e38e38e38e38e38e38daaaaa8c7,
    0xe38e38e38e38e38e38e38e38e38e38,
    0x8e38,
]);
global K1_1: Secp256k1Fq = Secp256k1Fq::from_slice([
    0x95d2fc0bf63b92dfff1044f17c6581,
    0xd4c80bc321d5b9f315cea7fd44c5d5,
    0x7d3,
]);
global K1_2: Secp256k1Fq = Secp256k1Fq::from_slice([
    0x506144037c40314ecbd0b53d9dd262,
    0x328d23f234e6e2a413deca25caece4,
    0x534c,
]);
global K1_3: Secp256k1Fq = Secp256k1Fq::from_slice([
    0xe38e38e38e38e38e38e38daaaaa88c,
    0xe38e38e38e38e38e38e38e38e38e38,
    0x8e38,
]);

global K2_0: Secp256k1Fq = Secp256k1Fq::from_slice([
    0xcd409542f8487d9fe6b745781eb49b,
    0x71193d94918a9ca34ccbb7b640dd86,
    0xd357,
]);
global K2_1: Secp256k1Fq = Secp256k1Fq::from_slice([
    0xd36b641f5e41bbc52a56612a8c6d14,
    0xc6f64383dc1df7c4b2d51b54225406,
    0xedad,
]);

global K3_0: Secp256k1Fq = Secp256k1Fq::from_slice([
    0x684bda12f684bda12f684b8e38e23c,
    0x12f684bda12f684bda12f684bda12f,
    0x4bda,
]);
global K3_1: Secp256k1Fq = Secp256k1Fq::from_slice([
    0x7ab046d686da6fdffc90fc201d71a3,
    0xc32d5cb7c0fa9d0a54b12a0a6d564,
    0xc75e,
]);
global K3_2: Secp256k1Fq = Secp256k1Fq::from_slice([
    0x2830a201be2018a765e85a9ecee931,
    0x194691f91a73715209ef6512e57672,
    0x29a6,
]);
global K3_3: Secp256k1Fq = Secp256k1Fq::from_slice([
    0xa12f684bda12f684bda12f38e38d84,
    0x4bda12f684bda12f684bda12f684bd,
    0x2f68,
]);

global K4_0: Secp256k1Fq = Secp256k1Fq::from_slice([
    0xfffffffffffffffffffffefffff93b,
    0xffffffffffffffffffffffffffffff,
    0xffff,
]);
global K4_1: Secp256k1Fq = Secp256k1Fq::from_slice([
    0x67c1bfc8e8d978dfb425d2685c2573,
    0x534bb8bdb49fd5e9e6632722c29894,
    0x7a06,
]);
global K4_2: Secp256k1Fq = Secp256k1Fq::from_slice([
    0x3d21162f0d6299a7bf8192bfd2a76f,
    0xaa716545ca2cf3a70c3fa8fe337e0a,
    0x6484,
]);

global Z: Secp256k1Fq = Secp256k1Fq::from_slice([
    0xfffffffffffffffffffffefffffc24,
    0xffffffffffffffffffffffffffffff,
    0xffff,
]);
global A: Secp256k1Fq = Secp256k1Fq::from_slice([
    0x53d363cb6f0e5d405447c01a444533,
    0x31abdd661adca08a5558f0f5d272e9,
    0x3f87,
]);
global B: Secp256k1Fq = Secp256k1Fq::from_slice([0x6eb, 0, 0]);

comptime global ONE: Secp256k1Fq = Secp256k1Fq::one();

pub fn hash_to_curve<let N: u32>(msg: [u8; N]) -> Secp256k1 {
    let u = hash_to_field(msg);

    let q0 = map_to_curve(u.x);
    let q1 = map_to_curve(u.y);

    iso_map(q0) + iso_map(q1)
}

pub fn hash_to_field<let N: u32>(msg: [u8; N]) -> Secp256k1 {
    let expand_message_xmd = expand_message_xmd(msg);

    let mut u0_bytes_to_registers = [0 as u8; 48];
    let mut u1_bytes_to_registers = [0 as u8; 48];

    for i in 0..48 {
        u0_bytes_to_registers[i] = expand_message_xmd[i];
        u1_bytes_to_registers[i] = expand_message_xmd[48 + i];
    }

    let u0_bytes_to_registers = bytes_to_registers(u0_bytes_to_registers);
    let u1_bytes_to_registers = bytes_to_registers(u1_bytes_to_registers);

    BigCurve { x: u0_bytes_to_registers, y: u1_bytes_to_registers, is_infinity: false }
}

fn bytes_to_registers(ui: [u8; 48]) -> Secp256k1Fq {
    let shift = Secp256k1Fq::from_slice([0, 0x100, 0]);
    let mut small = [0 as u8; 32];
    let mut big = [0 as u8; 32];

    for i in 0..16 {
        small[i + 16] = ui[i + 32];
    }
    for i in 0..32 {
        big[i] = ui[i];
    }
    let res = Secp256k1Fq::from_be_bytes(big);
    res * shift + Secp256k1Fq::from_be_bytes(small)
}

pub fn expand_message_xmd<let N: u32>(msg: [u8; N]) -> [u8; 96] {
    let b0 = msg_prime(msg);
    let b1 = hash_b(1, b0);
    let b2 = hash_bi(2, b0, b1);
    let b3 = hash_bi(3, b0, b2);

    let mut out = [0 as u8; 96];
    for i in 0..32 {
        out[i] = b1[i];
    }
    for i in 0..32 {
        out[32 + i] = b2[i];
    }
    for i in 0..32 {
        out[64 + i] = b3[i];
    }

    out
}

fn msg_prime<let N: u32>(msg: [u8; N]) -> [u8; 32] {
    let mut preimage = [0; 64 + N + 2 + 1 + 50];

    for i in 0..N {
        preimage[64 + i] = msg[i];
    }

    let lib_str = [0, 96];
    for i in 0..lib_str.len() {
        preimage[64 + N + i] = lib_str[i];
    }

    preimage[64 + N + 2] = 0;

    for i in 0..50 {
        preimage[64 + N + 2 + 1 + i] = DST_PRIME[i];
    }

    let packed_preimage = pack_bytes(preimage);
    hash(packed_preimage, packed_preimage.len()).to_le_bytes()
}

fn hash_bi(b_idx: u8, b0: [u8; 32], b1: [u8; 32]) -> [u8; 32] {
    assert(b_idx < 8);

    let mut res = [0 as u8; 32];
    for i in 0..32 {
        res[i] = b0[i] ^ b1[i];
    }

    hash_b(b_idx, res)
}

fn hash_b(b_idx: u8, b: [u8; 32]) -> [u8; 32] {
    assert(b_idx < 8);
    let mut preimage = [0; 32 + 1 + 50];

    for i in 0..32 {
        preimage[i] = b[i];
    }

    preimage[32] = b_idx;

    for i in 0..50 {
        preimage[32 + 1 + i] = DST_PRIME[i];
    }

    let packed_preimage = pack_bytes(preimage);

    hash(packed_preimage, packed_preimage.len()).to_le_bytes()
}


// Returns point E' isogeneous to secp256k1.
pub fn map_to_curve(u: Secp256k1Fq) -> Secp256k1 {
    let tv1 = ONE / (Z * Z * u * u * u * u + Z * u * u);
    let x1 = (B.neg() / A) * (ONE + tv1);

    let gx1 = x1 * x1 * x1 + A * x1 + B;
    let x2 = Z * u * u * x1;
    let gx2 = x2 * x2 * x2 + A * x2 + B;
    let (x, mut y) = select_xy(x1, x2, gx1, gx2);

    let ubyte: [u8; 32] = u.to_le_bytes();
    let ybyte: [u8; 32] = y.to_le_bytes();
    let u_sign: u1 = (ubyte[0] as Field).to_le_bits::<8>()[0];
    let y_sign: u1 = (ybyte[0] as Field).to_le_bits::<8>()[0];

    if u_sign != y_sign {
        y = y.neg();
    }

    BigCurve { x, y, is_infinity: false }
}

fn select_xy(
    x1: Secp256k1Fq,
    x2: Secp256k1Fq,
    gx1: Secp256k1Fq,
    gx2: Secp256k1Fq,
) -> (Secp256k1Fq, Secp256k1Fq) {
    let gx1_sqrt = unsafe { gx1.__tonelli_shanks_sqrt() };
    let gx2_sqrt = unsafe { gx2.__tonelli_shanks_sqrt() };

    let gx1_is_square = gx1_sqrt.is_some();

    let x: Secp256k1Fq = if gx1_is_square { x1 } else { x2 };
    let y = gx1_sqrt.xor(gx2_sqrt).unwrap();

    let y_preimage: Secp256k1Fq = if gx1_is_square { gx1 } else { gx2 };

    // Constrain out-of-circuit root computation.
    let y_squared = y * y;
    assert(y_preimage == y_squared, "Square root is incorrect");

    (x, y)
}


pub fn iso_map(p: Secp256k1) -> Secp256k1 {
    let x2 = p.x * p.x;
    let x3 = x2 * p.x;

    let x_num = x_num(p.x, x2, x3);
    let x_den = x_den(p.x, x2);
    let y_num = y_num(p.x, x2, x3);
    let y_den = y_den(p.x, x2, x3);

    let x = (x_num / x_den);
    let y = (p.y * y_num / y_den);

    BigCurve { x, y, is_infinity: false }
}

fn x_num(x: Secp256k1Fq, x2: Secp256k1Fq, x3: Secp256k1Fq) -> Secp256k1Fq {
    K1_0 + K1_1 * x + K1_2 * x2 + K1_3 * x3
}

fn x_den(x: Secp256k1Fq, x2: Secp256k1Fq) -> Secp256k1Fq {
    x2 + K2_1 * x + K2_0
}

fn y_num(x: Secp256k1Fq, x2: Secp256k1Fq, x3: Secp256k1Fq) -> Secp256k1Fq {
    K3_0 + K3_1 * x + K3_2 * x2 + K3_3 * x3
}

fn y_den(x: Secp256k1Fq, x2: Secp256k1Fq, x3: Secp256k1Fq) -> Secp256k1Fq {
    K4_0 + K4_1 * x + K4_2 * x2 + x3
}
