pragma circom 2.1.2;

include "./node_modules/circom-ecdsa/circuits/ecdsa.circom";
include "./node_modules/circom-ecdsa/circuits/secp256k1.circom";
include "./node_modules/circom-ecdsa/circuits/secp256k1_func.circom";
include "./node_modules/secp256k1_hash_to_curve_circom/circom/hash_to_curve.circom";
include "./node_modules/secp256k1_hash_to_curve_circom/circom/Sha256.circom";
include "./node_modules/circomlib/circuits/bitify.circom";
include "./node_modules/circomlib/circuits/comparators.circom";

// Verifies that a nullifier belongs to a specific public key \
// This blog explains the intuition behind the construction https://blog.aayushg.com/posts/nullifier
template plume_v1(n, k, message_length) {
    signal input c[k];
    signal input s[k];
    signal input plume_message[message_length];
    signal input pk[2][k];
    signal input nullifier[2][k];

    // precomputed values for the hash_to_curve component
    signal input q0_gx1_sqrt[4];
    signal input q0_gx2_sqrt[4];
    signal input q0_y_pos[4];
    signal input q0_x_mapped[4];
    signal input q0_y_mapped[4];

    signal input q1_gx1_sqrt[4];
    signal input q1_gx2_sqrt[4];
    signal input q1_y_pos[4];
    signal input q1_x_mapped[4];
    signal input q1_y_mapped[4];

    component check_ec_equations = check_ec_equations(n, k, message_length);

    check_ec_equations.c <== c;
    check_ec_equations.s <== s;
    check_ec_equations.pk <== pk;
    check_ec_equations.nullifier <== nullifier;

    check_ec_equations.plume_message <== plume_message;

    check_ec_equations.q0_gx1_sqrt <== q0_gx1_sqrt;
    check_ec_equations.q0_gx2_sqrt <== q0_gx2_sqrt;
    check_ec_equations.q0_y_pos <== q0_y_pos;
    check_ec_equations.q0_x_mapped <== q0_x_mapped;
    check_ec_equations.q0_y_mapped <== q0_y_mapped;

    check_ec_equations.q1_gx1_sqrt <== q1_gx1_sqrt;
    check_ec_equations.q1_gx2_sqrt <== q1_gx2_sqrt;
    check_ec_equations.q1_y_pos <== q1_y_pos;
    check_ec_equations.q1_x_mapped <== q1_x_mapped;
    check_ec_equations.q1_y_mapped <== q1_y_mapped;

    // calculate c as sha256(g, pk, h, nullifier, g^r, h^r)
    component c_sha256 = sha256_12_coordinates(n, k);
    var g[2][100];
    g[0] = get_genx(n, k);
    g[1] = get_geny(n, k);

    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < k; j++) {
            c_sha256.coordinates[i][j] <== g[i][j];
            c_sha256.coordinates[2+i][j] <== pk[i][j];
            c_sha256.coordinates[4+i][j] <== check_ec_equations.hashed_to_curve[i][j];
            c_sha256.coordinates[6+i][j] <== nullifier[i][j];
            c_sha256.coordinates[8+i][j] <== check_ec_equations.r_point[i][j];
            c_sha256.coordinates[10+i][j] <== check_ec_equations.hashed_to_curve_r[i][j];
        }
    }

    // check that the input c is the same as the hash value c
    component c_bits[k];
    for (var i = 0; i < k; i++) {
        c_bits[i] = Num2Bits(n);
        c_bits[i].in <== c[i];
    }

    for (var i = 0; i < k; i++) {
        for (var j = 0; j < n; j++) {
            // We may have 3 registers of 86 bits, which means we end up getting two extra 0 bits which don't have to be equal to the sha256 hash
            // TODO: verify that we don't have to equate these to 0
            if (i*k + j < 256) {
                c_sha256.out[i*n + j] === c_bits[k-1-i].out[n-1-j]; // The sha256 output is little endian, whereas the c_bits is big endian (both at the register and bit level)
            }
        }
    }
}

// v2 is the same as v1, except that the sha256 check is done outside the circuit.
// We output `r_point` ($g^r$) and `hashed_to_curve_r` ($hash^r$) as public values so that the verifier can calculate the hash themselves.
// The change is explained here https://www.notion.so/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff
template plume_v2(n, k, message_length) {
    signal input c[k];
    signal input s[k];
    signal input plume_message[message_length];
    signal input pk[2][k];
    signal input nullifier[2][k];

    signal output r_point[2][k];
    signal output hashed_to_curve_r[2][k];

    // precomputed values for the hash_to_curve component
    signal input q0_gx1_sqrt[4];
    signal input q0_gx2_sqrt[4];
    signal input q0_y_pos[4];
    signal input q0_x_mapped[4];
    signal input q0_y_mapped[4];

    signal input q1_gx1_sqrt[4];
    signal input q1_gx2_sqrt[4];
    signal input q1_y_pos[4];
    signal input q1_x_mapped[4];
    signal input q1_y_mapped[4];

    component check_ec_equations = check_ec_equations(n, k, message_length);

    check_ec_equations.c <== c;
    check_ec_equations.s <== s;
    check_ec_equations.pk <== pk;
    check_ec_equations.nullifier <== nullifier;

    check_ec_equations.plume_message <== plume_message;

    check_ec_equations.q0_gx1_sqrt <== q0_gx1_sqrt;
    check_ec_equations.q0_gx2_sqrt <== q0_gx2_sqrt;
    check_ec_equations.q0_y_pos <== q0_y_pos;
    check_ec_equations.q0_x_mapped <== q0_x_mapped;
    check_ec_equations.q0_y_mapped <== q0_y_mapped;

    check_ec_equations.q1_gx1_sqrt <== q1_gx1_sqrt;
    check_ec_equations.q1_gx2_sqrt <== q1_gx2_sqrt;
    check_ec_equations.q1_y_pos <== q1_y_pos;
    check_ec_equations.q1_x_mapped <== q1_x_mapped;
    check_ec_equations.q1_y_mapped <== q1_y_mapped;

    hashed_to_curve_r <== check_ec_equations.hashed_to_curve_r;
    r_point <== check_ec_equations.r_point;
}

template check_ec_equations(n, k, message_length) {
    signal input c[k];
    signal input s[k];
    signal input plume_message[message_length];
    signal input pk[2][k];
    signal input nullifier[2][k];

    signal output r_point[2][k];
    signal output hashed_to_curve_r[2][k];
    signal output hashed_to_curve[2][k];

    // precomputed values for the hash_to_curve component
    signal input q0_gx1_sqrt[4];
    signal input q0_gx2_sqrt[4];
    signal input q0_y_pos[4];
    signal input q0_x_mapped[4];
    signal input q0_y_mapped[4];

    signal input q1_gx1_sqrt[4];
    signal input q1_gx2_sqrt[4];
    signal input q1_y_pos[4];
    signal input q1_x_mapped[4];
    signal input q1_y_mapped[4];

    // calculate g^r
    // g^r = g^s / pk^c (where g is the generator)
    // Note this implicitly checks the first equation in the blog

    // Calculates g^s. Note, turning a private key to a public key is the same operation as
    // raising the generator g to some power, and we are *not* dealing with private keys in this circuit.
    component s_point = ECDSAPrivToPub(n, k);
    s_point.privkey <== s;

    component r_point_comp = a_div_b_pow_c(n, k);
    r_point_comp.a <== s_point.pubkey;
    r_point_comp.b <== pk;
    r_point_comp.c <== c;

    // Calculate hash[m, pk]^r
    // hash[m, pk]^r = hash[m, pk]^s / (hash[m, pk]^sk)^c
    // Note this implicitly checks the second equation in the blog

    // Calculate hash[m, pk]^r
    component hash_to_curve = HashToCurve(message_length + 33);
    for (var i = 0; i < message_length; i++) {
        hash_to_curve.msg[i] <== plume_message[i];
    }

    component pk_compressor = compress_ec_point(n, k);

    pk_compressor.uncompressed <== pk;    

    for (var i = 0; i < 33; i++) {
        hash_to_curve.msg[message_length + i] <== pk_compressor.compressed[i];
    }

    // Input precalculated values into HashToCurve
    hash_to_curve.q0_gx1_sqrt <== q0_gx1_sqrt;
    hash_to_curve.q0_gx2_sqrt <== q0_gx2_sqrt;
    hash_to_curve.q0_y_pos <== q0_y_pos;
    hash_to_curve.q0_x_mapped <== q0_x_mapped;
    hash_to_curve.q0_y_mapped <== q0_y_mapped;
    hash_to_curve.q1_gx1_sqrt <== q1_gx1_sqrt;
    hash_to_curve.q1_gx2_sqrt <== q1_gx2_sqrt;
    hash_to_curve.q1_y_pos <== q1_y_pos;
    hash_to_curve.q1_x_mapped <== q1_x_mapped;
    hash_to_curve.q1_y_mapped <== q1_y_mapped;

    component h_pow_s = Secp256k1ScalarMult(n, k);
    h_pow_s.scalar <== s;
    h_pow_s.point <== hash_to_curve.out;

    component hashed_to_curve_r_comp = a_div_b_pow_c(n, k);
    hashed_to_curve_r_comp.a <== h_pow_s.out;
    hashed_to_curve_r_comp.b <== nullifier;
    hashed_to_curve_r_comp.c <== c;

    hashed_to_curve <== hash_to_curve.out;

    hashed_to_curve_r <== hashed_to_curve_r_comp.out;

    r_point <== r_point_comp.out;
}

template a_div_b_pow_c(n, k) {
    signal input a[2][k];
    signal input b[2][k];
    signal input c[k];
    signal output out[2][k];

    // Calculates b^c. Note that the spec uses multiplicative notation to preserve intuitions about
    // discrete log, and these comments follow the spec to make comparison simpler. But the circom-ecdsa library uses
    // additive notation. This is why we appear to calculate an exponentiation using a multiplication component.
    component b_pow_c = Secp256k1ScalarMult(n, k);
    b_pow_c.scalar <== c;
    b_pow_c.point <== b; 

    // Calculates inverse of b^c by finding the modular inverse of its y coordinate
    var prime[100] = get_secp256k1_prime(n, k);
    component b_pow_c_inv_y = BigSub(n, k);
    for (var i = 0; i < k; i++) {
        b_pow_c_inv_y.a[i] <== prime[i];
        b_pow_c_inv_y.b[i] <== b_pow_c.out[1][i];
    }

    b_pow_c_inv_y.underflow === 0;

    // Calculates a * (b^c)-1
    component final_result = Secp256k1AddUnequal(n, k);

    final_result.a <== a;
    final_result.b[0] <== b_pow_c.out[0];       
    final_result.b[1] <== b_pow_c_inv_y.out;

    out <== final_result.out;
}

template sha256_12_coordinates(n, k) {
    signal input coordinates[12][k];
    signal output out[256];

    // compress coordinates
    component compressors[6];
    for (var i = 0; i < 6; i++) {
        compressors[i] = compress_ec_point(n, k);
        compressors[i].uncompressed[0] <== coordinates[2*i];
        compressors[i].uncompressed[1] <== coordinates[2*i + 1];
    }

    // decompose coordinates inputs into binary
    component binary[6*33];
    for (var i = 0; i < 6; i++) { // for each compressor
        for (var j = 0; j < 33; j++) { // for each byte
            binary[33*i + j] = Num2Bits(8);
            binary[33*i + j].in <== compressors[i].compressed[j];
        }
    }

    var message_bits = 6*33*8; // 6 compressed coordinates of 33 bytes
    var total_bits = (message_bits \ 512) * 512;
    if (message_bits % 512 != 0) {
        total_bits += 512;
    }

    component sha256 = Sha256Hash(total_bits);
    for (var i = 0; i < 6*33; i++) {
        for (var j = 0; j < 8; j++) {
            sha256.msg[8*i + 7 - j] <== binary[i].out[j]; // Num2Bits is little endian, but compressed EC key form is big endian
        }
    }

    for (var i = message_bits; i < total_bits; i++) {
        sha256.msg[i] <== 0;
    }

    // Message is padded with 1, a series of 0s, then the bit length of the message https://en.wikipedia.org/wiki/SHA-2#Pseudocode:~:text=append%20a%20single%20%271%27%20bit
    // TODO: move padding calculating into upstream repo to simplify API
    for (var i = 0; i < total_bits - 64; i++) {
        if (i == 1584) {
            sha256.padded_bits[1584] <== 1;
        } else {
            sha256.padded_bits[i] <== sha256.msg[i];
        }
    }
  
    component bit_length_binary = Num2Bits(64);
    bit_length_binary.in <== message_bits;
    for (var i = 0; i < 64; i++) {
        sha256.padded_bits[total_bits - i - 1] <== bit_length_binary.out[i];
    }

    // feels like a needed check as `Num2Bits.in` doesn't participate in a quadratic constraint
    component preimage_bit_length_check = ForceEqualIfEnabled();
    preimage_bit_length_check.enabled <== 1;
    preimage_bit_length_check.in <== [message_bits, bit_length_binary.in];

    out <== sha256.out;
}

// We use elliptic curve points in uncompressed form to do elliptic curve arithmetic, but we use them in compressed form when
// hashing to save constraints (as hash cost is generally parameterised in the input length).
// Elliptic curves are symmteric about the x-axis, and for every possible x coordinate there are exactly
// 2 possible y coordinates. Over a prime field, one of those points is even and the other is odd.
// The convention is to represent the even point with the byte 02, and the odd point with the byte 03.
// Because our hash functions work over bytes, our output is a 33 byte array.
template compress_ec_point(n, k) {
    assert(n == 64 && k == 4);
    signal input uncompressed[2][k];
    signal output compressed[33];

    compressed[0] <-- uncompressed[1][0] % 2 + 2;
    var bytes_per_register = 32/k;
    for (var i = 0; i < 32; i++) {
        compressed[32-i] <-- uncompressed[0][i \ bytes_per_register] \ (256 ** (i % bytes_per_register)) % 256;
    }

    component verify = verify_ec_compression(n, k);
    verify.uncompressed <== uncompressed;    
    verify.compressed <== compressed;
}

// We have a separate internal compression verification template for testing 
// purposes. An adversarial prover can set any compressed values, so it's 
// useful to be able to test adversarial inputs.
template verify_ec_compression(n, k) {
    signal input uncompressed[2][k];
    signal input compressed[33];

    // Get the bit string of the smallest register \
    // Make sure the least significant bit's evenness matches the evenness 
    // specified by the first byte in the compressed version
    component num2bits = Num2Bits(n);
    num2bits.in <== uncompressed[1][0]; // Note, circom-ecdsa uses little endian, so we check the 0th register of the y value
    compressed[0] === num2bits.out[0] + 2;

    // Make sure the compressed and uncompressed x coordinates represent 
    // the same number \
    // `l_bytes` is an algebraic expression for the bytes of each register
    var l_bytes[k];
    for (var i = 1; i < 33; i++) {
        var j = i - 1; // ignores the first byte specifying the compressed y coordinate
        l_bytes[j \ 8] += compressed[33-i] * (256 ** (j % 8));
    }

    uncompressed[0] === l_bytes;
}

// Equivalent to get_gx and get_gy in circom-ecdsa, except we also have values 
// for n = 64, k = 4. \
// This is necessary because hash_to_curve is only implemented for n = 64, 
// k = 4 but circom-ecdsa only g's coordinates for n = 86, k = 3 \
// TODO: merge this upstream into circom-ecdsa
function get_genx(n, k) {
    assert((n == 86 && k == 3) || (n == 64 && k == 4));
    var ret[100];
    if (n == 86 && k == 3) {
        ret[0] = 17117865558768631194064792;
        ret[1] = 12501176021340589225372855;
        ret[2] = 9198697782662356105779718;
    }
    if (n == 64 && k == 4) {
        ret[0] = 6481385041966929816;
        ret[1] = 188021827762530521;
        ret[2] = 6170039885052185351;
        ret[3] = 8772561819708210092;
    }
    return ret;
}

function get_geny(n, k) {
    assert((n == 86 && k == 3) || (n == 64 && k == 4));
    var ret[100];
    if (n == 86 && k == 3) {
        ret[0] = 6441780312434748884571320;
        ret[1] = 57953919405111227542741658;
        ret[2] = 5457536640262350763842127;
    }
    if (n == 64 && k == 4) {
        ret[0] = 11261198710074299576;
        ret[1] = 18237243440184513561;
        ret[2] = 6747795201694173352;
        ret[3] = 5204712524664259685;
    }
    return ret;
}
