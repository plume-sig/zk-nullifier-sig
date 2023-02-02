pragma circom 2.1.2;

include "./node_modules/circom-ecdsa/circuits/ecdsa.circom";
include "./node_modules/circom-ecdsa/circuits/secp256k1.circom";
include "./node_modules/circom-ecdsa/circuits/secp256k1_func.circom";
include "./node_modules/secp256k1_hash_to_curve_circom/circom/hash_to_curve.circom";
include "./node_modules/secp256k1_hash_to_curve_circom/circom/sha256.circom";
include "./node_modules/circomlib/circuits/bitify.circom";

// Verifies that a nullifier belongs to a specific public key
// This blog explains the intuition behind the construction https://blog.aayushg.com/posts/nullifier
template verify_nullifier(n, k, msg_length) {
    signal input c[k];
    signal input s[k];
    signal input m[msg_length];
    signal input public_key[2][k];
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

    // calculate g^r
    // g^r = g^s / pk^c (where g is the generator)
    // Note this implicitly checks the first equation in the blog

    // Calculates g^s. Note, turning a private key to a public key is the same operation as
    // raising the generator g to some power, and we are *not* dealing with private keys in this circuit.
    component g_to_the_s = ECDSAPrivToPub(n, k);
    for (var i = 0; i < k; i++) {
        g_to_the_s.privkey[i] <== s[i];
    }

    component g_to_the_r = a_div_b_pow_c(n, k);
    for (var i = 0; i < k; i++) {
        g_to_the_r.a[0][i] <== g_to_the_s.pubkey[0][i];
        g_to_the_r.a[1][i] <== g_to_the_s.pubkey[1][i];
        g_to_the_r.b[0][i] <== public_key[0][i];
        g_to_the_r.b[1][i] <== public_key[1][i];
        g_to_the_r.c[i] <== c[i];
    }

    // Calculate hash[m, pk]^r
    // hash[m, pk]^r = hash[m, pk]^s / (hash[m, pk]^sk)^c
    // Note this implicitly checks the second equation in the blog

    // Calculate hash[m, pk]^r
    component h = HashToCurve(msg_length + 2*k);
    for (var i = 0; i < msg_length; i++) {
        h.msg[i] <== m[i];
    }
    for (var i = 0; i < k; i++) {
        h.msg[msg_length + i] <== public_key[0][i];
        h.msg[msg_length + k + i] <== public_key[1][i];
    }
    // Input precalculated values
    for (var i = 0; i < k; i++) {
        h.q0_gx1_sqrt[i] <== q0_gx1_sqrt[i];
        h.q0_gx2_sqrt[i] <== q0_gx2_sqrt[i];
        h.q0_y_pos[i] <== q0_y_pos[i];
        h.q0_x_mapped[i] <== q0_x_mapped[i];
        h.q0_y_mapped[i] <== q0_y_mapped[i];
        h.q1_gx1_sqrt[i] <== q1_gx1_sqrt[i];
        h.q1_gx2_sqrt[i] <== q1_gx2_sqrt[i];
        h.q1_y_pos[i] <== q1_y_pos[i];
        h.q1_x_mapped[i] <== q1_x_mapped[i];
        h.q1_y_mapped[i] <== q1_y_mapped[i];
    }

    component h_to_the_s = Secp256k1ScalarMult(n, k);
    for (var i = 0; i < k; i++) {
        h_to_the_s.scalar[i] <== s[i];
        h_to_the_s.point[0][i] <== h.out[0][i];
        h_to_the_s.point[1][i] <== h.out[1][i];
    }

    component h_to_the_r = a_div_b_pow_c(n, k);
    for (var i = 0; i < k; i++) {
        h_to_the_r.a[0][i] <== h_to_the_s.out[0][i];
        h_to_the_r.a[1][i] <== h_to_the_s.out[1][i];
        h_to_the_r.b[0][i] <== nullifier[0][i];
        h_to_the_r.b[1][i] <== nullifier[1][i];
        h_to_the_r.c[i] <== c[i];
    }

    // calculate c as sha256(g, pk, h, nullifier, g^r, h^r)
    component c_sha256 = sha256_12_coordinates(n, k);
    var g[2][100];
    g[0] = get_genx(n, k);
    g[1] = get_geny(n, k);
    for (var j = 0; j < 2; j++) {
        for (var i = 0; i < k; i++) {
            c_sha256.coordinates[j][i] <== g[j][i];
            c_sha256.coordinates[2+j][i] <== public_key[j][i];
            c_sha256.coordinates[4+j][i] <== h.out[j][i];
            c_sha256.coordinates[6+j][i] <== nullifier[j][i];
            c_sha256.coordinates[8+j][i] <== g_to_the_r.out[j][i];
            c_sha256.coordinates[10+j][i] <== h_to_the_r.out[j][i];
        }
    }

    // check that the input c is the same as the hash value c
    component c_bits[k];
    for (var i = 0; i < k; i++) {
        c_bits[i] = Num2Bits(n);
        c_bits[i].in <== c[i];
        for (var j = 0; j < n; j++) {
            // We may have 3 registers of 86 bits, which means we end up getting two extra 0 bits which don't have to be equal to the sha256 hash
            // TODO: verify that we don't have to equate these to 0
            if (i*k + j < 256) {
                c_sha256.out[i*k + j] === c_bits[i].out[j];
            }
        }
    }
}

template a_div_b_pow_c(n, k) {
    signal input a[2][k];
    signal input b[2][k];
    signal input c[k];
    signal output out[2][k];

    // Calculates b^c. Note that the spec uses multiplicative notation to preserve intuitions about
    // discrete log, and these comments follow the spec to make comparison simpler. But the circom-ecdsa library uses
    // additive notation. This is why we appear to calculate an expnentiation using a multiplication component.
    component b_to_the_c = Secp256k1ScalarMult(n, k);
    for (var i = 0; i < k; i++) {
        b_to_the_c.scalar[i] <== c[i];
        b_to_the_c.point[0][i] <== b[0][i];
        b_to_the_c.point[1][i] <== b[1][i];
    }

    // Calculates inverse of b^c by finding the modular inverse of its y coordinate
    var prime[100] = get_secp256k1_prime(n, k);
    component b_to_the_c_inv_y = BigSub(n, k);
    for (var i = 0; i < k; i++) {
        b_to_the_c_inv_y.a[i] <== prime[i];
        b_to_the_c_inv_y.b[i] <== b_to_the_c.out[1][i];
    }
    b_to_the_c_inv_y.underflow === 0;

    // Calculates a^s * (b^c)-1
    component final_result = Secp256k1AddUnequal(n, k);
    for (var i = 0; i < k; i++) {
        final_result.a[0][i] <== a[0][i];
        final_result.a[1][i] <== a[1][i];
        final_result.b[0][i] <== b_to_the_c.out[0][i];
        final_result.b[1][i] <== b_to_the_c_inv_y.out[i];
    }

    for (var i = 0; i < k; i++) {
        out[0][i] <== final_result.out[0][i];
        out[1][i] <== final_result.out[1][i];
    }
}

template sha256_12_coordinates(n, k) {
    signal input coordinates[12][k];
    signal output out[256];

    // decompose hash inputs into binary
    component binary[12*k];
    for (var i = 0; i < 12; i++) { // for each coordinate
        for (var j = 0; j < k; j++) { // for each register
            binary[k*i + j] = Num2Bits(n);
            binary[k*i + j].in <== coordinates[i][j];
        }
    }

    var message_bits = n*k*12;
    var total_bits = (message_bits \ 512) * 512;

    component sha256 = Sha256Hash(total_bits);
    for (var i = 0; i < 12*k; i++) {
        for (var j = 0; j < n; j++) {
            // TODO: what is the difference between padded_bits and msg? Am I using it right?
            sha256.padded_bits[n*i + j] <== binary[i].out[j];
            sha256.msg[n*i + j] <== binary[i].out[j];
        }
    }

    for (var i = message_bits; i < total_bits; i++) {
        sha256.padded_bits[i] <== 0;
        sha256.msg[i] <== 0;
    }

    for (var i = 0; i < 256; i++) {
        out[i] <== sha256.out[i];
    }
}

// Equivalent to get_gx and get_gy in circom-ecdsa, except we also have values for n = 64, k = 4.
// This is necessary because hash_to_curve is only implemented for n=64, k = 4
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
