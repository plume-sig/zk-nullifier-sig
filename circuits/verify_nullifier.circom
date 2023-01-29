include "../node_modules/0xparc/circom-ecdsa/circuits/ecdsa.circom";
include "../node_modules/0xparc/circom-ecdsa/circuits/secp256k1.circom";
include "../node_modules/geometryresearch/secp256k1_hash_to_curve/circuits/circom/hash_to_curve.circom";

// Verifies that a nullifier belongs to a specific public key
// This blog explains the intuition behind the construction https://blog.aayushg.com/posts/nullifier
template verify_nullifier(n, k, msg_length) {
    signal input c[k];
    signal input s[k];
    signal input m[msg_length];
    signal input public_key[2][k];

    // calculate g^r
    // g^r = g^s / pk^c (where g is the generator)
    // Note this implicitly checks the first equation in the blog

    // Calculates g^s. Note, turning a private key to a public key is the same operation as
    // raising the generator g to some power, and we are *not* dealing with private keys in this circuit.
    component g_to_the_s = ECDSAPrivToPub(n, k);
    for (var i = 0; i < k; i++) {
        g_to_the_s.privkey[i] <== s[i];
    }

    // Calculates pk^c. Note that the spec uses multiplicative notation to preserve intuitions about
    // discrete log, and these comments follow the spec to make comparison simpler. But the circom-ecdsa library uses
    // additive notation, hence calculating an expnentiation with a multiplication component.
    component pk_to_the_c = Secp256k1ScalarMult(n, k);
    for (var i = 0; i < k; i++) {
        pk_to_the_c.scalar[i] <== c[i];
        pk_to_the_c.point[0] <== public_key[0][i];
        pk_to_the_c.point[1] <== public_key[1][i];
    }

    // Calculates inverse of pk^c by finding the modular inverse of its y coordinate
    var prime[100] = get_secp256k1_prime(n, k);
    component pk_to_the_c_inv_y = BigSub(n, k);
    for (var i = 0; i < k; i++) {
        pk_to_the_c_inv_y.a[i] <== prime[i];
        pk_to_the_c_inv_y.b[i] <== pk_to_the_c[1][i];
    }
    pk_to_the_c_inv_y.underflow === 0;

    // Calculates g^r = g^s * (pk^c)-1
    component g_to_the_r = Secp256k1AddUnequal(n, k);
    for (var i = 0; i < k; i++) {
        g_to_the_r.a[0][i] <== g_to_the_s.public_key[0][i];
        g_to_the_r.a[1][i] <== g_to_the_s.public_key[1][i];
        g_to_the_r.b[0][i] <== pk_to_the_c[0][i];
        g_to_the_r.b[1][i] <== pk_to_the_c_inv_y[i];
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
        h[msg_length + i] <== pk[0][i];
        h[msg_length + k + i] <== pk[1][i];
    }
    // TODO: input auxiliary values, q0_gx1_sqrt etc

}

component a_over_b_to_the_c(n, k) {
    signal input a[2][k];
    signal input b[2][k];
    signal input c[k];
}