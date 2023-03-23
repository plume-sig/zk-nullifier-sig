#!/bin/bash

# Our structure naturally creates 3 version of circomlib, which causes
# a "duplicate symbol" compiler error. We depend on circomlib directly, so
# does circom-ecdsa, and so does hash_to_curve (both via circom-ecdsa)

# This script manually flattens our nested dependencies, including the nested dependency
# in our hash_to_curve dependency.

# Make circom-ecdsa point to node_modules/circomlib
for file in `find node_modules/circom-ecdsa/circuits -name "*.circom"`; do
    sed -i.bak 's/"\.\.\/\.\.\/node_modules\/circomlib/"\.\.\/\.\.\/\.\.\/circomlib/' $file
    rm $file.bak
    sed -i.bak 's/"\.\.\/node_modules\/circomlib/"\.\.\/\.\.\/circomlib/' $file
    rm $file.bak
done

# Make hash_to_curve point to ...
for file in `find node_modules/secp256k1_hash_to_curve_circom/circom -name "*.circom"`; do
    # node_modules/circomlib, if it was pointing at its dependency's dependency and ...
    sed -i.bak 's/\.\.\/node_modules\/circom-ecdsa\/node_modules\/circomlib/\.\.\/\.\.\/circomlib/' $file
    rm $file.bak
    # node_modules/circom-ecdsa
    sed -i.bak 's/"\.\.\/node_modules\/circom-ecdsa/"\.\.\/\.\.\/circom-ecdsa/' $file
    rm $file.bak
done
