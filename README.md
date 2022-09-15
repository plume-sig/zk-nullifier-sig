# Signatures with Deterministic Nullifiers

## Implementations

- `rust-k256`: Rust, using the k256 library
- `rust-arkworks`: Rust, using arkworks

## TODO

- zk verifier circuits 
- change SHA512 to SHA256 (or even Poseidon?)
- improve `rust-k256` to use a similar interface as `rust-arkworks` - i.e.
  generate/accept arbitrary keypairs and `r` values, and not just hardcoded
  values

## Resources

### Paper
https://aayushg.com/thesis.pdf

### Slides
https://docs.google.com/presentation/d/1mKtOI4XgKrWBEPpKFAYkRjxZsBomwhy6Cc2Ia87hAnY/edit#slide=id.g13e97fbcd2c_0_76

### Unpublished Blog Post
https://docs.google.com/document/d/1Q9nUNGaeiKoZYAiN9ndh4iE9e-_ql-Rf7MESTo7UB8s/edit
