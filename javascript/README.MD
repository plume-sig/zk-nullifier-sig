JavaScript implementation of the PLUME signature scheme.

## API
### sign(message, privateKey)
Signs a message using the provided private key.
* `message` - String message to sign
* `privateKey` - Hex private key

Returns the PLUME signature.

### `verify(message, publicKey, signature)`
Verifies a signature matches the message and public key.
* `message` - Original string message
* `publicKey` - Hex public key
* `signature` - PLUME signature

Returns true if the signature is valid, false otherwise.

### License
MIT