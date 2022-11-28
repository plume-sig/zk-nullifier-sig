const utf8Encoder = new TextEncoder();

export function messageToUint8Array(message: string): Uint8Array {
  return utf8Encoder.encode(message);
}

export function hexToUint8Array(hexString: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hexString, "hex"));
}

export function uint8ArrayToHex(buffer: Uint8Array) {
  return Buffer.from(buffer).toString("hex");
}

export function hexToBigInt(hex: string): bigint {
  return BigInt("0x" + hex);
}

export function uint8ArrayToBigInt(buffer: Uint8Array): bigint {
  return hexToBigInt(uint8ArrayToHex(buffer));
}

export function asciitobytes(s: string): number[] {
  var b = [],
    i: number;
  for (i = 0; i < s.length; i++) {
    b.push(s.charCodeAt(i));
  }
  return b;
}

export function concatUint8Arrays(arrays: Uint8Array[]) {
  // sum of individual array lengths
  let totalLength = arrays.reduce((acc, value) => acc + value.length, 0);

  let result = new Uint8Array(totalLength);

  if (!arrays.length) return result;

  // for each array - copy it over result
  // next array is copied right after the previous one
  let length = 0;
  for (let array of arrays) {
    result.set(array, length);
    length += array.length;
  }

  return result;
}
