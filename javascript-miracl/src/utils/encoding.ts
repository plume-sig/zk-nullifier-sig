const utf8Encoder = new TextEncoder();

export function messageToUint8Array(message: string): Uint8Array {
  return utf8Encoder.encode(message);
}

export function hexToUint8Array(hexString: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hexString, "hex"));
}

export function asciitobytes(s: string): number[] {
  var b = [],
    i: number;
  for (i = 0; i < s.length; i++) {
    b.push(s.charCodeAt(i));
  }
  return b;
}
