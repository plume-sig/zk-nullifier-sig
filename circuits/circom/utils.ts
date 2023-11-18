import { Point } from "@noble/secp256k1";

export function circuitValueToScalar(registers: bigint[]) {
  if (registers.length !== 4) {
    throw new Error(`Circuit values have 4 registers, got ${registers.length}`);
  }

  return registersToBigint(registers, 64n);
}

export function scalarToCircuitValue(value: bigint): bigint[] {
  return bigIntToRegisters(value, 64n, 4n);
}

export function pointToCircuitValue(p: Point): bigint[][] {
  return [scalarToCircuitValue(p.x), scalarToCircuitValue(p.y)];
}

export function circuitValueToPoint(coordinates: bigint[][]): Point {
  if (coordinates.length !== 2) {
    throw new Error(
      `Elliptic curve points have 2 coordinates, got ${coordinates.length}`,
    );
  }

  return new Point(
    circuitValueToScalar(coordinates[0]),
    circuitValueToScalar[1],
  );
}

export function bigIntToRegisters(
  value: bigint,
  bits_per_register: bigint,
  register_count: bigint,
): bigint[] {
  const register_size = 2n ** bits_per_register;

  if (value >= register_size ** register_count) {
    throw new Error(
      `BigInt ${value} can't fit into ${register_count} registers of ${bits_per_register} bits.`,
    );
  }

  const registers: bigint[] = [];
  for (let i = 0; i < register_count; i++) {
    registers[i] = (value / register_size ** BigInt(i)) % register_size;
  }

  return registers;
}

export function registersToBigint(
  registers: bigint[],
  bits_per_register: bigint,
): bigint {
  const register_size = 2n ** bits_per_register;
  let value = 0n;
  let e = 1n;

  for (let i = 0; i < registers.length; i++) {
    value += registers[i] * e;
    e *= register_size;
  }

  return value;
}
