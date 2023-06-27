import * as fs from 'fs';
import * as path from 'path';
import { plainToClass } from 'class-transformer';
import { Transform } from 'class-transformer';
import { Point } from '@noble/secp256k1';

class TestData {
  @Transform(value => new Uint8Array(Object.values(value.value)), { toClassOnly: true })
  testSecretKey: Uint8Array;
  @Transform(value => new Point(BigInt(value.value.x), BigInt(value.value.y)), { toClassOnly: true })
  testPublicKeyPoint: Point;
  @Transform(value => new Uint8Array(Object.values(value.value)), { toClassOnly: true })
  testPublicKey: Uint8Array;
  @Transform(value => new Uint8Array(Object.values(value.value)), { toClassOnly: true })
  testR: Uint8Array;
  testMessageString: String;
  @Transform(value => new Uint8Array(Object.values(value.value)), { toClassOnly: true })
  testMessage: Uint8Array;
  @Transform(value => new Point(BigInt(value.value.x), BigInt(value.value.y)), { toClassOnly: true })
  hashMPk: Point;
  @Transform(value => new Point(BigInt(value.value.x), BigInt(value.value.y)), { toClassOnly: true })
  nullifier: Point;
  @Transform(value => new Point(BigInt(value.value.x), BigInt(value.value.y)), { toClassOnly: true })
  hashMPkPowR: Point;
  @Transform(value => new Point(BigInt(value.value.x), BigInt(value.value.y)), { toClassOnly: true })
  gPowR: Point;
  c_v1: String;
  s_v1: String;
  c_v2: String;
  s_v2: String;
}

var jsonPath = path.join(__dirname, 'test_consts.json');
let plain = JSON.parse(fs.readFileSync(jsonPath).toString());
let consts = plainToClass(TestData, plain)

export const testSecretKey = consts.testSecretKey;
export const testPublicKeyPoint = consts.testPublicKeyPoint;
export const testPublicKey = consts.testPublicKey;
export const testR = consts.testR;
export const testMessageString = consts.testMessageString;
export const testMessage = consts.testMessage;
export const hashMPk = consts.hashMPk;
export const nullifier = consts.nullifier;
export const hashMPkPowR = consts.hashMPkPowR;
export const gPowR = consts.gPowR;
export const c_v1 = consts.c_v1;
export const s_v1 = consts.s_v1;
export const c_v2 = consts.c_v2;
export const s_v2 = consts.s_v2;
