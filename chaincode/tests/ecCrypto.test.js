// Unit tests for secp256k1 curve helpers re-exported from iamContract under CHAINCODE_UNIT_TEST.
'use strict';

const tc = require('../lib/iamContract').testCrypto;

const mod = tc.mod;
const modPow = tc.modPow;
const inv = tc.inv;
const pointAdd = tc.pointAdd;
const pointMul = tc.pointMul;
const pointEq = tc.pointEq;
const encodePoint = tc.encodePoint;
const decodePoint = tc.decodePoint;
const deriveGeneratorH = tc.deriveGeneratorH;
const G = tc.G;
const INF = tc.INF;
const CURVE = tc.CURVE;
const H = tc.H;

function bigIntModPow(base, exp, m) {
  let b = ((base % m) + m) % m;
  let e = exp;
  let out = 1n;
  while (e > 0n) {
    if (e & 1n) out = (out * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return out;
}

function nextScalar(seed) {
  let s = seed;
  return () => {
    s = (s * 1103515245n + 12345n) % (CURVE.N - 1n);
    return s + 1n;
  };
}

describe('ecCrypto (chaincode)', () => {
  test('mod() handles negative numbers correctly', () => {
    expect(mod(-1n, 7n)).toBe(6n);
    expect(mod(-8n, 5n)).toBe(2n);
    expect(mod(0n, CURVE.P)).toBe(0n);
  });

  test('modPow() matches BigInt ground truth on small inputs', () => {
    for (let i = 0; i < 20; i++) {
      const base = BigInt(i - 5);
      const exp = BigInt(i);
      expect(modPow(base, exp, 97n)).toBe(bigIntModPow(base, exp, 97n));
    }
  });

  test('inv() times original equals 1 (mod N)', () => {
    const a = 1234567890987654321n;
    const i = inv(a, CURVE.N);
    expect(mod(a * i, CURVE.N)).toBe(1n);
  });

  test('pointAdd(G, G) equals pointMul(G, 2n)', () => {
    expect(pointEq(pointAdd(G, G), pointMul(G, 2n))).toBe(true);
  });

  test('pointMul(G, 0n) returns point at infinity', () => {
    expect(pointMul(G, 0n).inf).toBe(true);
  });

  test('encodePoint/decodePoint round-trip for 50 seeded scalars', () => {
    const scalar = nextScalar(42n);
    for (let i = 0; i < 50; i++) {
      const k = scalar();
      const p = pointMul(G, k);
      if (!p.inf) {
        const h = encodePoint(p);
        expect(pointEq(decodePoint(h), p)).toBe(true);
      }
    }
  });

  test('deriveGeneratorH() is deterministic', () => {
    const h1 = deriveGeneratorH();
    const h2 = deriveGeneratorH();
    expect(h1.x).toBe(h2.x);
    expect(h1.y).toBe(h2.y);
    expect(pointEq(H, h1)).toBe(true);
  });

  test('H lies on the curve', () => {
    const x = H.x;
    const y = H.y;
    expect(mod(y * y - (x ** 3n + 7n), CURVE.P)).toBe(0n);
  });

  test('decodePoint rejects invalid encoding', () => {
    expect(() => decodePoint('04' + 'aa'.repeat(32))).toThrow();
    expect(() => decodePoint('031122')).toThrow();
  });
});
