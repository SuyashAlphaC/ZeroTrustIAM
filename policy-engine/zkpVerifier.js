'use strict';

/**
 * Elliptic-curve Pedersen range proofs for risk-score verification.
 *
 * This module proves, without revealing the risk score, that a committed
 * integer risk value is in the range:
 *
 *   0 <= risk_scaled < threshold_scaled
 *
 * The proof uses:
 * - secp256k1 group arithmetic
 * - Pedersen commitments C = v*G + r*H
 * - bit decomposition of v and threshold - 1 - v
 * - Fiat-Shamir transformed OR proofs that each committed bit is 0 or 1
 * - a Schnorr proof linking C + D to the public threshold
 *
 * It is intentionally closer to Fabric Token SDK's privacy driver shape than
 * the old demo: validation is proof-driven and does not require the verifier
 * to see the raw risk score.
 */

const crypto = require('crypto');

const CURVE = {
  P: BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'),
  N: BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
  Gx: BigInt('0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
  Gy: BigInt('0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'),
};

const PARAMS = {
  curve: 'secp256k1',
  proofType: 'PedersenBitRangeProof',
  scale: 1000,
  hDomain: 'ZeroTrustIAM/risk/H/v1',
};

const INF = { inf: true };
const G = { x: CURVE.Gx, y: CURVE.Gy };
const H = deriveGeneratorH();

function mod(a, m = CURVE.P) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base, exp, m) {
  let b = mod(base, m);
  let e = exp;
  let out = 1n;
  while (e > 0n) {
    if (e & 1n) out = (out * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return out;
}

function inv(a, m = CURVE.N) {
  if (mod(a, m) === 0n) throw new Error('inverse of zero');
  return modPow(mod(a, m), m - 2n, m);
}

function isInf(p) {
  return !p || p.inf;
}

function pointNeg(p) {
  return isInf(p) ? INF : { x: p.x, y: mod(-p.y) };
}

function pointAdd(p, q) {
  if (isInf(p)) return q;
  if (isInf(q)) return p;
  if (p.x === q.x && mod(p.y + q.y) === 0n) return INF;

  const lambda = p.x === q.x && p.y === q.y
    ? mod((3n * p.x * p.x) * inv(2n * p.y, CURVE.P), CURVE.P)
    : mod((q.y - p.y) * inv(q.x - p.x, CURVE.P), CURVE.P);
  const x = mod(lambda * lambda - p.x - q.x);
  const y = mod(lambda * (p.x - x) - p.y);
  return { x, y };
}

function pointSub(p, q) {
  return pointAdd(p, pointNeg(q));
}

function pointMul(p, scalar) {
  let n = mod(scalar, CURVE.N);
  let acc = INF;
  let base = p;
  while (n > 0n) {
    if (n & 1n) acc = pointAdd(acc, base);
    base = pointAdd(base, base);
    n >>= 1n;
  }
  return acc;
}

function scalarMulAdd(gScalar, hScalar) {
  return pointAdd(pointMul(G, gScalar), pointMul(H, hScalar));
}

function hex32(n) {
  return n.toString(16).padStart(64, '0');
}

function encodePoint(p) {
  if (isInf(p)) throw new Error('cannot encode infinity');
  return `${p.y & 1n ? '03' : '02'}${hex32(p.x)}`;
}

function decodePoint(hex) {
  if (typeof hex !== 'string' || !/^(02|03)[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('invalid compressed point');
  }
  const odd = hex.slice(0, 2) === '03';
  const x = BigInt(`0x${hex.slice(2)}`);
  const y2 = mod(x ** 3n + 7n);
  let y = modPow(y2, (CURVE.P + 1n) / 4n, CURVE.P);
  if (mod(y * y) !== y2) throw new Error('point is not on curve');
  if (Boolean(y & 1n) !== odd) y = mod(-y);
  return { x, y };
}

function hashHex(...parts) {
  const h = crypto.createHash('sha256');
  for (const part of parts) {
    h.update(String(part));
    h.update('|');
  }
  return h.digest('hex');
}

function hashScalar(...parts) {
  return BigInt(`0x${hashHex(...parts)}`) % CURVE.N;
}

function deriveGeneratorH() {
  for (let i = 0; i < 1024; i++) {
    const x = BigInt(`0x${hashHex(PARAMS.hDomain, i)}`) % CURVE.P;
    const y2 = mod(x ** 3n + 7n);
    let y = modPow(y2, (CURVE.P + 1n) / 4n, CURVE.P);
    if (mod(y * y) === y2) {
      if (y & 1n) y = mod(-y);
      return { x, y };
    }
  }
  throw new Error('failed to derive secondary generator');
}

function randomScalar() {
  let x = 0n;
  while (x === 0n) {
    x = BigInt(`0x${crypto.randomBytes(32).toString('hex')}`) % CURVE.N;
  }
  return x;
}

function randomBlindingFactor() {
  return randomScalar();
}

function commitScaled(scaledValue, blindingFactor) {
  return scalarMulAdd(BigInt(scaledValue), blindingFactor);
}

function commit(value, blindingFactor) {
  return encodePoint(commitScaled(Math.round(value * PARAMS.scale), blindingFactor));
}

function ceilLog2(n) {
  let bits = 0;
  let value = Math.max(1, n - 1);
  while (value > 0) {
    bits++;
    value >>= 1;
  }
  return bits;
}

function decomposeBits(value, bitLength) {
  const bits = [];
  let v = value;
  for (let i = 0; i < bitLength; i++) {
    bits.push(v & 1);
    v >>= 1;
  }
  if (v !== 0) throw new Error('value does not fit bit length');
  return bits;
}

function makeBitCommitments(value, totalBlind, bitLength, domain) {
  const bits = decomposeBits(value, bitLength);
  const blinds = new Array(bitLength);
  let weightedBlindSum = 0n;

  for (let i = 0; i < bitLength - 1; i++) {
    blinds[i] = randomScalar();
    weightedBlindSum = mod(weightedBlindSum + (2n ** BigInt(i)) * blinds[i], CURVE.N);
  }

  const lastWeight = 2n ** BigInt(bitLength - 1);
  blinds[bitLength - 1] = mod((totalBlind - weightedBlindSum) * inv(lastWeight), CURVE.N);

  return bits.map((bit, index) => {
    const commitment = scalarMulAdd(BigInt(bit), blinds[index]);
    return {
      commitment: encodePoint(commitment),
      proof: createBitProof(commitment, bit, blinds[index], index, domain),
    };
  });
}

function createBitProof(commitment, bit, blind, index, domain) {
  const p0 = commitment;
  const p1 = pointSub(commitment, G);
  let e0;
  let e1;
  let z0;
  let z1;
  let a0;
  let a1;

  if (bit === 0) {
    const w0 = randomScalar();
    e1 = randomScalar();
    z1 = randomScalar();
    a0 = pointMul(H, w0);
    a1 = pointSub(pointMul(H, z1), pointMul(p1, e1));
    const e = hashScalar('bit-or', domain, index, encodePoint(commitment), encodePoint(a0), encodePoint(a1));
    e0 = mod(e - e1, CURVE.N);
    z0 = mod(w0 + e0 * blind, CURVE.N);
  } else if (bit === 1) {
    const w1 = randomScalar();
    e0 = randomScalar();
    z0 = randomScalar();
    a0 = pointSub(pointMul(H, z0), pointMul(p0, e0));
    a1 = pointMul(H, w1);
    const e = hashScalar('bit-or', domain, index, encodePoint(commitment), encodePoint(a0), encodePoint(a1));
    e1 = mod(e - e0, CURVE.N);
    z1 = mod(w1 + e1 * blind, CURVE.N);
  } else {
    throw new Error('bit must be 0 or 1');
  }

  return {
    a0: encodePoint(a0),
    a1: encodePoint(a1),
    e0: e0.toString(16),
    e1: e1.toString(16),
    z0: z0.toString(16),
    z1: z1.toString(16),
  };
}

function verifyBitProof(commitment, proof, index, domain) {
  const p0 = commitment;
  const p1 = pointSub(commitment, G);
  const a0 = decodePoint(proof.a0);
  const a1 = decodePoint(proof.a1);
  const e0 = BigInt(`0x${proof.e0}`);
  const e1 = BigInt(`0x${proof.e1}`);
  const z0 = BigInt(`0x${proof.z0}`);
  const z1 = BigInt(`0x${proof.z1}`);
  const e = hashScalar('bit-or', domain, index, encodePoint(commitment), proof.a0, proof.a1);

  if (mod(e0 + e1, CURVE.N) !== e) return false;
  const lhs0 = pointMul(H, z0);
  const rhs0 = pointAdd(a0, pointMul(p0, e0));
  const lhs1 = pointMul(H, z1);
  const rhs1 = pointAdd(a1, pointMul(p1, e1));
  return pointEq(lhs0, rhs0) && pointEq(lhs1, rhs1);
}

function pointEq(a, b) {
  if (isInf(a) && isInf(b)) return true;
  if (isInf(a) || isInf(b)) return false;
  return a.x === b.x && a.y === b.y;
}

function weightedCommitmentSum(bitProofs) {
  return bitProofs.reduce((acc, item, index) => {
    return pointAdd(acc, pointMul(decodePoint(item.commitment), 2n ** BigInt(index)));
  }, INF);
}

function createLinkProof(statement, witness, context) {
  const nonce = randomScalar();
  const nonceCommitment = pointMul(H, nonce);
  const challenge = hashScalar('link', context, encodePoint(statement), encodePoint(nonceCommitment));
  const response = mod(nonce + challenge * witness, CURVE.N);
  return {
    statement: encodePoint(statement),
    nonceCommitment: encodePoint(nonceCommitment),
    challenge: challenge.toString(16),
    response: response.toString(16),
  };
}

function verifyLinkProof(proof, expectedStatement, context) {
  const statement = decodePoint(proof.statement);
  if (!pointEq(statement, expectedStatement)) return false;
  const nonceCommitment = decodePoint(proof.nonceCommitment);
  const challenge = BigInt(`0x${proof.challenge}`);
  const expectedChallenge = hashScalar('link', context, proof.statement, proof.nonceCommitment);
  if (challenge !== expectedChallenge) return false;
  const response = BigInt(`0x${proof.response}`);
  const lhs = pointMul(H, response);
  const rhs = pointAdd(nonceCommitment, pointMul(statement, challenge));
  return pointEq(lhs, rhs);
}

function createRangeProof(value, threshold, blindingFactor) {
  const scaledValue = Math.round(value * PARAMS.scale);
  const scaledThreshold = Math.round(threshold * PARAMS.scale);
  const maxValue = scaledThreshold - 1;

  if (scaledValue < 0 || scaledValue > maxValue) {
    return null;
  }

  const bitLength = ceilLog2(scaledThreshold);
  const valueBlind = mod(blindingFactor, CURVE.N);
  const diffValue = maxValue - scaledValue;
  const diffBlind = randomScalar();
  const valueCommitment = commitScaled(scaledValue, valueBlind);
  const diffCommitment = commitScaled(diffValue, diffBlind);
  const valueBits = makeBitCommitments(scaledValue, valueBlind, bitLength, 'value');
  const diffBits = makeBitCommitments(diffValue, diffBlind, bitLength, 'diff');
  const thresholdPoint = pointMul(G, BigInt(maxValue));
  const linkStatement = pointSub(pointAdd(valueCommitment, diffCommitment), thresholdPoint);
  const context = [
    encodePoint(valueCommitment),
    encodePoint(diffCommitment),
    scaledThreshold,
    bitLength,
    PARAMS.proofType,
  ].join('|');

  return {
    proofType: PARAMS.proofType,
    curve: PARAMS.curve,
    scale: PARAMS.scale,
    threshold: scaledThreshold,
    bitLength,
    valueCommitment: encodePoint(valueCommitment),
    diffCommitment: encodePoint(diffCommitment),
    valueBits,
    diffBits,
    linkProof: createLinkProof(linkStatement, mod(valueBlind + diffBlind, CURVE.N), context),
    timestamp: new Date().toISOString(),
    proofId: crypto.randomUUID(),
  };
}

function verifyRangeProof(proof) {
  if (!proof || proof.proofType !== PARAMS.proofType) {
    return { valid: false, reason: 'Invalid proof type' };
  }

  try {
    if (proof.curve !== PARAMS.curve || proof.scale !== PARAMS.scale) {
      return { valid: false, reason: 'Unsupported proof parameters' };
    }
    if (!Number.isInteger(proof.threshold) || proof.threshold <= 0) {
      return { valid: false, reason: 'Invalid threshold' };
    }
    if (!Number.isInteger(proof.bitLength) || proof.bitLength !== ceilLog2(proof.threshold)) {
      return { valid: false, reason: 'Invalid bit length' };
    }
    if (!Array.isArray(proof.valueBits) || !Array.isArray(proof.diffBits)) {
      return { valid: false, reason: 'Missing bit commitments' };
    }
    if (proof.valueBits.length !== proof.bitLength || proof.diffBits.length !== proof.bitLength) {
      return { valid: false, reason: 'Bit commitment length mismatch' };
    }

    const valueCommitment = decodePoint(proof.valueCommitment);
    const diffCommitment = decodePoint(proof.diffCommitment);
    if (!pointEq(weightedCommitmentSum(proof.valueBits), valueCommitment)) {
      return { valid: false, reason: 'Value bit decomposition mismatch' };
    }
    if (!pointEq(weightedCommitmentSum(proof.diffBits), diffCommitment)) {
      return { valid: false, reason: 'Difference bit decomposition mismatch' };
    }

    for (let i = 0; i < proof.bitLength; i++) {
      if (!verifyBitProof(decodePoint(proof.valueBits[i].commitment), proof.valueBits[i].proof, i, 'value')) {
        return { valid: false, reason: `Invalid value bit proof at index ${i}` };
      }
      if (!verifyBitProof(decodePoint(proof.diffBits[i].commitment), proof.diffBits[i].proof, i, 'diff')) {
        return { valid: false, reason: `Invalid difference bit proof at index ${i}` };
      }
    }

    const maxValue = BigInt(proof.threshold - 1);
    const thresholdPoint = pointMul(G, maxValue);
    const expectedStatement = pointSub(pointAdd(valueCommitment, diffCommitment), thresholdPoint);
    const context = [
      proof.valueCommitment,
      proof.diffCommitment,
      proof.threshold,
      proof.bitLength,
      proof.proofType,
    ].join('|');

    if (!verifyLinkProof(proof.linkProof, expectedStatement, context)) {
      return { valid: false, reason: 'Threshold link proof failed' };
    }

    return {
      valid: true,
      proofId: proof.proofId,
      threshold: proof.threshold / PARAMS.scale,
      commitment: proof.valueCommitment,
      message: 'Risk commitment verified in range without revealing the risk score',
    };
  } catch (err) {
    return { valid: false, reason: 'Proof verification error: ' + err.message };
  }
}

function createZKPPackage(riskScore, threshold) {
  const blindingFactor = randomBlindingFactor();
  const rangeProof = createRangeProof(riskScore, threshold, blindingFactor);

  if (!rangeProof) {
    return {
      success: false,
      reason: 'Risk score is not in the required range',
    };
  }

  return {
    success: true,
    commitment: rangeProof.valueCommitment,
    rangeProof,
    metadata: {
      scheme: 'secp256k1 Pedersen Bit-Decomposition Range Proof',
      securityLevel: '128-bit classical group security',
      property: `0 <= risk_score < ${threshold}`,
      blindingFactorUsed: true,
      rawRiskDisclosedToVerifier: false,
    },
  };
}

module.exports = {
  commit,
  createRangeProof,
  verifyRangeProof,
  createZKPPackage,
  randomBlindingFactor,
  PARAMS,
};
