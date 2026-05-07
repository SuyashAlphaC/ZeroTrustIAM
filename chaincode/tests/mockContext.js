// In-memory ChaincodeStub and client identity for deterministic Jest tests.
'use strict';

class RangeQueryIterator {
  constructor(entries) {
    this._entries = entries;
    this._i = 0;
  }

  async next() {
    if (this._i >= this._entries.length) {
      return { done: true, value: undefined };
    }
    const { key, value } = this._entries[this._i++];
    const buf =
      Buffer.isBuffer(value)
        ? value
        : value instanceof Uint8Array
          ? Buffer.from(value)
          : Buffer.from(String(value), 'utf8');
    return {
      done: false,
      value: {
        key: Buffer.from(key, 'utf8'),
        value: buf,
      },
    };
  }

  async close() {
    this._entries = [];
  }
}

class MockStub {
  constructor(options = {}) {
    this._store = options.store instanceof Map ? options.store : new Map();
    /** @type {string} */
    this._txId = options.txId || 'test-txid-1';
    /** @type {string} */
    this._mspId = options.stubMspId || 'Org1MSP';
    /** @type {number} */
    this._tsMs = options.timestampMs ?? Date.now();
    this._txCounter = 0;
  }

  setTxId(txId) {
    this._txId = txId;
  }

  bumpTx(newId) {
    this._txId = newId || `test-txid-${++this._txCounter}`;
  }

  getState(key) {
    const v = this._store.get(key);
    return Promise.resolve(v ? Buffer.from(v) : Buffer.alloc(0));
  }

  putState(key, value) {
    const buf = Buffer.isBuffer(value) ? value : Buffer.from(value);
    this._store.set(key, Uint8Array.from(buf));
    return Promise.resolve();
  }

  deleteState(key) {
    this._store.delete(key);
    return Promise.resolve();
  }

  getTxID() {
    return this._txId;
  }

  getMspID() {
    return this._mspId;
  }

  getDateTimestamp() {
    const sec = Math.floor(this._tsMs / 1000);
    return { seconds: { low: sec, high: 0, unsigned: false }, nanos: (this._tsMs % 1000) * 1e6 };
  }

  getTxTimestamp() {
    return this.getDateTimestamp();
  }

  setTimestampMs(ms) {
    this._tsMs = ms;
  }

  createCompositeKey(objectType, attributes) {
    return [objectType, ...attributes].join('\x00');
  }

  async getStateByPartialCompositeKey(objectType, attributes) {
    const prefix = this.createCompositeKey(objectType, attributes);
    const entries = [...this._store.keys()]
      .filter((k) => k.startsWith(prefix))
      .sort()
      .map((key) => ({ key, value: this._store.get(key) }));
    return new RangeQueryIterator(entries);
  }

  async getStateByRange(startKey, endKey) {
    const entries = [...this._store.keys()]
      .filter((k) => typeof k === 'string' && k.startsWith('AuditLog:') && k >= startKey && k < endKey)
      .sort()
      .map((key) => ({ key, value: this._store.get(key) }));
    return new RangeQueryIterator(entries);
  }

  /** @returns {number} */
  worldStateKeyCount() {
    return this._store.size;
  }

  /** @returns {string[]} */
  snapshotKeys() {
    return [...this._store.keys()].sort();
  }
}

class MockClientIdentity {
  constructor(mspId, id) {
    this._mspId = mspId || 'Org1MSP';
    this._id = id || 'x509::CN=test::';
  }

  getMSPID() {
    return this._mspId;
  }

  getID() {
    return this._id;
  }
}

class MockContext {
  constructor(options = {}) {
    this.stub = new MockStub(options);
    this.clientIdentity = new MockClientIdentity(options.mspId, options.certId);
  }
}

module.exports = { MockContext, MockStub };
