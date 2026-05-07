'use strict';

// S3 client is fully mocked — no real network/S3 calls.
// Variables prefixed with `mock` are allowed inside jest.mock factory.
const mockSend = jest.fn();
const mockPutObjectCommand = jest.fn(function (params) { this.params = params; });

jest.mock('@aws-sdk/client-s3', () => ({
  S3Client: jest.fn().mockImplementation(() => ({
    send: mockSend,
    destroy: jest.fn(),
  })),
  PutObjectCommand: mockPutObjectCommand,
}), { virtual: true });

describe('auditMirror', () => {
  let auditMirror;

  beforeEach(() => {
    jest.resetModules();
    mockSend.mockReset();
    mockPutObjectCommand.mockClear();
    delete process.env.AUDIT_MIRROR_BUCKET;
  });

  afterEach(async () => {
    if (auditMirror) await auditMirror.close();
  });

  test('no-op when AUDIT_MIRROR_BUCKET is not set', async () => {
    auditMirror = require('../../auditMirror');
    await auditMirror.mirrorAuditEntry({ entryHash: 'abc123', txId: 'tx-1' });
    expect(mockPutObjectCommand).not.toHaveBeenCalled();
    expect(mockSend).not.toHaveBeenCalled();
  });

  test('issues PutObjectCommand with COMPLIANCE lock when bucket configured', async () => {
    process.env.AUDIT_MIRROR_BUCKET = 'ztiam-audit-mirror';
    mockSend.mockResolvedValueOnce({ ETag: '"deadbeef"' });

    auditMirror = require('../../auditMirror');
    const entry = { entryHash: 'a'.repeat(64), txId: 'tx-42', userId: 'alice', decision: 'ALLOW' };
    await auditMirror.mirrorAuditEntry(entry);

    expect(mockPutObjectCommand).toHaveBeenCalledTimes(1);
    const params = mockPutObjectCommand.mock.calls[0][0];
    expect(params.Bucket).toBe('ztiam-audit-mirror');
    expect(params.Key).toMatch(/^audit\/\d{4}\/\d{2}\/\d{2}\/a{64}\.json$/);
    expect(params.ObjectLockMode).toBe('COMPLIANCE');
    expect(params.ObjectLockRetainUntilDate).toBeInstanceOf(Date);
    const retainMs = params.ObjectLockRetainUntilDate.getTime() - Date.now();
    expect(retainMs).toBeGreaterThan(89 * 24 * 3600 * 1000);
    expect(retainMs).toBeLessThan(91 * 24 * 3600 * 1000);
    expect(mockSend).toHaveBeenCalledTimes(1);
  });

  test('S3 errors do not propagate', async () => {
    process.env.AUDIT_MIRROR_BUCKET = 'ztiam-audit-mirror';
    mockSend.mockRejectedValueOnce(new Error('network down'));

    auditMirror = require('../../auditMirror');
    await expect(
      auditMirror.mirrorAuditEntry({ entryHash: 'b'.repeat(64), txId: 'tx-err' })
    ).resolves.toBeUndefined();
  });
});
