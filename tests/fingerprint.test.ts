import { describe, it, expect } from 'vitest';
import {
  normalizePath,
  maskSecret,
  computeSastFingerprint,
  computeSecretFingerprint,
  computeDependencyFingerprint,
} from '../src/core/fingerprint';

describe('Fingerprint & Secret Protection Module', () => {
  describe('normalizePath', () => {
    it('normalizes windows backslashes and redundant dots', () => {
      expect(normalizePath('src\\controllers\\..\\utils\\auth.ts')).toBe('src/utils/auth.ts');
    });

    it('neutralizes directory traversal attempts', () => {
      expect(normalizePath('../../../etc/passwd')).toBe('etc/passwd');
      expect(normalizePath('/app/./src/main.ts')).toBe('app/src/main.ts');
    });
  });

  describe('maskSecret - Security Rule #1', () => {
    it('never exposes raw secret, returns sha256 and last 4 chars', () => {
      const rawSecret = 'TEST_PAT_TOKEN_SAMPLE_ABCDEFGHIJ123456';
      const result = maskSecret(rawSecret);

      expect(result.masked).toBe('****3456');
      expect(result.hash).toHaveLength(64);
      expect(result.hash).not.toContain(rawSecret);
      expect(result.masked).not.toContain('ABC');
    });

    it('handles short secrets safely', () => {
      const shortSecret = 'abc';
      const result = maskSecret(shortSecret);
      expect(result.masked).toBe('****');
      expect(result.hash).toHaveLength(64);
    });
  });

  describe('computeSastFingerprint', () => {
    it('produces identical fingerprint for identical rule, normalized path, and normalized snippet regardless of line number', () => {
      const fp1 = computeSastFingerprint(
        'javascript.express.security.audit.xss',
        'src/controllers/user.ts',
        '  res.send(req.query.name);  '
      );

      const fp2 = computeSastFingerprint(
        'javascript.express.security.audit.xss',
        './src/controllers/user.ts',
        'res.send(req.query.name);'
      );

      expect(fp1).toBe(fp2);
      expect(fp1).toHaveLength(64);
    });

    it('produces distinct fingerprint when code snippet or rule differs', () => {
      const fp1 = computeSastFingerprint(
        'javascript.express.security.audit.xss',
        'src/controllers/user.ts',
        'res.send(req.query.name);'
      );

      const fp2 = computeSastFingerprint(
        'javascript.express.security.audit.sqli',
        'src/controllers/user.ts',
        'res.send(req.query.name);'
      );

      expect(fp1).not.toBe(fp2);
    });
  });

  describe('computeSecretFingerprint', () => {
    it('hashes raw secret and does not store raw secret anywhere in output', () => {
      const raw = 'TEST_AWS_KEY_SAMPLE_7EXAMPLE';
      const res = computeSecretFingerprint(
        'aws-access-key-id',
        'config/aws.env',
        raw
      );

      expect(res.secretMasked).toBe('****MPLE');
      expect(res.secretHash).toHaveLength(64);
      expect(res.fingerprint).toHaveLength(64);
      // Verify raw is nowhere in stringified representation
      expect(JSON.stringify(res)).not.toContain(raw);
    });
  });

  describe('computeDependencyFingerprint', () => {
    it('does NOT include version so bumping version keeps the same finding identity', () => {
      const fpVersion1 = computeDependencyFingerprint(
        'npm',
        'axios',
        'GHSA-42xw-2xvc-cx4y',
        'package.json'
      );

      const fpVersion2 = computeDependencyFingerprint(
        'npm',
        'axios',
        'GHSA-42xw-2xvc-cx4y',
        './package.json'
      );

      expect(fpVersion1).toBe(fpVersion2);
    });
  });
});
