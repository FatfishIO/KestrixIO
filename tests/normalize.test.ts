import { describe, it, expect } from 'vitest';
import {
  normalizeSemgrepSarif,
  normalizeGitleaksJson,
  normalizeOsvScannerJson,
  assertTeamAccess,
} from '../src/core/normalize';

describe('Multi-Scanner Report Normalizer & Team RBAC Guard', () => {
  describe('normalizeSemgrepSarif (SARIF 2.1.0)', () => {
    it('prioritizes SARIF partialFingerprints when provided by scanner and sanitizes file paths', () => {
      const sampleSarif = {
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'Semgrep OSS',
                semanticVersion: '1.92.0',
              },
            },
            results: [
              {
                ruleId: 'javascript.express.security.audit.sqli',
                message: { text: 'Detected SQL injection in query builder' },
                level: 'error',
                partialFingerprints: {
                  primaryLocationLineHash: 'sarif-provided-fp-99887766',
                },
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: {
                        uri: '../../src/routes/auth.ts',
                      },
                      region: {
                        startLine: 42,
                        endLine: 44,
                        snippet: {
                          text: 'db.query(`SELECT * FROM users WHERE id = ${req.query.id}`)',
                        },
                      },
                    },
                  },
                ],
              },
            ],
          },
        ],
      };

      const normalized = normalizeSemgrepSarif(sampleSarif);
      expect(normalized).toHaveLength(1);
      expect(normalized[0].type).toBe('sast');
      expect(normalized[0].ruleOrVulnId).toBe('javascript.express.security.audit.sqli');
      expect(normalized[0].filePath).toBe('src/routes/auth.ts');
      // Uses partialFingerprints priority
      expect(normalized[0].fingerprint).toContain('sarif-provided-fp-99887766');
    });

    it('falls back to deterministic computeSastFingerprint when partialFingerprints is missing', () => {
      const sarifWithoutPartialFp = {
        version: '2.1.0',
        runs: [
          {
            tool: { driver: { name: 'Semgrep', semanticVersion: '1.92.0' } },
            results: [
              {
                ruleId: 'javascript.express.xss',
                message: { text: 'Reflected XSS' },
                level: 'warning',
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: 'src/views/render.ts' },
                      region: {
                        startLine: 10,
                        endLine: 12,
                        snippet: { text: 'res.send(req.query.input)' },
                      },
                    },
                  },
                ],
              },
            ],
          },
        ],
      };

      const normalized = normalizeSemgrepSarif(sarifWithoutPartialFp);
      expect(normalized).toHaveLength(1);
      expect(normalized[0].fingerprint).toHaveLength(64);
    });
  });

  describe('normalizeGitleaksJson (Rule #1 Secret Protection)', () => {
    it('hashes and masks secrets immediately and never retains raw secret', () => {
      const rawLeak = 'TEST_PAT_TOKEN_SAMPLE_9876543210ABCD';
      const gitleaksReport = [
        {
          Description: 'GitHub Personal Access Token',
          RuleID: 'github-pat',
          File: '../config/deploy.env',
          StartLine: 8,
          EndLine: 8,
          Secret: rawLeak,
          Match: `GITHUB_TOKEN=${rawLeak}`,
        },
      ];

      const normalized = normalizeGitleaksJson(gitleaksReport);
      expect(normalized).toHaveLength(1);
      expect(normalized[0].type).toBe('secret');
      expect(normalized[0].filePath).toBe('config/deploy.env');
      expect(normalized[0].secretMasked).toBe('****ABCD');
      expect(normalized[0].secretHash).toHaveLength(64);
      // Verify raw secret is completely absent from serialized output
      expect(JSON.stringify(normalized)).not.toContain(rawLeak);
    });
  });

  describe('normalizeOsvScannerJson (Dependency Scanning)', () => {
    it('normalizes OSV-Scanner output and excludes package version from fingerprint', () => {
      const osvReport = {
        results: [
          {
            source: { path: './package-lock.json', type: 'lockfile' },
            packages: [
              {
                package: { name: 'axios', version: '0.21.1', ecosystem: 'npm' },
                vulnerabilities: [
                  {
                    id: 'GHSA-42xw-2xvc-cx4y',
                    summary: 'Axios Cross-Site Request Forgery Vulnerability',
                    aliases: ['CVE-2023-45857'],
                  },
                ],
              },
            ],
          },
        ],
      };

      const normalized = normalizeOsvScannerJson(osvReport);
      expect(normalized).toHaveLength(1);
      expect(normalized[0].type).toBe('dependency');
      expect(normalized[0].ruleOrVulnId).toBe('GHSA-42xw-2xvc-cx4y');
      expect(normalized[0].filePath).toBe('package-lock.json');
      expect(normalized[0].fingerprint).toHaveLength(64);
    });
  });

  describe('assertTeamAccess (Rule #7 Service-Layer RBAC)', () => {
    it('allows access when actor team matches asset teamId or is admin', () => {
      expect(() => assertTeamAccess('team-core', 'team-core')).not.toThrow();
      expect(() => assertTeamAccess('team-admin', 'team-checkout', true)).not.toThrow();
    });

    it('throws structured FORBIDDEN_TEAM_ACCESS error on cross-team access', () => {
      expect(() => assertTeamAccess('team-mobile', 'team-checkout')).toThrow(
        /FORBIDDEN_TEAM_ACCESS/
      );
    });
  });
});
