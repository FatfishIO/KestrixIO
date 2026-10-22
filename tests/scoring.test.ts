import { describe, it, expect } from 'vitest';
import { calculateRiskScore, type AssetContext, type FindingSignals } from '../src/core/scoring';

describe('Deterministic Risk Scoring Engine (SSVC / Contextual Decision Tree)', () => {
  const prodInternetFacingAsset: AssetContext = {
    criticality: 1,
    internetFacing: true,
    environment: 'production',
    dataClass: 'pci_dss',
  };

  const devInternalAsset: AssetContext = {
    criticality: 4,
    internetFacing: false,
    environment: 'development',
    dataClass: 'internal',
  };

  describe('Dependency Risk Rules', () => {
    it('promotes to P1 (7-day SLA) when in CISA KEV + reachable on internet-facing asset', () => {
      const signals: FindingSignals = {
        type: 'dependency',
        inKev: true,
        reachable: true,
        epssScore: 0.85,
        cvssScore: 9.8,
      };

      const result = calculateRiskScore(signals, prodInternetFacingAsset);
      expect(result.riskLevel).toBe('P1');
      expect(result.slaDays).toBe(7);
      expect(result.riskReasons).toEqual(
        expect.arrayContaining([
          expect.stringContaining('CISA KEV'),
          expect.stringContaining('Internet-facing'),
        ])
      );
    });

    it('assigns P2 (30-day SLA) when EPSS > 0.1 and CVSS >= 7 on production but not in KEV', () => {
      const signals: FindingSignals = {
        type: 'dependency',
        inKev: false,
        reachable: false,
        epssScore: 0.25,
        cvssScore: 7.5,
      };

      const result = calculateRiskScore(signals, prodInternetFacingAsset);
      expect(result.riskLevel).toBe('P2');
      expect(result.slaDays).toBe(30);
      expect(result.riskReasons.some((r) => r.includes('EPSS > 0.1'))).toBe(true);
    });

    it('assigns P3 (90-day SLA) for internal dev asset without KEV exploit', () => {
      const signals: FindingSignals = {
        type: 'dependency',
        inKev: false,
        reachable: false,
        epssScore: 0.02,
        cvssScore: 7.5,
      };

      const result = calculateRiskScore(signals, devInternalAsset);
      expect(result.riskLevel).toBe('P3');
      expect(result.slaDays).toBe(90);
    });
  });

  describe('SAST Risk Rules', () => {
    it('promotes Injection/Auth on internet-facing production to P1', () => {
      const signals: FindingSignals = {
        type: 'sast',
        cweCategory: 'CWE-89 SQL Injection',
        isProductionPath: true,
        ruleSeverity: 'ERROR',
        ruleConfidence: 'HIGH',
      };

      const result = calculateRiskScore(signals, prodInternetFacingAsset);
      expect(result.riskLevel).toBe('P1');
      expect(result.slaDays).toBe(7);
      expect(result.riskReasons.some((r) => r.includes('Injection/Auth'))).toBe(true);
    });

    it('classifies low-confidence flaw in test path as P4 (no SLA)', () => {
      const signals: FindingSignals = {
        type: 'sast',
        cweCategory: 'CWE-200 Information Exposure',
        isProductionPath: false,
        ruleSeverity: 'INFO',
        ruleConfidence: 'LOW',
      };

      const result = calculateRiskScore(signals, devInternalAsset);
      expect(result.riskLevel).toBe('P4');
      expect(result.slaDays).toBeNull();
    });
  });

  describe('Secret Risk Rules', () => {
    it('promotes verified active secret in production/public asset to P1', () => {
      const signals: FindingSignals = {
        type: 'secret',
        secretActive: true,
        secretType: 'github-pat',
        isGitHistory: false,
      };

      const result = calculateRiskScore(signals, prodInternetFacingAsset);
      expect(result.riskLevel).toBe('P1');
      expect(result.slaDays).toBe(7);
      expect(result.riskReasons.some((r) => r.includes('Secret còn hiệu lực'))).toBe(true);
    });

    it('demotes inactive/historical secret on internal dev to P3', () => {
      const signals: FindingSignals = {
        type: 'secret',
        secretActive: false,
        secretType: 'generic-api-key',
        isGitHistory: true,
      };

      const result = calculateRiskScore(signals, devInternalAsset);
      expect(result.riskLevel).toBe('P3');
      expect(result.slaDays).toBe(90);
    });
  });
});
