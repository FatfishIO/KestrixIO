import { describe, it, expect } from 'vitest';
import {
  calculateAlertReductionFunnel,
  evaluatePatchVerificationGate,
  resolveVulnerabilityCvss,
} from '../src/core/pipeline';

describe('Closed-Loop Vulnerability Pipeline & Self-Correction Guardrails', () => {
  describe('calculateAlertReductionFunnel (Deterministic Dedup + SSVC Filtering)', () => {
    it('reduces raw detections via fingerprint deduplication and SSVC P1/P2 filtering', () => {
      const rawDetections = [
        { assetId: 'a1', fingerprint: 'fp-1', riskLevel: 'P1' as const },
        { assetId: 'a1', fingerprint: 'fp-1', riskLevel: 'P1' as const }, // duplicate occurrence
        { assetId: 'a1', fingerprint: 'fp-1', riskLevel: 'P1' as const }, // duplicate occurrence
        { assetId: 'a1', fingerprint: 'fp-2', riskLevel: 'P2' as const },
        { assetId: 'a1', fingerprint: 'fp-3', riskLevel: 'P3' as const },
        { assetId: 'a1', fingerprint: 'fp-4', riskLevel: 'P4' as const },
      ];

      const stats = calculateAlertReductionFunnel(rawDetections);
      expect(stats.rawDetectionsCount).toBe(6);
      expect(stats.deduplicatedFindingsCount).toBe(4);
      expect(stats.actionablePriorityCount).toBe(2); // P1 + P2 only
      expect(stats.llmEligibleCount).toBe(2); // Only P1-P2 sent to LLM per guardrail
      expect(stats.totalReductionPercent).toBeCloseTo(66.7, 1);
    });
  });

  describe('resolveVulnerabilityCvss (CNA Official vs Predicted Fallback)', () => {
    it('never overwrites official CNA CVSS score with AI predicted score', () => {
      const resolved = resolveVulnerabilityCvss(
        { cvssScore: 9.8, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cvssSource: 'CNA' },
        { predictedScore: 6.5, predictedVector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N', confidence: 0.89 }
      );

      expect(resolved.score).toBe(9.8);
      expect(resolved.source).toBe('CNA');
      expect(resolved.isPredicted).toBe(false);
    });

    it('uses predicted CVSS with mandatory [Dự đoán] flag only when official score is missing', () => {
      const resolved = resolveVulnerabilityCvss(
        { cvssScore: undefined, cvssVector: undefined, cvssSource: undefined },
        { predictedScore: 8.1, predictedVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', confidence: 0.89 }
      );

      expect(resolved.score).toBe(8.1);
      expect(resolved.isPredicted).toBe(true);
      expect(resolved.confidence).toBe(0.89);
      expect(resolved.badgeLabel).toContain('Dự đoán');
    });
  });

  describe('evaluatePatchVerificationGate (Self-Correction Loop & Sandbox)', () => {
    it('triggers self-correction retry when re-running scanner still detects the vulnerability', () => {
      const gate = evaluatePatchVerificationGate({
        attempt: 1,
        maxAttempts: 3,
        scannerReRunRemainingFindings: 1,
        sandboxTestsEnabled: true,
        sandboxTestsPassed: true,
      });

      expect(gate.status).toBe('self_correct_retry');
      expect(gate.canOpenDraftPr).toBe(false);
      expect(gate.autoMergeAllowed).toBe(false);
      expect(gate.reason).toContain('Scanner vẫn phát hiện lỗ hổng');
    });

    it('blocks Draft PR if sandbox unit tests fail', () => {
      const gate = evaluatePatchVerificationGate({
        attempt: 2,
        maxAttempts: 3,
        scannerReRunRemainingFindings: 0,
        sandboxTestsEnabled: true,
        sandboxTestsPassed: false,
      });

      expect(gate.status).toBe('self_correct_retry');
      expect(gate.canOpenDraftPr).toBe(false);
      expect(gate.autoMergeAllowed).toBe(false);
      expect(gate.reason).toContain('Test của repo thất bại trong sandbox');
    });

    it('approves opening Draft PR (never auto-merge) only when both scanner re-run and sandbox tests pass', () => {
      const gate = evaluatePatchVerificationGate({
        attempt: 2,
        maxAttempts: 3,
        scannerReRunRemainingFindings: 0,
        sandboxTestsEnabled: true,
        sandboxTestsPassed: true,
      });

      expect(gate.status).toBe('verified_ready_for_draft_pr');
      expect(gate.canOpenDraftPr).toBe(true);
      expect(gate.autoMergeAllowed).toBe(false);
    });
  });
});
