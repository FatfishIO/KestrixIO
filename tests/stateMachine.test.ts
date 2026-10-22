import { describe, it, expect } from 'vitest';
import {
  transitionFindingStatus,
  processScanDiffAutoFixed,
  type FindingStateItem,
} from '../src/core/stateMachine';

describe('Finding Lifecycle State Machine & Audit', () => {
  const sampleFinding: FindingStateItem = {
    id: 'f-101',
    assetId: 'asset-1',
    type: 'sast',
    fingerprint: 'fp-101',
    status: 'new',
    reopened: false,
  };

  describe('Human State Transitions', () => {
    it('allows human to triage a new finding with required reason', () => {
      const { updatedFinding, statusChange } = transitionFindingStatus(
        sampleFinding,
        'triaged',
        'secops@company.com',
        'Confirmed valid vulnerability in auth controller'
      );

      expect(updatedFinding.status).toBe('triaged');
      expect(statusChange.fromStatus).toBe('new');
      expect(statusChange.toStatus).toBe('triaged');
      expect(statusChange.actor).toBe('secops@company.com');
      expect(statusChange.reason).toContain('Confirmed valid');
    });

    it('rejects human transition if reason is missing or empty', () => {
      expect(() => {
        transitionFindingStatus(
          sampleFinding,
          'triaged',
          'secops@company.com',
          ''
        );
      }).toThrow(/Bắt buộc phải có lý do/);
    });

    it('requires expiresAt date when moving to risk_accepted', () => {
      expect(() => {
        transitionFindingStatus(
          sampleFinding,
          'risk_accepted',
          'ciso@company.com',
          'Business need requires delay',
          undefined
        );
      }).toThrow(/expires_at/);

      const futureDate = new Date(Date.now() + 86400000 * 30);
      const res = transitionFindingStatus(
        sampleFinding,
        'risk_accepted',
        'ciso@company.com',
        'Business need requires delay',
        futureDate
      );
      expect(res.updatedFinding.status).toBe('risk_accepted');
      expect(res.statusChange.expiresAt).toEqual(futureDate.toISOString());
    });

    it('rejects human transition directly to fixed (must be done by scanner diff)', () => {
      expect(() => {
        transitionFindingStatus(
          sampleFinding,
          'fixed',
          'developer@company.com',
          'I fixed this in commit abc'
        );
      }).toThrow(/Chỉ hệ thống/);
    });
  });

  describe('Automated Scanner Diffing: Auto-fixed & Reopened', () => {
    it('automatically transitions absent findings to fixed when full scan completes', () => {
      const currentFindings: FindingStateItem[] = [
        { id: 'f-1', assetId: 'a1', type: 'sast', fingerprint: 'fp-1', status: 'triaged', reopened: false },
        { id: 'f-2', assetId: 'a1', type: 'sast', fingerprint: 'fp-2', status: 'new', reopened: false },
        { id: 'f-3', assetId: 'a1', type: 'sast', fingerprint: 'fp-3', status: 'false_positive', reopened: false },
      ];

      // Scan only detected fp-1 (fp-2 is gone and was resolved)
      const scannedFingerprints = new Set(['fp-1']);

      const { updatedFindings, statusChanges } = processScanDiffAutoFixed(
        currentFindings,
        'a1',
        'sast',
        scannedFingerprints,
        'scan-999',
        'c0ffee123'
      );

      const f2 = updatedFindings.find((f) => f.id === 'f-2');
      expect(f2?.status).toBe('fixed');

      const change = statusChanges.find((c) => c.findingId === 'f-2');
      expect(change?.actor).toBe('system');
      expect(change?.toStatus).toBe('fixed');
      expect(change?.reason).toContain('Resolved in scan scan-999');

      // False positive shouldn't be touched by auto-fixed
      const f3 = updatedFindings.find((f) => f.id === 'f-3');
      expect(f3?.status).toBe('false_positive');
    });

    it('reopens finding and sets reopened=true if a fixed finding reappears in a scan', () => {
      const fixedFinding: FindingStateItem = {
        id: 'f-99',
        assetId: 'a1',
        type: 'sast',
        fingerprint: 'fp-99',
        status: 'fixed',
        reopened: false,
      };

      const scannedFingerprints = new Set(['fp-99']);

      const { updatedFindings, statusChanges } = processScanDiffAutoFixed(
        [fixedFinding],
        'a1',
        'sast',
        scannedFingerprints,
        'scan-1000',
        'deadbeef'
      );

      const reopened = updatedFindings.find((f) => f.id === 'f-99');
      expect(reopened?.status).toBe('triaged');
      expect(reopened?.reopened).toBe(true);

      const change = statusChanges.find((c) => c.findingId === 'f-99');
      expect(change?.actor).toBe('system');
      expect(change?.fromStatus).toBe('fixed');
      expect(change?.toStatus).toBe('triaged');
      expect(change?.reason).toContain('Reappeared in scan scan-1000');
    });
  });
});
