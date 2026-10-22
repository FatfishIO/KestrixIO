import { RiskLevel } from './types';

export interface RawDetectionItem {
  assetId: string;
  fingerprint: string;
  riskLevel: RiskLevel;
}

export interface AlertReductionFunnelStats {
  rawDetectionsCount: number;
  deduplicatedFindingsCount: number;
  actionablePriorityCount: number; // P1 & P2
  llmEligibleCount: number; // Only P1 & P2 sent to LLM per token budget guardrail
  totalReductionPercent: number;
}

/**
 * Deterministic Alert Reduction Funnel:
 * Stage 1: Raw detections from Semgrep / Gitleaks / OSV-Scanner
 * Stage 2: Deduplicated findings by (assetId, fingerprint)
 * Stage 3: SSVC / EPSS / KEV contextual filtering -> P1 & P2 priority items
 */
export function calculateAlertReductionFunnel(
  detections: RawDetectionItem[]
): AlertReductionFunnelStats {
  const rawDetectionsCount = detections.length;
  if (rawDetectionsCount === 0) {
    return {
      rawDetectionsCount: 0,
      deduplicatedFindingsCount: 0,
      actionablePriorityCount: 0,
      llmEligibleCount: 0,
      totalReductionPercent: 0,
    };
  }

  const uniqueMap = new Map<string, RiskLevel>();
  for (const d of detections) {
    const key = `${d.assetId}:${d.fingerprint}`;
    if (!uniqueMap.has(key)) {
      uniqueMap.set(key, d.riskLevel);
    }
  }

  const deduplicatedFindingsCount = uniqueMap.size;
  let actionablePriorityCount = 0;

  for (const level of uniqueMap.values()) {
    if (level === 'P1' || level === 'P2') {
      actionablePriorityCount++;
    }
  }

  const totalReductionPercent =
    ((rawDetectionsCount - actionablePriorityCount) / rawDetectionsCount) * 100;

  return {
    rawDetectionsCount,
    deduplicatedFindingsCount,
    actionablePriorityCount,
    llmEligibleCount: actionablePriorityCount,
    totalReductionPercent,
  };
}

export interface OfficialCvssInput {
  cvssScore?: number;
  cvssVector?: string;
  cvssSource?: string;
}

export interface PredictedCvssInput {
  predictedScore: number;
  predictedVector: string;
  confidence: number;
}

export interface ResolvedCvssResult {
  score: number;
  vector: string;
  source: string;
  isPredicted: boolean;
  confidence?: number;
  badgeLabel: string;
}

/**
 * Resolves CVSS score strictly respecting CNA authority:
 * - Official CNA / CVE.org score is NEVER overwritten by AI prediction.
 * - Predicted CVSS is used ONLY when official score is absent, and always carries [Dự đoán].
 */
export function resolveVulnerabilityCvss(
  official: OfficialCvssInput,
  predicted: PredictedCvssInput
): ResolvedCvssResult {
  if (typeof official.cvssScore === 'number' && official.cvssVector) {
    const source = official.cvssSource || 'CNA';
    return {
      score: official.cvssScore,
      vector: official.cvssVector,
      source,
      isPredicted: false,
      badgeLabel: `Chính thức (${source})`,
    };
  }

  return {
    score: predicted.predictedScore,
    vector: predicted.predictedVector,
    source: 'AI_PREDICTED',
    isPredicted: true,
    confidence: predicted.confidence,
    badgeLabel: `[Dự đoán · Tin cậy ${(predicted.confidence * 100).toFixed(0)}%]`,
  };
}

export interface PatchVerificationInput {
  attempt: number;
  maxAttempts: number;
  scannerReRunRemainingFindings: number;
  sandboxTestsEnabled: boolean;
  sandboxTestsPassed: boolean;
}

export interface PatchVerificationGateResult {
  status: 'verified_ready_for_draft_pr' | 'self_correct_retry' | 'aborted_max_retries';
  canOpenDraftPr: boolean;
  autoMergeAllowed: false; // Strictly false per Security Rule #6 & PLAN.md
  reason: string;
}

/**
 * Self-Correction Remediation Loop Verification Gate (Phase 5):
 * 1. Apply patch in isolated sandbox.
 * 2. Re-run scanner on patched file (must yield 0 findings for the rule).
 * 3. Run repo test suite in sandbox (if enabled on asset).
 * 4. Only open a Draft PR via GitHub App when both pass. Never auto-merge.
 */
export function evaluatePatchVerificationGate(
  input: PatchVerificationInput
): PatchVerificationGateResult {
  if (input.scannerReRunRemainingFindings > 0) {
    if (input.attempt >= input.maxAttempts) {
      return {
        status: 'aborted_max_retries',
        canOpenDraftPr: false,
        autoMergeAllowed: false,
        reason: `Đã vượt quá số lần thử tối đa (${input.maxAttempts}). Scanner vẫn phát hiện ${input.scannerReRunRemainingFindings} lỗ hổng.`,
      };
    }
    return {
      status: 'self_correct_retry',
      canOpenDraftPr: false,
      autoMergeAllowed: false,
      reason: `Lần thử ${input.attempt}/${input.maxAttempts}: Scanner vẫn phát hiện lỗ hổng sau khi áp patch. Kích hoạt Self-Correction Loop.`,
    };
  }

  if (input.sandboxTestsEnabled && !input.sandboxTestsPassed) {
    if (input.attempt >= input.maxAttempts) {
      return {
        status: 'aborted_max_retries',
        canOpenDraftPr: false,
        autoMergeAllowed: false,
        reason: `Đã vượt quá số lần thử tối đa (${input.maxAttempts}). Test của repo thất bại trong sandbox.`,
      };
    }
    return {
      status: 'self_correct_retry',
      canOpenDraftPr: false,
      autoMergeAllowed: false,
      reason: `Lần thử ${input.attempt}/${input.maxAttempts}: Test của repo thất bại trong sandbox. Kích hoạt Self-Correction Loop để sửa lỗi hồi quy.`,
    };
  }

  return {
    status: 'verified_ready_for_draft_pr',
    canOpenDraftPr: true,
    autoMergeAllowed: false,
    reason:
      'Bản vá đã vượt qua cả bước quét lại bằng Scanner (0 finding) và bộ Test trong Sandbox. Đủ điều kiện mở Draft PR qua GitHub App.',
  };
}
