import { FindingStatus, FindingType, StatusChange } from './types';

export interface FindingStateItem {
  id: string;
  assetId: string;
  type: FindingType;
  fingerprint: string;
  status: FindingStatus;
  reopened: boolean;
}

export interface TransitionResult {
  updatedFinding: FindingStateItem;
  statusChange: StatusChange;
}

/**
 * Validates and executes a human-driven status change.
 * AI or unauthenticated scripts cannot call this directly.
 */
export function transitionFindingStatus(
  finding: FindingStateItem,
  toStatus: FindingStatus,
  actor: string,
  reason: string,
  expiresAt?: Date | null
): TransitionResult {
  if (!actor || actor.trim() === '') {
    throw new Error('Actor định danh người thực hiện là bắt buộc.');
  }

  if (!reason || reason.trim() === '') {
    throw new Error('Bắt buộc phải có lý do (reason) cho mọi thay đổi trạng thái của finding.');
  }

  // Security Rule: Human cannot arbitrarily mark a finding as 'fixed'.
  // 'fixed' is strictly automated: only when a full scan no longer detects the issue.
  if (toStatus === 'fixed') {
    throw new Error(
      'Chỉ hệ thống (System) mới có quyền chuyển trạng thái sang "fixed" khi kết quả quét sau không còn thấy lỗi.'
    );
  }

  if (toStatus === 'risk_accepted' && !expiresAt) {
    throw new Error(
      'Chấp nhận rủi ro (risk_accepted) bắt buộc phải có thời hạn hết hiệu lực (expires_at).'
    );
  }

  const validTransitions: Record<FindingStatus, FindingStatus[]> = {
    new: ['triaged', 'false_positive', 'risk_accepted'],
    triaged: ['in_progress', 'false_positive', 'risk_accepted'],
    in_progress: ['triaged', 'false_positive', 'risk_accepted'],
    fixed: ['triaged'], // Can only be reopened, handled primarily by system
    false_positive: ['triaged'],
    risk_accepted: ['triaged'],
  };

  const allowed = validTransitions[finding.status] || [];
  if (!allowed.includes(toStatus)) {
    throw new Error(
      `Chuyển đổi trạng thái không hợp lệ: Không thể chuyển từ "${finding.status}" sang "${toStatus}".`
    );
  }

  const updatedFinding: FindingStateItem = {
    ...finding,
    status: toStatus,
  };

  const statusChange: StatusChange = {
    id: `sc-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    findingId: finding.id,
    fromStatus: finding.status,
    toStatus,
    actor,
    reason: reason.trim(),
    expiresAt: expiresAt ? expiresAt.toISOString() : null,
    changedAt: new Date().toISOString(),
  };

  return { updatedFinding, statusChange };
}

/**
 * Automated Scanner Diffing:
 * When a full scan completes for an asset and finding type:
 * 1. Findings absent from the scan that are in ('new', 'triaged', 'in_progress') are marked 'fixed' by system.
 * 2. Findings previously 'fixed' that reappear are marked 'triaged' and reopened = true by system.
 */
export function processScanDiffAutoFixed(
  currentFindings: FindingStateItem[],
  assetId: string,
  findingType: FindingType,
  scannedFingerprints: Set<string>,
  scanId: string,
  commitSha: string
): { updatedFindings: FindingStateItem[]; statusChanges: StatusChange[] } {
  const updatedFindings: FindingStateItem[] = [];
  const statusChanges: StatusChange[] = [];
  const now = new Date().toISOString();

  for (const finding of currentFindings) {
    if (finding.assetId !== assetId || finding.type !== findingType) {
      updatedFindings.push(finding);
      continue;
    }

    const isPresentInScan = scannedFingerprints.has(finding.fingerprint);

    // Rule 1: Finding was active, but no longer detected in this scan -> AUTO-FIXED
    if (
      !isPresentInScan &&
      (finding.status === 'new' ||
        finding.status === 'triaged' ||
        finding.status === 'in_progress')
    ) {
      updatedFindings.push({
        ...finding,
        status: 'fixed',
      });

      statusChanges.push({
        id: `sc-auto-fixed-${finding.id}-${Date.now()}`,
        findingId: finding.id,
        fromStatus: finding.status,
        toStatus: 'fixed',
        actor: 'system',
        reason: `Resolved in scan ${scanId} (commit ${commitSha})`,
        changedAt: now,
      });
      continue;
    }

    // Rule 2: Finding was 'fixed', but reappeared in this scan -> REOPENED
    if (isPresentInScan && finding.status === 'fixed') {
      updatedFindings.push({
        ...finding,
        status: 'triaged',
        reopened: true,
      });

      statusChanges.push({
        id: `sc-reopened-${finding.id}-${Date.now()}`,
        findingId: finding.id,
        fromStatus: 'fixed',
        toStatus: 'triaged',
        actor: 'system',
        reason: `Reappeared in scan ${scanId} (commit ${commitSha})`,
        changedAt: now,
      });
      continue;
    }

    // Unchanged
    updatedFindings.push(finding);
  }

  return { updatedFindings, statusChanges };
}
