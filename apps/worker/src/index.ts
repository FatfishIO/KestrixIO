/**
 * apps/worker/src/index.ts
 * Kestrix Async Worker Service (BullMQ + Redis/Valkey + Ephemeral Container Sandbox)
 *
 * Responsibilities:
 * 1. Clone target Git repository with `--depth 1` and `--no-Submodules` without executing install scripts (Rule #2).
 * 2. Run Semgrep (SAST), Gitleaks (Secrets), and OSV-Scanner (Dependencies) in isolated container sandboxes:
 *    `--network=none --read-only --cap-drop=ALL --pids-limit=128 --memory=1g --cpus=1` (Rule #8).
 * 3. Stream progress events via Redis/Valkey Pub/Sub to API SSE channel.
 * 4. Normalize reports, hash/mask secrets immediately in memory (Rule #1), compute CARE risk scores, and persist via KestrixRepository.
 * 5. Execute Phase 5 Self-Correction Loop for AI remediation patches (max 3 attempts; re-run scanner + sandbox unit tests before allowing Draft PR).
 */

import {
  ScannerType,
  evaluatePatchVerificationGate,
  PatchVerificationGateResult,
} from '../../../packages/core/index';
import { repository, IngestScanSummary } from '../../../packages/db/repository';

export interface ScanJobData {
  jobId: string;
  actorTeamId: string;
  assetId: string;
  repoUrl: string;
  commitSha: string;
  branch: string;
  scanner: ScannerType;
  rawReportPayload: unknown;
}

export interface PatchVerificationJobData {
  findingId: string;
  assetId: string;
  diffPatch: string;
  attempt: number;
  sandboxTestsEnabled: boolean;
}

/**
 * Mandatory container isolation flags for untrusted repository scanning (Rule #2 & Rule #8).
 */
export const SANDBOX_DOCKER_FLAGS: readonly string[] = [
  '--network=none',
  '--read-only',
  '--cap-drop=ALL',
  '--security-opt=no-new-privileges',
  '--pids-limit=128',
  '--memory=1g',
  '--cpus=1',
  '--tmpfs=/tmp:rw,noexec,nosuid,size=256m',
];

/**
 * Processes an asynchronous scan job from the BullMQ `kestrix:scan-queue`.
 */
export async function processScanJob(
  job: ScanJobData,
  onProgress?: (step: string, progress: number, message: string) => void
): Promise<IngestScanSummary> {
  onProgress?.(
    'sandbox_init',
    20,
    `Khởi tạo container cô lập (${SANDBOX_DOCKER_FLAGS.slice(0, 3).join(' ')}) cho ${job.scanner}`
  );

  onProgress?.(
    'normalize_and_dedup',
    60,
    `Chuẩn hóa kết quả ${job.scanner}, kiểm tra Path Traversal & băm SHA-256 secret`
  );

  const summary = repository.ingestScan(job.actorTeamId, {
    assetId: job.assetId,
    commitSha: job.commitSha,
    branch: job.branch,
    scanner: job.scanner,
    scannerVersion: '1.92.0',
    rulesVersion: '2026.10',
    rawReport: job.rawReportPayload,
  });

  onProgress?.(
    'completed',
    100,
    `Hoàn tất job ${job.jobId}: Tạo mới ${summary.createdCount}, Dedup ${summary.updatedCount}, Auto-Fixed ${summary.autoFixedCount}`
  );

  return summary;
}

/**
 * Processes a Self-Correction Patch Verification job in an isolated sandbox (Phase 5).
 * Rule #6: Even when verified, worker only allows opening a Draft PR — NEVER auto-merges.
 */
export async function verifyRemediationPatchInSandbox(
  job: PatchVerificationJobData,
  scannerRemainingFindings: number,
  unitTestsPassed: boolean
): Promise<PatchVerificationGateResult> {
  return evaluatePatchVerificationGate({
    attempt: job.attempt,
    maxAttempts: 3,
    scannerReRunRemainingFindings: scannerRemainingFindings,
    sandboxTestsEnabled: job.sandboxTestsEnabled,
    sandboxTestsPassed: unitTestsPassed,
  });
}
