import {
  Team,
  Asset,
  Scan,
  Finding,
  Occurrence,
  Vulnerability,
  StatusChange,
  AiOutput,
  FindingStatus,
  ScannerType,
  FindingType,
} from '../../src/core/types';
import {
  INITIAL_TEAMS,
  INITIAL_ASSETS,
  INITIAL_SCANS,
  INITIAL_FINDINGS,
  INITIAL_OCCURRENCES,
  INITIAL_STATUS_CHANGES,
} from '../../src/data/mockData';
import {
  assertTeamAccess,
  NormalizedScanFinding,
  normalizeSemgrepSarif,
  normalizeGitleaksJson,
  normalizeOsvScannerJson,
} from '../../src/core/normalize';
import { calculateRiskScore, calculateSlaDueDate } from '../../src/core/scoring';
import {
  transitionFindingStatus,
  processScanDiffAutoFixed,
} from '../../src/core/stateMachine';

export interface IngestScanPayload {
  assetId: string;
  commitSha: string;
  branch?: string;
  scanner: ScannerType;
  scannerVersion: string;
  rulesVersion: string;
  rawReport?: unknown;
  normalizedFindings?: NormalizedScanFinding[];
}

export interface IngestScanSummary {
  scan: Scan;
  createdCount: number;
  updatedCount: number;
  autoFixedCount: number;
  reopenedCount: number;
  findings: Finding[];
}

const INITIAL_VULNERABILITIES: Vulnerability[] = [
  {
    id: 'GHSA-42xw-2xvc-cx4y',
    aliases: ['CVE-2023-45857'],
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
    cvssScore: 6.5,
    cvssSource: 'CNA (GitHub Advisory)',
    epss: 0.8812,
    kev: true,
    ssvc: 'Act',
    fixedVersions: ['1.6.0', '1.7.4'],
    fetchedAt: '2026-10-22T00:00:00Z',
  },
  {
    id: 'CVE-2024-29041',
    aliases: ['GHSA-rv95-896h-c2vc'],
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    cvssScore: 6.1,
    cvssSource: 'CNA (OpenJS Foundation)',
    epss: 0.142,
    kev: false,
    ssvc: 'Attend',
    fixedVersions: ['4.19.2'],
    fetchedAt: '2026-10-22T00:00:00Z',
  },
];

export class KestrixRepository {
  private teams: Team[] = [...INITIAL_TEAMS];
  private assets: Asset[] = [...INITIAL_ASSETS];
  private scans: Scan[] = [...INITIAL_SCANS];
  private findings: Finding[] = [...INITIAL_FINDINGS];
  private occurrences: Occurrence[] = [...INITIAL_OCCURRENCES];
  private statusChanges: StatusChange[] = [...INITIAL_STATUS_CHANGES];
  private aiOutputs: AiOutput[] = [];
  private vulnerabilities: Vulnerability[] = [...INITIAL_VULNERABILITIES];

  getTeams(): Team[] {
    return this.teams;
  }

  getAssets(actorTeamId: string): Asset[] {
    if (actorTeamId === 'all') return this.assets;
    return this.assets.filter((a) => a.teamId === actorTeamId);
  }

  createAsset(
    actorTeamId: string,
    payload: Omit<Asset, 'id' | 'createdAt'>
  ): Asset {
    assertTeamAccess(actorTeamId, payload.teamId);
    const created: Asset = {
      ...payload,
      id: `asset-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      createdAt: new Date().toISOString(),
    };
    this.assets = [created, ...this.assets];
    return created;
  }

  getFindings(
    actorTeamId: string,
    filters?: {
      assetId?: string;
      status?: string;
      riskLevel?: string;
      type?: string;
    }
  ): Finding[] {
    const allowedAssetIds = new Set(
      this.getAssets(actorTeamId).map((a) => a.id)
    );

    return this.findings.filter((f) => {
      if (!allowedAssetIds.has(f.assetId)) return false;
      if (filters?.assetId && f.assetId !== filters.assetId) return false;
      if (filters?.status && filters.status !== 'all' && f.status !== filters.status)
        return false;
      if (
        filters?.riskLevel &&
        filters.riskLevel !== 'all' &&
        f.riskLevel !== filters.riskLevel
      )
        return false;
      if (filters?.type && filters.type !== 'all' && f.type !== filters.type)
        return false;
      return true;
    });
  }

  getFindingById(actorTeamId: string, findingId: string): { finding: Finding; asset: Asset } {
    const finding = this.findings.find((f) => f.id === findingId);
    if (!finding) {
      throw new Error(`NOT_FOUND: Finding "${findingId}" không tồn tại.`);
    }
    const asset = this.assets.find((a) => a.id === finding.assetId);
    if (!asset) {
      throw new Error(`NOT_FOUND: Asset "${finding.assetId}" không tồn tại.`);
    }
    // Enforce Rule #7 service-level RBAC
    assertTeamAccess(actorTeamId, asset.teamId);
    return { finding, asset };
  }

  getOccurrences(actorTeamId: string): Occurrence[] {
    const allowedFindingIds = new Set(
      this.getFindings(actorTeamId).map((f) => f.id)
    );
    return this.occurrences.filter((o) => allowedFindingIds.has(o.findingId));
  }

  getScans(actorTeamId: string): Scan[] {
    const allowedAssetIds = new Set(
      this.getAssets(actorTeamId).map((a) => a.id)
    );
    return this.scans.filter((s) => allowedAssetIds.has(s.assetId));
  }

  getStatusChanges(actorTeamId: string): StatusChange[] {
    const allowedFindingIds = new Set(
      this.getFindings(actorTeamId).map((f) => f.id)
    );
    return this.statusChanges.filter((sc) =>
      allowedFindingIds.has(sc.findingId)
    );
  }

  getAiOutputs(actorTeamId: string): AiOutput[] {
    const allowedFindingIds = new Set(
      this.getFindings(actorTeamId).map((f) => f.id)
    );
    return this.aiOutputs.filter((ao) => allowedFindingIds.has(ao.findingId));
  }

  getVulnerabilities(): Vulnerability[] {
    return this.vulnerabilities;
  }

  recordAiOutput(actorTeamId: string, output: AiOutput): AiOutput {
    this.getFindingById(actorTeamId, output.findingId);
    this.aiOutputs = [output, ...this.aiOutputs];
    return output;
  }

  updateFindingStatus(
    actorTeamId: string,
    findingId: string,
    toStatus: FindingStatus,
    actor: string,
    reason: string,
    expiresAt?: Date | null
  ): { finding: Finding; statusChange: StatusChange } {
    const { finding } = this.getFindingById(actorTeamId, findingId);

    const { updatedFinding, statusChange } = transitionFindingStatus(
      {
        id: finding.id,
        assetId: finding.assetId,
        type: finding.type,
        fingerprint: finding.fingerprint,
        status: finding.status,
        reopened: finding.reopened,
      },
      toStatus,
      actor,
      reason,
      expiresAt
    );

    const merged: Finding = {
      ...finding,
      status: updatedFinding.status,
      reopened: updatedFinding.reopened,
    };

    this.findings = this.findings.map((f) => (f.id === findingId ? merged : f));
    this.statusChanges = [statusChange, ...this.statusChanges];

    return { finding: merged, statusChange };
  }

  /**
   * Ingests a full scan from Semgrep SARIF, Gitleaks JSON, or OSV-Scanner JSON.
   * Performs:
   * 1. RBAC ownership verification on Asset
   * 2. Report normalization & path sanitization (Rule #9) & secret hashing (Rule #1)
   * 3. Auto-Fixed & Reopened state transitions for existing findings of the same asset + type
   * 4. Upsert by unique (asset_id, fingerprint) and contextual SSVC risk scoring
   */
  ingestScan(actorTeamId: string, payload: IngestScanPayload): IngestScanSummary {
    const asset = this.assets.find((a) => a.id === payload.assetId);
    if (!asset) {
      throw new Error(`NOT_FOUND: Asset "${payload.assetId}" không tồn tại.`);
    }
    assertTeamAccess(actorTeamId, asset.teamId);

    let normalizedItems: NormalizedScanFinding[] = [];
    if (Array.isArray(payload.normalizedFindings)) {
      normalizedItems = payload.normalizedFindings;
    } else if (payload.rawReport !== undefined) {
      if (payload.scanner === 'semgrep') {
        normalizedItems = normalizeSemgrepSarif(payload.rawReport);
      } else if (payload.scanner === 'gitleaks') {
        normalizedItems = normalizeGitleaksJson(payload.rawReport);
      } else if (payload.scanner === 'osv-scanner') {
        normalizedItems = normalizeOsvScannerJson(payload.rawReport);
      }
    }

    const findingType: FindingType =
      payload.scanner === 'semgrep'
        ? 'sast'
        : payload.scanner === 'gitleaks'
        ? 'secret'
        : 'dependency';

    const scanId = `scan-${payload.scanner}-${Date.now()}`;
    const nowIso = new Date().toISOString();

    const scannedFingerprints = new Set(normalizedItems.map((i) => i.fingerprint));

    // Step 1: Run Auto-Fixed and Reopened diff for existing findings on this asset + type
    const diffResult = processScanDiffAutoFixed(
      this.findings.map((f) => ({
        id: f.id,
        assetId: f.assetId,
        type: f.type,
        fingerprint: f.fingerprint,
        status: f.status,
        reopened: f.reopened,
      })),
      asset.id,
      findingType,
      scannedFingerprints,
      scanId,
      payload.commitSha
    );

    const autoFixedCount = diffResult.statusChanges.filter(
      (sc) => sc.toStatus === 'fixed'
    ).length;
    const reopenedCount = diffResult.statusChanges.filter(
      (sc) => sc.fromStatus === 'fixed' && sc.toStatus === 'triaged'
    ).length;

    // Apply diff updates
    const diffMap = new Map(diffResult.updatedFindings.map((u) => [u.id, u]));
    this.findings = this.findings.map((f) => {
      const up = diffMap.get(f.id);
      return up ? { ...f, status: up.status, reopened: up.reopened } : f;
    });
    if (diffResult.statusChanges.length > 0) {
      this.statusChanges = [...diffResult.statusChanges, ...this.statusChanges];
    }

    // Step 2: Upsert findings by unique (assetId, fingerprint)
    let createdCount = 0;
    let updatedCount = 0;

    for (const item of normalizedItems) {
      const existing = this.findings.find(
        (f) => f.assetId === asset.id && f.fingerprint === item.fingerprint
      );

      if (existing) {
        updatedCount++;
        this.findings = this.findings.map((f) =>
          f.id === existing.id ? { ...f, lastSeen: nowIso } : f
        );
        this.occurrences = [
          {
            id: `occ-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
            findingId: existing.id,
            scanId,
            filePath: item.filePath,
            lineStart: item.lineStart,
            lineEnd: item.lineEnd,
            snippetHash: item.snippetHash,
          },
          ...this.occurrences,
        ];
      } else {
        createdCount++;
        const score = calculateRiskScore(item.signals, asset);
        const newFindingId = `f-${item.type}-${Date.now()}-${Math.random()
          .toString(36)
          .slice(2, 6)}`;

        const newFinding: Finding = {
          id: newFindingId,
          assetId: asset.id,
          type: item.type,
          fingerprint: item.fingerprint,
          ruleOrVulnId: item.ruleOrVulnId,
          title: item.title,
          status: 'new',
          riskLevel: score.riskLevel,
          riskReasons: score.riskReasons,
          firstSeen: nowIso,
          lastSeen: nowIso,
          slaDue: calculateSlaDueDate(score.slaDays)?.toISOString() || null,
          reopened: false,
          secretHash: item.secretHash,
          secretMasked: item.secretMasked,
        };

        this.findings = [newFinding, ...this.findings];
        this.occurrences = [
          {
            id: `occ-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
            findingId: newFindingId,
            scanId,
            filePath: item.filePath,
            lineStart: item.lineStart,
            lineEnd: item.lineEnd,
            snippetHash: item.snippetHash,
          },
          ...this.occurrences,
        ];
      }
    }

    const scanRecord: Scan = {
      id: scanId,
      assetId: asset.id,
      commitSha: payload.commitSha,
      branch: payload.branch || 'main',
      scanner: payload.scanner,
      scannerVersion: payload.scannerVersion,
      rulesVersion: payload.rulesVersion,
      status: 'completed',
      findingsCount: normalizedItems.length,
      startedAt: nowIso,
      completedAt: new Date().toISOString(),
    };

    this.scans = [scanRecord, ...this.scans];

    return {
      scan: scanRecord,
      createdCount,
      updatedCount,
      autoFixedCount,
      reopenedCount,
      findings: this.getFindings(actorTeamId, { assetId: asset.id }),
    };
  }
}

export const repository = new KestrixRepository();
