import {
  normalizePath,
  sha256,
  computeSastFingerprint,
  computeSecretFingerprint,
  computeDependencyFingerprint,
} from './fingerprint';
import { FindingType } from './types';
import { FindingSignals } from './scoring';

export interface NormalizedScanFinding {
  type: FindingType;
  fingerprint: string;
  ruleOrVulnId: string;
  title: string;
  filePath: string;
  lineStart?: number;
  lineEnd?: number;
  snippetHash?: string;
  secretHash?: string;
  secretMasked?: string;
  signals: FindingSignals;
}

/**
 * Service-layer RBAC guard (Security Rule #7)
 * Ensures every service operation verifies team ownership before returning or mutating data.
 */
export function assertTeamAccess(
  actorTeamId: string,
  resourceTeamId: string,
  isAdmin = false
): void {
  if (isAdmin || actorTeamId === 'all') return;
  if (!actorTeamId || actorTeamId !== resourceTeamId) {
    throw new Error(
      `FORBIDDEN_TEAM_ACCESS: Team "${actorTeamId}" không có quyền truy cập tài nguyên của team "${resourceTeamId}".`
    );
  }
}

/**
 * Normalizes Semgrep / Opengrep SARIF 2.1.0 output.
 * Rule from PLAN.md: Prioritize SARIF `partialFingerprints` when provided by scanner;
 * otherwise compute deterministic SHA-256 over ruleId + normalizedPath + snippet.
 */
export function normalizeSemgrepSarif(sarifJson: any): NormalizedScanFinding[] {
  const results: NormalizedScanFinding[] = [];
  const runs = Array.isArray(sarifJson?.runs) ? sarifJson.runs : [];

  for (const run of runs) {
    const runResults = Array.isArray(run?.results) ? run.results : [];
    for (const item of runResults) {
      const ruleId = String(item?.ruleId || 'semgrep.unknown-rule').trim();
      const messageText = String(
        item?.message?.text || `SAST finding from rule ${ruleId}`
      ).trim();

      const loc = item?.locations?.[0]?.physicalLocation;
      const rawUri = String(loc?.artifactLocation?.uri || 'unknown');
      const filePath = normalizePath(rawUri);
      const lineStart = typeof loc?.region?.startLine === 'number' ? loc.region.startLine : undefined;
      const lineEnd = typeof loc?.region?.endLine === 'number' ? loc.region.endLine : lineStart;
      const rawSnippet = String(loc?.region?.snippet?.text || messageText);
      const snippetHash = sha256(rawSnippet.trim());

      // Check SARIF partialFingerprints priority
      const partialFp =
        item?.partialFingerprints?.primaryLocationLineHash ||
        item?.partialFingerprints?.['semgrep/fingerprint/v1'];

      const fingerprint = partialFp
        ? `sarif:${normalizePath(rawUri)}:${String(partialFp)}`
        : computeSastFingerprint(ruleId, filePath, rawSnippet);

      const level = String(item?.level || 'warning').toUpperCase();
      const ruleSeverity: 'ERROR' | 'WARNING' | 'INFO' =
        level === 'ERROR' ? 'ERROR' : level === 'NOTE' ? 'INFO' : 'WARNING';

      const isTestPath = /(^|\/)(test|tests|__tests__|spec|mock)\//i.test(filePath);

      results.push({
        type: 'sast',
        fingerprint,
        ruleOrVulnId: ruleId,
        title: messageText.slice(0, 220),
        filePath,
        lineStart,
        lineEnd,
        snippetHash,
        signals: {
          type: 'sast',
          cweCategory: ruleId,
          isProductionPath: !isTestPath,
          ruleSeverity,
          ruleConfidence: ruleSeverity === 'ERROR' ? 'HIGH' : 'MEDIUM',
        },
      });
    }
  }

  return results;
}

/**
 * Normalizes Gitleaks JSON report.
 * Strictly enforces Security Rule #1: Raw secret is hashed with SHA-256 and masked to last 4 chars immediately.
 * Raw secret is never returned or stored.
 */
export function normalizeGitleaksJson(gitleaksJson: any): NormalizedScanFinding[] {
  const items = Array.isArray(gitleaksJson)
    ? gitleaksJson
    : Array.isArray(gitleaksJson?.findings)
    ? gitleaksJson.findings
    : [];

  const results: NormalizedScanFinding[] = [];

  for (const item of items) {
    const ruleId = String(item?.RuleID || item?.ruleId || 'gitleaks-generic-secret').trim();
    const description = String(
      item?.Description || item?.description || `Exposed secret (${ruleId})`
    ).trim();
    const rawFile = String(item?.File || item?.file || 'unknown');
    const filePath = normalizePath(rawFile);
    const lineStart = typeof item?.StartLine === 'number' ? item.StartLine : item?.lineStart;
    const lineEnd = typeof item?.EndLine === 'number' ? item.EndLine : lineStart;
    const rawSecret = String(item?.Secret || item?.secret || 'unknown-secret-value');

    const { fingerprint, secretHash, secretMasked } = computeSecretFingerprint(
      ruleId,
      filePath,
      rawSecret
    );

    results.push({
      type: 'secret',
      fingerprint,
      ruleOrVulnId: ruleId,
      title: `${description} in ${filePath}`,
      filePath,
      lineStart,
      lineEnd,
      secretHash,
      secretMasked,
      signals: {
        type: 'secret',
        secretActive: Boolean(item?.Verified ?? true),
        secretType: ruleId,
        isGitHistory: Boolean(item?.Commit && item?.Commit !== 'worktree'),
      },
    });
  }

  return results;
}

/**
 * Normalizes OSV-Scanner JSON report.
 * Fingerprint excludes package version so upgrading to a still-vulnerable version retains the same finding identity.
 */
export function normalizeOsvScannerJson(osvJson: any): NormalizedScanFinding[] {
  const results: NormalizedScanFinding[] = [];
  const scanResults = Array.isArray(osvJson?.results) ? osvJson.results : [];

  for (const sourceBlock of scanResults) {
    const rawPath = String(sourceBlock?.source?.path || 'package.json');
    const filePath = normalizePath(rawPath);
    const packages = Array.isArray(sourceBlock?.packages) ? sourceBlock.packages : [];

    for (const pkgEntry of packages) {
      const pkgName = String(pkgEntry?.package?.name || 'unknown-pkg');
      const ecosystem = String(pkgEntry?.package?.ecosystem || 'npm');
      const vulns = Array.isArray(pkgEntry?.vulnerabilities) ? pkgEntry.vulnerabilities : [];

      for (const vuln of vulns) {
        const vulnId = String(vuln?.id || 'OSV-UNKNOWN');
        const summary = String(
          vuln?.summary || `Dependency vulnerability ${vulnId} in ${pkgName}`
        );
        const fingerprint = computeDependencyFingerprint(
          ecosystem,
          pkgName,
          vulnId,
          filePath
        );

        const inKev = Boolean(vuln?.database_specific?.cisa_kev || vuln?.inKev);
        const epssScore =
          typeof vuln?.database_specific?.epss === 'number'
            ? vuln.database_specific.epss
            : 0.15;
        const cvssScore =
          typeof vuln?.database_specific?.cvss_score === 'number'
            ? vuln.database_specific.cvss_score
            : 7.8;

        results.push({
          type: 'dependency',
          fingerprint,
          ruleOrVulnId: vulnId,
          title: `${pkgName}: ${summary}`.slice(0, 220),
          filePath,
          signals: {
            type: 'dependency',
            inKev,
            reachable: Boolean(vuln?.reachable ?? true),
            epssScore,
            cvssScore,
          },
        });
      }
    }
  }

  return results;
}
